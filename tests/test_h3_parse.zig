const std = @import("std");
const h3 = @import("h3_server");

fn encVar(v: u64, out: []u8) usize {
    if (v < (1 << 6)) {
        out[0] = @as(u8, @intCast(v));
        return 1;
    }
    if (v < (1 << 14)) {
        out[0] = @as(u8, @intCast(v >> 8)) | 0b01 << 6;
        out[1] = @as(u8, @intCast(v & 0xff));
        return 2;
    }
    if (v < (1 << 30)) {
        out[0] = @as(u8, @intCast(v >> 24)) | 0b10 << 6;
        out[1] = @as(u8, @intCast((v >> 16) & 0xff));
        out[2] = @as(u8, @intCast((v >> 8) & 0xff));
        out[3] = @as(u8, @intCast(v & 0xff));
        return 4;
    }
    return 0;
}

fn encPref(val: u64, out: []u8, prefix_bits: u3) usize {
    const max = (@as(u8, 1) << (8 - prefix_bits)) - 1;
    if (val < max) {
        out[0] |= @as(u8, @intCast(val));
        return 1;
    }
    out[0] |= max;
    var k: usize = 1;
    var rem = val - max;
    while (true) {
        var b: u8 = @intCast(rem & 0x7f);
        rem >>= 7;
        if (rem != 0) b |= 0x80;
        out[k] = b;
        k += 1;
        if (rem == 0) break;
    }
    return k;
}

fn makeHeadersForPath(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0);
    try blk.append(0);
    try blk.append(0b0101_0000);
    var namebuf: [8]u8 = .{0} ** 8;
    namebuf[0] = 0;
    const nk = encPref(1, namebuf[0..], 4);
    try blk.appendSlice(namebuf[0..nk]);
    var vbuf: [64]u8 = .{0} ** 64;
    vbuf[0] = 0;
    var off: usize = 0;
    off = encPref(path.len, vbuf[0..], 7);
    try blk.appendSlice(vbuf[0..off]);
    try blk.appendSlice(path);
    const block = try blk.toOwnedSlice();

    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    return try fr.toOwnedSlice();
}

fn makeHeadersForPathHuffman(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0);
    try blk.append(0);
    try blk.append(0b0101_0000);
    var namebuf: [8]u8 = .{0} ** 8;
    namebuf[0] = 0;
    const nk = encPref(1, namebuf[0..], 4);
    try blk.appendSlice(namebuf[0..nk]);
    const enc = try h3.H3Server.hpackHuffmanEncode(alloc, path);
    defer alloc.free(enc);
    var vbuf: [64]u8 = .{0} ** 64;
    vbuf[0] = 0x80;
    var off: usize = 0;
    off = encPref(enc.len, vbuf[0..], 7);
    try blk.appendSlice(vbuf[0..off]);
    try blk.appendSlice(enc);
    const block = try blk.toOwnedSlice();

    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    return try fr.toOwnedSlice();
}

fn makeHeadersLiteralName(alloc: std.mem.Allocator, name: []const u8, value: []const u8) ![]u8 {
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0);
    try blk.append(0);
    var b: u8 = 0b0010_0000;
    try blk.append(b);
    var nbuf: [64]u8 = .{0} ** 64;
    nbuf[0] = 0;
    var k: usize = 0;
    k = encPref(name.len, nbuf[0..], 3);
    try blk.appendSlice(nbuf[0..k]);
    try blk.appendSlice(name);
    var vbuf: [64]u8 = .{0} ** 64;
    vbuf[0] = 0;
    var k2: usize = 0;
    k2 = encPref(value.len, vbuf[0..], 7);
    try blk.appendSlice(vbuf[0..k2]);
    try blk.appendSlice(value);
    const block = try blk.toOwnedSlice();

    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    return try fr.toOwnedSlice();
}

test "h3 parsePathFromHeadersFrame extracts path" {
    const alloc = std.testing.allocator;
    const frame = try makeHeadersForPath(alloc, "/foo.html");
    defer alloc.free(frame);
    var out: [64]u8 = undefined;
    const p = h3.H3Server.parsePathFromHeadersFrame(frame, out[0..]) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, "/foo.html"));
}

test "h3 parses Huffman-coded :path value" {
    const alloc = std.testing.allocator;
    const frame = try makeHeadersForPathHuffman(alloc, "/index.html");
    defer alloc.free(frame);
    var out: [64]u8 = undefined;
    const p = h3.H3Server.parsePathFromHeadersFrame(frame, out[0..]) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, "/index.html"));
}

test "h3 parses literal-name/literal-value :path" {
    const alloc = std.testing.allocator;
    const frame = try makeHeadersLiteralName(alloc, ":path", "/bar");
    defer alloc.free(frame);
    var out: [32]u8 = undefined;
    const p = h3.H3Server.parsePathFromHeadersFrame(frame, out[0..]) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, "/bar"));
}

test "h3 parses Huffman-coded literal name :path" {
    const alloc = std.testing.allocator;
    const name = ":path";
    const value = "/huff";
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0);
    try blk.append(0);
    var hdrb: u8 = 0b0010_1000; // 001 N H, N=0, H=1
    try blk.append(hdrb);
    const encn = try h3.H3Server.hpackHuffmanEncode(alloc, name);
    defer alloc.free(encn);
    var nbuf: [64]u8 = .{0} ** 64;
    nbuf[0] = 0;
    var k: usize = 0;
    k = encPref(encn.len, nbuf[0..], 3);
    try blk.appendSlice(nbuf[0..k]);
    try blk.appendSlice(encn);
    var vbuf: [64]u8 = .{0} ** 64;
    vbuf[0] = 0; // value not huffman
    var k2: usize = 0;
    k2 = encPref(value.len, vbuf[0..], 7);
    try blk.appendSlice(vbuf[0..k2]);
    try blk.appendSlice(value);
    const block = try blk.toOwnedSlice();

    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    const frame = try fr.toOwnedSlice();
    defer alloc.free(frame);
    var out: [32]u8 = undefined;
    const p = h3.H3Server.parsePathFromHeadersFrame(frame, out[0..]) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, value));
}

test "h3 captures method and authority into ReqState" {
    const alloc = std.testing.allocator;
    // Build a block with literal :method POST and literal :authority example
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0); // RIC
    try blk.append(0); // Base
    // literal name ":method"
    try blk.append(0b0010_0000); // 001 N H, N=0,H=0
    var nbuf: [64]u8 = .{0} ** 64;
    nbuf[0] = 0;
    var nk: usize = 0;
    nk = encPref(":method".len, nbuf[0..], 3);
    try blk.appendSlice(nbuf[0..nk]);
    try blk.appendSlice(":method");
    var v1: [64]u8 = .{0} ** 64;
    v1[0] = 0;
    var vk1: usize = 0;
    vk1 = encPref("POST".len, v1[0..], 7);
    try blk.appendSlice(v1[0..vk1]);
    try blk.appendSlice("POST");
    // literal name ":authority"
    try blk.append(0b0010_0000);
    nbuf[0] = 0;
    nk = encPref(":authority".len, nbuf[0..], 3);
    try blk.appendSlice(nbuf[0..nk]);
    try blk.appendSlice(":authority");
    var v2: [64]u8 = .{0} ** 64;
    v2[0] = 0;
    var vk2: usize = 0;
    vk2 = encPref("example".len, v2[0..], 7);
    try blk.appendSlice(v2[0..vk2]);
    try blk.appendSlice("example");
    // literal name ":path"
    try blk.append(0b0010_0000);
    nbuf[0] = 0;
    nk = encPref(":path".len, nbuf[0..], 3);
    try blk.appendSlice(nbuf[0..nk]);
    try blk.appendSlice(":path");
    var v3: [64]u8 = .{0} ** 64;
    v3[0] = 0;
    var vk3: usize = 0;
    vk3 = encPref("/x".len, v3[0..], 7);
    try blk.appendSlice(v3[0..vk3]);
    try blk.appendSlice("/x");
    const block = try blk.toOwnedSlice();

    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    const frame = try fr.toOwnedSlice();
    defer alloc.free(frame);
    var out: [32]u8 = undefined;
    var rs: h3.H3Server.ReqState = .{};
    const p = h3.H3Server.parseReqFromHeadersFrame(frame, out[0..], &rs) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, "/x"));
    try std.testing.expect(std.mem.eql(u8, rs.method, "POST"));
    try std.testing.expect(std.mem.eql(u8, rs.authority, "example"));
}

test "h3 parses post-base name reference (skip)" {
    const alloc = std.testing.allocator;
    // Minimal block: RIC=0, Base=0, Indexed with post-base index (0001 idx=0) then a literal with post-base name reference (0000 N idx=0) with value "/"
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    try blk.append(0);
    try blk.append(0);
    // Indexed with post-base index: 0001 + index=0
    try blk.append(0b0001_0000);
    // Literal with post-base name reference: 0000 N nameidx(3+)
    try blk.append(0b0000_0000);
    // Value literal (H=0, len=1, "/")
    var vbuf: [8]u8 = .{0} ** 8;
    vbuf[0] = 0; // H=0
    var vk: usize = 0;
    vk = encPref(1, vbuf[0..], 7);
    try blk.appendSlice(vbuf[0..vk]);
    try blk.append('/');
    const block = try blk.toOwnedSlice();
    var fr = std.ArrayList(u8).init(alloc);
    defer fr.deinit();
    var hdr: [16]u8 = .{0} ** 16;
    var i: usize = 0;
    i += encVar(0x01, hdr[i..]);
    i += encVar(block.len, hdr[i..]);
    try fr.appendSlice(hdr[0..i]);
    try fr.appendSlice(block);
    const frame = try fr.toOwnedSlice();
    defer alloc.free(frame);
    var rs: h3.H3Server.ReqState = .{};
    var out: [8]u8 = undefined;
    _ = h3.H3Server.parseReqFromHeadersFrame(frame, out[0..], &rs) orelse null;
    // We only assert that parsing does not crash on post-base forms (we skipped these entries)
    try std.testing.expect(true);
}
