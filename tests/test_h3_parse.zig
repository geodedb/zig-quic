const std = @import("std");
const h3 = @import("h3_server");

fn encVar(v: u64, out: []u8) usize {
    if (v < (1 << 6)) { out[0] = @as(u8, @intCast(v)); return 1; }
    if (v < (1 << 14)) { out[0] = @as(u8, @intCast(v >> 8)) | 0b01 << 6; out[1] = @as(u8, @intCast(v & 0xff)); return 2; }
    if (v < (1 << 30)) { out[0] = @as(u8, @intCast(v >> 24)) | 0b10 << 6; out[1] = @as(u8, @intCast((v >> 16) & 0xff)); out[2] = @as(u8, @intCast((v >> 8) & 0xff)); out[3] = @as(u8, @intCast(v & 0xff)); return 4; }
    return 0;
}

fn encPref(val: u64, out: []u8, prefix_bits: u3) usize {
    const max = (@as(u8, 1) << (8 - prefix_bits)) - 1;
    if (val < max) { out[0] |= @as(u8, @intCast(val)); return 1; }
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

// Build a minimal HEADERS frame encoding a header block with RIC=0, Base=0 and
// :path "/index.html" encoded as literal-with-name-reference to static name :path (idx=1).
fn makeHeadersForPath(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    var blk = std.ArrayList(u8).init(alloc);
    defer blk.deinit();
    // RIC=0, Base=0
    try blk.append(0);
    try blk.append(0);
    // Literal with name reference (01 N T ...), N=0, T=1 (static), name idx=1 (:path)
    try blk.append(0b0101_0000);
    var namebuf: [8]u8 = .{0} ** 8;
    namebuf[0] = 0;
    const nk = encPref(1, namebuf[0..], 4);
    try blk.appendSlice(namebuf[0..nk]);
    // value literal (8-bit prefix, no Huffman)
    var vbuf: [64]u8 = .{0} ** 64;
    vbuf[0] = 0; // H=0
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

test "h3 parsePathFromHeadersFrame extracts path" {
    const alloc = std.testing.allocator;
    const frame = try makeHeadersForPath(alloc, "/foo.html");
    defer alloc.free(frame);
    const p = h3.H3Server.parsePathFromHeadersFrame(frame) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.eql(u8, p, "/foo.html"));
}
