const std = @import("std");
const ks = @import("quic_tls");
const pkt = @import("quic_packet");

// RFC 9001 Appendix A.3 Server Initial, byte-exact compare of header and a known tail chunk.

fn hexToBytes(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = try std.fmt.parseInt(u8, s[i * 2 .. i * 2 + 1], 16);
        const lo = try std.fmt.parseInt(u8, s[i * 2 + 1 .. i * 2 + 2], 16);
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn decodeHex(alloc: std.mem.Allocator, multi: []const []const u8) ![]u8 {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(alloc);
    for (multi) |line| {
        var j: usize = 0;
        while (j < line.len) : (j += 1) {
            const c = line[j];
            if (c == ' ' or c == '\n' or c == '\r' or c == '\t') continue;
            const start = j;
            var k = j;
            while (k < line.len and line[k] != ' ') : (k += 1) {}
            const chunk = line[start..k];
            if (chunk.len > 0) {
                const b = try hexToBytes(alloc, chunk);
                defer alloc.free(b);
                try buf.appendSlice(alloc, b);
            }
            j = k;
        }
    }
    return buf.toOwnedSlice(alloc);
}

test "rfc9001_a3_server_initial_byte_exact" {
    var gpa = std.heap.page_allocator;

    // Server payload (ACK + CRYPTO), no padding
    const plaintext = try decodeHex(gpa, &[_][]const u8{
        "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739",
        "88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94",
        "0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00",
        "020304",
    });
    defer gpa.free(plaintext);

    // Initial secrets derived from client's Initial DCID (Appendix A.2)
    const client_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const initial = ks.deriveInitialSecret(false, &client_dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const sk = ks.deriveKeyIvHp(pair.server);
    const keys: pkt.InitialKeys = .{ .key = sk.key, .iv = sk.iv, .hp = sk.hp };

    // Server header fields per RFC:
    // DCID length = 0, SCID length = 8 with new connection ID below.
    const dcid_empty = [_]u8{};
    const scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

    const packet_bytes = try pkt.encodeInitialProtected(
        gpa,
        0x00000001, // version v1
        &dcid_empty,
        &scid,
        &[_]u8{}, // token empty
        1, // PN
        2, // PN length 2
        plaintext,
        keys,
    );
    defer gpa.free(packet_bytes);

    // Expected protected header (including PN bytes after masking)
    const expected_header = try decodeHex(gpa, &[_][]const u8{
        "cf000000010008f067a5502a4262b5004075c0d9",
    });
    defer gpa.free(expected_header);
    try std.testing.expectEqualSlices(u8, expected_header, packet_bytes[0..expected_header.len]);

    // Verify known ending bytes appear
    const tail = try decodeHex(gpa, &[_][]const u8{"2158407dd074ee"});
    defer gpa.free(tail);
    try std.testing.expect(std.mem.indexOf(u8, packet_bytes, tail) != null);
}
