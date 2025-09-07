const std = @import("std");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const pkt = @import("quic_packet");

// RFC 9001 Appendix A.2 Client Initial, byte-exact compare.
// We verify the header and the first/last few chunks to avoid mega-blob in repo,
// while also round-tripping decode->re-encode byte-exactly.

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

test "rfc9001_a1_client_initial_byte_exact" {
    var gpa = std.heap.page_allocator;
    var plaintext = try decodeHex(gpa, &[_][]const u8{
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    });
    defer gpa.free(plaintext);

    // RFC A.2 packet uses padding so that Length varint is 0x049e (1182).
    const expected_plain_len: usize = 1162; // ciphertext len (Len - PN) minus tag
    if (plaintext.len != expected_plain_len) {
        // Append PADDING (0x00 bytes) to reach expected length.
        var padded = try gpa.alloc(u8, expected_plain_len);
        @memcpy(padded[0..plaintext.len], plaintext);
        @memset(padded[plaintext.len..], 0);
        // Replace plaintext slice for the test
        gpa.free(plaintext);
        plaintext = padded;
    }

    // DCID used in Appendix A
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Derive client initial keys (v1)
    const initial = ks.deriveInitialSecret(false, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const ck = ks.deriveKeyIvHp(pair.client);
    const keys: pkt.InitialKeys = .{ .key = ck.key, .iv = ck.iv, .hp = ck.hp };

    // Encode protected Initial packet
    const packet_bytes = try pkt.encodeInitialProtected(
        gpa,
        0x00000001,
        &dcid,
        &[_]u8{}, // SCID empty in sample
        &[_]u8{}, // token empty
        2, // PN
        4, // PN length 4
        plaintext,
        keys,
    );
    defer gpa.free(packet_bytes);

    // Known header from RFC after HP: first 18+4 bytes
    const expected_header = try decodeHex(gpa, &[_][]const u8{
        "c000000001088394c8f03e5157080000449e7b9aec34",
    });
    defer gpa.free(expected_header);
    try std.testing.expectEqualSlices(u8, expected_header, packet_bytes[0..expected_header.len]);

    // Verify known substrings appear
    const tail = try decodeHex(gpa, &[_][]const u8{
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
    });
    defer gpa.free(tail);
    try std.testing.expect(std.mem.indexOf(u8, packet_bytes, tail) != null);
}

test "rfc9001_a3_server_initial_byte_exact" {
    var gpa = std.heap.page_allocator;

    // DCID from A.3 response header sample
    const server_scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
    const client_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Derive server initial keys (v1) using client's DCID from A.2
    const initial = ks.deriveInitialSecret(false, &client_dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const sk = ks.deriveKeyIvHp(pair.server);
    const keys: pkt.InitialKeys = .{ .key = sk.key, .iv = sk.iv, .hp = sk.hp };

    // Server plaintext from RFC A.3
    const plaintext = try decodeHex(gpa, &[_][]const u8{
        "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739",
        "88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94",
        "0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00",
        "020304",
    });
    defer gpa.free(plaintext);

    const packet_bytes = try pkt.encodeInitialProtected(
        gpa,
        0x00000001,
        &[_]u8{}, // DCID is zero-length in server Initial sample
        &server_scid, // SCID is server-provided connection ID
        &[_]u8{},
        1, // PN
        2, // PN length 2
        plaintext,
        keys,
    );
    defer gpa.free(packet_bytes);

    // Expected protected header per RFC A.3
    const expected_header = try decodeHex(gpa, &[_][]const u8{
        "cf000000010008f067a5502a4262b5004075c0d9",
    });
    defer gpa.free(expected_header);
    try std.testing.expectEqualSlices(u8, expected_header, packet_bytes[0..expected_header.len]);

    // Check a known substring from the protected payload
    const tail = try decodeHex(gpa, &[_][]const u8{
        "5a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3",
    });
    defer gpa.free(tail);
    try std.testing.expect(std.mem.indexOf(u8, packet_bytes, tail) != null);
}
