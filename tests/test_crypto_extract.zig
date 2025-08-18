const std = @import("std");
const pkt = @import("quic_packet");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const frame = @import("quic_frame");

fn decodeHex(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len / 2);
    var j: usize = 0;
    var i: usize = 0;
    while (i + 1 < s.len) : (i += 2) {
        if (s[i] == ' ' or s[i] == '\n') continue;
        const hi = try std.fmt.charToDigit(s[i], 16);
        const lo = try std.fmt.charToDigit(s[i + 1], 16);
        out[j] = @as(u8, @intCast(hi * 16 + lo));
        j += 1;
    }
    return out[0..j];
}

// Use RFC 9001 A.2 client initial; decrypt and ensure we can decode a CRYPTO frame at offset 0
// and the prefix matches ClientHello handshake bytes ("\x01\x00\x00\xed\x03\x03...")
// This validates endpoint/packet/frame integration for Initial decrypt + CRYPTO extraction.
test "tls_key_schedule_kat: crypto extract from A.2 client initial" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Construct the same protected packet our RFC A.2 test builds
    const dcid = try decodeHex(alloc, "8394c8f03e515708");
    defer alloc.free(dcid);
    const initial = ks.deriveInitialSecret(false, dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const ck = ks.deriveKeyIvHp(pair.client);
    const keys: pkt.InitialKeys = .{ .key = ck.key, .iv = ck.iv, .hp = ck.hp };

    const plaintext = try decodeHex(alloc, "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff");
    defer alloc.free(plaintext);

    const packet_bytes = try pkt.encodeInitialProtected(alloc, 0x00000001, dcid, &[_]u8{}, &[_]u8{}, 2, 4, plaintext, keys);
    defer alloc.free(packet_bytes);

    // Now decode protected packet using client-initial keys (server uses these to decrypt client Initials)
    const ck2 = ks.deriveKeyIvHp(pair.client);
    const server_keys: pkt.InitialKeys = .{ .key = ck2.key, .iv = ck2.iv, .hp = ck2.hp };
    const decoded = try pkt.decodeInitialProtected(alloc, packet_bytes, server_keys);
    defer alloc.free(decoded.payload);

    // First frame should be CRYPTO with offset 0
    const fr = try frame.decodeOne(decoded.payload);
    try std.testing.expectEqual(@as(usize, 0), fr.f.crypto.offset);
    // Check first 6 bytes of client hello: 01 00 00 ed 03 03
    try std.testing.expectEqualSlices(u8, fr.f.crypto.data[0..6], &[_]u8{ 0x01, 0x00, 0x00, 0xed, 0x03, 0x03 });
}
