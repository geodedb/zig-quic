const std = @import("std");
const packet = @import("quic_packet");
const crypto = @import("quic_crypto");
const ks = @import("quic_tls");

test "0RTT packet encode and decode" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const payload = "Early data from 0-RTT";
    const pn: u64 = 42;

    // Encode 0-RTT packet
    const encoded = try packet.encode0RTTProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        pn,
        2, // pn_len
        payload,
        .{
            .key = [_]u8{0x01} ** 16,
            .iv = [_]u8{0x02} ** 12,
            .hp = [_]u8{0x03} ** 16,
        },
    );
    defer alloc.free(encoded);

    // Verify packet structure
    try std.testing.expect(encoded.len > 20);
    try std.testing.expect((encoded[0] & 0x80) != 0); // Long header
    try std.testing.expect(((encoded[0] >> 4) & 0x03) == 0x01); // 0-RTT type

    // Decode 0-RTT packet
    const decoded = try packet.decode0RTTProtected(alloc, encoded, .{
        .key = [_]u8{0x01} ** 16,
        .iv = [_]u8{0x02} ** 12,
        .hp = [_]u8{0x03} ** 16,
    });
    defer alloc.free(decoded.payload);

    // Verify decoded content
    try std.testing.expectEqual(pn, decoded.packet_number);
    try std.testing.expectEqualStrings(payload, decoded.payload);
}

test "0RTT with different packet number lengths" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x09, 0x0a, 0x0b, 0x0c };

    // Test with different PN lengths
    const pn_lengths = [_]u8{ 1, 2, 3, 4 };
    const packet_numbers = [_]u64{ 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF };

    for (pn_lengths, packet_numbers) |pn_len, pn| {
        const payload = "Test payload";

        const encoded = try packet.encode0RTTProtected(
            alloc,
            packet.QUIC_V1,
            &dcid,
            &scid,
            pn,
            pn_len,
            payload,
            .{
                .key = [_]u8{0xaa} ** 16,
                .iv = [_]u8{0xbb} ** 12,
                .hp = [_]u8{0xcc} ** 16,
            },
        );
        defer alloc.free(encoded);

        const decoded = try packet.decode0RTTProtected(alloc, encoded, .{
            .key = [_]u8{0xaa} ** 16,
            .iv = [_]u8{0xbb} ** 12,
            .hp = [_]u8{0xcc} ** 16,
        });
        defer alloc.free(decoded.payload);

        // Verify truncated packet number is correctly reconstructed
        const mask: u64 = (@as(u64, 1) << @intCast(pn_len * 8)) - 1;
        const truncated_pn = pn & mask;
        try std.testing.expectEqual(truncated_pn, decoded.packet_number);
        try std.testing.expectEqualStrings(payload, decoded.payload);
    }
}

test "0RTT decryption failure with wrong keys" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const scid = [_]u8{ 0xca, 0xfe, 0xba, 0xbe };

    // Encode with correct keys
    const encoded = try packet.encode0RTTProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        123,
        2,
        "Secret data",
        .{
            .key = [_]u8{0x11} ** 16,
            .iv = [_]u8{0x22} ** 12,
            .hp = [_]u8{0x33} ** 16,
        },
    );
    defer alloc.free(encoded);

    // Try to decode with wrong keys - should fail
    const result = packet.decode0RTTProtected(alloc, encoded, .{
        .key = [_]u8{0x44} ** 16,
        .iv = [_]u8{0x55} ** 12,
        .hp = [_]u8{0x66} ** 16,
    });
    try std.testing.expectError(error.DecryptionFailed, result);
}
