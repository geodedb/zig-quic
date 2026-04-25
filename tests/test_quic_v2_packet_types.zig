const std = @import("std");
const packet = @import("quic_packet");

const zero_keys = packet.InitialKeys{
    .key = .{0} ** 16,
    .iv = .{0} ** 12,
    .hp = .{0} ** 16,
};

test "QUIC v2 long header type mapping is version aware" {
    try std.testing.expectEqual(packet.LongHeaderPacketType.Initial, packet.longHeaderPacketType(packet.QUIC_V1, 0xc0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.ZeroRtt, packet.longHeaderPacketType(packet.QUIC_V1, 0xd0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.Handshake, packet.longHeaderPacketType(packet.QUIC_V1, 0xe0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.Retry, packet.longHeaderPacketType(packet.QUIC_V1, 0xf0).?);

    try std.testing.expectEqual(packet.LongHeaderPacketType.Retry, packet.longHeaderPacketType(packet.QUIC_V2, 0xc0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.Initial, packet.longHeaderPacketType(packet.QUIC_V2, 0xd0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.ZeroRtt, packet.longHeaderPacketType(packet.QUIC_V2, 0xe0).?);
    try std.testing.expectEqual(packet.LongHeaderPacketType.Handshake, packet.longHeaderPacketType(packet.QUIC_V2, 0xf0).?);
}

test "QUIC v2 Initial encoder uses v2 type bits and remains decodable" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11, 12 };
    const keys = packet.derive_initial_keys(true, &dcid).client;

    const payload = [_]u8{0x01} ** 32;
    const encoded = try packet.encodeInitialProtected(allocator, packet.QUIC_V2, &dcid, &scid, &[_]u8{}, 7, 2, &payload, keys);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(u8, 0x10), encoded[0] & 0x30);

    const decoded = try packet.decodeInitialProtected(allocator, encoded, keys);
    defer allocator.free(decoded.payload);
    try std.testing.expectEqual(packet.QUIC_V2, decoded.version);
}

test "QUIC v2 Handshake 0-RTT and Retry encoders use remapped type bits" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 1, 2, 3, 4 };
    const scid = [_]u8{ 5, 6, 7, 8 };
    const odcid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    const token = [_]u8{ 0xaa, 0xbb, 0xcc };

    const handshake = try packet.encodeHandshakeProtected(allocator, packet.QUIC_V2, &dcid, &scid, 3, 2, &[_]u8{0x01}, zero_keys);
    defer allocator.free(handshake);
    try std.testing.expectEqual(@as(u8, 0x30), handshake[0] & 0x30);

    const zero_rtt = try packet.encode0RTTProtected(allocator, packet.QUIC_V2, &dcid, &scid, 4, 2, &[_]u8{0x01}, zero_keys);
    defer allocator.free(zero_rtt);
    try std.testing.expectEqual(@as(u8, 0x20), zero_rtt[0] & 0x30);
    const decoded_zero_rtt = try packet.decode0RTTProtected(allocator, zero_rtt, zero_keys);
    defer allocator.free(decoded_zero_rtt.payload);
    try std.testing.expectEqual(@as(u64, 4), decoded_zero_rtt.packet_number);

    const retry = try packet.encodeRetry(allocator, packet.QUIC_V2, &dcid, &scid, &odcid, &token);
    defer allocator.free(retry);
    try std.testing.expectEqual(@as(u8, 0x00), retry[0] & 0x30);
    try std.testing.expect(packet.verifyRetry(&odcid, retry));
}
