const std = @import("std");
const packet = @import("quic_packet");
const varint = @import("quic_varint");

fn zeroInitialKeys() packet.InitialKeys {
    return .{
        .key = [_]u8{0} ** 16,
        .iv = [_]u8{0} ** 12,
        .hp = [_]u8{0} ** 16,
    };
}

fn zero0RttKeys() struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    return .{
        .key = [_]u8{0} ** 16,
        .iv = [_]u8{0} ** 12,
        .hp = [_]u8{0} ** 16,
    };
}

fn expectLen(result: varint.Error!struct { n: usize, value: u64 }, expected_n: usize, expected_value: u64) !void {
    const decoded = try result;
    try std.testing.expectEqual(expected_n, decoded.n);
    try std.testing.expectEqual(expected_value, decoded.value);
}

// RFC 9000 §17.2 requires long-header Length fields to use the minimum-length varint encoding.
// This suite verifies that each encode helper emits minimal encodings for small payloads.

test "encodeInitialProtected uses minimal Length varint" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const payload = [_]u8{0xAA};
    const pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &[_]u8{0x11},
        &[_]u8{},
        &[_]u8{},
        1,
        1,
        payload[0..],
        zeroInitialKeys(),
    );
    defer alloc.free(pkt);

    var idx: usize = 0;
    idx += 1; // first byte
    idx += 4; // version
    const dcid_len = pkt[idx];
    idx += 1 + dcid_len;
    const scid_len = pkt[idx];
    idx += 1 + scid_len;
    const token_dec = varint.decode(pkt[idx..]) catch unreachable;
    try std.testing.expectEqual(@as(usize, 1), token_dec.n);
    try std.testing.expectEqual(@as(u64, 0), token_dec.value);
    idx += token_dec.n;
    try expectLen(varint.decode(pkt[idx..]), 1, payload.len + 16 + 1);
}

test "encodeHandshakeProtected uses minimal Length varint" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const payload = [_]u8{0xBB};
    const pkt = try packet.encodeHandshakeProtected(
        alloc,
        packet.QUIC_V1,
        &[_]u8{},
        &[_]u8{},
        1,
        1,
        payload[0..],
        zeroInitialKeys(),
    );
    defer alloc.free(pkt);

    var idx: usize = 0;
    idx += 1; // first byte
    idx += 4; // version
    const dcid_len = pkt[idx];
    idx += 1 + dcid_len;
    const scid_len = pkt[idx];
    idx += 1 + scid_len;
    try expectLen(varint.decode(pkt[idx..]), 1, payload.len + 16 + 1);
}

test "encode0RTTProtected uses minimal Length varint" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const payload = [_]u8{0xCC};
    const pkt = try packet.encode0RTTProtected(
        alloc,
        packet.QUIC_V1,
        &[_]u8{},
        &[_]u8{},
        1,
        1,
        payload[0..],
        zero0RttKeys(),
    );
    defer alloc.free(pkt);

    var idx: usize = 0;
    idx += 1; // first byte
    idx += 4; // version
    const dcid_len = pkt[idx];
    idx += 1 + dcid_len;
    const scid_len = pkt[idx];
    idx += 1 + scid_len;
    try expectLen(varint.decode(pkt[idx..]), 1, payload.len + 16 + 1);
}
