const std = @import("std");
const pkt = @import("quic_packet");

test "vn_decode_and_downgrade_protection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = "abcdef";
    const scid = "1234";
    const versions = [_]u32{ pkt.QUIC_V1, pkt.QUIC_V2 };
    const buf = try pkt.encodeVersionNegotiation(alloc, dcid, scid, &versions);
    defer alloc.free(buf);

    const vn = try pkt.decodeVersionNegotiation(alloc, buf);
    defer alloc.free(vn.versions);

    try std.testing.expectEqualStrings(dcid, vn.dcid);
    try std.testing.expectEqualStrings(scid, vn.scid);
    try std.testing.expectEqual(@as(usize, 2), vn.versions.len);
    try std.testing.expect(vn.versions[0] == pkt.QUIC_V1 or vn.versions[0] == pkt.QUIC_V2);
    try std.testing.expect(vn.versions[1] == pkt.QUIC_V1 or vn.versions[1] == pkt.QUIC_V2);

    // Downgrade protection: if VN lists our attempted version, ignore VN
    try std.testing.expect(!pkt.shouldAcceptVersionNegotiation(pkt.QUIC_V1, vn.versions));
    // If original version is not present, accept VN
    try std.testing.expect(pkt.shouldAcceptVersionNegotiation(0x0a0a0a0a, vn.versions));
}

test "vn_malformed_versions_length" {
    // Build a bogus VN with versions length not multiple of 4
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const w = buf.writer(std.testing.allocator);
    try w.writeByte(0x80);
    try w.writeAll(&[_]u8{ 0, 0, 0, 0 });
    try w.writeByte(2); // dcid len
    try w.writeAll("aa");
    try w.writeByte(2); // scid len
    try w.writeAll("bb");
    try w.writeByte(0x12); // one extra byte -> not multiple of 4
    const res = pkt.decodeVersionNegotiation(std.testing.allocator, buf.items);
    try std.testing.expectError(error.MalformedVersions, res);
}
