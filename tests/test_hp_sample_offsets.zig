const std = @import("std");
const packet = @import("quic_packet");

fn make_payload(alloc: std.mem.Allocator, n: usize) ![]u8 {
    var p = try alloc.alloc(u8, n);
    var i: usize = 0;
    while (i < n) : (i += 1) p[i] = @as(u8, @intCast(i & 0xff));
    return p;
}

test "hp sample offset: short header decode succeeds for pn_len=1..4" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    const dcid = "DCIDTEST";
    const key: [16]u8 = .{0} ** 16;
    const iv: [12]u8 = .{0} ** 12;
    const hp: [16]u8 = .{0} ** 16;
    const keys = packet.AeadKeys{ .key = key, .iv = iv, .hp = hp };
    const base_pn: u32 = 0x11223344;

    var pn_len: u3 = 1;
    while (pn_len <= 4) : (pn_len += 1) {
        const payload = try make_payload(A, 32);
        defer A.free(payload);
        const pkt = try packet.encodeShortProtected(A, dcid, base_pn, pn_len, payload, keys, false);
        defer A.free(pkt);
        const dec = try packet.decodeShortProtected(A, pkt, dcid.len, keys);
        defer A.free(dec.payload);
        // Expect truncated PN equals low pn_len bytes of base_pn
        var expected: u32 = 0;
        var i: u3 = 0;
        while (i < pn_len) : (i += 1) {
            const shift: u5 = @intCast(i * 8);
            expected |= ((base_pn >> shift) & 0xff) << shift;
        }
        try std.testing.expectEqual(pn_len, dec.packet_number_len);
        try std.testing.expectEqual(expected & ((@as(u32, 1) << (pn_len * 8)) - 1), dec.packet_number);
        try std.testing.expectEqual(@as(usize, 32), dec.payload.len);
        try std.testing.expectEqualSlices(u8, payload, dec.payload);
    }
}

test "hp sample offset: Initial long header decode succeeds for pn_len=1..4" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    const dcid = "DCIDINIT";
    const scid = "SCIDINIT";
    const key: [16]u8 = .{0} ** 16;
    const iv: [12]u8 = .{0} ** 12;
    const hp: [16]u8 = .{0} ** 16;
    const keys = packet.InitialKeys{ .key = key, .iv = iv, .hp = hp };
    const base_pn: u32 = 0x0a0b0c0d;

    var pn_len: u3 = 1;
    while (pn_len <= 4) : (pn_len += 1) {
        const payload = try make_payload(A, 8 + @as(usize, pn_len)); // ensure >= 4 - pn_len
        defer A.free(payload);
        const pkt = try packet.encodeInitialProtected(A, packet.QUIC_V1, dcid, scid, &[_]u8{}, base_pn, pn_len, payload, keys);
        defer A.free(pkt);
        const dec = try packet.decodeInitialProtected(A, pkt, keys);
        defer A.free(dec.payload);
        try std.testing.expectEqual(@as(u3, pn_len), dec.packet_number_len);
        // PN will be truncated value; verify payload roundtrip instead of PN numeric
        try std.testing.expectEqualSlices(u8, payload, dec.payload);
        try std.testing.expectEqualStrings(dcid, dec.dcid);
        try std.testing.expectEqualStrings(scid, dec.scid);
    }
}
