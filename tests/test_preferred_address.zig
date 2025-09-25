const std = @import("std");
const tp = @import("quic_transport_params");

test "preferred address parsing" {
    // Construct a valid preferred address
    var data: [256]u8 = undefined;
    var pos: usize = 0;

    // IPv4 address: 192.168.1.100
    data[pos] = 192;
    data[pos + 1] = 168;
    data[pos + 2] = 1;
    data[pos + 3] = 100;
    pos += 4;

    // IPv4 port: 4433
    data[pos] = 0x11;
    data[pos + 1] = 0x51;
    pos += 2;

    // IPv6 address: 2001:db8::1
    data[pos] = 0x20;
    data[pos + 1] = 0x01;
    data[pos + 2] = 0x0d;
    data[pos + 3] = 0xb8;
    @memset(data[pos + 4 .. pos + 14], 0);
    data[pos + 14] = 0x00;
    data[pos + 15] = 0x01;
    pos += 16;

    // IPv6 port: 4434
    data[pos] = 0x11;
    data[pos + 1] = 0x52;
    pos += 2;

    // Connection ID length: 8
    data[pos] = 8;
    pos += 1;

    // Connection ID
    @memcpy(data[pos .. pos + 8], "PREFADDR");
    pos += 8;

    // Stateless reset token
    @memset(data[pos .. pos + 16], 0xaa);
    pos += 16;

    // Parse
    const pref_addr = try tp.parsePreferredAddress(data[0..pos]);

    // Verify IPv4
    try std.testing.expect(pref_addr.ipv4_addr != null);
    try std.testing.expectEqual(@as(u8, 192), pref_addr.ipv4_addr.?.ip[0]);
    try std.testing.expectEqual(@as(u8, 168), pref_addr.ipv4_addr.?.ip[1]);
    try std.testing.expectEqual(@as(u8, 1), pref_addr.ipv4_addr.?.ip[2]);
    try std.testing.expectEqual(@as(u8, 100), pref_addr.ipv4_addr.?.ip[3]);
    try std.testing.expectEqual(@as(u16, 0x1151), pref_addr.ipv4_addr.?.port);

    // Verify IPv6
    try std.testing.expect(pref_addr.ipv6_addr != null);
    try std.testing.expectEqual(@as(u8, 0x20), pref_addr.ipv6_addr.?.ip[0]);
    try std.testing.expectEqual(@as(u8, 0x01), pref_addr.ipv6_addr.?.ip[1]);
    try std.testing.expectEqual(@as(u16, 0x1152), pref_addr.ipv6_addr.?.port);

    // Verify Connection ID
    try std.testing.expectEqualStrings("PREFADDR", pref_addr.connection_id);

    // Verify stateless reset token
    try std.testing.expectEqual(@as(u8, 0xaa), pref_addr.stateless_reset_token[0]);
}

test "preferred address with only IPv4" {
    var data: [256]u8 = undefined;
    var pos: usize = 0;

    // IPv4 address: 10.0.0.1
    data[pos] = 10;
    data[pos + 1] = 0;
    data[pos + 2] = 0;
    data[pos + 3] = 1;
    pos += 4;

    // IPv4 port: 443
    data[pos] = 0x01;
    data[pos + 1] = 0xbb;
    pos += 2;

    // IPv6 address: all zeros (not present)
    @memset(data[pos .. pos + 16], 0);
    pos += 16;

    // IPv6 port: 0
    data[pos] = 0;
    data[pos + 1] = 0;
    pos += 2;

    // Connection ID length: 4
    data[pos] = 4;
    pos += 1;

    // Connection ID
    data[pos] = 0xde;
    data[pos + 1] = 0xad;
    data[pos + 2] = 0xbe;
    data[pos + 3] = 0xef;
    pos += 4;

    // Stateless reset token
    @memset(data[pos .. pos + 16], 0xff);
    pos += 16;

    // Parse
    const pref_addr = try tp.parsePreferredAddress(data[0..pos]);

    // Verify IPv4 is present
    try std.testing.expect(pref_addr.ipv4_addr != null);
    try std.testing.expectEqual(@as(u8, 10), pref_addr.ipv4_addr.?.ip[0]);
    try std.testing.expectEqual(@as(u16, 443), pref_addr.ipv4_addr.?.port);

    // Verify IPv6 is not present
    try std.testing.expect(pref_addr.ipv6_addr == null);
}

test "preferred address integration with transport params" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Create transport params with preferred address
    var params = tp.TransportParams{};
    defer params.deinit(alloc);

    // Build preferred address raw data
    var pref_data: [64]u8 = undefined;
    var pos: usize = 0;

    // Simple IPv4 only
    @memcpy(pref_data[pos .. pos + 4], &[_]u8{ 127, 0, 0, 1 });
    pos += 4;
    @memcpy(pref_data[pos .. pos + 2], &[_]u8{ 0x10, 0x00 }); // port 4096
    pos += 2;
    @memset(pref_data[pos .. pos + 18], 0); // No IPv6
    pos += 18;
    pref_data[pos] = 8; // CID length
    pos += 1;
    @memcpy(pref_data[pos .. pos + 8], "TESTCID8");
    pos += 8;
    @memset(pref_data[pos .. pos + 16], 0x42); // Reset token
    pos += 16;

    params.preferred_address_raw = try alloc.dupe(u8, pref_data[0..pos]);

    // Parse when needed
    if (params.preferred_address_raw) |raw| {
        const pref = try tp.parsePreferredAddress(raw);
        try std.testing.expect(pref.ipv4_addr != null);
        try std.testing.expectEqual(@as(u8, 127), pref.ipv4_addr.?.ip[0]);
    }
}
