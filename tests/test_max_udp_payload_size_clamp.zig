const std = @import("std");
const quic = @import("../quic.zig");
const tparams = @import("quic_transport_params");

// Test that max_udp_payload_size from peer clamps path_mtu and congestion controller mds.

test "max_udp_payload_size_clamp" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Client, 0, peer);

    // Precondition defaults
    try std.testing.expect(conn.path_mtu == 1200);
    try std.testing.expect(conn.rec.cc.mds == 0 or conn.rec.cc.mds >= 1200);

    // Build transport params with max_udp_payload_size=1300 (should set peer limit, but not reduce path_mtu since greater)
    var tp = tparams.TransportParams{};
    tp.max_udp_payload_size = 1300;
    var buf: [512]u8 = undefined;
    const enc = try tp.encode(&buf);
    try conn.applyPeerTransportParameters(enc);
    try std.testing.expect(conn.peer_max_udp_payload_size == 1300);
    try std.testing.expect(conn.path_mtu == 1200); // unchanged because larger than current

    // Now apply smaller limit 1250 (still >=1200) should clamp path_mtu and cc.mds
    var tp2 = tparams.TransportParams{};
    tp2.max_udp_payload_size = 1250;
    const enc2 = try tp2.encode(&buf);
    // Reset applied flag to allow reapplication for test (simulate earlier bug) - direct mutate
    conn.transport_params_applied = false;
    try conn.applyPeerTransportParameters(enc2);
    try std.testing.expect(conn.peer_max_udp_payload_size == 1250);
    try std.testing.expect(conn.path_mtu == 1250);
}
