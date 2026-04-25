const std = @import("std");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const endpoint = @import("quic_endpoint");
const handshake = @import("handshake_integration");
const transport_params = @import("transport_params");

fn fakePeer(ip_last_octet: u8, port: u16) conn_mod.SockAddr {
    return conn_mod.SockAddr.ipv4(127, 0, 0, ip_last_octet, port);
}

test "disable_active_migration is encoded in local transport parameters" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, fakePeer(1, 4433));
    defer conn.deinit();

    conn.our_scid.len = 4;
    std.mem.copyForwards(u8, conn.our_scid.bytes[0..4], "DMIG");

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.disable_active_migration = true;

    try handshake.setupClientTransportParams(&conn, &cfg, allocator);

    const raw = conn.getLocalTransportParams() orelse return error.TransportParamsNotSet;
    var decoded = try transport_params.TransportParams.decode(allocator, raw);
    defer decoded.deinit(allocator);

    try std.testing.expect(decoded.disable_active_migration);
    try std.testing.expect(conn.disable_active_migration_advertised);
}

test "disable_active_migration rejects peer address changes instead of validating new path" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.disable_active_migration = true;

    var ep = try endpoint.Endpoint.init(allocator, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var conn = try ep.connectClient("127.0.0.1:4433");
    const original_peer = conn.peer;
    conn.address_validated = true;
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.app_rx_keys = conn.app_tx_keys;
    conn.our_scid.len = 4;
    std.mem.copyForwards(u8, conn.our_scid.bytes[0..4], "DMIG");

    var probe: [8]u8 = .{0} ** 8;
    probe[0] = 0x40;
    std.mem.copyForwards(u8, probe[1..5], conn.our_scid.bytes[0..4]);
    ep.testInject(fakePeer(99, 4433), &probe);

    try std.testing.expect(conn_mod.SockAddr.eq(&conn.peer, &original_peer));
    try std.testing.expect(conn.address_validated);
    try std.testing.expect(!conn.path_validation_pending);
    try std.testing.expectEqual(@as(usize, 0), ep.captureLen());
}

test "peer disable_active_migration transport parameter is recorded" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, fakePeer(2, 4433));
    defer conn.deinit();

    var scid = [_]u8{ 1, 2, 3, 4 };
    var peer_params = transport_params.TransportParams{
        .initial_source_connection_id = scid[0..],
        .disable_active_migration = true,
    };
    const raw = try transport_params.TransportParams.encode(&peer_params, allocator);
    defer allocator.free(raw);

    try conn.applyPeerTransportParameters(raw);

    try std.testing.expect(conn.peer_disable_active_migration);
}
