const std = @import("std");
const api = @import("quic_api");

// Test: real TLS handshake progresses automatically through CH -> SH -> EE -> Finished.
// We assert (indirectly) via ALPN negotiation that Finished exchange likely occurred.

test "real_tls_full_handshake_finished_flags" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var srv_cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true, // allow skipping cert path for now
        .real_tls = true,
    };
    var cli_cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .real_tls = true,
    };
    const ep_server = try api.endpointInit(&alloc, "127.0.0.1:0", &srv_cfg);
    defer api.endpointDeinit(ep_server);
    const ep_client = try api.endpointInit(&alloc, "127.0.0.1:0", &cli_cfg);
    defer api.endpointDeinit(ep_client);

    var buf: [64]u8 = undefined;
    const port = api.getPort(ep_server);
    const addr_str = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{port});
    const conn_client = try api.connect(ep_client, addr_str, "test.local");

    var handshake_ticks: usize = 0;
    while (handshake_ticks < 200) : (handshake_ticks += 1) {
        _ = api.poll(ep_client, 5) catch {};
        _ = api.poll(ep_server, 5) catch {};
        // Break early if client reports handshake complete in public API once available.
        // Currently we rely on ALPN negotiation as proxy.
        if (api.getNegotiatedAlpn(conn_client) != null) break;
    }

    const accepted = api.accept(ep_server) orelse return error.TestExpectedAccept;
    // After further polling, Finished messages should have been exchanged.
    var post_ticks: usize = 0;
    while (post_ticks < 100) : (post_ticks += 1) {
        _ = api.poll(ep_client, 5) catch {};
        _ = api.poll(ep_server, 5) catch {};
    }

    const alpn_client = api.getNegotiatedAlpn(conn_client) orelse return error.MissingAlpnClient;
    const alpn_server = api.getNegotiatedAlpn(accepted) orelse return error.MissingAlpnServer;
    _ = alpn_client;
    _ = alpn_server;
    std.testing.expect(api.handshakeComplete(conn_client)) catch |e| return e;
    std.testing.expect(api.handshakeComplete(accepted)) catch |e| return e;
}
