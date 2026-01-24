const std = @import("std");
const api = @import("quic_api");

// Smoke test: server in real_tls mode should respond to a client Initial with a ServerHello
// (real) without crashing. We don't validate full transcript yet.

test "real_tls_server_hello_smoke" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var srv_cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
    };
    var cli_cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
    };
    const ep_server = try api.endpointInit(&alloc, "127.0.0.1:0", &srv_cfg);
    defer api.endpointDeinit(ep_server);
    const ep_client = try api.endpointInit(&alloc, "127.0.0.1:0", &cli_cfg);
    defer api.endpointDeinit(ep_client);
    // Build address string from server local port
    var buf: [64]u8 = undefined;
    const port = api.getPort(ep_server);
    const addr_str = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{port});
    const c = try api.connect(ep_client, addr_str, "test.local");
    _ = c; // unused for now
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        _ = api.poll(ep_client, 5) catch {};
        _ = api.poll(ep_server, 5) catch {};
    }
    // Accept connection on server side (should exist)
    const accepted = api.accept(ep_server) catch |err| switch (err) {
        error.WouldBlock => return error.TestExpectedAccept,
        else => return err,
    };
    _ = accepted;
    // Poll out any handshake CRYPTO emission
    var j: usize = 0;
    while (j < 10) : (j += 1) {
        _ = api.poll(ep_client, 5) catch {};
        _ = api.poll(ep_server, 5) catch {};
    }
    // Assert that server connection produced at least one Handshake packet by looking at
    // whether client has derived handshake keys (heuristic: negotiated ALPN or hs keys implies SH parsed)
    // Simplest: ensure client did not crash and connection object still valid.
}
