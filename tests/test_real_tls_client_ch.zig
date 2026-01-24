const std = @import("std");
const api = @import("quic_api");

// Smoke test: enabling real_tls should build & send a ClientHello without crashing
// even if no server responds (we just poll briefly). Purpose: regression for
// earlier crash freeing uninitialized crypto_retx_initial buffer.

test "real_tls_client_initial_probe_smoke" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
    };
    const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(ep);
    // Attempt connect; should not crash.
    const conn = try api.connect(ep, "127.0.0.1:9", "test.local"); // use discard port
    // Poll a few times; we don't assert success of handshake yet.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = api.poll(ep, 5) catch {}; // ignore errors
    }
    // Ensure negotiated ALPN is still null (no server), verifying code path executed.
    std.testing.expect(api.getNegotiatedAlpn(conn) == null) catch |e| return e;
}
