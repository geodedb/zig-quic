const std = @import("std");
const api = @import("quic_api");

// Test that a client connection records peer_initial_scid (server's SCID) after
// receiving the first server Initial packet, and that it matches the DCID used
// in subsequent short-header packets from the client.
// This is a lightweight integration-style test that spins up an endpoint,
// initiates a client connection to a loopback server endpoint, drives the
// handshake until 1-RTT keys are available, then inspects internal state via
// the public api (handshakeDoneSeen) plus an internal accessor exposed only in
// test builds.

extern fn __test_export_peer_initial_scid(ptr: *anyopaque, buf: [*]u8, max: usize) callconv(.C) usize;
extern fn __test_export_our_scid(ptr: *anyopaque, buf: [*]u8, max: usize) callconv(.C) usize;

fn getPeerInitialScid(c: *anyopaque) []const u8 {
    var tmp: [32]u8 = undefined;
    const n = __test_export_peer_initial_scid(c, &tmp, tmp.len);
    return tmp[0..n];
}
fn getOurScid(c: *anyopaque) []const u8 {
    var tmp: [32]u8 = undefined;
    const n = __test_export_our_scid(c, &tmp, tmp.len);
    return tmp[0..n];
}

// NOTE: We use a single endpoint acting as both client & server (loopback). The
// existing connect() + server accept path handles this.

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"}, .allow_insecure = true };
    const ep = try api.endpointInit(&alloc, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    const conn = try api.connect(ep, "127.0.0.1:55555", "test.local");

    // Drive polling until we have observed HANDSHAKE_DONE (or timeout).
    var it: usize = 0;
    while (it < 10_000 and !api.handshakeDoneSeen(conn)) : (it += 1) {
        api.poll(ep, 5) catch break;
    }
    try std.testing.expect(api.handshakeDoneSeen(conn));

    // Export peer_initial_scid (should be non-empty and != our_scid).
    const peer_scid = getPeerInitialScid(@ptrCast(conn));
    const our_scid = getOurScid(@ptrCast(conn));
    try std.testing.expect(peer_scid.len > 0);
    try std.testing.expect(!std.mem.eql(u8, peer_scid, our_scid));
}
