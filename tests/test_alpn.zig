const std = @import("std");
const conn_mod = @import("quic_conn");
const tls13 = @import("quic_tls13");

// Test that when negotiated ALPN matches allowed list, getter returns it and enforcement does not flip peer_finished_verified.
test "alpn accept and getter" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var c: conn_mod.Connection = undefined;
    c.init(&alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer c.deinit();

    c.allowed_alpns = &[_][]const u8{"h3"};
    c.peer_finished_verified = true; // should remain true on accept

    // Directly set negotiated ALPN (simulating negotiated value from EncryptedExtensions)
    const alpn_copy = try alloc.dupe(u8, "h3");
    errdefer alloc.free(alpn_copy);
    c.negotiated_alpn = alpn_copy;

    // Validate ALPN against allowed list (inline logic from pushCrypto)
    if (c.negotiated_alpn) |a| {
        if (c.allowed_alpns.len > 0) {
            var ok = false;
            for (c.allowed_alpns) |p| {
                if (std.mem.eql(u8, a, p)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) c.updatePeerFinishedStatus(false);
        }
    }

    const got = c.getNegotiatedAlpn() orelse return error.ExpectedAlpn;
    try std.testing.expect(std.mem.eql(u8, got, "h3"));
    try std.testing.expect(c.peer_finished_verified);
}

// Test that when negotiated ALPN is not allowed, enforcement flips peer_finished_verified to false.
test "alpn reject not in allowed" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var c: conn_mod.Connection = undefined;
    c.init(&alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer c.deinit();

    c.allowed_alpns = &[_][]const u8{"hq-interop"};
    c.peer_finished_verified = true; // will be cleared on reject

    // Directly set negotiated ALPN (simulating negotiated value from EncryptedExtensions)
    const alpn_copy = try alloc.dupe(u8, "h3");
    errdefer alloc.free(alpn_copy);
    c.negotiated_alpn = alpn_copy;

    // Validate ALPN against allowed list (inline logic from pushCrypto)
    if (c.negotiated_alpn) |a| {
        if (c.allowed_alpns.len > 0) {
            var ok = false;
            for (c.allowed_alpns) |p| {
                if (std.mem.eql(u8, a, p)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) c.updatePeerFinishedStatus(false);
        }
    }

    try std.testing.expect(!c.peer_finished_verified);
}
