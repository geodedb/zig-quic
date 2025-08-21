const std = @import("std");
const conn_mod = @import("quic_conn");
const tls13 = @import("quic_tls13");

// Test that when negotiated ALPN matches allowed list, getter returns it and enforcement does not flip finished_verified.
test "alpn accept and getter" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var c: conn_mod.Connection = undefined;
    c.init(&alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer c.deinit();

    c.allowed_alpns = &[_][]const u8{"h3"};
    c.tls.allow_insecure = false;
    c.tls.finished_verified = true; // should remain true on accept

    const ee_body = [_]u8{ 'A', 'L', 'P', 'N', 2, 'h', '3' };
    const hs = try tls13.encodeHandshake(alloc, .encrypted_extensions, ee_body[0..]);
    defer alloc.free(hs);
    try c.pushCrypto(hs);

    const got = c.getNegotiatedAlpn() orelse return error.ExpectedAlpn;
    try std.testing.expect(std.mem.eql(u8, got, "h3"));
    try std.testing.expect(c.tls.finished_verified);
}

// Test that when negotiated ALPN is not allowed, enforcement flips finished_verified to false.
test "alpn reject not in allowed" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var c: conn_mod.Connection = undefined;
    c.init(&alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer c.deinit();

    c.allowed_alpns = &[_][]const u8{"hq-interop"};
    c.tls.allow_insecure = false;
    c.tls.finished_verified = true; // will be cleared on reject

    const ee_body = [_]u8{ 'A', 'L', 'P', 'N', 2, 'h', '3' };
    const hs = try tls13.encodeHandshake(alloc, .encrypted_extensions, ee_body[0..]);
    defer alloc.free(hs);
    try c.pushCrypto(hs);

    try std.testing.expect(!c.tls.finished_verified);
}
