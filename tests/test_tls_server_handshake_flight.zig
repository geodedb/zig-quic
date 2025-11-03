const std = @import("std");
const tls = @import("quic_tls13");

// Ensure queueServerHandshakeFlight stages the server handshake flight exactly once
// and updates internal flags when Handshake secrets are available.
test "tls_engine_server_handshake_flight_single_enqueue" {
    const alloc = std.testing.allocator;

    var client = tls.Engine.init(alloc, .Client);
    defer client.deinit();
    client.allow_insecure = true;

    var server = tls.Engine.init(alloc, .Server);
    defer server.deinit();
    server.allow_insecure = true;

    // Client sends a full ClientHello so the server derives handshake secrets.
    try client.queueMinimalClientHello();
    var buf: [2048]u8 = undefined;
    const ch_len = client.popCrypto(buf[0..]);
    try std.testing.expect(ch_len > 0);
    server.onCryptoRecv(buf[0..ch_len]);

    // Server emits ServerHello, which should populate the Initial CRYPTO outbox
    // and derive handshake secrets needed for the Handshake flight.
    try server.queueRealServerHello();
    try std.testing.expect(server.handshake_server_secret != null);

    const before_len = server.outbox.items.len;
    try std.testing.expect(before_len > 0); // ServerHello is queued

    server.queueServerHandshakeFlight();
    try std.testing.expect(server.server_handshake_flight_enqueued);
    try std.testing.expect(server.finished_sent);
    try std.testing.expect(server.ee_sent);
    const after_len = server.outbox.items.len;
    try std.testing.expect(after_len > before_len);

    // Subsequent calls must be idempotent and not append duplicate messages.
    server.queueServerHandshakeFlight();
    try std.testing.expectEqual(after_len, server.outbox.items.len);
}
