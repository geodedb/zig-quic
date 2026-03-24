const std = @import("std");
const tls = @import("../src/quic/tls/tls13.zig");

test "session_ticket_store" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var server = tls.Engine.init(alloc, .Server);
    defer server.deinit();
    var client = tls.Engine.init(alloc, .Client);
    defer client.deinit();
    // Minimal key shares
    try client.queueMinimalClientHello();
    var buf: [4096]u8 = undefined;
    var n = client.popCrypto(buf[0..]);
    try server.onCryptoRecv(buf[0..n]);
    try server.queueMinimalServerHello();
    n = server.popCrypto(buf[0..]);
    try client.onCryptoRecv(buf[0..n]);
    // Derive secrets
    _ = client.computeHandshakeSecrets();
    _ = server.computeHandshakeSecrets();
    // Simulate Finished exchange (skip full correctness)
    if (!client.finished_sent and client.handshake_client_secret) try client.queueFinished(client.handshake_client_secret.?);
    n = client.popCrypto(buf[0..]);
    try server.onCryptoRecv(buf[0..n]);
    if (!server.finished_sent and server.handshake_server_secret) try server.queueFinished(server.handshake_server_secret.?);
    n = server.popCrypto(buf[0..]);
    try client.onCryptoRecv(buf[0..n]);
    // Compute application secrets to set master_secret
    _ = client.computeApplicationSecrets();
    _ = server.computeApplicationSecrets();
    // Server emits ticket
    const ticket_payload = "ticket123";
    try server.queueNewSessionTicket(60, ticket_payload);
    n = server.popCrypto(buf[0..]);
    try client.onCryptoRecv(buf[0..n]);
    // Ensure client stored ticket
    try std.testing.expect(client.peekTicket() != null);
    const t = client.peekTicket().?;
    try std.testing.expectEqual(@as(usize, ticket_payload.len), t.identity.len);
}
