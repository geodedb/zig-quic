const std = @import("std");
const tls = @import("../src/quic/tls/tls13.zig");

test "psk_client_hello_offer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var client = tls.Engine.init(alloc, .Client);
    defer client.deinit();
    var server = tls.Engine.init(alloc, .Server);
    defer server.deinit();
    client.enableReal();
    server.enableReal();
    // Perform one handshake to get ticket
    try client.queueMinimalClientHello();
    var buf: [4096]u8 = undefined;
    var n = client.popCrypto(buf[0..]);
    server.onCryptoRecv(buf[0..n]);
    try server.queueMinimalServerHello();
    n = server.popCrypto(buf[0..]);
    client.onCryptoRecv(buf[0..n]);
    _ = client.computeHandshakeSecrets();
    _ = server.computeHandshakeSecrets();
    if (!client.finished_sent and client.handshake_client_secret) try client.queueFinished(client.handshake_client_secret.?);
    n = client.popCrypto(buf[0..]);
    server.onCryptoRecv(buf[0..n]);
    if (!server.finished_sent and server.handshake_server_secret) try server.queueFinished(server.handshake_server_secret.?);
    n = server.popCrypto(buf[0..]);
    client.onCryptoRecv(buf[0..n]);
    _ = client.computeApplicationSecrets();
    _ = server.computeApplicationSecrets();
    try server.queueNewSessionTicket(120, "psk_ticket");
    n = server.popCrypto(buf[0..]);
    client.onCryptoRecv(buf[0..n]);
    try std.testing.expect(client.peekTicket() != null);
    // Second ClientHello should include PSK extensions
    try client.queueMinimalClientHello();
    n = client.popCrypto(buf[0..]);
    // Find pre_shared_key extension type 0x0029 in buffer
    var found: bool = false;
    var i: usize = 0;
    while (i + 3 < n) : (i += 1) {
        if (buf[i] == 0x00 and buf[i + 1] == 0x29) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}
