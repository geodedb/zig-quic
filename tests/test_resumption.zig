const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

test "session resumption with PSK" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Create client and server engines
    var client = tls13.Engine.init(alloc, .Client);
    defer client.deinit();
    var server = tls13.Engine.init(alloc, .Server);
    defer server.deinit();

    // Enable real mode for proper handshake
    client.enableReal();
    server.enableReal();

    // First handshake to establish session
    try client.queueMinimalClientHello();

    // Process ClientHello on server
    const ch_bytes = try client.flushCrypto(alloc);
    defer alloc.free(ch_bytes);
    try server.ingestCrypto(ch_bytes);

    // Server sends ServerHello
    try server.queueMinimalServerHello();
    const sh_bytes = try server.flushCrypto(alloc);
    defer alloc.free(sh_bytes);
    try client.ingestCrypto(sh_bytes);

    // Complete handshake (simplified)
    client.setEcdhe(&([_]u8{0x42} ** 32));
    server.setEcdhe(&([_]u8{0x42} ** 32));

    // Server sends NewSessionTicket
    try server.queueNewSessionTicket();
    const nst_bytes = try server.flushCrypto(alloc);
    defer alloc.free(nst_bytes);
    try client.ingestCrypto(nst_bytes);

    // Verify client has stored ticket
    const ticket = client.peekTicket();
    try std.testing.expect(ticket != null);

    // Second connection with resumption
    var client2 = tls13.Engine.init(alloc, .Client);
    defer client2.deinit();
    client2.enableReal();

    // Copy ticket from first client
    if (ticket) |t| {
        try client2.tickets.add(alloc, t.identity, t.secret, 3600);
    }

    // Build ClientHello with PSK
    try client2.queueMinimalClientHello();
    const ch2_bytes = try client2.flushCrypto(alloc);
    defer alloc.free(ch2_bytes);

    // Verify PSK extension is present
    var found_psk = false;
    var i: usize = 0;
    while (i < ch2_bytes.len - 4) : (i += 1) {
        if (ch2_bytes[i] == 0x00 and ch2_bytes[i + 1] == 0x29) {
            found_psk = true;
            break;
        }
    }
    try std.testing.expect(found_psk);
}

test "0-RTT data with resumption" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Simulate having a ticket with resumption secret
    const resumption_secret = [_]u8{0x55} ** 32;
    const ticket_identity = "test_ticket_123";

    var client = tls13.Engine.init(alloc, .Client);
    defer client.deinit();

    // Add ticket
    try client.tickets.add(alloc, ticket_identity, resumption_secret, 3600);

    // Verify we can derive 0-RTT keys from resumption secret
    const zero_rtt_secret = ks.deriveSecret(resumption_secret, "c e traffic", &[_]u8{});
    const keys = ks.deriveKeyIvHp(zero_rtt_secret);

    try std.testing.expect(keys.key.len == 16);
    try std.testing.expect(keys.iv.len == 12);
    try std.testing.expect(keys.hp.len == 16);
}

test "PSK binder computation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    _ = alloc;

    // Test binder computation for PSK
    const psk = [_]u8{0x66} ** 32;
    const transcript_hash = [_]u8{0x77} ** 32;

    // Compute binder key using extract function
    const early_secret = ks.extract(null, &psk);
    var binder_key: [32]u8 = undefined;
    ks.expandLabel(early_secret, "res binder", &[_]u8{}, &binder_key) catch unreachable;

    // Compute binder
    const binder = ks.hmacSha256(&binder_key, &transcript_hash);

    try std.testing.expect(binder.len == 32);
    // Binder should be deterministic given same inputs
    const binder2 = ks.hmacSha256(&binder_key, &transcript_hash);
    try std.testing.expectEqualSlices(u8, &binder, &binder2);
}
