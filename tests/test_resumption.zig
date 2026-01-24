const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

test "session resumption with PSK" {
    // TODO: PSK extension building not yet implemented in queueRealClientHello()
    // The function needs to check tickets store and add pre_shared_key extension (0x0029)
    // when tickets are available. Currently it only generates ECDHE key_share.
    // SKIP: Functionality not yet implemented
    return error.SkipZigTest;
}

test "0-RTT data with resumption" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Simulate having a ticket with resumption secret
    const resumption_secret = [_]u8{0x55} ** 32;
    const resumption_secret_wrap = ks.Secret.fromSlice(.sha256, &resumption_secret);
    const ticket_identity = "test_ticket_123";

    var client = tls13.Engine.init(alloc, .Client);
    defer client.deinit();

    // Add ticket - need to set allocator first
    client.tickets.allocator = alloc;
    try client.tickets.store(ticket_identity, resumption_secret_wrap, 3600);

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
    ks.expandLabel(&early_secret, "res binder", &[_]u8{}, &binder_key) catch unreachable;

    // Compute binder
    const binder = ks.hmacSha256(&binder_key, &transcript_hash);

    try std.testing.expect(binder.len == 32);
    // Binder should be deterministic given same inputs
    const binder2 = ks.hmacSha256(&binder_key, &transcript_hash);
    try std.testing.expectEqualSlices(u8, &binder, &binder2);
}
