//! RFC 9001 §4.9.2 regression (geode KMS ConcurrencyStress): the client keeps
//! its Handshake keys, and the retransmit copy of its Finished, until the
//! handshake is confirmed.
const std = @import("std");
const handshake = @import("quic_endpoint_handshake_integration");
const conn_mod = @import("quic_conn");
const key_schedule = @import("vendor_ztls_key_schedule");

test "RFC 9001 §4.9.2: the client keeps its Handshake keys and Finished retransmit copy when 1-RTT keys install" {
    // The client discards its Handshake keys only once the handshake is
    // CONFIRMED (HANDSHAKE_DONE, processShortHeader). Dropping them -- and the
    // retransmit copy of its Finished -- when the 1-RTT keys were installed
    // made a lost client Finished unrecoverable: the server never derived
    // 1-RTT keys and dropped every request the client sent (geode's KMS
    // ConcurrencyStress timeouts on starved CI pods).
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    const hs_client = key_schedule.Secret.fromSlice(.sha256, &([_]u8{0x11} ** 32));
    const hs_server = key_schedule.Secret.fromSlice(.sha256, &([_]u8{0x22} ** 32));
    try handshake.installHandshakeKeys(&conn, hs_client, hs_server);
    // The client has sent its Finished in a Handshake packet.
    conn.handshake_packet_sent = true;
    conn.crypto_retx_handshake = try allocator.dupe(u8, "client-finished");

    const app_client = key_schedule.Secret.fromSlice(.sha256, &([_]u8{0x33} ** 32));
    const app_server = key_schedule.Secret.fromSlice(.sha256, &([_]u8{0x44} ** 32));
    try handshake.installApplicationKeys(&conn, app_client, app_server);

    try std.testing.expect(conn.app_tx_keys != null);
    try std.testing.expect(conn.hs_tx_keys != null);
    try std.testing.expect(conn.hs_rx_keys != null);
    try std.testing.expectEqualStrings("client-finished", conn.crypto_retx_handshake.?);
}
