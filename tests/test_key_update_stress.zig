// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Key update stress on one connection (RFC 9001 §6), driving the production
// send and receive paths: a real client endpoint (Endpoint.testInject for
// received packets, onShortHeaderPacketSent/onAckReceivedSpace for sent
// ones) with keys seeded on its connection. SONNY-6656: rewritten from the
// 16-packet previous-key allowance that SONNY-6649 replaced with three PTOs
// (RFC 9001 §6.5), and from the update rule that SONNY-6522 corrected.

const std = @import("std");
const endpoint = @import("quic_endpoint");
const ooo = @import("key_update_inject.zig");

test "rx key update: a burst of previous-phase packets reordered behind the update is opened within three PTOs" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:3");
    const keys = try ooo.seedKeys(c);

    // The peer updates at packet 200 while 0..199 are in flight, and they
    // all arrive after the first packet of the new generation. The
    // receiver used to open 16 of them with the previous keys and drop the
    // rest.
    try ooo.inject(A, &ep, c, 200, keys.gen1, true);
    try std.testing.expectEqual(@as(u64, 1), c.rx_key_gen);
    const failures_before = c.aead_rx_invalid_count;
    var pn: u64 = 0;
    while (pn < 200) : (pn += 1) try ooo.inject(A, &ep, c, pn, keys.gen0, false);
    try std.testing.expectEqual(failures_before, c.aead_rx_invalid_count);
    pn = 0;
    while (pn < 200) : (pn += 1) try std.testing.expect(ooo.received(c, pn));
    try std.testing.expect(c.rx_prev_keys != null);
    try std.testing.expectEqual(@as(u64, 1), c.rx_key_gen);
}

test "tx key update: repeated updates each wait for an acknowledgement of the new keys (RFC 9001 §6.1)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:4");
    _ = try ooo.seedKeys(c);
    c.disable_auto_key_update = false;
    var empty = [_]@import("quic_frame").AckRange{};

    var gen: u64 = 0;
    while (gen < 4) : (gen += 1) {
        // Send until the next update starts (512 packets or 1 MiB).
        const phase_before = c.tx_key_phase;
        var sent: usize = 0;
        while (!c.tx_update_in_progress and sent < 2000) : (sent += 1) c.onShortHeaderPacketSent(1200, true);
        try std.testing.expect(c.tx_update_in_progress);
        try std.testing.expectEqual(gen + 1, c.tx_key_gen);
        try std.testing.expect(c.tx_key_phase != phase_before);
        try std.testing.expect(c.tx_prev_keys != null);
        // The packet that triggered the update went out with the old keys:
        // the new generation starts at the next packet number (SONNY-6522).
        const start_pn = c.tx_update_start_pn;
        try std.testing.expectEqual(c.pn_app_tx, start_pn);

        // However much more is sent, no further update starts before a
        // packet of this generation is acknowledged.
        for (0..1500) |_| c.onShortHeaderPacketSent(1200, true);
        try std.testing.expectEqual(gen + 1, c.tx_key_gen);

        // An acknowledgement of the last old-key packet does not complete
        // the update; one of the first new-key packet does, and the old
        // keys are discarded.
        c.onAckReceivedSpace(.Application, start_pn - 1, 0, empty[0..0], null);
        try std.testing.expect(c.tx_update_in_progress);
        try std.testing.expect(c.tx_prev_keys != null);
        c.onAckReceivedSpace(.Application, start_pn, 0, empty[0..0], null);
        try std.testing.expect(!c.tx_update_in_progress);
        try std.testing.expect(c.tx_prev_keys == null);
    }
    try std.testing.expectEqual(@as(u64, 4), c.tx_key_gen);
}
