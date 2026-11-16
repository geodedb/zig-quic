// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// RFC 9001 §6.5: after a key update the previous receive keys open packets
// that were reordered behind it, for no more than three PTOs; after that,
// packets protected with them are discarded. Packets are injected into a
// real client endpoint's receive path (Endpoint.testInject) with keys
// seeded on its connection; nothing in the receive path is replaced.
// The relay tests in test_rx_packet_protection.zig cover the same window
// end to end; this one pins it down packet by packet, across a packet
// number gap (SONNY-6656: rewritten from the 16-packet allowance that
// SONNY-6649 replaced).

const std = @import("std");
const linux = std.os.linux;
const endpoint = @import("quic_endpoint");
const inj = @import("key_update_inject.zig");
const seedKeys = inj.seedKeys;
const inject = inj.inject;
const received = inj.received;
const nowNs = inj.nowNs;

test "key update: previous-phase packets across a packet number gap are opened for three PTOs, then discarded (RFC 9001 §6.5)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:11");
    const keys = try seedKeys(c);

    // Generation 0, then the peer's key update at packet 100: packets 5..99
    // are still on their way.
    for (0..5) |pn| try inject(A, &ep, c, pn, keys.gen0, false);
    for (0..5) |pn| try std.testing.expect(received(c, pn));
    try inject(A, &ep, c, 100, keys.gen1, true);
    try std.testing.expect(received(c, 100));
    try std.testing.expect(c.rx_key_phase);
    try std.testing.expectEqual(@as(u64, 1), c.rx_key_gen);
    try std.testing.expect(c.rx_prev_keys != null);
    try std.testing.expect(c.rx_prev_discard_ns > nowNs());

    // Reordered packets of generation 0 from across the gap, more than the
    // 16 the receiver used to allow, are opened with the previous keys.
    const failures_before = c.aead_rx_invalid_count;
    var pn: u64 = 20;
    while (pn < 60) : (pn += 1) try inject(A, &ep, c, pn, keys.gen0, false);
    try std.testing.expect(nowNs() < c.rx_prev_discard_ns);
    try std.testing.expectEqual(failures_before, c.aead_rx_invalid_count);
    pn = 20;
    while (pn < 60) : (pn += 1) try std.testing.expect(received(c, pn));
    // Generation 1 continues meanwhile.
    try inject(A, &ep, c, 101, keys.gen1, true);
    try std.testing.expect(received(c, 101));

    // Three PTOs after the update the previous keys are gone, and a late
    // packet of generation 0 is discarded as undecryptable.
    const deadline = c.rx_prev_discard_ns;
    const give_up = nowNs() + 15 * std.time.ns_per_s;
    while (nowNs() <= deadline and nowNs() < give_up) {
        const ts = linux.timespec{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    try std.testing.expect(nowNs() > deadline);
    try inject(A, &ep, c, 70, keys.gen0, false);
    try std.testing.expectEqual(failures_before + 1, c.aead_rx_invalid_count);
    try std.testing.expect(!received(c, 70));
    try std.testing.expect(c.rx_prev_keys == null);
    // The current keys still work.
    try inject(A, &ep, c, 102, keys.gen1, true);
    try std.testing.expect(received(c, 102));
}
