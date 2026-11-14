// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6454): loss detection deviations from RFC 9002.

const std = @import("std");
const testing = std.testing;
const recovery = @import("quic_recovery");

const ms: u64 = std.time.ns_per_ms;

fn seededRecovery(srtt_ns: u64, rttvar_ns: u64) recovery.Recovery {
    var rec = recovery.Recovery.init(testing.allocator);
    rec.rtt.have_sample = true;
    rec.rtt.min_rtt_ns = srtt_ns;
    rec.rtt.latest_rtt_ns = srtt_ns;
    rec.rtt.smoothed_rtt_ns = srtt_ns;
    rec.rtt.rttvar_ns = rttvar_ns;
    return rec;
}

test "RFC 9002 6.1.2 time threshold is at least kGranularity" {
    // 9/8 of a 100 us RTT is 112.5 us; the threshold must not drop below
    // the 1 ms timer granularity.
    try testing.expectEqual(@as(u64, 1 * ms), recovery.LossDetector.timeThresholdNs(100_000, 100_000));
    // Above the floor the 9/8 rule is unchanged.
    try testing.expectEqual(@as(u64, 112_500_000), recovery.LossDetector.timeThresholdNs(100 * ms, 80 * ms));
}

test "RFC 9002 6.1 a packet sent after the largest acknowledged is not lost by time" {
    var rec = seededRecovery(10 * ms, 5 * ms);
    defer rec.deinit();
    const base: u64 = 1_000 * ms;
    try rec.onPacketSent(.Application, 1, 1200, true, base);
    try rec.onPacketSent(.Application, 2, 1200, true, base + 1 * ms);

    // PN 1 is acknowledged after 2 ms (a 2 ms RTT sample); the same ACK
    // arrives again 100 ms later with no new sample. PN 2 is then far older
    // than the time threshold (~10 ms) but was sent after PN 1, so it is not
    // lost (RFC 9002 section 6.1 requires an acknowledged later packet).
    _ = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 1, .hi = 1 }}, 0, base + 2 * ms, null);
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 1, .hi = 1 }}, 0, base + 100 * ms, null);
    try testing.expectEqual(@as(usize, 0), res.bytes_lost);
    try testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 2));

    // The loss timer cannot declare it lost either.
    try testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(base + 10_000 * ms));
    try testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 2));
}

test "RFC 9002 6.1 nothing is lost by time before any packet is acknowledged" {
    var rec = seededRecovery(10 * ms, 5 * ms);
    defer rec.deinit();
    try rec.onPacketSent(.Application, 1, 1200, true, 1_000 * ms);
    try testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(60_000 * ms));
    try testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 1));
}

test "RFC 9002 6.1 time-threshold loss below the largest acknowledged still applies" {
    var rec = seededRecovery(10 * ms, 5 * ms);
    defer rec.deinit();
    const base: u64 = 1_000 * ms;
    try rec.onPacketSent(.Application, 1, 1200, true, base);
    try rec.onPacketSent(.Application, 2, 1200, true, base + 1 * ms);
    // PN 2 acknowledged after 11 ms: PN 1 is only one packet older (no
    // packet-threshold loss) and not yet past 9/8 RTT. A later ACK with no
    // new RTT sample finds it past the time threshold: lost by time.
    const first = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 2, .hi = 2 }}, 0, base + 12 * ms, null);
    try testing.expectEqual(@as(usize, 0), first.bytes_lost);
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 2, .hi = 2 }}, 0, base + 100 * ms, null);
    try testing.expectEqual(@as(usize, 1200), res.bytes_lost);
}

test "RFC 9002 largest acknowledged is set when only packet 0 is acknowledged" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();
    try rec.onPacketSent(.Application, 0, 1200, true, 1_000 * ms);
    _ = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 0, .hi = 0 }}, 0, 1_020 * ms, null);
    const app = @intFromEnum(recovery.PacketNumberSpace.Application);
    try testing.expectEqual(@as(?u64, 0), rec.spaces[app].largest_acked);
    // Acknowledging the largest packet yields the first RTT sample.
    try testing.expect(rec.rtt.have_sample);
    try testing.expectEqual(@as(u64, 20 * ms), rec.rtt.latest_rtt_ns);
}

test "RFC 9002 7.6.2 an acknowledged packet between two lost ones rules out persistent congestion" {
    var rec = seededRecovery(10 * ms, 5 * ms);
    defer rec.deinit();
    // PTO = 10 + 4*5 + 1 = 31 ms; persistent congestion period = 93 ms.
    const base: u64 = 1_000 * ms;
    try rec.onPacketSent(.Application, 1, 1200, true, base);
    try rec.onPacketSent(.Application, 2, 1200, true, base + 200 * ms);
    try rec.onPacketSent(.Application, 3, 1200, true, base + 400 * ms);
    try rec.onPacketSent(.Application, 4, 1200, true, base + 401 * ms);
    try rec.onPacketSent(.Application, 7, 1200, true, base + 402 * ms);
    const cwnd_before = rec.cc.cwnd;

    // PN 2 and PN 7 acknowledged: 1, 3 and 4 are lost. 1 and 3 span 400 ms
    // but PN 2 between them was acknowledged; 3 and 4 span only 1 ms.
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{ .{ .lo = 7, .hi = 7 }, .{ .lo = 2, .hi = 2 } }, 0, base + 410 * ms, null);
    try testing.expectEqual(@as(usize, 3 * 1200), res.bytes_lost);
    // An ordinary loss response, not the persistent-congestion collapse.
    try testing.expect(rec.cc.cwnd < cwnd_before);
    try testing.expect(rec.cc.cwnd > 2 * rec.cc.mds);
}

test "RFC 9002 7.6.2 a run of lost packets spanning the period is persistent congestion" {
    var rec = seededRecovery(10 * ms, 5 * ms);
    defer rec.deinit();
    const base: u64 = 1_000 * ms;
    try rec.onPacketSent(.Application, 1, 1200, true, base);
    try rec.onPacketSent(.Application, 2, 1200, true, base + 200 * ms);
    try rec.onPacketSent(.Application, 3, 1200, true, base + 400 * ms);
    try rec.onPacketSent(.Application, 7, 1200, true, base + 402 * ms);
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 7, .hi = 7 }}, 0, base + 410 * ms, null);
    try testing.expectEqual(@as(usize, 3 * 1200), res.bytes_lost);
    try testing.expectEqual(2 * rec.cc.mds, rec.cc.cwnd);
}

test "RFC 9002 6.4 discarding a handshake space releases its packets and resets the PTO backoff" {
    // RFC 9002 §6.4 / A.11. Hundreds of Initial/Handshake PTO probes left
    // in flight with the backoff past 300 made the application PTO
    // deadline effectively infinite (SONNY-6478 v0.1.51 CI).
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();
    const t0: u64 = 1_000 * std.time.ns_per_s;
    var pn: u64 = 0;
    while (pn < 300) : (pn += 1) try rec.onPacketSent(.Handshake, pn, 1200, true, t0 + pn);
    try rec.onPacketSent(.Initial, 0, 1200, true, t0);
    rec.pto_count = 318;
    try rec.onPacketSent(.Application, 0, 500, true, t0 + 1_000);
    try testing.expectEqual(@as(usize, 301 * 1200 + 500), rec.cc.bytes_in_flight);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), rec.ptoDeadlineNs(.Application).?);

    rec.discardSpace(.Initial);
    rec.discardSpace(.Handshake);
    try testing.expectEqual(@as(usize, 500), rec.cc.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), rec.pto_count);
    try testing.expectEqual(@as(usize, 0), rec.spaces[1].sent.items.len);
    try testing.expect(rec.ptoDeadlineNs(.Handshake) == null);
    // The application PTO is again one un-backed-off PTO after its send.
    const pto = rec.rtt.computePtoNsWithBackoff(0, rec.timer_granularity_ns);
    try testing.expectEqual(t0 + 1_000 + pto, rec.ptoDeadlineNs(.Application).?);

    // Only the first discard has an effect; a late send into a discarded
    // space is not counted.
    rec.pto_count = 2;
    rec.discardSpace(.Handshake);
    try testing.expectEqual(@as(u32, 2), rec.pto_count);
    try rec.onPacketSent(.Handshake, 400, 1200, true, t0 + 2_000);
    try testing.expectEqual(@as(usize, 500), rec.cc.bytes_in_flight);
    try testing.expectEqual(@as(usize, 0), rec.spaces[1].sent.items.len);
}
