const std = @import("std");
const rec = @import("quic_recovery");
const frame = @import("quic_frame");

fn ms(n: u64) u64 {
    return n * std.time.ns_per_ms;
}

test "rtt_estimator_updates_and_pto" {
    var s = rec.RttState{};
    // First sample initializes all
    s.onAck(100 * std.time.ns_per_ms, 0);
    try std.testing.expect(s.have_sample);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), s.min_rtt_ns);
    // Next sample with ack delay smaller than measured RTT, smoothed/latesr move
    s.onAck(140 * std.time.ns_per_ms, 10 * std.time.ns_per_ms);
    try std.testing.expect(s.smoothed_rtt_ns > 100 * std.time.ns_per_ms);
    const pto = s.computePtoNs();
    try std.testing.expect(pto >= s.smoothed_rtt_ns);
}

test "ack_eliciting_classification" {
    // ACK is not ack-eliciting
    try std.testing.expect(!rec.isAckElicitingFrame(frame.Frame{ .ack = .{ .largest = 1, .ack_delay = 0, .first_range = 0, .ranges = &[_]frame.AckRange{} } }));
    // PADDING is not ack-eliciting
    try std.testing.expect(!rec.isAckElicitingFrame(frame.Frame{ .padding = 1 }));
    // PING is ack-eliciting
    try std.testing.expect(rec.isAckElicitingFrame(frame.Frame{ .ping = {} }));
}

test "pto_backoff_scales_by_power_of_two" {
    var s = rec.RttState{};
    s.onAck(ms(100), 0);
    const g = ms(1);
    const b0 = s.computePtoNsWithBackoff(0, g);
    const b1 = s.computePtoNsWithBackoff(1, g);
    const b2 = s.computePtoNsWithBackoff(2, g);
    try std.testing.expect(b1 >= 2 * b0 or b1 == std.math.maxInt(u64));
    try std.testing.expect(b2 >= 2 * b1 or b2 == std.math.maxInt(u64));
}

test "time_threshold_loss_is_1p125x_of_rtt" {
    const thr1 = rec.LossDetector.timeThresholdNs(ms(100), ms(90));
    try std.testing.expect(thr1 == ms(100) + ms(100) / 8);
    const thr2 = rec.LossDetector.timeThresholdNs(ms(80), ms(120));
    try std.testing.expect(thr2 == ms(120) + ms(120) / 8);
}

test "recovery_on_ack_updates_cwnd_and_bif" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    const space = rec.PacketNumberSpace.Application;
    try r.onPacketSent(space, 1, 1200, true, 0);
    try r.onPacketSent(space, 2, 1200, true, 1);
    const before_cwnd = r.cc.cwnd;
    try std.testing.expectEqual(@as(usize, 2400), r.cc.bytes_in_flight);

    const res = r.onAckReceived(space, &[_]u64{2}, 0, 2);
    try std.testing.expectEqual(@as(usize, 1200), res.bytes_acked);
    try std.testing.expectEqual(@as(usize, 0), res.bytes_lost);
    try std.testing.expect(r.cc.cwnd > before_cwnd);
    try std.testing.expectEqual(@as(usize, 1200), r.cc.bytes_in_flight);
}

test "packet_threshold_loss_marks_and_halves_cwnd" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    const space = rec.PacketNumberSpace.Application;
    try r.onPacketSent(space, 1, 1200, true, 0);
    try r.onPacketSent(space, 2, 1200, true, 1);
    try r.onPacketSent(space, 3, 1200, true, 2);
    try r.onPacketSent(space, 4, 1200, true, 3);

    const res = r.onAckReceived(space, &[_]u64{4}, 0, 4);
    // pn=1 becomes lost by packet-threshold (kPacketThreshold=3)
    try std.testing.expectEqual(@as(usize, 1200), res.bytes_lost);
    // cwnd increased by acked (1200) from 12000 to 13200, then halved on loss => 6600
    try std.testing.expectEqual(@as(usize, 6600), r.cc.cwnd);
}

test "time_threshold_loss_and_loss_time_scheduling" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    // Seed RTT to 100ms
    r.rtt.onAck(ms(100), 0);

    const space = rec.PacketNumberSpace.Application;
    try r.onPacketSent(space, 1, 1200, true, 0);
    try r.onPacketSent(space, 2, 1200, true, ms(10));

    // No ACKs, advance time beyond time-threshold to trigger loss
    const thr = rec.LossDetector.timeThresholdNs(r.rtt.smoothed_rtt_ns, r.rtt.latest_rtt_ns);
    const lost = r.onLossTimeExpired(thr + 1);
    try std.testing.expect(lost >= 1200);
    try std.testing.expect(r.cc.cwnd <= 12000 and r.cc.cwnd >= 2400);
}

test "pto_deadline_computation_with_backoff" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    r.rtt.onAck(ms(50), 0);
    const space = rec.PacketNumberSpace.Application;
    try r.onPacketSent(space, 1, 1200, true, 1000);

    const now: u64 = 1000;
    const base_deadline = r.computeNextPtoTimeNs(now) orelse unreachable;
    const expected = 1000 + r.rtt.computePtoNsWithBackoff(0, r.timer_granularity_ns);
    try std.testing.expectEqual(expected, base_deadline);

    r.pto_count = 2;
    const backoff_deadline = r.computeNextPtoTimeNs(now) orelse unreachable;
    const expected_bo = 1000 + r.rtt.computePtoNsWithBackoff(2, r.timer_granularity_ns);
    try std.testing.expectEqual(expected_bo, backoff_deadline);
}

test "persistent_congestion_reduces_cwnd_to_min" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    // Seed RTT to 100ms so PTO base is stable
    r.rtt.onAck(ms(100), 0);
    const space = rec.PacketNumberSpace.Application;

    // Compute persistent congestion period (kPto * k_pc_threshold)
    const pto_base = r.rtt.computePtoNsWithBackoff(0, r.timer_granularity_ns);
    const pc_period = pto_base * r.k_pc_threshold;

    // Send two ack-eliciting packets spanning more than the PC period
    const t0: u64 = 0;
    const t1: u64 = pc_period + 1;
    try r.onPacketSent(space, 1, 1200, true, t0);
    try r.onPacketSent(space, 2, 1200, true, t1);

    // Advance time past time-threshold for both, to declare them lost
    const thr = rec.LossDetector.timeThresholdNs(r.rtt.smoothed_rtt_ns, r.rtt.latest_rtt_ns);
    const now = t1 + thr + 1;
    const lost = r.onLossTimeExpired(now);
    try std.testing.expect(lost >= 2400);

    // Upon persistent congestion, cwnd collapses to 2 * max_datagram_size (assume 1200)
    try std.testing.expectEqual(@as(usize, 2400), r.cc.cwnd);
}

test "ack_driven_persistent_congestion_packet_threshold" {
    var r = rec.Recovery.init(std.testing.allocator);
    defer r.deinit();

    // Seed RTT to 50ms for a stable PTO base.
    r.rtt.onAck(ms(50), 0);
    const pto_base = r.rtt.computePtoNsWithBackoff(0, r.timer_granularity_ns);
    const pc_window = pto_base * r.k_pc_threshold;

    const space = rec.PacketNumberSpace.Application;

    // Construct a span of packets such that the earliest and a near-latest packet
    // that become lost by packet-threshold cover > pc_window in send time.
    const t0: u64 = 1;
    const t_last: u64 = t0 + pc_window + ms(1);

    // Earliest packet in the span
    try r.onPacketSent(space, 1, 1200, true, t0);
    // A near-last packet that will be declared lost when we ACK a much larger PN
    try r.onPacketSent(space, 197, 1200, true, t_last);
    // The largest packet which we will ACK to trigger packet-threshold loss
    try r.onPacketSent(space, 200, 1200, true, t_last);

    // ACK only the largest packet to trigger packet-threshold loss of PN<=197.
    const res = r.onAckReceived(space, &[_]u64{200}, 0, t_last + ms(50));
    // At least two packets (1 and 197) are lost, i.e., >= 2400 bytes.
    try std.testing.expect(res.bytes_lost >= 2400);

    // The span between first and last lost packets exceeds the PC window, so PC triggers.
    try std.testing.expectEqual(@as(usize, 2 * r.cc.mds), r.cc.cwnd);
}
