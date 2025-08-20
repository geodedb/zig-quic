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
