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
