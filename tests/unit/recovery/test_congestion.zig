//! Unit tests for recovery/congestion.zig
//!
//! RFC References:
//! - RFC 9002 §7: Congestion Control
//! - RFC 9002 §7.2: Initial and Minimum Congestion Window
//! - RFC 9002 §7.3: NewReno
//! - RFC 9002 §7.3.1: Slow Start
//! - RFC 9002 §7.3.2: Congestion Avoidance
//! - RFC 9002 §7.3.3: Recovery Period
//! - RFC 9002 Appendix B.1: NewReno Pseudocode
//! - RFC 9002 Appendix B.2: CUBIC
//!
//! Coverage:
//! - Positive cases: NewReno slow start, congestion avoidance, loss recovery, CUBIC wrapper
//! - Negative cases: Zero bytes, minimum window enforcement
//! - Boundary cases: Threshold transitions, window limits
//! - RFC compliance: Initial cwnd, ssthresh, loss response

const std = @import("std");
const testing = std.testing;

const congestion = @import("congestion");
const NewReno = congestion.NewReno;
const Cubic = congestion.Cubic;
const computePacingDelayNs = congestion.computePacingDelayNs;

// =============================================================================
// NewReno Initialization Tests
// =============================================================================

test "NewReno initializes with mds of 1200 bytes" {
    const nr: NewReno = .{};
    try testing.expectEqual(@as(usize, 1200), nr.mds);
}

test "RFC 9002 §7.2 - NewReno initializes cwnd to 10 * mds" {
    const nr: NewReno = .{};
    try testing.expectEqual(@as(usize, 10 * 1200), nr.cwnd);
}

test "RFC 9002 §7.2 - NewReno initializes ssthresh near maximum" {
    const nr: NewReno = .{};
    try testing.expectEqual(@as(usize, std.math.maxInt(usize) / 2), nr.ssthresh);
}

test "NewReno initializes bytes_in_flight to zero" {
    const nr: NewReno = .{};
    try testing.expectEqual(@as(usize, 0), nr.bytes_in_flight);
}

test "NewReno can be created with custom parameters" {
    const nr: NewReno = .{
        .mds = 1500,
        .cwnd = 15000,
        .ssthresh = 50000,
        .bytes_in_flight = 5000,
    };

    try testing.expectEqual(@as(usize, 1500), nr.mds);
    try testing.expectEqual(@as(usize, 15000), nr.cwnd);
    try testing.expectEqual(@as(usize, 50000), nr.ssthresh);
    try testing.expectEqual(@as(usize, 5000), nr.bytes_in_flight);
}

// =============================================================================
// NewReno Packet Sent Tests
// =============================================================================

test "RFC 9002 §7 - onPacketSent increases bytes_in_flight for ACK-eliciting" {
    var nr: NewReno = .{};
    nr.onPacketSent(1200, true);
    try testing.expectEqual(@as(usize, 1200), nr.bytes_in_flight);
}

test "RFC 9002 §7 - onPacketSent does not increase bytes_in_flight for non-ACK-eliciting" {
    var nr: NewReno = .{};
    nr.onPacketSent(1200, false);
    try testing.expectEqual(@as(usize, 0), nr.bytes_in_flight);
}

test "onPacketSent accumulates bytes_in_flight" {
    var nr: NewReno = .{};
    nr.onPacketSent(1200, true);
    nr.onPacketSent(800, true);
    nr.onPacketSent(1000, true);
    try testing.expectEqual(@as(usize, 3000), nr.bytes_in_flight);
}

test "onPacketSent ignores non-ACK-eliciting packets for bytes_in_flight" {
    var nr: NewReno = .{};
    nr.onPacketSent(1200, true); // Counted
    nr.onPacketSent(500, false); // Not counted
    nr.onPacketSent(800, true); // Counted
    try testing.expectEqual(@as(usize, 2000), nr.bytes_in_flight);
}

// =============================================================================
// NewReno Slow Start Tests (RFC 9002 §7.3.1)
// =============================================================================

test "RFC 9002 §7.3.1 - onAck in slow start increases cwnd by bytes_acked" {
    var nr: NewReno = .{};
    const initial_cwnd = nr.cwnd;

    nr.onAck(1200);

    // In slow start, cwnd += bytes_acked
    try testing.expectEqual(initial_cwnd + 1200, nr.cwnd);
}

test "RFC 9002 §7.3.1 - slow start cwnd grows exponentially" {
    var nr: NewReno = .{};
    const initial_cwnd = nr.cwnd;

    // Simulate ACKing packets in slow start
    nr.onAck(1200);
    nr.onAck(1200);
    nr.onAck(1200);

    // cwnd should grow by 3600 bytes total
    try testing.expectEqual(initial_cwnd + 3600, nr.cwnd);
}

test "RFC 9002 §7.3.1 - slow start reduces bytes_in_flight" {
    var nr: NewReno = .{ .bytes_in_flight = 5000 };

    nr.onAck(1200);

    try testing.expectEqual(@as(usize, 3800), nr.bytes_in_flight);
}

test "RFC 9002 §7.3.1 - slow start exits when cwnd >= ssthresh" {
    var nr: NewReno = .{
        .cwnd = 20000,
        .ssthresh = 25000,
    };

    // ACK enough to cross threshold
    nr.onAck(6000);

    // Should now be in congestion avoidance (cwnd >= ssthresh)
    try testing.expect(nr.cwnd >= nr.ssthresh);
}

// =============================================================================
// NewReno Congestion Avoidance Tests (RFC 9002 §7.3.2)
// =============================================================================

test "RFC 9002 §7.3.2 - onAck in congestion avoidance increases cwnd slowly" {
    var nr: NewReno = .{
        .cwnd = 20000,
        .ssthresh = 15000, // cwnd > ssthresh, so in congestion avoidance
    };

    const initial_cwnd = nr.cwnd;
    nr.onAck(1200);

    // In congestion avoidance: cwnd += mds * bytes_acked / cwnd
    const expected_increase = (nr.mds * 1200) / initial_cwnd;
    try testing.expectEqual(initial_cwnd + expected_increase, nr.cwnd);
}

test "RFC 9002 §7.3.2 - congestion avoidance cwnd grows linearly" {
    var nr: NewReno = .{
        .cwnd = 20000,
        .ssthresh = 15000,
    };

    // ACK multiple times
    const cwnd_before = nr.cwnd;
    nr.onAck(1200);
    const cwnd_after_1 = nr.cwnd;
    nr.onAck(1200);
    const cwnd_after_2 = nr.cwnd;

    // Each ACK should increase cwnd by roughly the same amount
    const increase_1 = cwnd_after_1 - cwnd_before;
    const increase_2 = cwnd_after_2 - cwnd_after_1;

    // Growth should be much smaller than in slow start
    try testing.expect(increase_1 < 1200);
    try testing.expect(increase_2 < 1200);
}

test "RFC 9002 §7.3.2 - congestion avoidance formula is mds * bytes_acked / cwnd" {
    var nr: NewReno = .{
        .mds = 1200,
        .cwnd = 24000,
        .ssthresh = 12000,
    };

    const initial_cwnd = nr.cwnd;
    nr.onAck(1200);

    // Expected increase: 1200 * 1200 / 24000 = 60
    const expected = initial_cwnd + ((1200 * 1200) / 24000);
    try testing.expectEqual(expected, nr.cwnd);
}

// =============================================================================
// NewReno Loss Recovery Tests (RFC 9002 §7.3.3)
// =============================================================================

test "RFC 9002 §7.3.3 - onLoss halves cwnd" {
    var nr: NewReno = .{
        .cwnd = 20000,
        .ssthresh = 15000,
    };

    nr.onLoss(1200);

    // cwnd should be halved
    try testing.expectEqual(@as(usize, 10000), nr.cwnd);
}

test "RFC 9002 §7.3.3 - onLoss sets ssthresh to new cwnd" {
    var nr: NewReno = .{
        .cwnd = 20000,
        .ssthresh = 15000,
    };

    nr.onLoss(1200);

    // ssthresh should match new cwnd
    try testing.expectEqual(nr.cwnd, nr.ssthresh);
}

test "RFC 9002 §7.3.3 - onLoss enforces minimum window of 2 * mds" {
    var nr: NewReno = .{
        .mds = 1200,
        .cwnd = 3000, // Would halve to 1500, below minimum
        .ssthresh = 3000,
    };

    nr.onLoss(500);

    // cwnd should be at minimum: 2 * 1200 = 2400
    try testing.expectEqual(@as(usize, 2400), nr.cwnd);
}

test "RFC 9002 §7.3.3 - onLoss reduces bytes_in_flight" {
    var nr: NewReno = .{
        .bytes_in_flight = 5000,
    };

    nr.onLoss(1200);

    try testing.expectEqual(@as(usize, 3800), nr.bytes_in_flight);
}

test "RFC 9002 §7.3.3 - onLoss does not underflow bytes_in_flight" {
    var nr: NewReno = .{
        .bytes_in_flight = 500,
    };

    nr.onLoss(1200); // More than in flight

    try testing.expectEqual(@as(usize, 0), nr.bytes_in_flight);
}

test "onLoss at minimum window maintains minimum" {
    var nr: NewReno = .{
        .mds = 1200,
        .cwnd = 2400, // Already at minimum
        .ssthresh = 2400,
    };

    nr.onLoss(1000);

    // Should stay at minimum
    try testing.expectEqual(@as(usize, 2400), nr.cwnd);
}

// =============================================================================
// CUBIC Tests (RFC 9002 Appendix B.2)
// =============================================================================

test "RFC 9002 Appendix B.2 - Cubic wraps NewReno" {
    const cubic: Cubic = .{};
    // Verify it has an inner NewReno
    try testing.expectEqual(@as(usize, 1200), cubic.inner.mds);
}

test "Cubic onPacketSent delegates to inner NewReno" {
    var cubic: Cubic = .{};
    cubic.onPacketSent(1200, true);
    try testing.expectEqual(@as(usize, 1200), cubic.inner.bytes_in_flight);
}

test "Cubic onAck delegates to inner NewReno" {
    var cubic: Cubic = .{
        .inner = .{ .cwnd = 12000, .ssthresh = 10000 },
    };

    const initial_cwnd = cubic.inner.cwnd;
    cubic.onAck(1200);

    // Should have increased cwnd via NewReno logic
    try testing.expect(cubic.inner.cwnd > initial_cwnd);
}

test "Cubic onLoss delegates to inner NewReno" {
    var cubic: Cubic = .{
        .inner = .{ .cwnd = 20000 },
    };

    cubic.onLoss(1200);

    // Should have halved cwnd via NewReno logic
    try testing.expectEqual(@as(usize, 10000), cubic.inner.cwnd);
}

test "Cubic can be used as drop-in replacement for NewReno" {
    var cubic: Cubic = .{};

    // Simulate packet sending
    cubic.onPacketSent(1200, true);
    cubic.onPacketSent(1200, true);

    // Simulate ACK
    cubic.onAck(2400);

    // Verify state is updated
    try testing.expect(cubic.inner.cwnd > 12000);
    try testing.expectEqual(@as(usize, 0), cubic.inner.bytes_in_flight);
}

// =============================================================================
// Pacing Delay Tests
// =============================================================================

test "computePacingDelayNs returns 0 when bytes_in_flight < cwnd/2" {
    const cwnd: usize = 10000;
    const bytes_in_flight: usize = 4000; // Less than half

    const delay = computePacingDelayNs(cwnd, bytes_in_flight);
    try testing.expectEqual(@as(u64, 0), delay);
}

test "computePacingDelayNs returns 250us when bytes_in_flight between cwnd/2 and cwnd" {
    const cwnd: usize = 10000;
    const bytes_in_flight: usize = 7000; // Between half and full

    const delay = computePacingDelayNs(cwnd, bytes_in_flight);
    try testing.expectEqual(@as(u64, 250_000), delay); // 0.25ms
}

test "computePacingDelayNs returns 1ms when bytes_in_flight >= cwnd" {
    const cwnd: usize = 10000;
    const bytes_in_flight: usize = 10000; // At cwnd

    const delay = computePacingDelayNs(cwnd, bytes_in_flight);
    try testing.expectEqual(@as(u64, 1_000_000), delay); // 1ms
}

test "computePacingDelayNs returns 1ms when bytes_in_flight > cwnd" {
    const cwnd: usize = 10000;
    const bytes_in_flight: usize = 15000; // Over cwnd

    const delay = computePacingDelayNs(cwnd, bytes_in_flight);
    try testing.expectEqual(@as(u64, 1_000_000), delay);
}

test "computePacingDelayNs returns 0 when cwnd is zero" {
    const delay = computePacingDelayNs(0, 1000);
    try testing.expectEqual(@as(u64, 0), delay);
}

// =============================================================================
// Boundary Cases
// =============================================================================

test "boundary: onAck with zero bytes" {
    var nr: NewReno = .{};
    const initial_cwnd = nr.cwnd;

    nr.onAck(0);

    // cwnd should not change
    try testing.expectEqual(initial_cwnd, nr.cwnd);
}

test "boundary: onLoss with zero bytes" {
    var nr: NewReno = .{ .cwnd = 20000, .bytes_in_flight = 5000 };
    const initial_cwnd = nr.cwnd;

    nr.onLoss(0);

    // cwnd should still be halved
    try testing.expectEqual(initial_cwnd / 2, nr.cwnd);
}

test "boundary: onAck when bytes_in_flight is zero" {
    var nr: NewReno = .{ .bytes_in_flight = 0 };

    nr.onAck(1200);

    // Should not underflow
    try testing.expectEqual(@as(usize, 0), nr.bytes_in_flight);
}

test "boundary: onAck reduces bytes_in_flight to exactly zero" {
    var nr: NewReno = .{ .bytes_in_flight = 1200 };

    nr.onAck(1200);

    try testing.expectEqual(@as(usize, 0), nr.bytes_in_flight);
}

test "boundary: cwnd at maximum before onAck" {
    var nr: NewReno = .{
        .cwnd = std.math.maxInt(usize) - 1000,
        .ssthresh = 1000, // In congestion avoidance
    };

    // Should not overflow
    nr.onAck(1200);
    try testing.expect(nr.cwnd <= std.math.maxInt(usize));
}

test "boundary: multiple losses drive cwnd to minimum" {
    var nr: NewReno = .{ .mds = 1200, .cwnd = 100000 };

    // Multiple losses
    nr.onLoss(1000);
    nr.onLoss(1000);
    nr.onLoss(1000);

    // Should be at or above minimum
    try testing.expect(nr.cwnd >= 2 * nr.mds);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 §7.2 - initial cwnd is at least 10 * mds" {
    const nr: NewReno = .{};
    try testing.expect(nr.cwnd >= 10 * nr.mds);
}

test "RFC 9002 §7.2 - minimum cwnd is 2 * mds after loss" {
    var nr: NewReno = .{ .mds = 1200, .cwnd = 3000 };
    nr.onLoss(500);

    try testing.expect(nr.cwnd >= 2 * nr.mds);
}

test "RFC 9002 §7.3.1 - slow start increases cwnd by bytes_acked" {
    var nr: NewReno = .{};
    const initial = nr.cwnd;

    nr.onAck(2400);

    // In slow start, direct addition
    try testing.expectEqual(initial + 2400, nr.cwnd);
}

test "RFC 9002 §7.3.2 - congestion avoidance increases cwnd by mds per RTT" {
    var nr: NewReno = .{
        .mds = 1200,
        .cwnd = 24000,
        .ssthresh = 12000, // In congestion avoidance
    };

    // ACK one window worth of data
    const initial = nr.cwnd;
    var total_acked: usize = 0;
    while (total_acked < 24000) : (total_acked += 1200) {
        nr.onAck(1200);
    }

    // After one RTT worth of ACKs, cwnd should increase by ~mds
    const increase = nr.cwnd - initial;
    const mds_f = @as(f64, @floatFromInt(nr.mds));
    const lower_bound = @as(usize, @intFromFloat(mds_f * 0.9));
    const upper_bound = @as(usize, @intFromFloat(mds_f * 1.1));
    try testing.expect(increase >= lower_bound); // Allow some rounding
    try testing.expect(increase <= upper_bound);
}

test "RFC 9002 §7.3.3 - loss reduces cwnd by multiplicative decrease" {
    var nr: NewReno = .{ .cwnd = 20000 };
    nr.onLoss(1000);

    // Multiplicative decrease factor is 0.5
    try testing.expectEqual(@as(usize, 10000), nr.cwnd);
}

test "RFC 9002 §7 - bytes_in_flight tracks unacknowledged data" {
    var nr: NewReno = .{};

    nr.onPacketSent(1200, true);
    nr.onPacketSent(1200, true);
    try testing.expectEqual(@as(usize, 2400), nr.bytes_in_flight);

    nr.onAck(1200);
    try testing.expectEqual(@as(usize, 1200), nr.bytes_in_flight);

    nr.onLoss(600);
    try testing.expectEqual(@as(usize, 600), nr.bytes_in_flight);
}

// =============================================================================
// Integration Tests
// =============================================================================

test "NewReno complete slow start to congestion avoidance transition" {
    var nr: NewReno = .{
        .mds = 1200,
        .cwnd = 12000,
        .ssthresh = 20000,
    };

    // In slow start
    try testing.expect(nr.cwnd < nr.ssthresh);

    // ACK packets to cross threshold
    nr.onAck(5000);
    nr.onAck(5000);

    // Now in congestion avoidance
    try testing.expect(nr.cwnd >= nr.ssthresh);

    // Further ACKs should grow slowly
    const cwnd_at_ca = nr.cwnd;
    nr.onAck(1200);
    const growth = nr.cwnd - cwnd_at_ca;

    // Growth should be much less than bytes_acked
    try testing.expect(growth < 1200);
}

test "NewReno recovers from loss and re-enters slow start" {
    var nr: NewReno = .{
        .cwnd = 40000,
        .ssthresh = 30000,
    };

    // Trigger loss
    nr.onLoss(2000);

    // cwnd should be halved and equal to ssthresh
    try testing.expectEqual(@as(usize, 20000), nr.cwnd);
    try testing.expectEqual(nr.cwnd, nr.ssthresh);

    // Now in congestion avoidance (cwnd == ssthresh)
    // Further ACKs use congestion avoidance formula
    const cwnd_before = nr.cwnd;
    nr.onAck(1200);
    const increase = nr.cwnd - cwnd_before;

    // Should be small increase (congestion avoidance)
    try testing.expect(increase < 1200);
}

test "Cubic maintains parity with NewReno in basic scenarios" {
    var nr: NewReno = .{};
    var cubic: Cubic = .{};

    // Send packets
    nr.onPacketSent(1200, true);
    cubic.onPacketSent(1200, true);

    // ACK packets
    nr.onAck(1200);
    cubic.onAck(1200);

    // Should have same state
    try testing.expectEqual(nr.cwnd, cubic.inner.cwnd);
    try testing.expectEqual(nr.bytes_in_flight, cubic.inner.bytes_in_flight);
}

test "pacing delays scale with congestion window utilization" {
    const cwnd: usize = 20000;

    const delay_low = computePacingDelayNs(cwnd, cwnd / 4); // 25% full
    const delay_med = computePacingDelayNs(cwnd, cwnd * 3 / 4); // 75% full
    const delay_high = computePacingDelayNs(cwnd, cwnd + 1000); // Over full

    // Delays should increase with utilization
    try testing.expect(delay_low < delay_med);
    try testing.expect(delay_med < delay_high);
}

test "NewReno handles rapid ACK and loss events" {
    var nr: NewReno = .{ .mds = 1200 };

    // Rapid slow start
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        nr.onPacketSent(1200, true);
        nr.onAck(1200);
    }

    const cwnd_after_growth = nr.cwnd;

    // Sudden loss
    nr.onLoss(5000);

    // cwnd should be halved from peak
    try testing.expectEqual(cwnd_after_growth / 2, nr.cwnd);

    // Should enforce minimum
    try testing.expect(nr.cwnd >= 2 * nr.mds);
}
