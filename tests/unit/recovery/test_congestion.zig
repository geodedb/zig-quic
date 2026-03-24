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
// CUBIC Tests (RFC 8312)
// =============================================================================

test "RFC 8312 - Cubic initializes with standard defaults" {
    const cubic: Cubic = .{};
    try testing.expectEqual(@as(usize, 1200), cubic.mds);
    try testing.expectEqual(@as(usize, 10 * 1200), cubic.cwnd);
    try testing.expectEqual(@as(usize, std.math.maxInt(usize) / 2), cubic.ssthresh);
    try testing.expectEqual(@as(usize, 0), cubic.bytes_in_flight);
    try testing.expectEqual(@as(usize, 0), cubic.w_max);
    try testing.expect(cubic.epoch_start_ns == null);
}

test "RFC 8312 - Cubic constants are correct" {
    try testing.expectEqual(@as(f64, 0.4), Cubic.C);
    try testing.expectEqual(@as(f64, 0.7), Cubic.BETA);
}

test "RFC 8312 - Cubic onPacketSent tracks bytes_in_flight" {
    var cubic: Cubic = .{};
    cubic.onPacketSent(1200, true);
    try testing.expectEqual(@as(usize, 1200), cubic.bytes_in_flight);
    cubic.onPacketSent(800, false); // non-ACK-eliciting
    try testing.expectEqual(@as(usize, 1200), cubic.bytes_in_flight);
    cubic.onPacketSent(1200, true);
    try testing.expectEqual(@as(usize, 2400), cubic.bytes_in_flight);
}

test "RFC 8312 - computeK returns zero for zero w_max" {
    const k = Cubic.computeK(0, 1200);
    try testing.expectEqual(@as(f64, 0.0), k);
}

test "RFC 8312 - computeK returns correct value" {
    // W_max = 120000 bytes, mds = 1200 => W_max_mss = 100
    // K = cbrt(100 * (1 - 0.7) / 0.4) = cbrt(100 * 0.3 / 0.4) = cbrt(75) ~= 4.2172
    const k = Cubic.computeK(120000, 1200);
    const expected = std.math.cbrt(@as(f64, 75.0));
    try testing.expectApproxEqAbs(expected, k, 0.0001);
}

test "RFC 8312 - computeK scales with w_max" {
    // Larger W_max should produce larger K
    const k_small = Cubic.computeK(12000, 1200);
    const k_large = Cubic.computeK(120000, 1200);
    try testing.expect(k_large > k_small);
}

test "RFC 8312 - wCubicBytes at t=K returns W_max" {
    const w_max: usize = 120000;
    const mds: usize = 1200;
    const k = Cubic.computeK(w_max, mds);
    // At t=K, (t-K)^3 = 0, so W_cubic = W_max
    const w = Cubic.wCubicBytes(k, k, w_max, mds);
    try testing.expectEqual(w_max, w);
}

test "RFC 8312 - wCubicBytes grows beyond W_max for t > K" {
    const w_max: usize = 120000;
    const mds: usize = 1200;
    const k = Cubic.computeK(w_max, mds);
    // At t > K, cubic curve is above W_max
    const w = Cubic.wCubicBytes(k + 1.0, k, w_max, mds);
    try testing.expect(w > w_max);
}

test "RFC 8312 - wCubicBytes below W_max for t < K" {
    const w_max: usize = 120000;
    const mds: usize = 1200;
    const k = Cubic.computeK(w_max, mds);
    // At t < K, cubic curve is below W_max (recovering from loss)
    const w = Cubic.wCubicBytes(k / 2.0, k, w_max, mds);
    try testing.expect(w < w_max);
}

test "RFC 8312 - wCubicBytes returns 0 for mds=0" {
    const w = Cubic.wCubicBytes(1.0, 0.5, 120000, 0);
    try testing.expectEqual(@as(usize, 0), w);
}

test "RFC 8312 - computeWEst provides TCP-friendly estimate" {
    const w_max: usize = 120000;
    const mds: usize = 1200;
    const rtt_sec: f64 = 0.1; // 100ms RTT
    // At t=0, W_est = W_max * beta = 120000 * 0.7 = 84000
    const w_est_0 = Cubic.computeWEst(0.0, rtt_sec, w_max, mds);
    try testing.expectEqual(@as(usize, 84000), w_est_0);

    // At t=1s (10 RTTs), W_est should be higher
    const w_est_1 = Cubic.computeWEst(1.0, rtt_sec, w_max, mds);
    try testing.expect(w_est_1 > w_est_0);
}

test "RFC 8312 - computeWEst returns 0 for zero RTT" {
    const w_est = Cubic.computeWEst(1.0, 0.0, 120000, 1200);
    try testing.expectEqual(@as(usize, 0), w_est);
}

test "RFC 8312 - computeWEst grows linearly with time" {
    const w_max: usize = 120000;
    const mds: usize = 1200;
    const rtt_sec: f64 = 0.05;
    const w1 = Cubic.computeWEst(1.0, rtt_sec, w_max, mds);
    const w2 = Cubic.computeWEst(2.0, rtt_sec, w_max, mds);
    const w3 = Cubic.computeWEst(3.0, rtt_sec, w_max, mds);
    // Linear growth: differences should be approximately equal
    const diff_12 = w2 - w1;
    const diff_23 = w3 - w2;
    try testing.expect(diff_12 > 0);
    // Allow 1 byte rounding tolerance
    try testing.expectApproxEqAbs(@as(f64, @floatFromInt(diff_12)), @as(f64, @floatFromInt(diff_23)), 2.0);
}

test "RFC 8312 - onLoss reduces cwnd by beta=0.7 (not 0.5)" {
    var cubic: Cubic = .{
        .cwnd = 100000,
        .ssthresh = 50000,
    };
    cubic.onLoss(1000);

    // cwnd should be 100000 * 0.7 = 70000 (using integer: 100000 * 7 / 10)
    try testing.expectEqual(@as(usize, 70000), cubic.cwnd);
    try testing.expectEqual(cubic.cwnd, cubic.ssthresh);
}

test "RFC 8312 - onLoss saves W_max" {
    var cubic: Cubic = .{
        .cwnd = 100000,
        .ssthresh = 50000,
    };
    cubic.onLoss(1000);

    // W_max should be the cwnd before loss
    try testing.expectEqual(@as(usize, 100000), cubic.w_max);
}

test "RFC 8312 - onLoss resets epoch" {
    var cubic: Cubic = .{
        .cwnd = 100000,
        .epoch_start_ns = 1000,
        .k_sec = 5.0,
    };
    cubic.onLoss(1000);

    try testing.expect(cubic.epoch_start_ns == null);
    try testing.expectEqual(@as(f64, 0.0), cubic.k_sec);
}

test "RFC 8312 - onLoss enforces minimum window" {
    var cubic: Cubic = .{
        .mds = 1200,
        .cwnd = 3000, // 3000 * 0.7 = 2100, below 2*1200 = 2400
    };
    cubic.onLoss(500);

    try testing.expectEqual(@as(usize, 2400), cubic.cwnd);
}

test "RFC 8312 - onLoss reduces bytes_in_flight" {
    var cubic: Cubic = .{
        .bytes_in_flight = 5000,
    };
    cubic.onLoss(1200);

    try testing.expectEqual(@as(usize, 3800), cubic.bytes_in_flight);
}

test "RFC 8312 - onAck in slow start uses exponential growth" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    var cubic: Cubic = .{};
    const initial_cwnd = cubic.cwnd;
    cubic.onAck(1200, 1_000_000, rtt_ns);

    // In slow start, cwnd += bytes_acked
    try testing.expectEqual(initial_cwnd + 1200, cubic.cwnd);
}

test "RFC 8312 - onAck in congestion avoidance initializes epoch" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    var cubic: Cubic = .{
        .cwnd = 50000,
        .ssthresh = 40000,
        .w_max = 60000,
    };
    try testing.expect(cubic.epoch_start_ns == null);

    const now: u64 = 1_000_000_000;
    cubic.onAck(1200, now, rtt_ns);

    try testing.expectEqual(now, cubic.epoch_start_ns.?);
    try testing.expect(cubic.k_sec > 0.0);
}

test "RFC 8312 - cwnd eventually reaches and exceeds W_max" {
    const rtt_ns: u64 = 50 * std.time.ns_per_ms;
    const mds: usize = 1200;
    // Start post-loss: cwnd = W_max * 0.7
    const w_max: usize = 120000;
    var cubic: Cubic = .{
        .mds = mds,
        .cwnd = w_max * 7 / 10, // 84000
        .ssthresh = w_max * 7 / 10,
        .w_max = w_max,
    };

    // Simulate many ACKs over a long period
    var now: u64 = 1_000_000_000;
    const dt: u64 = rtt_ns / 10; // 5ms per ACK
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        cubic.onAck(mds, now, rtt_ns);
        now += dt;
    }

    // After sufficient time, cwnd should exceed W_max
    try testing.expect(cubic.cwnd >= w_max);
}

test "RFC 8312 - TCP-friendliness ensures cwnd >= AIMD estimate" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    const mds: usize = 1200;
    const w_max: usize = 120000;

    // Use the W_est formula to check friendliness
    // At various time points, verify computeWEst gives reasonable AIMD growth
    const rtt_sec: f64 = 0.1;

    // After 10 RTTs (1 second), W_est should grow noticeably from base
    const base = Cubic.computeWEst(0.0, rtt_sec, w_max, mds);
    const after_10_rtt = Cubic.computeWEst(1.0, rtt_sec, w_max, mds);
    try testing.expect(after_10_rtt > base);

    // Run CUBIC and check it stays at or above W_est at each step
    var cubic: Cubic = .{
        .mds = mds,
        .cwnd = w_max * 7 / 10,
        .ssthresh = w_max * 7 / 10,
        .w_max = w_max,
    };

    var now: u64 = 1_000_000_000;
    const dt: u64 = rtt_ns / 10;
    var j: usize = 0;
    while (j < 200) : (j += 1) {
        cubic.onAck(mds, now, rtt_ns);
        now += dt;

        // After epoch starts, cwnd should never be below initial ssthresh
        // (CUBIC and W_est both start from cwnd_after_loss)
        try testing.expect(cubic.cwnd >= w_max * 7 / 10);
    }
}

test "RFC 8312 - onAck with zero bytes does nothing" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    var cubic: Cubic = .{ .cwnd = 50000, .ssthresh = 40000 };
    const initial_cwnd = cubic.cwnd;
    cubic.onAck(0, 1_000_000, rtt_ns);
    try testing.expectEqual(initial_cwnd, cubic.cwnd);
}

test "RFC 8312 - cwnd never decreases on ACK" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    const mds: usize = 1200;
    var cubic: Cubic = .{
        .mds = mds,
        .cwnd = 50000,
        .ssthresh = 40000,
        .w_max = 60000,
    };

    var now: u64 = 1_000_000_000;
    var prev_cwnd: usize = cubic.cwnd;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        cubic.onAck(mds, now, rtt_ns);
        try testing.expect(cubic.cwnd >= prev_cwnd);
        prev_cwnd = cubic.cwnd;
        now += rtt_ns / 10;
    }
}

test "RFC 8312 - CUBIC loss-recovery cycle" {
    const rtt_ns: u64 = 50 * std.time.ns_per_ms;
    const mds: usize = 1200;

    var cubic: Cubic = .{
        .mds = mds,
        .cwnd = 100000,
        .ssthresh = 80000,
    };

    // Trigger loss
    cubic.onLoss(2000);
    try testing.expectEqual(@as(usize, 70000), cubic.cwnd);
    try testing.expectEqual(@as(usize, 100000), cubic.w_max);

    // Grow back via ACKs
    var now: u64 = 1_000_000_000;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        cubic.onAck(mds, now, rtt_ns);
        now += rtt_ns / 10;
    }

    // Should have grown back toward W_max
    try testing.expect(cubic.cwnd > 70000);

    // Trigger another loss
    const cwnd_before_loss2 = cubic.cwnd;
    cubic.onLoss(1000);
    try testing.expectEqual(cwnd_before_loss2, cubic.w_max);
    try testing.expectEqual(@max(cwnd_before_loss2 * 7 / 10, 2 * mds), cubic.cwnd);
}

// =============================================================================
// Pacing Delay Tests (RFC 9002 Section 7.7)
// =============================================================================

test "RFC 9002 §7.7 - computePacingDelayNs returns 0 when bytes_in_flight <= cwnd/2" {
    const cwnd: usize = 10000;
    const bytes_in_flight: usize = 4000; // Less than half
    const smoothed_rtt_ns: u64 = 100_000; // 100us
    const packet_size: usize = 1200;

    const delay = computePacingDelayNs(cwnd, bytes_in_flight, smoothed_rtt_ns, packet_size);
    try testing.expectEqual(@as(u64, 0), delay);
}

test "RFC 9002 §7.7 - computePacingDelayNs uses RTT-based formula when above half cwnd" {
    const cwnd: usize = 12000;
    const bytes_in_flight: usize = 7000; // Between half and full
    const smoothed_rtt_ns: u64 = 100_000; // 100us
    const packet_size: usize = 1200;

    const delay = computePacingDelayNs(cwnd, bytes_in_flight, smoothed_rtt_ns, packet_size);
    // Expected: packet_size * smoothed_rtt_ns / cwnd = 1200 * 100000 / 12000 = 10000 ns
    try testing.expectEqual(@as(u64, 10_000), delay);
}

test "RFC 9002 §7.7 - computePacingDelayNs at cwnd returns RTT-based delay" {
    const cwnd: usize = 12000;
    const bytes_in_flight: usize = 12000; // At cwnd
    const smoothed_rtt_ns: u64 = 100_000; // 100us
    const packet_size: usize = 1200;

    const delay = computePacingDelayNs(cwnd, bytes_in_flight, smoothed_rtt_ns, packet_size);
    // Expected: 1200 * 100000 / 12000 = 10000 ns
    try testing.expectEqual(@as(u64, 10_000), delay);
}

test "RFC 9002 §7.7 - computePacingDelayNs above cwnd returns RTT-based delay" {
    const cwnd: usize = 12000;
    const bytes_in_flight: usize = 15000; // Over cwnd
    const smoothed_rtt_ns: u64 = 100_000; // 100us
    const packet_size: usize = 1200;

    const delay = computePacingDelayNs(cwnd, bytes_in_flight, smoothed_rtt_ns, packet_size);
    // Same formula regardless of how far over cwnd we are
    try testing.expectEqual(@as(u64, 10_000), delay);
}

test "RFC 9002 §7.7 - computePacingDelayNs returns 0 when cwnd is zero" {
    const delay = computePacingDelayNs(0, 1000, 100_000, 1200);
    try testing.expectEqual(@as(u64, 0), delay);
}

test "RFC 9002 §7.7 - computePacingDelayNs returns 0 when smoothed_rtt is zero" {
    const delay = computePacingDelayNs(12000, 8000, 0, 1200);
    try testing.expectEqual(@as(u64, 0), delay);
}

test "RFC 9002 §7.7 - pacing delay scales linearly with RTT" {
    const cwnd: usize = 12000;
    const bytes_in_flight: usize = 8000; // Above half
    const packet_size: usize = 1200;

    const delay_100us = computePacingDelayNs(cwnd, bytes_in_flight, 100_000, packet_size);
    const delay_200us = computePacingDelayNs(cwnd, bytes_in_flight, 200_000, packet_size);

    // Doubling RTT should double the pacing delay
    try testing.expectEqual(delay_100us * 2, delay_200us);
}

test "RFC 9002 §7.7 - pacing delay inversely proportional to cwnd" {
    const bytes_in_flight: usize = 8000;
    const smoothed_rtt_ns: u64 = 120_000; // 120us (chosen for clean division)
    const packet_size: usize = 1200;

    const delay_small_cwnd = computePacingDelayNs(12000, bytes_in_flight, smoothed_rtt_ns, packet_size);
    const delay_large_cwnd = computePacingDelayNs(24000, bytes_in_flight, smoothed_rtt_ns, packet_size);

    // Doubling cwnd should halve the pacing delay
    try testing.expectEqual(delay_small_cwnd, delay_large_cwnd * 2);
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

test "Cubic slow start matches NewReno behavior" {
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    var nr: NewReno = .{};
    var cubic: Cubic = .{};

    // Send packets
    nr.onPacketSent(1200, true);
    cubic.onPacketSent(1200, true);

    // ACK packets (both in slow start)
    nr.onAck(1200);
    cubic.onAck(1200, 1_000_000, rtt_ns);

    // In slow start, both should grow identically
    try testing.expectEqual(nr.cwnd, cubic.cwnd);
    try testing.expectEqual(nr.bytes_in_flight, cubic.bytes_in_flight);
}

test "pacing delays scale with congestion window utilization" {
    const cwnd: usize = 20000;
    const smoothed_rtt_ns: u64 = 100_000; // 100us
    const packet_size: usize = 1200;

    const delay_low = computePacingDelayNs(cwnd, cwnd / 4, smoothed_rtt_ns, packet_size); // 25% full - below half, returns 0
    const delay_med = computePacingDelayNs(cwnd, cwnd * 3 / 4, smoothed_rtt_ns, packet_size); // 75% full - above half, returns formula
    const delay_high = computePacingDelayNs(cwnd, cwnd + 1000, smoothed_rtt_ns, packet_size); // Over full - same formula

    // Low utilization returns 0 (slow-start exemption), medium returns non-zero
    try testing.expectEqual(@as(u64, 0), delay_low);
    try testing.expect(delay_med > 0);
    // Above half-cwnd, the formula is constant (same packet_size, rtt, cwnd)
    try testing.expectEqual(delay_med, delay_high);
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
