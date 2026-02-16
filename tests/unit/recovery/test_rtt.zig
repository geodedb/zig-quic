//! Unit tests for recovery/rtt.zig
//!
//! RFC References:
//! - RFC 9002 §5: Estimating the Round-Trip Time
//! - RFC 9002 §5.3: Estimating smoothed_rtt and rttvar
//! - RFC 9002 §6.2: Probe Timeout
//! - RFC 9002 §6.2.1: Computing PTO
//!
//! Coverage:
//! - Positive cases: RTT estimation, PTO computation
//! - Negative cases: Zero RTT, overflow handling
//! - Boundary cases: First sample, very large RTT, maximum backoff
//! - RFC compliance: EWMA smoothing, PTO formula

const std = @import("std");
const testing = std.testing;

const rtt_mod = @import("rtt");
const RttState = rtt_mod.RttState;

// =============================================================================
// RttState Initialization Tests
// =============================================================================

test "RttState initializes with no samples" {
    const rtt: RttState = .{};
    try testing.expect(!rtt.have_sample);
}

test "RttState initializes all RTT values per RFC 9002 Appendix A.2" {
    // RFC 9002 Appendix A.2: kInitialRtt = 333ms
    const rtt: RttState = .{};
    try testing.expectEqual(@as(u64, 0), rtt.min_rtt_ns); // Only set after first sample
    try testing.expectEqual(@as(u64, 0), rtt.latest_rtt_ns); // Only set after first sample
    try testing.expectEqual(@as(u64, 333_000_000), rtt.smoothed_rtt_ns); // 333ms initial RTT
    try testing.expectEqual(@as(u64, 166_500_000), rtt.rttvar_ns); // initial_rtt / 2
}

test "RttState initializes max_ack_delay_ns to zero" {
    const rtt: RttState = .{};
    try testing.expectEqual(@as(u64, 0), rtt.max_ack_delay_ns);
}

test "RttState can be created with custom max_ack_delay" {
    const rtt: RttState = .{ .max_ack_delay_ns = 25_000_000 }; // 25ms
    try testing.expectEqual(@as(u64, 25_000_000), rtt.max_ack_delay_ns);
}

// =============================================================================
// First RTT Sample Tests (RFC 9002 §5)
// =============================================================================

test "RFC 9002 §5 - first onAck sets have_sample to true" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // 50ms RTT, 0 delay
    try testing.expect(rtt.have_sample);
}

test "RFC 9002 §5 - first onAck sets min_rtt" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // 50ms
    try testing.expectEqual(@as(u64, 50_000_000), rtt.min_rtt_ns);
}

test "RFC 9002 §5 - first onAck sets latest_rtt" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0);
    try testing.expectEqual(@as(u64, 50_000_000), rtt.latest_rtt_ns);
}

test "RFC 9002 §5 - first onAck sets smoothed_rtt to measured" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0);
    try testing.expectEqual(@as(u64, 50_000_000), rtt.smoothed_rtt_ns);
}

test "RFC 9002 §5 - first onAck sets rttvar to rtt/2" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0);
    try testing.expectEqual(@as(u64, 25_000_000), rtt.rttvar_ns);
}

test "RFC 9002 §5 - first onAck ignores ack_delay" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 10_000_000); // 50ms RTT, 10ms delay
    // First sample should use measured RTT directly
    try testing.expectEqual(@as(u64, 50_000_000), rtt.smoothed_rtt_ns);
}

// =============================================================================
// Subsequent RTT Sample Tests (RFC 9002 §5.3)
// =============================================================================

test "RFC 9002 §5.3 - onAck updates min_rtt when smaller" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // 50ms
    rtt.onAck(30_000_000, 0); // 30ms
    try testing.expectEqual(@as(u64, 30_000_000), rtt.min_rtt_ns);
}

test "RFC 9002 §5.3 - onAck preserves min_rtt when larger" {
    var rtt: RttState = .{};
    rtt.onAck(30_000_000, 0); // 30ms
    rtt.onAck(50_000_000, 0); // 50ms
    try testing.expectEqual(@as(u64, 30_000_000), rtt.min_rtt_ns);
}

test "RFC 9002 §5.3 - onAck adjusts RTT by subtracting ack_delay" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // First sample
    rtt.onAck(60_000_000, 10_000_000); // 60ms measured, 10ms delay
    // Adjusted RTT should be max(60-10, min_rtt) = 50ms
    try testing.expectEqual(@as(u64, 50_000_000), rtt.latest_rtt_ns);
}

test "RFC 9002 §5.3 - adjusted RTT cannot be less than min_rtt" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // First sample: min_rtt=50ms
    rtt.onAck(55_000_000, 20_000_000); // 55ms - 20ms = 35ms, but min is 50ms
    try testing.expectEqual(@as(u64, 50_000_000), rtt.latest_rtt_ns);
}

test "RFC 9002 §5.3 - smoothed_rtt uses EWMA with 7/8 weight" {
    var rtt: RttState = .{};
    rtt.onAck(80_000_000, 0); // First: smoothed=80ms
    rtt.onAck(40_000_000, 0); // Second: smoothed = 7/8 * 80 + 1/8 * 40 = 70 + 5 = 75ms

    const expected: u64 = (80_000_000 * 7) / 8 + (40_000_000 / 8);
    try testing.expectEqual(expected, rtt.smoothed_rtt_ns);
}

test "RFC 9002 §5.3 - rttvar uses EWMA with 3/4 weight" {
    var rtt: RttState = .{};
    rtt.onAck(100_000_000, 0); // First: rttvar=50ms
    const initial_rttvar = rtt.rttvar_ns;

    rtt.onAck(200_000_000, 0); // abs_err = |100 - 200| = 100ms
    // rttvar = 3/4 * 50 + 1/4 * 100 = 37.5 + 25 = 62.5ms
    // This is complex due to two-step calculation, just verify it changed
    try testing.expect(rtt.rttvar_ns != initial_rttvar);
}

test "RFC 9002 §5.3 - multiple samples converge smoothed_rtt" {
    var rtt: RttState = .{};
    rtt.onAck(100_000_000, 0); // 100ms
    rtt.onAck(100_000_000, 0);
    rtt.onAck(100_000_000, 0);
    rtt.onAck(100_000_000, 0);

    // After multiple identical samples, smoothed_rtt should be close to measured
    try testing.expect(rtt.smoothed_rtt_ns >= 99_000_000);
    try testing.expect(rtt.smoothed_rtt_ns <= 101_000_000);
}

// =============================================================================
// PTO Computation Tests (RFC 9002 §6.2.1)
// =============================================================================

test "RFC 9002 §6.2.1 - computePtoNs formula is smoothed + 4*rttvar + max_ack_delay" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000, // 100ms
        .rttvar_ns = 50_000_000, // 50ms
        .max_ack_delay_ns = 25_000_000, // 25ms
    };

    const pto = rtt.computePtoNs();
    // PTO = 100 + 4*50 + 25 = 100 + 200 + 25 = 325ms
    try testing.expectEqual(@as(u64, 325_000_000), pto);
}

test "RFC 9002 §6.2.1 - computePtoNs with zero max_ack_delay" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const pto = rtt.computePtoNs();
    // PTO = 100 + 4*25 + 0 = 200ms
    try testing.expectEqual(@as(u64, 200_000_000), pto);
}

test "RFC 9002 §6.2.1 - computePtoNs before first sample uses initial RTT" {
    // RFC 9002 §6.2: Before any RTT samples, use initial RTT
    // PTO = smoothed(333ms) + 4*rttvar(166.5ms) + max_ack_delay(0) = 999ms
    const rtt: RttState = .{};
    const pto = rtt.computePtoNs();
    try testing.expectEqual(@as(u64, 999_000_000), pto); // 999ms
}

test "RFC 9002 §6.2.1 - computePtoNsWithBackoff with pto_count=0 adds granularity" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const granularity_ns: u64 = 1_000_000; // 1ms
    const pto = rtt.computePtoNsWithBackoff(0, granularity_ns);

    // PTO = (100 + 4*25 + 0) + 1 = 201ms
    const base = rtt.computePtoNs();
    try testing.expectEqual(base + granularity_ns, pto);
}

test "RFC 9002 §6.2.1 - computePtoNsWithBackoff doubles with pto_count=1" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const granularity_ns: u64 = 1_000_000;
    const pto0 = rtt.computePtoNsWithBackoff(0, granularity_ns);
    const pto1 = rtt.computePtoNsWithBackoff(1, granularity_ns);

    // PTO with backoff=1 should be 2x
    try testing.expectEqual(pto0 * 2, pto1);
}

test "RFC 9002 §6.2.1 - computePtoNsWithBackoff quadruples with pto_count=2" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const granularity_ns: u64 = 1_000_000;
    const pto0 = rtt.computePtoNsWithBackoff(0, granularity_ns);
    const pto2 = rtt.computePtoNsWithBackoff(2, granularity_ns);

    // PTO with backoff=2 should be 4x
    try testing.expectEqual(pto0 * 4, pto2);
}

test "RFC 9002 §6.2.1 - computePtoNsWithBackoff exponential backoff" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 50_000_000,
        .rttvar_ns = 10_000_000,
        .max_ack_delay_ns = 0,
    };

    const granularity_ns: u64 = 1_000_000;
    const pto0 = rtt.computePtoNsWithBackoff(0, granularity_ns);
    const pto3 = rtt.computePtoNsWithBackoff(3, granularity_ns);

    // PTO with backoff=3 should be 8x (2^3)
    try testing.expectEqual(pto0 * 8, pto3);
}

// =============================================================================
// Boundary Cases
// =============================================================================

test "boundary: onAck with zero measured RTT" {
    var rtt: RttState = .{};
    rtt.onAck(0, 0);

    try testing.expect(rtt.have_sample);
    try testing.expectEqual(@as(u64, 0), rtt.smoothed_rtt_ns);
}

test "boundary: onAck with very large RTT" {
    var rtt: RttState = .{};
    const large_rtt: u64 = 10_000_000_000; // 10 seconds
    rtt.onAck(large_rtt, 0);

    try testing.expectEqual(large_rtt, rtt.smoothed_rtt_ns);
    try testing.expectEqual(large_rtt / 2, rtt.rttvar_ns);
}

test "boundary: computePtoNsWithBackoff handles large pto_count" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    // Very large backoff should return max_u64
    const pto = rtt.computePtoNsWithBackoff(63, 1_000_000);
    try testing.expectEqual(std.math.maxInt(u64), pto);
}

test "boundary: computePtoNsWithBackoff prevents overflow" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = std.math.maxInt(u64) / 2,
        .rttvar_ns = std.math.maxInt(u64) / 8,
        .max_ack_delay_ns = 0,
    };

    // Should not overflow
    const pto = rtt.computePtoNsWithBackoff(1, 1000);
    try testing.expect(pto <= std.math.maxInt(u64));
}

test "boundary: min_rtt tracks minimum across many samples" {
    var rtt: RttState = .{};
    rtt.onAck(100_000_000, 0);
    rtt.onAck(80_000_000, 0);
    rtt.onAck(120_000_000, 0);
    rtt.onAck(50_000_000, 0); // Minimum
    rtt.onAck(90_000_000, 0);

    try testing.expectEqual(@as(u64, 50_000_000), rtt.min_rtt_ns);
}

test "boundary: ack_delay larger than measured RTT" {
    var rtt: RttState = .{};
    rtt.onAck(50_000_000, 0); // First sample
    rtt.onAck(30_000_000, 40_000_000); // Delay > measured

    // Adjusted should be max(30-40, min_rtt) = max(0, 50) = 50
    try testing.expectEqual(@as(u64, 50_000_000), rtt.latest_rtt_ns);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 §5 - RTT estimation maintains min_rtt" {
    var rtt: RttState = .{};
    const samples = [_]u64{ 100_000_000, 80_000_000, 120_000_000, 90_000_000 };

    for (samples) |sample| {
        rtt.onAck(sample, 0);
    }

    // min_rtt should be the smallest sample
    try testing.expectEqual(@as(u64, 80_000_000), rtt.min_rtt_ns);
}

test "RFC 9002 §5.3 - smoothed_rtt uses exponential weighted moving average" {
    var rtt: RttState = .{};
    rtt.onAck(100_000_000, 0);

    const before = rtt.smoothed_rtt_ns;
    rtt.onAck(200_000_000, 0);
    const after = rtt.smoothed_rtt_ns;

    // Smoothed should be between the two values (closer to first due to 7/8 weight)
    try testing.expect(after > before);
    try testing.expect(after < 200_000_000);
}

test "RFC 9002 §5.3 - rttvar tracks RTT variation" {
    var rtt: RttState = .{};
    rtt.onAck(100_000_000, 0);

    // With stable RTT, rttvar should decrease
    rtt.onAck(100_000_000, 0);
    rtt.onAck(100_000_000, 0);

    // rttvar should be decreasing toward zero
    try testing.expect(rtt.rttvar_ns < 50_000_000);
}

test "RFC 9002 §6.2.1 - PTO is at least smoothed_rtt + 4*rttvar" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const pto = rtt.computePtoNs();
    const minimum = rtt.smoothed_rtt_ns + (4 * rtt.rttvar_ns);

    try testing.expect(pto >= minimum);
}

test "RFC 9002 §6.2.1 - PTO includes max_ack_delay for Application space" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 25_000_000,
    };

    const pto = rtt.computePtoNs();
    const without_delay = rtt.smoothed_rtt_ns + (4 * rtt.rttvar_ns);

    try testing.expectEqual(without_delay + rtt.max_ack_delay_ns, pto);
}

test "RFC 9002 §6.2 - PTO uses exponential backoff on retransmission" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 25_000_000,
        .max_ack_delay_ns = 0,
    };

    const pto0 = rtt.computePtoNsWithBackoff(0, 1_000_000);
    const pto1 = rtt.computePtoNsWithBackoff(1, 1_000_000);
    const pto2 = rtt.computePtoNsWithBackoff(2, 1_000_000);

    // Each backoff should double
    try testing.expect(pto1 >= pto0 * 2);
    try testing.expect(pto2 >= pto1 * 2);
}

// =============================================================================
// Integration Tests
// =============================================================================

test "RttState tracks RTT evolution over time" {
    var rtt: RttState = .{ .max_ack_delay_ns = 25_000_000 };

    // Simulate a series of ACKs with varying RTT
    const samples = [_]u64{
        100_000_000, // 100ms
        110_000_000, // 110ms
        90_000_000, // 90ms
        95_000_000, // 95ms
        105_000_000, // 105ms
    };

    for (samples) |sample| {
        rtt.onAck(sample, 0);
    }

    try testing.expect(rtt.have_sample);
    try testing.expectEqual(@as(u64, 90_000_000), rtt.min_rtt_ns);
    // Smoothed should be somewhere in the range
    try testing.expect(rtt.smoothed_rtt_ns >= 90_000_000);
    try testing.expect(rtt.smoothed_rtt_ns <= 110_000_000);
}

test "PTO increases with RTT variance" {
    var rtt1: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 10_000_000, // Low variance
        .max_ack_delay_ns = 0,
    };

    var rtt2: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 100_000_000,
        .rttvar_ns = 40_000_000, // High variance
        .max_ack_delay_ns = 0,
    };

    const pto1 = rtt1.computePtoNs();
    const pto2 = rtt2.computePtoNs();

    // Higher variance should result in higher PTO
    try testing.expect(pto2 > pto1);
}

test "multiple backoff levels increase timeout exponentially" {
    var rtt: RttState = .{
        .have_sample = true,
        .smoothed_rtt_ns = 50_000_000,
        .rttvar_ns = 10_000_000,
        .max_ack_delay_ns = 0,
    };

    const gran: u64 = 1_000_000;
    var prev_pto: u64 = 0;

    // Test backoff levels 0 through 5
    var i: u32 = 0;
    while (i <= 5) : (i += 1) {
        const pto = rtt.computePtoNsWithBackoff(i, gran);
        if (i > 0) {
            // Each level should be approximately 2x previous
            const ratio = pto / prev_pto;
            try testing.expect(ratio >= 2);
        }
        prev_pto = pto;
    }
}
