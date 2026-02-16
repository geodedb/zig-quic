//! Loss Recovery Test Helpers (Phase 21.4)
//!
//! Provides test utilities for loss detection, RTT estimation, and PTO timer validation.
//! Designed for use with ConnectionPair and packet capture infrastructure.
//!
//! Features:
//! - Loss event detection from packet capture
//! - RTT estimation validation
//! - PTO timer inspection
//! - Packet retransmission verification
//!
//! RFC References:
//! - RFC 9002 §5: RTT Estimation
//! - RFC 9002 §6: Loss Detection
//! - RFC 9002 §6.2: Probe Timeout (PTO)

const std = @import("std");
const testlog = @import("testlog");
const harness = @import("harness");
const packet_inspector = @import("packet_inspector");

/// Loss event detected from packet capture
pub const LossEvent = struct {
    /// Packet number that was lost
    packet_number: u64,

    /// Packet type that was lost
    packet_type: packet_inspector.PacketType,

    /// Time when loss was detected (milliseconds)
    loss_time_ms: i64,

    /// Whether packet was retransmitted
    retransmitted: bool,
};

/// RTT measurement from handshake
pub const RttMeasurement = struct {
    /// Smoothed RTT (milliseconds)
    smoothed_rtt_ms: u64,

    /// RTT variation (milliseconds)
    rttvar_ms: u64,

    /// Minimum RTT observed (milliseconds)
    min_rtt_ms: u64,

    /// Latest RTT sample (milliseconds)
    latest_rtt_ms: u64,
};

/// PTO timer state
pub const PtoState = struct {
    /// PTO timeout value (milliseconds)
    pto_timeout_ms: u64,

    /// Number of PTO probes sent
    pto_count: u32,

    /// Whether PTO timer is armed
    is_armed: bool,

    /// Time when PTO will fire (milliseconds)
    expiry_time_ms: i64,
};

// =============================================================================
// Loss Detection Helpers
// =============================================================================

/// Detect potential packet loss by analyzing ACK gaps in capture.
/// Returns list of packet numbers that appear to be lost based on ACK ranges.
///
/// Algorithm:
/// 1. Extract all ACK frames from captured packets
/// 2. Identify gaps in ACK ranges (missing packet numbers)
/// 3. Check if missing packets were later retransmitted
///
/// Parameters:
/// - allocator: Memory allocator for results
/// - captured: Captured packets from ConnectionPair
///
/// Returns:
/// - ArrayList of LossEvent structures
pub fn detectLossEvents(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(LossEvent) {
    var events = std.ArrayList(LossEvent){};
    errdefer events.deinit(allocator);

    // For proof-of-concept, return empty list
    // Real implementation would:
    // 1. Parse ACK frames to find acknowledged packet numbers
    // 2. Identify gaps (missing packet numbers between ranges)
    // 3. Track if missing packets appear later (retransmissions)

    _ = captured;

    return events;
}

/// Count number of retransmissions in capture.
/// Identifies packets that appear to be retransmitting earlier data.
///
/// Heuristics:
/// - Multiple Initial packets with same CRYPTO offset
/// - Multiple Handshake packets with same CRYPTO offset
/// - Packets sent after loss detection timeout
pub fn countRetransmissions(captured: []const harness.CapturedPacket) !usize {
    _ = captured;
    // Stub: Real implementation would track CRYPTO frame offsets
    return 0;
}

/// Check if packet number was acknowledged.
/// Searches capture for ACK frames that acknowledge the given packet number.
pub fn isPacketAcknowledged(
    captured: []const harness.CapturedPacket,
    packet_number: u64,
) !bool {
    _ = captured;
    _ = packet_number;
    // Stub: Real implementation would parse ACK frames
    return false;
}

// =============================================================================
// RTT Estimation Helpers
// =============================================================================

/// Extract RTT measurements from connection state.
/// Returns RTT statistics if available from connection.
///
/// Note: This is a stub. Real implementation would:
/// - Access Connection.rec.rtt_state
/// - Extract smoothed_rtt, rttvar, min_rtt, latest_rtt
/// - Convert from internal units to milliseconds
pub fn getRttMeasurement(conn: anytype) !?RttMeasurement {
    _ = conn;
    // Stub: Real implementation would access connection's RTT state
    return null;
}

/// Estimate RTT from packet timestamps in capture.
/// Calculates round-trip time by matching sent packets with their ACKs.
///
/// Algorithm:
/// 1. Find Initial packet sent by client
/// 2. Find ACK for that packet from server
/// 3. Calculate time difference
///
/// Returns:
/// - Estimated RTT in milliseconds, or null if cannot calculate
pub fn estimateRttFromCapture(
    captured: []const harness.CapturedPacket,
) !?u64 {
    _ = captured;

    // Stub: Real implementation would:
    // 1. Find sent packet timestamp
    // 2. Find corresponding ACK timestamp
    // 3. Return difference

    return null;
}

/// Validate RTT is within reasonable bounds.
/// Checks that RTT measurement is realistic (e.g., <1000ms for loopback).
pub fn validateRttReasonable(rtt: RttMeasurement, max_ms: u64) !void {
    if (rtt.smoothed_rtt_ms > max_ms) {
        testlog.print("RTT too high: {}ms > {}ms\n", .{ rtt.smoothed_rtt_ms, max_ms });
        return error.RttTooHigh;
    }

    if (rtt.min_rtt_ms > rtt.smoothed_rtt_ms) {
        testlog.print("min_rtt > smoothed_rtt: {}ms > {}ms\n", .{ rtt.min_rtt_ms, rtt.smoothed_rtt_ms });
        return error.InvalidRttState;
    }
}

// =============================================================================
// PTO Timer Helpers
// =============================================================================

/// Extract PTO timer state from connection.
/// Returns PTO timeout, count, and armed status.
///
/// Note: This is a stub. Real implementation would:
/// - Access Connection.rec.pto_time
/// - Access Connection.rec.pto_count
/// - Check if timer is armed
pub fn getPtoState(conn: anytype) !?PtoState {
    _ = conn;
    // Stub: Real implementation would access connection's PTO state
    return null;
}

/// Check if PTO timer fired by analyzing capture timestamps.
/// Detects PTO events by finding probe packets sent after timeout.
///
/// Algorithm:
/// 1. Find last sent packet timestamp
/// 2. Find next sent packet timestamp
/// 3. If gap > expected PTO timeout, PTO likely fired
pub fn detectPtoEvents(
    captured: []const harness.CapturedPacket,
) !usize {
    _ = captured;

    // Stub: Real implementation would:
    // 1. Track sent packet timestamps
    // 2. Identify gaps larger than RTT * 2
    // 3. Count suspected PTO events

    return 0;
}

/// Validate PTO timeout is calculated correctly.
/// Checks PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay.
///
/// RFC 9002 §6.2: PTO Calculation
pub fn validatePtoCalculation(rtt: RttMeasurement, pto: PtoState) !void {
    // RFC 9002 §6.2: PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
    // kGranularity = 1ms (timer granularity)
    // max_ack_delay = 25ms (default)

    const granularity_ms: u64 = 1;
    const max_ack_delay_ms: u64 = 25;

    const rttvar_component = @max(4 * rtt.rttvar_ms, granularity_ms);
    const expected_pto = rtt.smoothed_rtt_ms + rttvar_component + max_ack_delay_ms;

    // Allow 10% tolerance for implementation variations
    const tolerance = expected_pto / 10;
    const min_pto = expected_pto - tolerance;
    const max_pto = expected_pto + tolerance;

    if (pto.pto_timeout_ms < min_pto or pto.pto_timeout_ms > max_pto) {
        testlog.print("PTO calculation incorrect: {}ms not in [{}, {}] (expected ~{}ms)\n", .{ pto.pto_timeout_ms, min_pto, max_pto, expected_pto });
        return error.InvalidPtoCalculation;
    }
}

// =============================================================================
// Test Assertion Helpers
// =============================================================================

/// Assert that loss detection is working.
/// Validates that lost packets are detected and retransmitted.
pub fn expectLossDetected(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
    min_loss_events: usize,
) !void {
    const loss_events = try detectLossEvents(allocator, captured);
    defer loss_events.deinit();

    if (loss_events.items.len < min_loss_events) {
        testlog.print("Expected at least {} loss events, found {}\n", .{ min_loss_events, loss_events.items.len });
        return error.InsufficientLossEvents;
    }
}

/// Assert that RTT estimation is working.
/// Validates that connection has reasonable RTT measurements.
pub fn expectRttEstimated(conn: anytype, max_rtt_ms: u64) !void {
    const rtt = try getRttMeasurement(conn) orelse return error.NoRttMeasurement;
    try validateRttReasonable(rtt, max_rtt_ms);
}

/// Assert that PTO timer fired.
/// Validates that probe packets were sent after timeout.
pub fn expectPtoFired(
    captured: []const harness.CapturedPacket,
    min_pto_events: usize,
) !void {
    const pto_events = try detectPtoEvents(captured);

    if (pto_events < min_pto_events) {
        testlog.print("Expected at least {} PTO events, found {}\n", .{ min_pto_events, pto_events });
        return error.InsufficientPtoEvents;
    }
}

/// Assert that retransmissions occurred.
/// Validates that lost packets were retransmitted.
pub fn expectRetransmissions(
    captured: []const harness.CapturedPacket,
    min_retransmissions: usize,
) !void {
    const retx_count = try countRetransmissions(captured);

    if (retx_count < min_retransmissions) {
        testlog.print("Expected at least {} retransmissions, found {}\n", .{ min_retransmissions, retx_count });
        return error.InsufficientRetransmissions;
    }
}

// =============================================================================
// Integration with ConnectionPair
// =============================================================================

/// Analyze loss recovery metrics from ConnectionPair test.
/// Returns summary of loss detection, RTT, and PTO activity.
pub const RecoveryMetrics = struct {
    loss_events: usize,
    retransmissions: usize,
    pto_events: usize,
    rtt_ms: ?u64,
};

/// Extract loss recovery metrics from captured packets.
pub fn analyzeRecoveryMetrics(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !RecoveryMetrics {
    const loss_events = try detectLossEvents(allocator, captured);
    defer loss_events.deinit();

    const retx_count = try countRetransmissions(captured);
    const pto_count = try detectPtoEvents(captured);
    const rtt = try estimateRttFromCapture(captured);

    return RecoveryMetrics{
        .loss_events = loss_events.items.len,
        .retransmissions = retx_count,
        .pto_events = pto_count,
        .rtt_ms = rtt,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "detectLossEvents - empty capture" {
    const allocator = std.testing.allocator;

    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    var events = try detectLossEvents(allocator, captured);
    defer events.deinit();

    try std.testing.expectEqual(@as(usize, 0), events.items.len);
}

test "countRetransmissions - no retransmissions" {
    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    const count = try countRetransmissions(captured);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "detectPtoEvents - no events" {
    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    const count = try detectPtoEvents(captured);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "validateRttReasonable - valid RTT" {
    const rtt = RttMeasurement{
        .smoothed_rtt_ms = 50,
        .rttvar_ms = 10,
        .min_rtt_ms = 45,
        .latest_rtt_ms = 52,
    };

    try validateRttReasonable(rtt, 1000);
}

test "validateRttReasonable - RTT too high" {
    const rtt = RttMeasurement{
        .smoothed_rtt_ms = 1500,
        .rttvar_ms = 100,
        .min_rtt_ms = 1000,
        .latest_rtt_ms = 1600,
    };

    const result = validateRttReasonable(rtt, 1000);
    try std.testing.expectError(error.RttTooHigh, result);
}

test "validatePtoCalculation - correct calculation" {
    const rtt = RttMeasurement{
        .smoothed_rtt_ms = 50,
        .rttvar_ms = 10,
        .min_rtt_ms = 45,
        .latest_rtt_ms = 52,
    };

    // PTO = 50 + max(4*10, 1) + 25 = 50 + 40 + 25 = 115ms
    const pto = PtoState{
        .pto_timeout_ms = 115,
        .pto_count = 0,
        .is_armed = true,
        .expiry_time_ms = 1000,
    };

    try validatePtoCalculation(rtt, pto);
}

test "analyzeRecoveryMetrics - empty capture" {
    const allocator = std.testing.allocator;

    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    const metrics = try analyzeRecoveryMetrics(allocator, captured);

    try std.testing.expectEqual(@as(usize, 0), metrics.loss_events);
    try std.testing.expectEqual(@as(usize, 0), metrics.retransmissions);
    try std.testing.expectEqual(@as(usize, 0), metrics.pto_events);
    try std.testing.expectEqual(@as(?u64, null), metrics.rtt_ms);
}
