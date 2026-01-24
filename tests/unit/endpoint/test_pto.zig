//! Unit tests for endpoint/pto.zig
//!
//! RFC References:
//! - RFC 9002 §6.2: Probe Timeout
//! - RFC 9002 §6.2.1: Computing PTO
//! - RFC 9002 §6.2.2.1: PTO Backoff
//! - RFC 9002 §6.2.4: Sending Probe Packets
//! - RFC 9000 §12.2: Coalescing Packets
//! - RFC 9000 §14.2: Path MTU Discovery
//!
//! Coverage:
//! - PTO probe generation: sendPtoProbe
//! - PTO timer scheduling: scheduleConnPto
//! - Per-space probe packets (Initial, Handshake, Application)
//! - PTO backoff mechanism
//! - ACK-eliciting frame selection
//! - Probe packet construction
//!
//! Note: These tests document expected behavior for the pto module.
//! Currently endpoint.zig contains the implementation. Tests designed for
//! future extraction to pto.zig.

const std = @import("std");
const testing = std.testing;

const pto = @import("pto");
const types = @import("types");

var test_allocator = std.testing.allocator;

// =============================================================================
// Helper Function Tests (Phase 4b)
// =============================================================================

test "RFC 9002 §6.2 - isPtoTimer identifies PTO timers" {
    // PTO timers should be identified correctly
    try testing.expect(pto.isPtoTimer(.PtoInitial));
    try testing.expect(pto.isPtoTimer(.PtoHandshake));
    try testing.expect(pto.isPtoTimer(.PtoApp));
}

test "RFC 9002 §6.2 - isPtoTimer rejects non-PTO timers" {
    // Generic and PMTUD timers are not PTO timers
    try testing.expect(!pto.isPtoTimer(.Generic));
    try testing.expect(!pto.isPtoTimer(.Pmtud));
}

test "RFC 9002 §6.2 - ptoTimerSpace maps Initial timer" {
    // PtoInitial should map to Initial packet number space
    const space = pto.ptoTimerSpace(.PtoInitial);
    try testing.expect(space != null);
    try testing.expectEqual(.Initial, space.?);
}

test "RFC 9002 §6.2 - ptoTimerSpace maps Handshake timer" {
    // PtoHandshake should map to Handshake packet number space
    const space = pto.ptoTimerSpace(.PtoHandshake);
    try testing.expect(space != null);
    try testing.expectEqual(.Handshake, space.?);
}

test "RFC 9002 §6.2 - ptoTimerSpace maps Application timer" {
    // PtoApp should map to Application packet number space
    const space = pto.ptoTimerSpace(.PtoApp);
    try testing.expect(space != null);
    try testing.expectEqual(.Application, space.?);
}

test "RFC 9002 §6.2 - ptoTimerSpace returns null for non-PTO timers" {
    // Generic and PMTUD timers don't map to packet number spaces
    try testing.expect(pto.ptoTimerSpace(.Generic) == null);
    try testing.expect(pto.ptoTimerSpace(.Pmtud) == null);
}

test "RFC 9002 §6.2 - all PTO timers have corresponding spaces" {
    // Every PTO timer should map to a packet number space
    const pto_timers = [_]types.TimerKind{
        .PtoInitial,
        .PtoHandshake,
        .PtoApp,
    };

    for (pto_timers) |timer_kind| {
        try testing.expect(pto.isPtoTimer(timer_kind));
        const space = pto.ptoTimerSpace(timer_kind);
        try testing.expect(space != null);
    }
}

// =============================================================================
// Probe Builder Tests (Phase 5 Tier 1)
// =============================================================================

test "RFC 9002 §6.2.4 - buildInitialProbe returns PING frame" {
    // RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
    // PING frame is ACK-eliciting and has minimal overhead.

    const payload = try pto.buildInitialProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Should be single PING frame (0x01)
    try testing.expectEqual(@as(usize, 1), payload.len);
    try testing.expectEqual(@as(u8, 0x01), payload[0]);
}

test "RFC 9002 §6.2.4 - buildHandshakeProbe returns PING frame" {
    // RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
    // Handshake probes use same PING frame as Initial probes.

    const payload = try pto.buildHandshakeProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Should be single PING frame (0x01)
    try testing.expectEqual(@as(usize, 1), payload.len);
    try testing.expectEqual(@as(u8, 0x01), payload[0]);
}

test "RFC 9002 §6.2.4 - buildApplicationProbe returns PING frame" {
    // RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
    // Application probes use PING frame (future: could include STREAM data).

    const payload = try pto.buildApplicationProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Should be single PING frame (0x01)
    try testing.expectEqual(@as(usize, 1), payload.len);
    try testing.expectEqual(@as(u8, 0x01), payload[0]);
}

test "RFC 9002 §6.2.4 - buildInitialProbe allocates memory correctly" {
    // Verify memory allocation and proper cleanup

    const payload = try pto.buildInitialProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Allocated slice has correct properties
    try testing.expect(payload.len > 0);
}

test "RFC 9002 §6.2.4 - buildHandshakeProbe allocates memory correctly" {
    // Verify memory allocation and proper cleanup

    const payload = try pto.buildHandshakeProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Allocated slice has correct properties
    try testing.expect(payload.len > 0);
}

test "RFC 9002 §6.2.4 - buildApplicationProbe allocates memory correctly" {
    // Verify memory allocation and proper cleanup

    const payload = try pto.buildApplicationProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Allocated slice has correct properties
    try testing.expect(payload.len > 0);
}

// =============================================================================
// End of Unit Tests
// =============================================================================
//
// NOTE: Integration tests for sendPtoProbe, scheduleConnPto, and full PTO
// behavior require a complete Connection object with TLS keys, recovery state,
// and UDP socket infrastructure. These should be implemented as integration
// tests in a separate test suite once the integration test framework is ready.
//
// The unit tests above verify the core helper functions (isPtoTimer,
// ptoTimerSpace) and probe builder functions (buildInitialProbe, etc.)
// which can be tested in isolation.
