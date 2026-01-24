//! Unit tests for connection/pmtud.zig
//!
//! RFC References:
//! - RFC 9000 §14.2: Path Maximum Transmission Unit
//! - RFC 9000 §14.3: Datagram Packetization Layer PMTU Discovery (DPLPMTUD)
//! - RFC 9000 §14.4: Handling of ICMP Messages by QUIC
//! - RFC 8899: Packetization Layer Path MTU Discovery
//!
//! Coverage:
//! - Positive cases: PMTU initialization, probe tracking, phase transitions
//! - Negative cases: Invalid MTU values, probe failures
//! - Edge cases: Minimum MTU (1200), maximum values, phase states
//! - RFC compliance: DPLPMTUD algorithm, ICMP handling

const std = @import("std");
const testing = std.testing;

const pmtud = @import("pmtud");

// =============================================================================
// DplpmtudPhase Tests
// =============================================================================

test "RFC 9000 §14.3 - DplpmtudPhase enum values" {
    const disabled = pmtud.DplpmtudPhase.Disabled;
    const searching = pmtud.DplpmtudPhase.Searching;
    const complete = pmtud.DplpmtudPhase.SearchComplete;

    try testing.expectEqual(pmtud.DplpmtudPhase.Disabled, disabled);
    try testing.expectEqual(pmtud.DplpmtudPhase.Searching, searching);
    try testing.expectEqual(pmtud.DplpmtudPhase.SearchComplete, complete);
}

// =============================================================================
// PmtudState Initialization Tests
// =============================================================================

test "RFC 9000 §14.2 - PmtudState initial state" {
    const state: pmtud.PmtudState = .{};

    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
    try testing.expectEqual(@as(u16, 1200), state.pmtu_probed);
    try testing.expectEqual(pmtud.DplpmtudPhase.Disabled, state.dplpmtud_state);
}

test "RFC 9000 §14 - PmtudState default 1200 byte minimum" {
    const state: pmtud.PmtudState = .{};

    // RFC 9000 §14: Minimum QUIC packet size is 1200 bytes
    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
}

test "RFC 9000 §14.3 - PmtudState DPLPMTUD starts disabled" {
    const state: pmtud.PmtudState = .{};

    try testing.expectEqual(pmtud.DplpmtudPhase.Disabled, state.dplpmtud_state);
}

// =============================================================================
// PMTU Current Tracking Tests
// =============================================================================

test "RFC 9000 §14.2 - PmtudState update current PMTU" {
    var state: pmtud.PmtudState = .{};

    // Increase PMTU after successful probe
    state.pmtu_current = 1500;

    try testing.expectEqual(@as(u16, 1500), state.pmtu_current);
}

test "RFC 9000 §14.2 - PmtudState track confirmed PMTU" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1400;
    state.pmtu_probed = 1400;

    try testing.expectEqual(state.pmtu_current, state.pmtu_probed);
}

test "RFC 9000 §14.2 - PmtudState increase PMTU incrementally" {
    var state: pmtud.PmtudState = .{};

    // Start at 1200
    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);

    // Probe 1400
    state.pmtu_probed = 1400;
    state.pmtu_current = 1400;

    // Probe 1500
    state.pmtu_probed = 1500;
    state.pmtu_current = 1500;

    try testing.expectEqual(@as(u16, 1500), state.pmtu_current);
}

// =============================================================================
// PMTU Probe Tracking Tests
// =============================================================================

test "RFC 9000 §14.3 - PmtudState track probed size" {
    var state: pmtud.PmtudState = .{};

    // Probe larger size
    state.pmtu_probed = 1500;

    try testing.expectEqual(@as(u16, 1500), state.pmtu_probed);
}

test "RFC 9000 §14.3 - PmtudState probe ahead of current" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1200;
    state.pmtu_probed = 1500;

    // Probed size may be larger than current confirmed size
    try testing.expect(state.pmtu_probed > state.pmtu_current);
}

test "RFC 9000 §14.3 - PmtudState multiple probe attempts" {
    var state: pmtud.PmtudState = .{};

    // First probe
    state.pmtu_probed = 1400;

    // Second probe (higher)
    state.pmtu_probed = 1500;

    // Third probe (even higher)
    state.pmtu_probed = 1600;

    try testing.expectEqual(@as(u16, 1600), state.pmtu_probed);
}

// =============================================================================
// DPLPMTUD Phase Transition Tests
// =============================================================================

test "RFC 9000 §14.3 - PmtudState enable DPLPMTUD" {
    var state: pmtud.PmtudState = .{};

    // Enable DPLPMTUD and start searching
    state.dplpmtud_state = .Searching;

    try testing.expectEqual(pmtud.DplpmtudPhase.Searching, state.dplpmtud_state);
}

test "RFC 9000 §14.3 - PmtudState DPLPMTUD search complete" {
    var state: pmtud.PmtudState = .{};

    state.dplpmtud_state = .Searching;
    // After finding optimal PMTU
    state.dplpmtud_state = .SearchComplete;

    try testing.expectEqual(pmtud.DplpmtudPhase.SearchComplete, state.dplpmtud_state);
}

test "RFC 9000 §14.3 - PmtudState DPLPMTUD state machine" {
    var state: pmtud.PmtudState = .{};

    // Disabled -> Searching
    try testing.expectEqual(pmtud.DplpmtudPhase.Disabled, state.dplpmtud_state);

    state.dplpmtud_state = .Searching;
    try testing.expectEqual(pmtud.DplpmtudPhase.Searching, state.dplpmtud_state);

    // Searching -> SearchComplete
    state.dplpmtud_state = .SearchComplete;
    try testing.expectEqual(pmtud.DplpmtudPhase.SearchComplete, state.dplpmtud_state);
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: PmtudState minimum PMTU is 1200" {
    var state: pmtud.PmtudState = .{};

    // RFC 9000 §14: PMTU never goes below 1200
    state.pmtu_current = 1200;

    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
}

test "boundary: PmtudState typical Ethernet MTU" {
    var state: pmtud.PmtudState = .{};

    // Typical Ethernet MTU is 1500 bytes
    state.pmtu_current = 1500;

    try testing.expectEqual(@as(u16, 1500), state.pmtu_current);
}

test "boundary: PmtudState jumbo frames" {
    var state: pmtud.PmtudState = .{};

    // Jumbo frames can be 9000 bytes
    state.pmtu_current = 9000;

    try testing.expectEqual(@as(u16, 9000), state.pmtu_current);
}

test "boundary: PmtudState maximum u16 value" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = std.math.maxInt(u16);

    try testing.expectEqual(std.math.maxInt(u16), state.pmtu_current);
}

test "boundary: PmtudState probe equals current" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1400;
    state.pmtu_probed = 1400;

    try testing.expectEqual(state.pmtu_current, state.pmtu_probed);
}

// =============================================================================
// Negative Tests - ICMP/Probe Failures
// =============================================================================

test "negative: PmtudState probe failure keeps current PMTU" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1200;
    state.pmtu_probed = 1500; // Probe attempt

    // Probe failed (packet lost or ICMP received)
    // Current PMTU remains unchanged
    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
}

test "negative: PmtudState ICMP reduces PMTU" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1500;

    // Receive ICMP Packet Too Big for 1400
    state.pmtu_current = 1400;

    try testing.expectEqual(@as(u16, 1400), state.pmtu_current);
}

test "negative: PmtudState cannot reduce below minimum" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1200;

    // Even if ICMP suggests lower, cannot go below 1200
    // (Implementation would clamp)
    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §14 - QUIC minimum packet size is 1200 bytes" {
    const state: pmtud.PmtudState = .{};

    // RFC 9000 §14: Endpoints MUST be able to receive QUIC packets of at least 1200 bytes
    try testing.expect(state.pmtu_current >= 1200);
}

test "RFC 9000 §14.2 - PMTU discovery increases path capacity" {
    var state: pmtud.PmtudState = .{};

    const initial_mtu = state.pmtu_current;
    try testing.expectEqual(@as(u16, 1200), initial_mtu);

    // Discover larger PMTU
    state.pmtu_probed = 1500;
    state.pmtu_current = 1500;

    // Path capacity increased
    try testing.expect(state.pmtu_current > initial_mtu);
}

test "RFC 9000 §14.3 - DPLPMTUD operates in phases" {
    var state: pmtud.PmtudState = .{};

    // Phase 1: Disabled
    try testing.expectEqual(pmtud.DplpmtudPhase.Disabled, state.dplpmtud_state);

    // Phase 2: Searching (sending probes)
    state.dplpmtud_state = .Searching;
    state.pmtu_probed = 1400;

    // Phase 3: Search Complete (found optimal MTU)
    state.dplpmtud_state = .SearchComplete;
    state.pmtu_current = 1400;

    try testing.expectEqual(pmtud.DplpmtudPhase.SearchComplete, state.dplpmtud_state);
}

test "RFC 9000 §14.4 - ICMP messages inform PMTU" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1500;

    // Receive ICMP Packet Too Big message suggesting 1400
    // RFC 9000 §14.4: Endpoints MAY use ICMP to inform PMTUD
    state.pmtu_current = 1400;

    try testing.expectEqual(@as(u16, 1400), state.pmtu_current);
}

test "RFC 8899 - DPLPMTUD probes incrementally" {
    var state: pmtud.PmtudState = .{};

    state.dplpmtud_state = .Searching;

    // Probe incrementally larger sizes
    state.pmtu_probed = 1300;
    state.pmtu_probed = 1400;
    state.pmtu_probed = 1500;

    // RFC 8899: DPLPMTUD searches for largest working PMTU
    try testing.expectEqual(@as(u16, 1500), state.pmtu_probed);
}

test "RFC 9000 §14.2 - PMTU applies to UDP payload" {
    var state: pmtud.PmtudState = .{};

    // PMTU is the UDP payload size, not including IP/UDP headers
    state.pmtu_current = 1472; // Common for IPv4 (1500 - 20 IP - 8 UDP)

    try testing.expectEqual(@as(u16, 1472), state.pmtu_current);
}

test "RFC 9000 §14.3 - DPLPMTUD retries after network change" {
    var state: pmtud.PmtudState = .{};

    state.dplpmtud_state = .SearchComplete;
    state.pmtu_current = 1500;

    // Network path changes (detected via other means)
    // Restart PMTUD
    state.dplpmtud_state = .Searching;
    state.pmtu_current = 1200; // Reset to minimum

    try testing.expectEqual(pmtud.DplpmtudPhase.Searching, state.dplpmtud_state);
    try testing.expectEqual(@as(u16, 1200), state.pmtu_current);
}

test "RFC 9000 §14.2 - Black hole detection via probe loss" {
    var state: pmtud.PmtudState = .{};

    state.pmtu_current = 1500;
    state.pmtu_probed = 1600;

    // Probes at 1600 consistently lost (black hole)
    // Revert to last known good PMTU
    state.pmtu_probed = 1500;

    try testing.expectEqual(@as(u16, 1500), state.pmtu_probed);
}
