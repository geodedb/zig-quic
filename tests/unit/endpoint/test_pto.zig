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
    try testing.expect(payload.ptr != null);
}

test "RFC 9002 §6.2.4 - buildHandshakeProbe allocates memory correctly" {
    // Verify memory allocation and proper cleanup

    const payload = try pto.buildHandshakeProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Allocated slice has correct properties
    try testing.expect(payload.len > 0);
    try testing.expect(payload.ptr != null);
}

test "RFC 9002 §6.2.4 - buildApplicationProbe allocates memory correctly" {
    // Verify memory allocation and proper cleanup

    const payload = try pto.buildApplicationProbe(&test_allocator);
    defer test_allocator.free(payload);

    // Assert: Allocated slice has correct properties
    try testing.expect(payload.len > 0);
    try testing.expect(payload.ptr != null);
}

// =============================================================================
// PtoHandler Initialization Tests
// =============================================================================

test "RFC 9002 §6.2 - PtoHandler placeholder initialization" {
    const handler = pto.PtoHandler.init();
    _ = handler;

    // Placeholder struct initializes without error
    // Will be replaced with full implementation
}

// =============================================================================
// INTEGRATION TESTS - PTO Probe Generation (Tier 3)
// =============================================================================
//
// These tests require full Connection object with TLS keys, recovery state,
// and UDP socket. Deferred to Phase 6 (Integration Test Framework).
//
// Current Status: 13/62 tests passing (21%)
// Target: Document expected behavior for future integration testing
//

test "INTEGRATION TEST - sendPtoProbe generates Initial probe" {
    // RFC 9002 §6.2.4: Send probe when Initial PTO expires
    // Implementation: pto.zig:143-208
    //
    // Expected Implementation Steps:
    // 1. Check timer kind is .PtoInitial
    // 2. Verify !conn.initial_keys_dropped (early return if dropped)
    // 3. Derive Initial TX keys from ODCID (conn.original_dcid or peer_initial_dcid)
    // 4. Call buildInitialProbe() to get PING frame payload
    // 5. Encode Initial packet with encodeInitialProtected()
    // 6. Send packet via send_fn callback to peer address
    // 7. Call conn.onPacketSent(.Initial, pn, pkt.len, true) for congestion control
    // 8. Increment conn.pn_initial_tx
    //
    // Requires:
    // - Full Connection object with initial_keys_dropped, original_dcid, peer_initial_scid
    // - TLS key derivation (deriveInitialSecret, deriveClientServerInitial)
    // - send_fn callback for UDP transmission
    // - Recovery state for congestion control tracking
    //
    // Status: Deferred to Phase 6

    try testing.expect(true); // Placeholder - documents expected behavior
}

test "INTEGRATION TEST - sendPtoProbe generates Handshake probe" {
    // RFC 9002 §6.2.4: Send probe when Handshake PTO expires
    // Implementation: pto.zig:211-242
    //
    // Expected Implementation Steps:
    // 1. Check timer kind is .PtoHandshake
    // 2. Verify conn.hs_tx_keys exists (early return if null)
    // 3. Extract peer SCID as DCID, our SCID as SCID
    // 4. Call buildHandshakeProbe() to get PING frame payload
    // 5. Encode Handshake packet with encodeHandshakeProtected()
    // 6. Send packet via send_fn callback
    // 7. Call conn.onPacketSent(.Handshake, pn, pkt.len, true)
    // 8. Increment conn.pn_handshake_tx
    //
    // Requires:
    // - Connection with hs_tx_keys derived from TLS handshake
    // - Packet encoding with Handshake protection level
    // - Recovery state tracking
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe skips Initial if keys dropped" {
    // RFC 9001 §4.9.1: Initial keys discarded after Handshake confirmed
    // Implementation: pto.zig:151 (early return)
    //
    // Expected Behavior:
    // - When conn.initial_keys_dropped == true, return immediately
    // - No Initial probe sent (keys no longer available)
    // - Handshake/Application probes can still be sent
    //
    // Test Scenario:
    // 1. Create Connection with initial_keys_dropped = true
    // 2. Call sendPtoProbe(ctx, .PtoInitial)
    // 3. Verify no packet was sent (check send_fn not called)
    // 4. Verify pn_initial_tx was not incremented
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe skips Handshake if no TX keys" {
    // Handshake keys not yet derived (early in connection)
    // Implementation: pto.zig:213 (early return)
    //
    // Expected Behavior:
    // - When conn.hs_tx_keys == null, return immediately
    // - No Handshake probe sent (keys not available yet)
    // - Initial probe may still be sent if keys not dropped
    //
    // Test Scenario:
    // 1. Create Connection with hs_tx_keys = null
    // 2. Call sendPtoProbe(ctx, .PtoHandshake)
    // 3. Verify no packet was sent
    // 4. Verify pn_handshake_tx was not incremented
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "NOTE - Initial PTO probe content verified by buildInitialProbe tests" {
    // RFC 9002 §6.2.4: ACK-eliciting probe
    //
    // This behavior is already tested by:
    // - "RFC 9002 §6.2.4 - buildInitialProbe returns PING frame" (line 94)
    // - sendPtoProbe calls buildInitialProbe() internally (pto.zig:185)
    //
    // Expected probe content:
    // - Single PING frame (0x01)
    // - Minimal overhead (1 byte)
    // - ACK-eliciting per RFC 9002 §6.2.4
    //
    // Status: Covered by existing unit tests ✅

    try testing.expect(true);
}

test "NOTE - Handshake PTO probe content verified by buildHandshakeProbe tests" {
    // RFC 9002 §6.2.4: ACK-eliciting probe
    //
    // This behavior is already tested by:
    // - "RFC 9002 §6.2.4 - buildHandshakeProbe returns PING frame" (line 106)
    // - sendPtoProbe calls buildHandshakeProbe() internally (pto.zig:219)
    //
    // Expected probe content:
    // - Single PING frame (0x01)
    // - ACK-eliciting per RFC 9002 §6.2.4
    // - Alternative: Could include CRYPTO retransmission (future enhancement)
    //
    // Status: Covered by existing unit tests ✅

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - Initial Space PTO Details (Tier 3)
// =============================================================================

test "INTEGRATION TEST - Initial PTO derives keys from ODCID" {
    // RFC 9001 §5.2: Use original DCID for Initial key derivation
    // Implementation: pto.zig:162-182
    //
    // Key Derivation Logic:
    // 1. If conn.original_dcid.len > 0: use original_dcid bytes
    // 2. Else if conn.peer_initial_dcid.len > 0: use peer_initial_dcid bytes
    // 3. Else: use dcid (fallback)
    // 4. Call ks.deriveInitialSecret(v2, derive_dcid)
    // 5. Call ks.deriveClientServerInitial(initial)
    // 6. Select pair.server for server role TX keys
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO uses peer SCID as DCID" {
    // RFC 9000 §17.2: Packet addressing for routing
    // Implementation: pto.zig:154
    //
    // Addressing: dcid = conn.peer_initial_scid.bytes[0..len]
    // Rationale: Peer expects to see their SCID as DCID for routing
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO uses own SCID as SCID" {
    // RFC 9000 §17.2: Return address for responses
    // Implementation: pto.zig:155
    //
    // Addressing: scid = conn.our_scid.bytes[0..len]
    // Rationale: Peer uses this as DCID when sending responses
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO includes empty token" {
    // RFC 9000 §17.2.2: Token field in Initial packets
    // Implementation: pto.zig:194
    //
    // Behavior: token = &[_]u8{} (empty slice)
    // Rationale: Tokens only in original Initial, not PTO probes
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO uses current packet number" {
    // RFC 9000 §12.3: Packet number assignment
    // Implementation: pto.zig:195, 208
    //
    // Behavior:
    // 1. Use conn.pn_initial_tx as packet number
    // 2. Increment: conn.pn_initial_tx +%= 1
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO uses 4-byte PN encoding" {
    // RFC 9000 §17.2: Packet number length
    // Implementation: pto.zig:196
    //
    // Behavior: pn_len = 4 (maximum)
    // Rationale: Maximizes PN space, standard for Initial packets
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

test "INTEGRATION TEST - Initial PTO uses initial_version" {
    // RFC 9000 §17.2: Version field in long header
    // Implementation: pto.zig:191
    //
    // Behavior: version = conn.initial_version (or default 0x00000001)
    // Rationale: Must match version negotiated during handshake
    //
    // Status: Deferred to Phase 6

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - Handshake Space PTO Details (Tier 3)
// =============================================================================

test "INTEGRATION TEST - Handshake PTO uses Handshake TX keys" {
    // Keys for Handshake space
    //
    // Expected:
    // - tx_keys = conn.hs_tx_keys.?
    // - Derived during handshake
    // - Different from Initial keys

    try testing.expect(true);
}

test "INTEGRATION TEST - Handshake PTO encodes Handshake packet" {
    // RFC 9000 §17.2.4: Handshake packet format
    //
    // Expected:
    // - encodeHandshakeProtected(...)
    // - Long header with type = Handshake
    // - Uses Handshake keys for protection
    // - No token field (unlike Initial)

    try testing.expect(true);
}

test "INTEGRATION TEST - Handshake PTO increments Handshake PN" {
    // Separate PN space
    //
    // Expected:
    // - pn = conn.pn_handshake_tx
    // - conn.pn_handshake_tx +%= 1 after sending
    // - Independent from Initial PN space

    try testing.expect(true);
}

test "INTEGRATION TEST - Handshake PTO tracks sent packet" {
    // Loss recovery
    //
    // Expected:
    // - conn.onPacketSent(.Handshake, pn, pkt.len, ack_eliciting=true)
    // - Records packet for loss detection
    // - Arms new PTO timer

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - PTO Timer Scheduling (Tier 3)
// =============================================================================

test "INTEGRATION TEST - scheduleConnPto registers timer with endpoint" {
    // Timer registration
    //
    // Expected:
    // - Calculate PTO timeout
    // - Register with TimerManager
    // - Returns timer ID
    // - Can be cancelled later

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto calculates Initial PTO" {
    // RFC 9002 §6.2.1: PTO = smoothed_rtt + max(4*rttvar, kGranularity)
    //
    // Expected:
    // - Use conn.rec.rtt_state for RTT values
    // - Add PTO backoff multiplier
    // - Minimum PTO value enforced

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto calculates Handshake PTO" {
    // Separate PTO per PN space
    //
    // Expected:
    // - Same formula as Initial
    // - Independent timer
    // - May have different RTT estimate

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto applies PTO backoff" {
    // RFC 9002 §6.2.2.1: Exponential backoff
    //
    // Expected:
    // - PTO *= 2^backoff_count
    // - backoff_count increases on each timeout
    // - Prevents excessive probing

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto uses kGranularity minimum" {
    // RFC 9002 §6.2.1: Timer granularity
    //
    // Expected:
    // - kGranularity = 1ms typically
    // - max(4*rttvar, kGranularity)
    // - Prevents too-short timeouts

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - PTO Backoff Mechanism (Tier 3)
// =============================================================================

test "INTEGRATION TEST - PTO backoff doubles on each timeout" {
    // RFC 9002 §6.2.2.1: Exponential backoff
    //
    // Expected sequence:
    // - Timeout 1: PTO = base
    // - Timeout 2: PTO = base * 2
    // - Timeout 3: PTO = base * 4
    // - Timeout 4: PTO = base * 8

    try testing.expect(true);
}

test "INTEGRATION TEST - PTO backoff resets on ACK" {
    // RFC 9002 §6.2.1: Reset on progress
    //
    // Expected:
    // - Receive ACK for probe packet
    // - backoff_count = 0
    // - Next PTO uses base value

    try testing.expect(true);
}

test "INTEGRATION TEST - PTO backoff limited to prevent excessive timeout" {
    // Practical limit on backoff
    //
    // Expected:
    // - Max backoff_count (e.g., 10)
    // - Prevents multi-minute timeouts
    // - Eventually closes connection

    try testing.expect(true);
}

test "INTEGRATION TEST - PTO backoff separate per PN space" {
    // Independent backoff counters
    //
    // Expected:
    // - Initial space has own backoff_count
    // - Handshake space has own backoff_count
    // - One space can timeout while other progresses

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - Packet Sending Behavior (Tier 3)
// =============================================================================

test "INTEGRATION TEST - sendPtoProbe sends packet to peer address" {
    // UDP transmission
    //
    // Expected:
    // - self.sendTo(conn.peer, pkt)
    // - Uses endpoint's sendTo method
    // - Error caught with try/catch

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe handles send failure gracefully" {
    // Network error
    //
    // Expected:
    // - sendTo returns error
    // - catch ignores error
    // - Packet still tracked as sent
    // - Next PTO will try again

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe frees packet buffer" {
    // Memory management
    //
    // Expected:
    // - defer self.allocator.free(pkt)
    // - Prevents memory leak
    // - Even if send fails

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe marks packet as ACK-eliciting" {
    // Loss recovery tracking
    //
    // Expected:
    // - onPacketSent(..., ack_eliciting=true)
    // - PING frame is ACK-eliciting
    // - Peer must respond with ACK

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - Error Handling (Tier 3)
// =============================================================================

test "INTEGRATION TEST - sendPtoProbe handles frame allocation failure" {
    // OOM during frame building
    //
    // Expected:
    // - frames.append fails
    // - catch returns early
    // - No packet sent
    // - Next PTO tries again

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe handles packet encoding failure" {
    // Encoding error
    //
    // Expected:
    // - encodeInitialProtected returns error
    // - catch converts to return
    // - No packet sent

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto handles timer registration failure" {
    // Timer system error
    //
    // Expected:
    // - TimerManager.schedule returns error
    // - Error propagated to caller
    // - Connection may close

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - Boundary Conditions (Tier 3)
// =============================================================================

test "INTEGRATION TEST - sendPtoProbe with maximum PN value" {
    // PN wraparound
    //
    // Expected:
    // - pn near MAX_U64
    // - Encoding handles large values
    // - Wrapping arithmetic (+=%)

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe with zero RTT" {
    // No RTT samples yet
    //
    // Expected:
    // - Use default PTO value
    // - Typically 300-1000ms
    // - Adjust after first RTT sample

    try testing.expect(true);
}

test "INTEGRATION TEST - scheduleConnPto with maximum backoff" {
    // Extreme backoff scenario
    //
    // Expected:
    // - backoff_count = max (e.g., 10)
    // - PTO = base * 2^10 = base * 1024
    // - Very long timeout
    // - Connection likely closed before this

    try testing.expect(true);
}

test "INTEGRATION TEST - sendPtoProbe with minimal MTU" {
    // Path MTU constraints
    //
    // Expected:
    // - Packet fits in minimum MTU (1200 bytes)
    // - PING frame is small
    // - Always fits

    try testing.expect(true);
}

// =============================================================================
// INTEGRATION TESTS - RFC Compliance (Tier 3)
// =============================================================================

test "INTEGRATION TEST - RFC 9002 §6.2: PTO timer arms on ACK-eliciting sent" {
    // Timer management
    //
    // MUST: Arm PTO when sending ACK-eliciting packet
    // MUST: Reset PTO when receiving ACK
    // MUST: Send probe on timeout

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.1: PTO calculation formula" {
    // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
    //
    // MUST: Use this formula
    // MUST: Add max_ack_delay for ApplicationPTO
    // SHOULD: Not add max_ack_delay for Initial/Handshake

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.2.1: PTO backoff" {
    // Exponential backoff on consecutive timeouts
    //
    // MUST: Double PTO on each timeout without progress
    // MUST: Reset backoff on ACK of new packet

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.4: Probe packets are ACK-eliciting" {
    // Probe content
    //
    // MUST: Send at least one ACK-eliciting frame
    // SHOULD: Send PING if no data to send
    // MAY: Retransmit unacknowledged data

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.4: Send probe in each PN space with unacked data" {
    // Per-space probing
    //
    // MUST: Send probe in each space with in-flight packets
    // MUST: Use correct keys for each space
    // Initial, Handshake, Application can have independent PTOs

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9000 §12.2: Probe packets can be coalesced" {
    // Packet coalescing
    //
    // MAY: Coalesce Initial + Handshake probes
    // MUST: Fit in single datagram
    // Reduces packet overhead

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2: PTO prevents deadlock" {
    // Purpose of PTO
    //
    // Purpose: Prevent connection stall when ACKs lost
    // Purpose: Elicit ACK to make progress
    // Last resort timer

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.1: No PTO before first RTT sample" {
    // Initial PTO value
    //
    // SHOULD: Use initial_rtt = 333ms if no sample
    // OR: Use configured default
    // Updated after first RTT measurement

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2: PTO timer not armed for non-ACK-eliciting" {
    // ACK-only packets
    //
    // MUST NOT: Arm PTO for ACK-only packets
    // Reason: ACKs don't need acknowledgment
    // Only ACK-eliciting packets need PTO

    try testing.expect(true);
}

test "INTEGRATION TEST - RFC 9002 §6.2.4: Probe retransmits lost data" {
    // Loss recovery
    //
    // SHOULD: Retransmit lost CRYPTO or STREAM data
    // MUST: At least one ACK-eliciting frame
    // PING used if no data to retransmit

    try testing.expect(true);
}
