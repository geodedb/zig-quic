//! Probe Timeout (PTO) handling (RFC 9002 §6.2).
//!
//! This module handles PTO timer management and probe packet generation:
//! - PTO timer scheduling per packet number space
//! - Probe packet generation (Initial, Handshake, Application)
//! - Exponential backoff mechanism
//! - ACK-eliciting frame selection
//!
//! RFC References:
//! - RFC 9002 §6.2: Probe Timeout
//! - RFC 9002 §6.2.1: Computing PTO
//! - RFC 9002 §6.2.2: Exponentials Backoff
//! - RFC 9002 §6.2.2.1: PTO Backoff
//! - RFC 9002 §6.2.4: Sending Probe Packets

const std = @import("std");
const types = @import("types.zig");

// Note: PTO functions currently require access to the full Endpoint structure.
// For Phase 4a, tests and external code should call these via the Endpoint instance.
// Full extraction to standalone functions is Phase 4b (future work).

/// PTO (Probe Timeout) functions are currently implemented in endpoint.zig
/// due to dependencies on Endpoint state (allocator, socket, timers, etc.).
///
/// Usage from tests:
///   const pto = @import("endpoint/pto.zig");
///   // Then call via endpoint instance:
///   const timer_id = try endpoint.scheduleConnPto(conn, .PtoInitial, delay_ms);
///   try endpoint.sendPtoProbe(conn, .PtoInitial);
///
/// The following functions are available via Endpoint methods:
///
/// **scheduleConnPto**(conn: *Connection, kind: TimerKind, delay_ms: u32) -> u64
///   Schedules a PTO timer for the specified connection and packet number space.
///   - kind: .PtoInitial, .PtoHandshake, or .PtoApp
///   - delay_ms: PTO delay computed by connection's loss detection
///   - Returns timer ID that can be used to cancel the timer
///   RFC 9002 §6.2: "PTO is used to detect packet loss when no acknowledgements are received."
///
/// **sendPtoProbe**(conn: *Connection, kind: TimerKind) -> void
///   Sends a probe packet for the specified packet number space:
///   - .PtoInitial: Sends Initial packet with PING frame
///     - Uses server Initial TX keys derived from original DCID
///     - Only sent if Initial keys not yet dropped
///   - .PtoHandshake: Sends Handshake packet with PING frame
///     - Uses Handshake TX keys
///     - Only sent if Handshake keys available
///   - .PtoApp: (Future) Send Application Data packet
///   Probe packets are ACK-eliciting (contain PING frame) to trigger acknowledgements.
///   RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
///
/// PTO Backoff Mechanism (RFC 9002 §6.2.2.1):
///   Each time a PTO timer expires, the connection doubles the PTO delay
///   for the next timeout. This exponential backoff prevents overwhelming
///   the network during packet loss.
///
/// Example usage:
/// ```zig
/// var endpoint = Endpoint.init(allocator, config);
/// const conn = endpoint.getConnection(peer);
///
/// // Compute PTO delay (done by connection)
/// const pto_ms = conn.computePto(.Initial);
///
/// // Schedule PTO timer
/// const timer_id = try endpoint.scheduleConnPto(conn, .PtoInitial, pto_ms);
///
/// // When timer expires (detected in endpoint.poll):
/// try endpoint.sendPtoProbe(conn, .PtoInitial);
/// ```

/// Module marker for Phase 4a modular structure.
/// Full implementation extraction is Phase 4b (future work).
pub const extracted = false; // Set to true when implementations are fully extracted

/// For documentation and test organization, these function signatures represent
/// the interface that will eventually be extracted. Currently implemented in endpoint.zig.
pub const Interface = struct {
    /// Schedule PTO timer for connection
    pub const ScheduleConnPtoSignature = fn (conn: *@import("../conn.zig").Connection, kind: types.TimerKind, delay_ms: u32) anyerror!u64;

    /// Send probe packet for packet number space
    pub const SendPtoProbeSignature = fn (conn: *@import("../conn.zig").Connection, kind: types.TimerKind) anyerror!void;
};

/// Helper: Check if a timer kind is a PTO timer.
/// Used to identify PTO timers vs generic or PMTUD timers.
pub fn isPtoTimer(kind: types.TimerKind) bool {
    return switch (kind) {
        .PtoInitial, .PtoHandshake, .PtoApp => true,
        .Generic, .Pmtud => false,
    };
}

/// Helper: Get the packet number space for a PTO timer kind.
/// Maps timer kind to the corresponding packet number space.
pub fn ptoTimerSpace(kind: types.TimerKind) ?enum { Initial, Handshake, Application } {
    return switch (kind) {
        .PtoInitial => .Initial,
        .PtoHandshake => .Handshake,
        .PtoApp => .Application,
        .Generic, .Pmtud => null,
    };
}
