//! Probe Timeout (PTO) handling.
//!
//! RFC 9002 §6.2: Probe Timeout
//! RFC 9002 §6.2.1: Computing PTO
//! RFC 9002 §6.2.4: Sending Probe Packets

const std = @import("std");
const conn_mod = @import("../conn.zig");
const types = @import("types.zig");

/// PTO probe packet generation.
/// This module will contain functions extracted from endpoint.zig for:
/// - sendPtoProbe: Generate and send PTO probe packets
/// - PTO timer expiry handling
/// - Probe packet construction for each PN space (Initial, Handshake, App)
///
/// RFC 9002 §6.2: PTO is used to detect loss when no packets are received.
/// Probe packets help elicit acknowledgements from the peer.

/// Placeholder for PTO probe handling.
/// Full implementation will be extracted from endpoint.zig during Phase 3.
pub const PtoHandler = struct {
    pub fn init() PtoHandler {
        return .{};
    }

    /// Send a PTO probe packet for the specified PN space.
    pub fn sendProbe(self: *PtoHandler, conn: *conn_mod.Connection, kind: types.TimerKind) !void {
        _ = self;
        _ = conn;
        _ = kind;
        // Implementation will be extracted from endpoint.zig:sendPtoProbe
    }
};
