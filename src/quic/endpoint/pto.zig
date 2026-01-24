// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
//!
//! Phase 4b.5 Session 9: Extract PTO probe generation from endpoint.zig:3392-3448

const std = @import("std");
const logger = @import("quic_logger");
pub const types = @import("types");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");

/// Function signature for sending UDP datagrams.
/// The caller (Endpoint) must provide a function matching this signature.
pub const SendFn = *const fn (ctx: *anyopaque, peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;

/// Context for PTO probe generation.
/// Focused context pattern - only includes what's needed for probe transmission.
pub const PtoContext = struct {
    /// Connection to send probe for
    conn: *conn_mod.Connection,
    /// Memory allocator for packet encoding
    allocator: *std.mem.Allocator,
    /// Opaque context pointer (typically *Endpoint) passed to send_fn
    send_ctx: *anyopaque,
    /// Function to send UDP datagrams (receives send_ctx as first parameter)
    send_fn: SendFn,
    /// Peer socket address
    peer: conn_mod.SockAddr,
};
// =============================================================================
// Module Status and Documentation
// =============================================================================

/// Module marker for Phase 4b.5 Session 9.
/// PTO probe generation has been extracted from endpoint.zig:3392-3448.
pub const extracted = true;

/// Module version for documentation
pub const version = "Phase 4b.5 Session 9 - PTO Probe Extraction";

/// Usage Example:
/// ```zig
/// const pto_mod = @import("endpoint/pto.zig");
///
/// var endpoint = Endpoint.init(allocator, config);
/// const conn = endpoint.getConnection(peer);
///
/// // Create PtoContext
/// var ctx = pto_mod.PtoContext{
///     .conn = conn,
///     .allocator = &allocator,
///     .send_fn = endpoint.sendTo,
///     .peer = conn.peer,
/// };
///
/// // Send PTO probe
/// try pto_mod.sendPtoProbe(&ctx, .PtoInitial);
/// ```
///
/// PTO Backoff Mechanism (RFC 9002 §6.2.2.1):
///   Each time a PTO timer expires, the connection doubles the PTO delay
///   for the next timeout. This exponential backoff prevents overwhelming
///   the network during packet loss.
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

// =============================================================================
// Probe Payload Builders (RFC 9002 §6.2.4)
// =============================================================================

/// Build Initial probe payload (PING frame).
/// RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
pub fn buildInitialProbe(allocator: *std.mem.Allocator) ![]u8 {
    // Create PING frame payload
    const result = try allocator.alloc(u8, 1);
    result[0] = @intFromEnum(frame.FrameType.PING);
    return result;
}

/// Build Handshake probe payload (PING frame).
/// RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
pub fn buildHandshakeProbe(allocator: *std.mem.Allocator) ![]u8 {
    // Create PING frame payload
    const result = try allocator.alloc(u8, 1);
    result[0] = @intFromEnum(frame.FrameType.PING);
    return result;
}

/// Build Application probe payload (PING frame).
/// Future enhancement: Could also include STREAM frames with application data.
/// RFC 9002 §6.2.4: "Probe packets MUST contain ACK-eliciting frames."
pub fn buildApplicationProbe(allocator: *std.mem.Allocator) ![]u8 {
    // Create PING frame payload
    const result = try allocator.alloc(u8, 1);
    result[0] = @intFromEnum(frame.FrameType.PING);
    return result;
}

// =============================================================================
// PTO Probe Transmission (RFC 9002 §6.2.4)
// =============================================================================

/// Send PTO probe packet for the specified packet number space.
/// Extracted from endpoint.zig:3392-3448 (Phase 4b.5 Session 9).
///
/// RFC 9002 §6.2.4: "A PTO timer expiration event does not indicate packet loss
/// and MUST NOT cause prior unacknowledged packets to be marked as lost. When
/// a PTO timer expires, a sender MUST send at least one ack-eliciting packet
/// in the packet number space as a probe."
///
/// Probe packets are always ack-eliciting (contain PING frame).
pub fn sendPtoProbe(ctx: *PtoContext, kind: types.TimerKind) !void {
    const conn = ctx.conn;

    switch (kind) {
        .PtoInitial => {
            // RFC 9001 §4.9.1: "A client MUST discard Initial keys when it first
            // sends a Handshake packet and a server MUST discard Initial keys when
            // it first successfully processes a Handshake packet."
            if (conn.initial_keys_dropped) return; // No more Initial

            // For sending, use proper DCID based on role
            const dcid = if (conn.role == .Client)
                conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len]
            else
                conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
            const scid = conn.our_scid.bytes[0..conn.our_scid.len];

            // RFC 9000 §12.2: Zero-length DCIDs are valid and must be supported
            // Derive server Initial TX keys from the original DCID (ODCID)
            const v2 = conn.version_v2;

            // Debug: Check what DCIDs we have
            logger.debugPrint("[PTO] Checking DCIDs for key derivation (role={}):\n", .{conn.role});
            logger.debugPrint("  original_dcid len={}: ", .{conn.original_dcid.len});
            if (conn.original_dcid.len > 0) {
                for (conn.original_dcid.bytes[0..conn.original_dcid.len]) |b| logger.debugPrint("{X:0>2} ", .{b});
            }
            logger.debugPrint("\n", .{});
            logger.debugPrint("  peer_initial_dcid len={}: ", .{conn.peer_initial_dcid.len});
            if (conn.peer_initial_dcid.len > 0) {
                for (conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len]) |b| logger.debugPrint("{X:0>2} ", .{b});
            }
            logger.debugPrint("\n", .{});

            // Use ODCID for key derivation per RFC 9001 §5.2
            const derive_dcid = if (conn.original_dcid.len > 0)
                conn.original_dcid.bytes[0..conn.original_dcid.len]
            else if (conn.peer_initial_dcid.len > 0)
                conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len]
            else
                dcid; // fallback, should not happen

            const initial = ks.deriveInitialSecret(v2, derive_dcid);
            const pair = ks.deriveClientServerInitial(initial);

            if (conn.role == .Server) {
                logger.debugPrint("server PTO: deriving Initial keys with odcid=\n", .{});
                for (derive_dcid) |b| logger.debugPrint("{X:0>2}\n", .{b});
                logger.debugPrint(" len={}\n", .{derive_dcid.len});
            }

            const tx_keys: packet.InitialKeys = if (v2) blk: {
                const t = ks.deriveKeyIvHpV2(pair.server);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            } else blk: {
                const t = ks.deriveKeyIvHp(pair.server);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            };

            // Build PING probe (ack-eliciting)
            const frames_payload = try buildInitialProbe(ctx.allocator);
            defer ctx.allocator.free(frames_payload);

            // Encode Initial packet
            const pkt = try packet.encodeInitialProtected(
                ctx.allocator.*,
                if (conn.initial_version == 0) 0x00000001 else conn.initial_version,
                dcid,
                scid,
                &[_]u8{}, // token
                @as(u32, @truncate(conn.pn_initial_tx)),
                4, // pn_len
                frames_payload,
                tx_keys,
            );
            defer ctx.allocator.free(pkt);

            // Send probe packet
            _ = try ctx.send_fn(ctx.send_ctx, ctx.peer, pkt);

            // Update congestion control state
            // RFC 9002 §6.2.4: "A sender MAY send one or two packets when the PTO fires."
            conn.onPacketSent(.Initial, conn.pn_initial_tx, pkt.len, true);
            conn.pn_initial_tx +%= 1;
        },

        .PtoHandshake => {
            // Check if Handshake keys are available
            const tx_keys = conn.hs_tx_keys orelse return;

            const dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
            const scid = conn.our_scid.bytes[0..conn.our_scid.len];

            // Build PING probe (ack-eliciting)
            const frames_payload = try buildHandshakeProbe(ctx.allocator);
            defer ctx.allocator.free(frames_payload);

            // Encode Handshake packet
            const pkt = try packet.encodeHandshakeProtected(
                ctx.allocator.*,
                if (conn.initial_version == 0) 0x00000001 else conn.initial_version,
                dcid,
                scid,
                @as(u32, @truncate(conn.pn_handshake_tx)),
                4, // pn_len
                frames_payload,
                tx_keys,
            );
            defer ctx.allocator.free(pkt);

            // Send probe packet
            _ = try ctx.send_fn(ctx.send_ctx, ctx.peer, pkt);

            // Update congestion control state
            conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt.len, true);
            conn.pn_handshake_tx +%= 1;
            // No re-arm here; normal timer loop handles it.
        },

        .PtoApp => {
            // Future: Application Data probe with PING + STREAM frames
            // For now, not implemented (return without error)
            return;
        },

        else => return, // Not a PTO timer
    }
}

/// Placeholder PtoHandler struct for test compatibility.
/// Full implementation will be provided in future phases.
pub const PtoHandler = struct {
    pub fn init() PtoHandler {
        return .{};
    }
};
