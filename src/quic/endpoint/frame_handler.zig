// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Frame handler module for QUIC 1-RTT packet processing (RFC 9000 §19).
//!
//! This module extracts the frame processing switch statement from endpoint.zig
//! into dedicated handler functions. Each handler processes one frame type and
//! updates connection state accordingly.
//!
//! RFC References:
//! - RFC 9000 §12: Packets and Frames
//! - RFC 9000 §19: Frame Types and Formats
//! - RFC 9000 §13.2: Acknowledgments (ACK generation, ack-eliciting)
//! - RFC 9000 §9: Path Validation (PATH_CHALLENGE, PATH_RESPONSE)
//! - RFC 9221: DATAGRAM Extension
//!
//! Phase 4b.5 Session 4: Extract frame handlers from endpoint.zig:1347-1475

const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const frame = @import("frame");
const packet = @import("packet");
const cfg = @import("config");

// PacketNumberSpace is defined in conn.zig via re-export from connection/types.zig
const PacketNumberSpace = enum { Initial, Handshake, Application };

/// Context for frame processing.
/// Focused context pattern - only includes what's needed for frame handling.
pub const FrameContext = struct {
    /// Connection being processed
    conn: *conn_mod.Connection,
    /// Memory allocator
    allocator: *std.mem.Allocator,
    /// Function to send UDP datagrams
    send_fn: SendFn,
    /// Peer socket address
    peer: conn_mod.SockAddr,
    /// Packet number space for this frame
    space: PacketNumberSpace,
    /// Endpoint configuration (for DATAGRAM echo, etc.)
    cfg: *const cfg.QuicConfig,
    /// Endpoint reference for onPathValidated callback
    endpoint: ?*anyopaque = null,
};

/// Function signature for sending UDP datagrams
pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;

/// Result of frame processing.
/// Tracks flags that affect ACK generation and connection state.
pub const FrameResult = struct {
    /// Whether this frame is ack-eliciting (RFC 9000 §13.2.1)
    saw_ack_eliciting: bool = false,
    /// Whether HANDSHAKE_DONE was received (triggers key drop)
    saw_handshake_done: bool = false,
    /// Whether CONNECTION_CLOSE was received (terminates processing)
    saw_close: bool = false,
};

// =============================================================================
// Frame Handlers (RFC 9000 §19)
// =============================================================================

/// Handle PING frame (RFC 9000 §19.2).
/// PING frames are ack-eliciting and have no other effect.
pub fn handlePing(ctx: *FrameContext) FrameResult {
    _ = ctx;
    return .{ .saw_ack_eliciting = true };
}

/// Handle NEW_CONNECTION_ID frame (RFC 9000 §19.15).
/// Records stateless reset token and updates connection ID management.
///
/// RFC 9000 §5.1.1: "An endpoint MAY send connection IDs to its peer using
/// the NEW_CONNECTION_ID frame."
pub fn handleNewConnectionId(
    ctx: *FrameContext,
    ncid: frame.NewConnectionId,
) FrameResult {
    // Record stateless reset token for later detection
    ctx.conn.onNewConnectionId(ncid.sequence, ncid.retire_prior_to, ncid.connection_id, ncid.stateless_reset_token);
    return .{ .saw_ack_eliciting = true };
}

/// Handle RETIRE_CONNECTION_ID frame (RFC 9000 §19.16).
/// Retires a previously issued connection ID.
///
/// RFC 9000 §5.1.2: "An endpoint sends a RETIRE_CONNECTION_ID frame to
/// indicate that it will no longer use a connection ID."
pub fn handleRetireConnectionId(
    ctx: *FrameContext,
    rc: frame.RetireConnectionId,
) FrameResult {
    ctx.conn.onRetireConnectionId(rc.sequence);
    return .{ .saw_ack_eliciting = true };
}

/// Handle STREAM frame (RFC 9000 §19.8).
/// Delivers stream data to the receive buffer.
///
/// RFC 9000 §2.2: "STREAM frames contain data from a single stream and can
/// be identified by their stream ID."
pub fn handleStream(
    ctx: *FrameContext,
    s: frame.Stream,
) !FrameResult {
    const off: u64 = s.offset orelse 0;
    logger.debugPrint("\n>>> ENDPOINT RECEIVED STREAM FRAME <<<\n", .{});
    if (ctx.conn.role == .Server) {
        logger.debugPrint("Server received STREAM frame - id={}, off={}, len={}, fin={}\n", .{ s.stream_id, off, s.data.len, s.fin });
    } else {
        logger.debugPrint("CLIENT received STREAM frame - id={}, off={}, len={}, fin={}\n", .{ s.stream_id, off, s.data.len, s.fin });
    }
    logger.debugPrint("Calling conn.pushStreamFrame()...\n", .{});
    ctx.conn.pushStreamFrame(s.stream_id, off, s.data, s.fin) catch |err| {
        logger.debugPrint("ERROR: pushStreamFrame failed: {}\n", .{err});
        return err;
    };
    logger.debugPrint("pushStreamFrame returned successfully\n", .{});
    return .{ .saw_ack_eliciting = true };
}

/// Handle DATAGRAM frame (RFC 9221).
/// Delivers unreliable datagram data and optionally echoes it back.
///
/// RFC 9221 §4: "A DATAGRAM frame contains application data in an unreliable
/// manner."
pub fn handleDatagram(
    ctx: *FrameContext,
    d: frame.Datagram,
) !FrameResult {
    // Push datagram to receive queue
    ctx.conn.pushDatagram(d.data) catch {};

    // Optional DATAGRAM echo response (test/debugging feature)
    if (ctx.cfg.enable_datagram) {
        if (ctx.conn.app_tx_keys) |txk| {
            var fb = std.ArrayList(u8){};
            defer fb.deinit(ctx.allocator.*);
            const w = fb.writer(ctx.allocator.*);
            _ = (frame.Frame{ .datagram = .{ .data = d.data } }).write(w) catch 0;

            const dcid_sh = if (ctx.conn.peer_initial_scid.len > 0)
                ctx.conn.peer_initial_scid.bytes[0..ctx.conn.peer_initial_scid.len]
            else
                &[_]u8{};

            const packet_storage = ctx.conn.packet_pool.checkout();
            defer ctx.conn.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                dcid_sh,
                @as(u32, @truncate(ctx.conn.pn_app_tx)),
                2,
                fb.items,
                txk,
                ctx.conn.tx_key_phase,
            ) catch 0;

            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                _ = ctx.send_fn(ctx.peer, pkt) catch {};
                ctx.conn.onShortHeaderPacketSent(pkt.len, true);
            }
        }
    }

    return .{ .saw_ack_eliciting = false }; // DATAGRAM is not ack-eliciting per RFC 9221
}

/// Handle ACK frame (RFC 9000 §19.3).
/// Processes acknowledgment and updates congestion control state.
///
/// RFC 9000 §13.2: "Receivers send ACK frames to inform senders of packets
/// they have received and processed."
pub fn handleAck(
    ctx: *FrameContext,
    a: frame.Ack,
) FrameResult {
    // PHASE 56 FIX: Re-enable ACK processing (was disabled for unit testing)
    // Forward Application ACK to recovery with actual ranges
    ctx.conn.onAckReceivedSpace(.Application, a.largest, a.first_range, a.ranges, a.ecn);

    // Cancel PTO timer on ACK receipt (RFC 9002 §6.2.1)
    ctx.conn.pto_app_count = 0;
    // Note: PTO timer cancellation requires endpoint access - handled in caller

    // Allow PMTUD state machine to progress upon probe ACK
    // Note: pmtudOnAckProgress requires endpoint access - handled in caller

    return .{ .saw_ack_eliciting = false }; // ACK is not ack-eliciting
}

/// Handle HANDSHAKE_DONE frame (RFC 9000 §19.20).
/// Signals handshake completion to the client.
///
/// RFC 9000 §19.20: "The server uses a HANDSHAKE_DONE frame to signal
/// confirmation of the handshake to the client."
pub fn handleHandshakeDone(ctx: *FrameContext) FrameResult {
    // Phase 24 DEBUG: Trace HANDSHAKE_DONE reception
    logger.debugPrint("[handleHandshakeDone] HANDSHAKE_DONE frame received, role={s}\n", .{
        if (ctx.conn.role == .Server) "Server" else "Client",
    });
    return .{
        .saw_ack_eliciting = true,
        .saw_handshake_done = true,
    };
}

/// Handle CONNECTION_CLOSE frame (RFC 9000 §19.19).
/// Terminates the connection.
///
/// RFC 9000 §10.2: "An endpoint sends a CONNECTION_CLOSE frame to notify
/// its peer that the connection is being closed."
pub fn handleConnectionClose(ctx: *FrameContext) FrameResult {
    _ = ctx;
    return .{ .saw_close = true };
}

/// Handle MAX_STREAM_DATA frame (RFC 9000 §19.10).
/// Updates the maximum data that can be sent on a stream.
///
/// RFC 9000 §4.1: "A receiver sends a MAX_STREAM_DATA frame to advertise
/// the maximum amount of data that can be sent on a stream."
pub fn handleMaxStreamData(
    ctx: *FrameContext,
    m: frame.MaxStreamData,
) FrameResult {
    // Stream 0 uses dedicated flow-control state in Connection.peer_max_stream_data.
    // Keep this in sync so legacy stream-0 senders can make forward progress.
    if (m.stream_id == 0) {
        if (m.max > ctx.conn.peer_max_stream_data) {
            const old_max0 = ctx.conn.peer_max_stream_data;
            ctx.conn.peer_max_stream_data = m.max;
            logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream=0, max={}) increased conn stream0 window from {}\n", .{ m.max, old_max0 });
        } else {
            logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream=0, max={}) ignored (current={})\n", .{ m.max, ctx.conn.peer_max_stream_data });
        }
    }

    // PHASE 57 PART 11: Update per-stream send-side flow control window (RFC 9000 §4.2)
    // RFC 9000 §4.1: MAX_STREAM_DATA can only increase the limit
    // Check if stream_txs is initialized before accessing
    if (!ctx.conn.stream_txs_init) {
        logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={}) but stream_txs not initialized\n", .{ m.stream_id, m.max });
        return .{ .saw_ack_eliciting = true };
    }
    if (ctx.conn.stream_txs.getPtr(m.stream_id)) |tx| {
        if (m.max > tx.peer_max_stream_data) {
            const old_max = tx.peer_max_stream_data;
            tx.peer_max_stream_data = m.max;
            logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={}) increased window from {}\n", .{ m.stream_id, m.max, old_max });
        } else {
            logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={}) ignored (current={})\n", .{ m.stream_id, m.max, tx.peer_max_stream_data });
        }
    } else {
        // Stream not yet created on our side - store for when it is created
        // Create TX state entry with the advertised limit
        logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={}) creating TX state\n", .{ m.stream_id, m.max });
        ctx.conn.stream_txs.put(m.stream_id, .{ .peer_max_stream_data = m.max }) catch {
            logger.debugPrint("[FC-TX] Failed to create TX state for stream {}\n", .{m.stream_id});
        };
    }
    return .{ .saw_ack_eliciting = true };
}

/// Handle MAX_DATA frame (RFC 9000 §19.9).
/// Updates the maximum data that can be sent on the connection.
///
/// RFC 9000 §4.1: "A receiver sends a MAX_DATA frame to advertise the
/// maximum amount of data that can be sent on the entire connection."
pub fn handleMaxData(
    ctx: *FrameContext,
    md: frame.MaxData,
) FrameResult {
    // PHASE 57 PART 11: Only update if new limit is greater (RFC 9000 §4.1)
    if (md.max > ctx.conn.peer_max_data) {
        const old_max = ctx.conn.peer_max_data;
        ctx.conn.peer_max_data = md.max;
        logger.debugPrint("[FC-CONN] Received MAX_DATA(max={}) increased from {}\n", .{ md.max, old_max });
    } else {
        logger.debugPrint("[FC-CONN] Received MAX_DATA(max={}) ignored (current={})\n", .{ md.max, ctx.conn.peer_max_data });
    }
    return .{ .saw_ack_eliciting = true };
}

/// Handle MAX_STREAMS (bidi) frame (RFC 9000 §19.11).
/// Updates the maximum number of bidirectional streams.
///
/// RFC 9000 §4.6: "A MAX_STREAMS frame increases the maximum number of
/// streams that an endpoint may initiate."
pub fn handleMaxStreamsBidi(
    ctx: *FrameContext,
    msb: frame.MaxStreamsBidi,
) FrameResult {
    ctx.conn.peer_max_streams_bidi = msb.max;
    return .{ .saw_ack_eliciting = true };
}

/// Handle MAX_STREAMS (uni) frame (RFC 9000 §19.11).
/// Updates the maximum number of unidirectional streams.
///
/// RFC 9000 §4.6: "A MAX_STREAMS frame increases the maximum number of
/// streams that an endpoint may initiate."
pub fn handleMaxStreamsUni(
    ctx: *FrameContext,
    msu: frame.MaxStreamsUni,
) FrameResult {
    ctx.conn.peer_max_streams_uni = msu.max;
    return .{ .saw_ack_eliciting = true };
}

/// Handle DATA_BLOCKED frame (RFC 9000 §19.12).
/// Peer indicates it is blocked by connection-level flow control.
///
/// RFC 9000 §4.1: "A sender sends a DATA_BLOCKED frame when it wishes to
/// send data but is unable to do so due to connection-level flow control."
///
/// When received, we proactively expand local_max_data and send MAX_DATA
/// so the peer can continue sending. This prevents connection stalls when
/// the peer has exhausted the initial_max_data allowance.
pub fn handleDataBlocked(ctx: *FrameContext, db: frame.DataBlocked) FrameResult {
    _ = db;
    // Expand the connection-level receive window by the initial window size.
    // This ensures the peer can always send more data.
    const conn_receive_window: u64 = 10 * 1024 * 1024; // 10MB
    const new_max = ctx.conn.conn_recv_total + conn_receive_window;
    if (new_max > ctx.conn.local_max_data) {
        ctx.conn.local_max_data = new_max;
        // Trigger MAX_DATA frame emission
        ctx.conn.advertiseInitialFlowControl();
    }
    return .{ .saw_ack_eliciting = true };
}

/// Handle STREAM_DATA_BLOCKED frame (RFC 9000 §19.13).
/// Peer indicates it is blocked by stream flow control.
///
/// RFC 9000 §4.1: "A sender sends a STREAM_DATA_BLOCKED frame to indicate
/// that it has data to send but is unable to do so due to stream-level
/// flow control."
///
/// NOTE: This implementation currently ignores STREAM_DATA_BLOCKED.
/// Future enhancement: Could trigger proactive MAX_STREAM_DATA increase.
pub fn handleStreamDataBlocked(ctx: *FrameContext, sdb: frame.StreamDataBlocked) FrameResult {
    _ = ctx;
    _ = sdb;
    // No action taken - informational only
    return .{ .saw_ack_eliciting = false };
}

/// Handle PATH_CHALLENGE frame (RFC 9000 §19.17).
/// Responds with PATH_RESPONSE for path validation.
///
/// RFC 9000 §8.2: "An endpoint responds to a PATH_CHALLENGE frame by echoing
/// the data contained in the frame in a PATH_RESPONSE frame."
pub fn handlePathChallenge(
    ctx: *FrameContext,
    pcv: frame.PathChallenge,
) !FrameResult {
    if (ctx.conn.app_tx_keys) |txk| {
        var fb = std.ArrayList(u8){};
        defer fb.deinit(ctx.allocator.*);
        const w = fb.writer(ctx.allocator.*);
        _ = (frame.Frame{ .path_response = pcv }).write(w) catch 0;

        const dcid_sh2 = if (ctx.conn.peer_initial_scid.len > 0)
            ctx.conn.peer_initial_scid.bytes[0..ctx.conn.peer_initial_scid.len]
        else
            &[_]u8{};

        const packet_storage = ctx.conn.packet_pool.checkout();
        defer ctx.conn.packet_pool.release(packet_storage);
        const pkt_len = packet.encodeShortProtectedInto(
            packet_storage,
            dcid_sh2,
            @as(u32, @truncate(ctx.conn.pn_app_tx)),
            2,
            fb.items,
            txk,
            ctx.conn.tx_key_phase,
        ) catch 0;

        if (pkt_len != 0) {
            const pkt = packet_storage[0..pkt_len];
            _ = ctx.send_fn(ctx.peer, pkt) catch {};
            ctx.conn.onShortHeaderPacketSent(pkt.len, true);
        }
    }

    return .{ .saw_ack_eliciting = true };
}

/// Handle PATH_RESPONSE frame (RFC 9000 §19.18).
/// Validates path challenge completion.
///
/// RFC 9000 §8.2: "On receiving a PATH_RESPONSE frame, an endpoint can
/// consider the path validated."
///
/// NOTE: Requires endpoint.onPathValidated() callback - must be called by caller.
pub fn handlePathResponse(
    ctx: *FrameContext,
    prv: frame.PathResponse,
) FrameResult {
    if (ctx.conn.path_validation_pending and std.mem.eql(u8, prv[0..], ctx.conn.path_challenge_data[0..])) {
        ctx.conn.path_validation_pending = false;
        ctx.conn.address_validated = true;
        ctx.conn.bytes_rx_unvalidated = 0;
        ctx.conn.bytes_tx_unvalidated = 0;
    }
    return .{ .saw_ack_eliciting = true };
}

/// Handle NEW_TOKEN frame (RFC 9000 §19.7).
/// Updates the token for future connection attempts.
///
/// RFC 9000 §8.1.3: "A client MAY use a token provided in a NEW_TOKEN frame
/// for any server that the connection is considered authoritative for."
pub fn handleNewToken(
    ctx: *FrameContext,
    nt: frame.NewToken,
) !FrameResult {
    ctx.conn.initial_token.clearRetainingCapacity();
    _ = ctx.conn.initial_token.appendSlice(ctx.allocator.*, nt.token) catch {};
    return .{ .saw_ack_eliciting = true };
}

// =============================================================================
// Frame Dispatcher
// =============================================================================

/// Process a single frame and return result flags.
/// Extracted from endpoint.zig:1361-1474 switch statement.
///
/// RFC 9000 §12.4: "An endpoint MUST treat receipt of a frame of unknown
/// type as a connection error of type FRAME_ENCODING_ERROR."
pub fn processFrame(ctx: *FrameContext, fr: frame.Frame) !FrameResult {
    return switch (fr) {
        .ping => handlePing(ctx),
        .new_connection_id => |ncid| handleNewConnectionId(ctx, ncid),
        .retire_connection_id => |rc| handleRetireConnectionId(ctx, rc),
        .stream => |s| try handleStream(ctx, s),
        .datagram => |d| try handleDatagram(ctx, d),
        .ack => |a| handleAck(ctx, a),
        .handshake_done => handleHandshakeDone(ctx),
        .connection_close => handleConnectionClose(ctx),
        .max_stream_data => |m| handleMaxStreamData(ctx, m),
        .max_data => |md| handleMaxData(ctx, md),
        .max_streams_bidi => |msb| handleMaxStreamsBidi(ctx, msb),
        .max_streams_uni => |msu| handleMaxStreamsUni(ctx, msu),
        .data_blocked => |db| handleDataBlocked(ctx, db),
        .stream_data_blocked => |sdb| handleStreamDataBlocked(ctx, sdb),
        .path_challenge => |pcv| try handlePathChallenge(ctx, pcv),
        .path_response => |prv| handlePathResponse(ctx, prv),
        .new_token => |nt| try handleNewToken(ctx, nt),
        else => .{}, // Unknown frames ignored (RFC 9000 §12.4)
    };
}

/// Module marker for Phase 4b.5 Session 4.
/// This module extracts frame handlers from endpoint.zig.
pub const extracted = true;

/// Module version for documentation
pub const version = "Phase 4b.5 Session 4 - Frame Handler Extraction";
