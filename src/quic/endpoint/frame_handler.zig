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

/// RFC 9000 §4.6: a stream count may not exceed 2^60. A larger MAX_STREAMS /
/// STREAMS_BLOCKED value is a FRAME_ENCODING_ERROR.
const max_streams_limit: u64 = 1 << 60;

/// Send CONNECTION_CLOSE under Connection.mu. Frame handlers run on the
/// receive path without it (module_c releases it before processFrames), and a
/// 1-RTT packet takes a packet number: sent unserialized, it could share one
/// (and its AEAD nonce) with a packet an application thread sends (SONNY-4379).
fn sendCloseLocked(ctx: *FrameContext, code: u64, reason: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    ctx.conn.lockForEndpoint();
    defer ctx.conn.mu.unlock(io);
    return ctx.conn.sendConnectionClose(code, reason);
}

/// Close the connection with FRAME_ENCODING_ERROR (0x07) and report the close.
/// Used for malformed frame-level violations (e.g. MAX_STREAMS > 2^60).
fn closeFrameEncodingError(ctx: *FrameContext) FrameResult {
    sendCloseLocked(ctx, 0x07, "FRAME_ENCODING_ERROR") catch |err| {
        logger.debugPrint("Failed to send CONNECTION_CLOSE (FRAME_ENCODING_ERROR): {}\n", .{err});
        ctx.conn.markClosed();
    };
    return .{ .saw_close = true };
}

/// Close the connection with STREAM_STATE_ERROR (0x05) and report the close.
/// Close the connection with a transport error code and report the close.
fn closeWithError(ctx: *FrameContext, code: u64, reason: []const u8) FrameResult {
    sendCloseLocked(ctx, code, reason) catch |err| {
        logger.debugPrint("Failed to send CONNECTION_CLOSE ({s}): {}\n", .{ reason, err });
        ctx.conn.markClosed();
    };
    return .{ .saw_close = true };
}

fn closeStreamStateError(ctx: *FrameContext) FrameResult {
    sendCloseLocked(ctx, 0x05, "STREAM_STATE_ERROR") catch |err| {
        logger.debugPrint("Failed to send CONNECTION_CLOSE (STREAM_STATE_ERROR): {}\n", .{err});
        ctx.conn.markClosed();
    };
    return .{ .saw_close = true };
}

/// True if `sid` is a unidirectional stream initiated by the peer — i.e. a
/// stream on which we are the receiver and never the sender. MAX_STREAM_DATA for
/// such a stream is a STREAM_STATE_ERROR (RFC 9000 §19.10).
fn isPeerInitiatedUniStream(conn: *const conn_mod.Connection, sid: u64) bool {
    const is_uni = (sid & 0x2) != 0;
    if (!is_uni) return false;
    const initiated_by_client = (sid & 0x1) == 0;
    const peer_is_client = (conn.role == .Server);
    return initiated_by_client == peer_is_client;
}

/// Upper bound on pre-created (not-yet-locally-opened) stream_txs entries, to
/// bound memory against a peer flooding MAX_STREAM_DATA for stream IDs we will
/// never open (QC-05). Comfortably exceeds realistic concurrent stream counts.
const max_pre_created_stream_tx: usize = 16384;

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
    /// Whether STREAM data was delivered to the application receive buffer.
    saw_stream: bool = false,
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
    // Record stateless reset token for later detection.
    ctx.conn.onNewConnectionId(ncid.sequence, ncid.retire_prior_to, ncid.connection_id, ncid.stateless_reset_token) catch |err| switch (err) {
        // RFC 9000 §5.1.1 (NEWGAP-03): peer exceeded our advertised
        // active_connection_id_limit. Close with CONNECTION_ID_LIMIT_ERROR (0x09).
        error.ConnectionIdLimitError => {
            sendCloseLocked(ctx, 0x09, "CONNECTION_ID_LIMIT_ERROR") catch |close_err| {
                logger.debugPrint("Failed to send CONNECTION_CLOSE for CID limit: {}\n", .{close_err});
                ctx.conn.markClosed();
            };
            return .{ .saw_close = true };
        },
    };
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
        // RFC 9000 §4.1-§4.2: a receive-side flow-control violation is a
        // connection error of type FLOW_CONTROL_ERROR (0x03). Emit the
        // CONNECTION_CLOSE here (pushStreamFrame has released conn.mu by now;
        // sendCloseLocked takes it) and report the close so the receive path
        // stops processing this connection.
        if (err == error.FlowControlError) {
            sendCloseLocked(ctx, 0x03, "FLOW_CONTROL_ERROR") catch |close_err| {
                logger.debugPrint("Failed to send CONNECTION_CLOSE for flow-control error: {}\n", .{close_err});
                ctx.conn.markClosed();
            };
            return .{ .saw_close = true };
        }
        // RFC 9000 §4.5 / §4.6 (SONNY-6486): these used to drop the packet
        // without an ACK or a close.
        if (err == error.FinalSizeError) return closeWithError(ctx, 0x06, "FINAL_SIZE_ERROR");
        if (err == error.StreamLimitExceeded) return closeWithError(ctx, 0x04, "STREAM_LIMIT_ERROR");
        return err;
    };
    logger.debugPrint("pushStreamFrame returned successfully\n", .{});
    return .{ .saw_ack_eliciting = true, .saw_stream = true };
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
    ctx.conn.pushDatagram(d.data) catch |err| {
        logger.warn("pushDatagram failed: {s}", .{@errorName(err)});
    };

    // Optional DATAGRAM echo response (test/debugging feature)
    if (ctx.cfg.enable_datagram) {
        // Every 1-RTT packet is sent under Connection.mu (SONNY-4379).
        ctx.conn.lockForEndpoint();
        defer ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (ctx.conn.app_tx_keys) |txk| {
            var fb: std.ArrayList(u8) = .empty;
            defer fb.deinit(ctx.allocator.*);
            const w = @import("compat").arrayListWriter(&fb, ctx.allocator.*);
            _ = (frame.Frame{ .datagram = .{ .data = d.data } }).write(w) catch 0;

            const dcid_sh = if (ctx.conn.peer_initial_scid.len > 0)
                ctx.conn.peer_initial_scid.bytes[0..ctx.conn.peer_initial_scid.len]
            else
                &[_]u8{};

            const packet_storage = try ctx.conn.packet_pool.checkout();
            defer ctx.conn.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                dcid_sh,
                ctx.conn.pn_app_tx,
                ctx.conn.appPacketNumberLen(ctx.conn.pn_app_tx),
                fb.items,
                txk,
                ctx.conn.tx_key_phase,
            ) catch 0;

            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                _ = ctx.send_fn(ctx.peer, pkt) catch |err| {
                    logger.warn("DATAGRAM echo send failed: {s}", .{@errorName(err)});
                };
                ctx.conn.onShortHeaderPacketSent(pkt.len, true);
            }
        }
    }

    // RFC 9221 §5.2: "DATAGRAM frames are ack-eliciting" (they are not
    // retransmitted on loss, but they do elicit an acknowledgement).
    return .{ .saw_ack_eliciting = true };
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
    // CANARY: REQ=REQ-QUIC-HC-143; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ContendedAckFrameShedding; STATUS=TESTED; TEST=frame_handler_server_ack_skips_when_connection_mutex_is_busy; OWNER=transport; UPDATED=2026-05-28
    // ACK-only work must not park endpoint poll workers behind response
    // writers. ACK frames are non-ack-eliciting and future ACK ranges are
    // cumulative, so under server-side contention it is better to drop this
    // receive-path ACK sample than to block delivery of unrelated STREAM data.
    const shed_if_busy = ctx.space == .Application and ctx.conn.role == .Server;
    var locked = false;
    if (shed_if_busy) {
        if (!ctx.conn.mu.tryLock()) return .{};
        locked = true;
    } else {
        ctx.conn.lockForEndpoint();
        locked = true;
    }

    // CANARY: REQ=REQ-QUIC-HC-069; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AckRecoveryMutex; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
    // ACK processing mutates recovery state and the application STREAM
    // retransmission map. Keep it under the same per-connection mutex as
    // writeStream()/PTO retransmission so a many-connection response burst
    // cannot race ACK cleanup against a concurrent send or timer callback.
    defer if (locked) ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());

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
            // QUIC-H3-004: If the stream was blocked at the old limit, it is now writable.
            if (tx.off >= old_max and tx.off < m.max) {
                ctx.conn.writable_streams.append(ctx.allocator.*, m.stream_id) catch |err| {
                    logger.err("writable_streams.append failed (OOM): {s}", .{@errorName(err)});
                };
            }
        } else {
            logger.debugPrint("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={}) ignored (current={})\n", .{ m.stream_id, m.max, tx.peer_max_stream_data });
        }
    } else {
        // RFC 9000 §19.10 (QC-05): MAX_STREAM_DATA only applies to streams we can
        // send on. A frame for a peer-initiated unidirectional stream (which is
        // receive-only for us) is a STREAM_STATE_ERROR.
        if (isPeerInitiatedUniStream(ctx.conn, m.stream_id)) {
            return closeStreamStateError(ctx);
        }
        // Credit for a retired stream is moot; do not recreate its state
        // (SONNY-6478).
        if (ctx.conn.isStreamRetired(m.stream_id)) return .{ .saw_ack_eliciting = true };
        // QC-05: bound pre-created TX state so a peer cannot grow stream_txs
        // without limit by advertising windows for streams we will never open.
        if (ctx.conn.stream_txs.count() >= max_pre_created_stream_tx) {
            logger.debugPrint("[FC-TX] stream_txs at cap ({}); ignoring MAX_STREAM_DATA for stream {}\n", .{ max_pre_created_stream_tx, m.stream_id });
            return .{ .saw_ack_eliciting = true };
        }
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
    // RFC 9000 §4.6/§19.11 (QC-08): a MAX_STREAMS value greater than 2^60 is a
    // FRAME_ENCODING_ERROR. Updates are also monotonic — ignore decreases.
    if (msb.max > max_streams_limit) {
        return closeFrameEncodingError(ctx);
    }
    if (msb.max > ctx.conn.peer_max_streams_bidi) ctx.conn.peer_max_streams_bidi = msb.max;
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
    // RFC 9000 §4.6/§19.11 (QC-08): values above 2^60 are a FRAME_ENCODING_ERROR;
    // updates are monotonic.
    if (msu.max > max_streams_limit) {
        return closeFrameEncodingError(ctx);
    }
    if (msu.max > ctx.conn.peer_max_streams_uni) ctx.conn.peer_max_streams_uni = msu.max;
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
    // The MAX_DATA answer is a 1-RTT packet: send it under Connection.mu like
    // every other (SONNY-4379).
    ctx.conn.lockForEndpoint();
    defer ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
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
/// The frame is ack-eliciting (RFC 9002 §2). It used to be ignored and
/// never acknowledged, so a blocked sender whose last data packets were
/// lost got no ACK that could reveal the loss (SONNY-6486). A frame for a
/// stream we cannot receive on is STREAM_STATE_ERROR (§19.13); otherwise any
/// credit the peer has not seen is sent again.
pub fn handleStreamDataBlocked(ctx: *FrameContext, sdb: frame.StreamDataBlocked) FrameResult {
    const is_uni = (sdb.stream_id & 0x2) != 0;
    if (is_uni and !ctx.conn.isPeerInitiatedStream(sdb.stream_id)) return closeStreamStateError(ctx);
    ctx.conn.lockForEndpoint();
    defer ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    ctx.conn.onStreamDataBlocked(sdb.stream_id, sdb.limit);
    return .{ .saw_ack_eliciting = true };
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
    // PATH_RESPONSE is a 1-RTT packet: send it under Connection.mu like
    // every other, or it can share a packet number (and AEAD nonce) with a
    // packet an application thread sends (SONNY-4379).
    ctx.conn.lockForEndpoint();
    defer ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    if (ctx.conn.app_tx_keys) |txk| {
        var fb: std.ArrayList(u8) = .empty;
        defer fb.deinit(ctx.allocator.*);
        const w = @import("compat").arrayListWriter(&fb, ctx.allocator.*);
        _ = (frame.Frame{ .path_response = pcv }).write(w) catch 0;

        const dcid_sh2 = if (ctx.conn.peer_initial_scid.len > 0)
            ctx.conn.peer_initial_scid.bytes[0..ctx.conn.peer_initial_scid.len]
        else
            &[_]u8{};

        const packet_storage = try ctx.conn.packet_pool.checkout();
        defer ctx.conn.packet_pool.release(packet_storage);
        const pkt_len = packet.encodeShortProtectedInto(
            packet_storage,
            dcid_sh2,
            ctx.conn.pn_app_tx,
            ctx.conn.appPacketNumberLen(ctx.conn.pn_app_tx),
            fb.items,
            txk,
            ctx.conn.tx_key_phase,
        ) catch 0;

        if (pkt_len != 0) {
            const pkt = packet_storage[0..pkt_len];
            _ = ctx.send_fn(ctx.peer, pkt) catch |err| {
                logger.warn("PATH_RESPONSE send failed: {s}", .{@errorName(err)});
            };
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
    _ = ctx.conn.onPathResponse(prv);
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
    _ = ctx.conn.initial_token.appendSlice(ctx.allocator.*, nt.token) catch |err| {
        logger.err("NEW_TOKEN appendSlice failed (OOM): {s}", .{@errorName(err)});
    };
    return .{ .saw_ack_eliciting = true };
}

// =============================================================================
// STOP_SENDING / RESET_STREAM Handlers (QUIC-H3-001)
// =============================================================================

/// Handle incoming STOP_SENDING frame (RFC 9000 §19.5).
///
/// The peer is requesting that we stop sending on the identified stream.
/// We respond by marking our TX as aborted and sending RESET_STREAM.
fn handleStopSending(ctx: *FrameContext, ss: frame.StopSending) FrameResult {
    ctx.conn.handleStopSending(ss.stream_id, ss.error_code) catch |err| {
        if (err == error.StreamStateError) return closeStreamStateError(ctx);
        logger.warn("handleStopSending failed for stream {d}: {s}", .{ ss.stream_id, @errorName(err) });
    };
    return .{ .saw_ack_eliciting = true };
}

/// Handle incoming RESET_STREAM frame (RFC 9000 §19.4).
///
/// The peer is aborting its send side of the identified stream. We mark our
/// RX state as aborted, cap final_size, and discard buffered data beyond it.
fn handleResetStreamFrame(ctx: *FrameContext, rs: frame.ResetStream) FrameResult {
    // RFC 9000 §4.5 (NEW-SEC-02): an inconsistent RESET_STREAM final size is a
    // FINAL_SIZE_ERROR (0x06).
    ctx.conn.handleResetStream(rs.stream_id, rs.error_code, rs.final_size) catch |err| switch (err) {
        error.FinalSizeError => return closeWithError(ctx, 0x06, "FINAL_SIZE_ERROR"),
        error.FlowControlError => return closeWithError(ctx, 0x03, "FLOW_CONTROL_ERROR"),
        error.StreamLimitExceeded => return closeWithError(ctx, 0x04, "STREAM_LIMIT_ERROR"),
        error.StreamStateError => return closeStreamStateError(ctx),
    };
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
        // QUIC-H3-001: Wire STOP_SENDING and RESET_STREAM frame handling.
        // RFC 9000 §19.5: STOP_SENDING requests the peer to stop sending on a stream.
        // RFC 9000 §19.4: RESET_STREAM aborts the sending part of a stream.
        .stop_sending => |ss| handleStopSending(ctx, ss),
        .reset_stream => |rs| handleResetStreamFrame(ctx, rs),
        .streams_blocked_bidi, .streams_blocked_uni => {
            // RFC 9000 §19.14: the peer has reached its stream limit. Send any
            // credit returned by retired streams now rather than waiting for
            // the batch threshold (SONNY-6478).
            ctx.conn.lockForEndpoint();
            defer ctx.conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            ctx.conn.maybeSendMaxStreams(true);
            return .{ .saw_ack_eliciting = true };
        },
        // PADDING (RFC 9000 §19.1): no-op by definition.
        // CRYPTO: handled by the handshake integration layer, not the 1-RTT frame dispatcher.
        // Unknown wire types never reach here -- they are caught by frame.decodeOne()
        // returning error.Unsupported before processFrame is called.
        .padding => .{},
        .crypto => .{},
    };
}

/// Module marker for Phase 4b.5 Session 4.
/// This module extracts frame handlers from endpoint.zig.
pub const extracted = true;

/// Module version for documentation
pub const version = "Phase 4b.5 Session 4 - Frame Handler Extraction";
