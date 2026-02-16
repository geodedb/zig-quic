const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const posix = std.posix;
const frame = @import("frame");
const frame_handler = @import("frame_handler");
const handshake_integration = @import("handshake_integration");
const lookup = @import("lookup");
const shared = @import("shared.zig");
const RxContext = shared.RxContext;
const SendFn = shared.SendFn;

fn invalidSocket() posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) {
        return @ptrFromInt(~@as(usize, 0));
    } else {
        return -1;
    }
}

pub const FrameProcessResult = struct {
    /// Whether any ack-eliciting frames were seen (RFC 9000 §13.2.1)
    saw_ack_eliciting: bool = false,
    /// Whether HANDSHAKE_DONE was received (triggers key drop)
    saw_handshake_done: bool = false,
    /// Whether CONNECTION_CLOSE was received (terminates processing)
    saw_close: bool = false,
};

/// Parse and process frames from decrypted 1-RTT payload.
/// Extracted from endpoint.zig lines 1347-1492 (Phase 4b.5 Session 3).
///
/// RFC 9000 §12: "After removing packet protection, the unprotected payload
/// includes frames."
///
/// This function:
/// 1. Parses frames one by one using frame.decodeOne()
/// 2. Dispatches each frame to frame_handler.processFrame()
/// 3. Tracks ack-eliciting status, HANDSHAKE_DONE, CONNECTION_CLOSE
/// 4. Handles post-frame-processing logic (key drops, connection closure)
///
/// Parameters:
/// - ctx: RxContext with allocator, config, connections
/// - conn: Connection receiving the frames
/// - peer: Socket address of the peer
/// - payload: Decrypted frame payload
/// - send_fn: Function to send UDP datagrams
///
/// Returns:
/// - FrameProcessResult with saw_ack_eliciting, saw_handshake_done, saw_close flags
///
/// RFC 9000 §13.2.1: "Packets that are ack-eliciting MUST be acknowledged
/// within the maximum ack delay."
pub fn processFrames(
    ctx: *RxContext,
    conn: *conn_mod.Connection,
    peer: conn_mod.SockAddr,
    payload: []const u8,
    send_fn: SendFn,
) !FrameProcessResult {
    // RFC 9000 §10.2: Discard frames for connections in the closing/draining state.
    // After sendConnectionClose() sets closed=true, no further frame processing
    // should occur to prevent accessing inconsistent connection state.
    if (conn.closed) return FrameProcessResult{};

    var result = FrameProcessResult{};
    var offset: usize = 0;

    logger.debugPrint("Parsing frames from payload, total_len={}, role={s}\n", .{
        payload.len,
        if (conn.role == .Server) "Server" else "Client",
    });

    // Parse frames from payload
    while (offset < payload.len) {
        const first_byte = if (payload[offset..].len > 0) payload[offset] else 0;
        const fr = frame.decodeOne(payload[offset..]) catch |err| {
            logger.debugPrint("Frame decode error at offset {}: {} (first_byte=0x{X:0>2})\n", .{ offset, err, first_byte });
            break;
        };
        logger.debugPrint("Decoded frame at offset {}: type={s}\n", .{ offset, @tagName(fr.f) });
        if (fr.f == .stream) {
            const s = fr.f.stream;
            logger.debugPrint("[STREAM-FRAME] id={} off={} len={} fin={}\n", .{ s.stream_id, s.offset orelse 0, s.data.len, s.fin });
        }
        offset += fr.n;

        // Create frame handler context
        var frame_ctx = frame_handler.FrameContext{
            .conn = conn,
            .allocator = ctx.allocator,
            .send_fn = send_fn,
            .peer = peer,
            .space = .Application,
            .cfg = ctx.cfg,
            .endpoint = null, // Will be set by caller if needed
        };

        // Process frame through handler
        const frame_result = try frame_handler.processFrame(&frame_ctx, fr.f);

        logger.debugPrint("[processFrames] Frame processed: saw_handshake_done={}\n", .{frame_result.saw_handshake_done});

        // Accumulate flags
        result.saw_ack_eliciting = result.saw_ack_eliciting or frame_result.saw_ack_eliciting;
        result.saw_handshake_done = result.saw_handshake_done or frame_result.saw_handshake_done;
        result.saw_close = result.saw_close or frame_result.saw_close;
    }

    logger.debugPrint("[processFrames] Returning result: saw_ack_eliciting={}, saw_handshake_done={}, saw_close={}\n", .{
        result.saw_ack_eliciting,
        result.saw_handshake_done,
        result.saw_close,
    });

    return result;
}

/// Context for ACK generation and transmission.
/// Contains only what's needed for generating and sending ACK responses.
pub const AckContext = struct {
    allocator: *std.mem.Allocator,
    conn: *conn_mod.Connection,
    peer: conn_mod.SockAddr,
    send_fn: SendFn,
    cfg: *const cfg.QuicConfig,
    test_capture_enabled: bool,
};

/// Generate and send ACK frame for received 1-RTT packet.
/// Extracted from endpoint.zig lines 1493-1669 (Phase 4b.5 Session 3).
///
/// RFC 9000 §13.2: "Receivers send ACK frames to inform senders of packets
/// they have received and processed."
///
/// This function handles:
/// 1. Deferred ECN ACK emission when amplification allows
/// 2. AEAD integrity limit CONNECTION_CLOSE (RFC 9000 §20, code 0x0f)
/// 3. Main ACK generation with ECN support
/// 4. Amplification limit enforcement (RFC 9000 §8.1)
/// 5. MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS piggybacking
/// 6. NEW_CONNECTION_ID frame piggybacking
/// 7. ACK-only fallback when amplification-limited
///
/// Parameters:
/// - ack_ctx: AckContext with allocator, connection, peer, send_fn, config
/// - frame_result: Result from frame processing (for ack-eliciting check)
/// - ecn_bits: ECN bits from IP header (if available)
///
/// Returns: void (errors are logged but not propagated)
///
/// RFC 9000 §8.1: "A server MAY send a single packet containing only an ACK
/// frame in response to each received datagram when under amplification limit."
pub fn generateAndSendAck(
    ack_ctx: *AckContext,
    frame_result: FrameProcessResult,
    ecn_bits: ?u8,
) !void {
    const conn = ack_ctx.conn;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    // Test-only debug logging
    if (ack_ctx.test_capture_enabled) {
        logger.debugPrint("APP saw_any={s}\n", .{if (frame_result.saw_ack_eliciting) "y" else "n"});
    }

    // Check if connection is closed (from CONNECTION_CLOSE frame)
    if (conn.closed) {
        return; // Stop processing
    }

    // If deferred ECN ACK is pending and amplification allows, emit it now
    if (conn.ecn_app_ack_pending and conn.app_tx_keys != null and conn.canSendUnderAmplification()) {
        var ack_buf = std.ArrayList(u8){};
        defer ack_buf.deinit(ack_ctx.allocator.*);
        const w = ack_buf.writer(ack_ctx.allocator.*);
        const ad = conn.buildAckApp();
        const ack_ecn_now = conn.getAckEcn(.Application);

        if (ack_ctx.test_capture_enabled and ack_ecn_now != null) {
            logger.debugPrint("APP pending ACK_ECN flush ce={d} ect0={d} ect1={d}\n", .{ ack_ecn_now.?.ce, ack_ecn_now.?.ect0, ack_ecn_now.?.ect1 });
        }

        const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
        const ackf = frame.Frame{ .ack = .{ .largest = ad.largest, .ack_delay = ack_delay, .first_range = ad.first_range, .ranges = ad.ranges, .ecn = ack_ecn_now } };
        _ = ackf.write(w) catch 0;

        const dcid_ack = if (conn.peer_initial_scid.len > 0)
            conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)]
        else
            &[_]u8{};

        const packet_storage = conn.packet_pool.checkout();
        defer conn.packet_pool.release(packet_storage);
        const pkt_len = packet.encodeShortProtectedInto(
            packet_storage,
            dcid_ack,
            @as(u32, @truncate(conn.pn_app_tx)),
            2,
            ack_buf.items,
            conn.app_tx_keys.?,
            conn.tx_key_phase,
        ) catch 0;

        if (pkt_len != 0) {
            const pkt = packet_storage[0..pkt_len];
            _ = ack_ctx.send_fn(ack_ctx.peer, pkt) catch {};
            conn.onShortHeaderPacketSent(pkt.len, false);
            conn.ecn_app_ack_pending = false;
            return; // Stop further processing
        }
    }

    // Enforce AEAD integrity limit: send CONNECTION_CLOSE if limit reached
    if (conn.closed) {
        if (conn.app_tx_keys) |tx_keys| {
            var fb = std.ArrayList(u8){};
            defer fb.deinit(ack_ctx.allocator.*);
            const w = fb.writer(ack_ctx.allocator.*);

            // AEAD_LIMIT_REACHED = 0x0f per RFC 9000 §20
            _ = (frame.Frame{ .connection_close = .{ .error_code = 0x0f, .frame_type = 0, .reason = "AEAD integrity limit reached" } }).write(w) catch 0;

            // Amplification gating: only send if validated or within 3x limit
            const allow_send = conn.canSendUnderAmplification();
            if (allow_send) {
                const dcid_ack2 = if (conn.peer_initial_scid.len > 0)
                    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                else
                    &[_]u8{};

                const packet_storage = conn.packet_pool.checkout();
                defer conn.packet_pool.release(packet_storage);
                const pkt_len = packet.encodeShortProtectedInto(
                    packet_storage,
                    dcid_ack2,
                    @as(u32, @truncate(conn.pn_app_tx)),
                    2,
                    fb.items,
                    tx_keys,
                    conn.tx_key_phase,
                ) catch 0;

                if (pkt_len != 0) {
                    const pkt = packet_storage[0..pkt_len];
                    _ = ack_ctx.send_fn(ack_ctx.peer, pkt) catch {};
                    conn.onShortHeaderPacketSent(pkt.len, true);
                }
            }
        }
        return;
    }

    // Generate ACK if we saw ack-eliciting frames or ECN bits
    if (frame_result.saw_ack_eliciting or (ecn_bits != null)) {
        if (ack_ctx.test_capture_enabled) {
            logger.debugPrint("APP have_tx_keys={s}\n", .{if (conn.app_tx_keys != null) "y" else "n"});
        }

        // PHASE 42 PART 21: Comprehensive ACK timing and trigger logging
        const ack_trigger_ns = now_ns;
        const last_rx_ns = conn.last_ack_eliciting_rx_app_ns;
        const delay_since_rx_us = if (last_rx_ns > 0 and ack_trigger_ns >= last_rx_ns)
            (ack_trigger_ns - last_rx_ns) / 1000
        else
            0;

        logger.debugPrint("[P42-21-ACK-TRIGGER] ⏰ ACK triggered: saw_ack_elicit={s} ecn={s} delay_since_rx={d}us\n", .{
            if (frame_result.saw_ack_eliciting) "Y" else "N",
            if (ecn_bits != null) "Y" else "N",
            delay_since_rx_us,
        });

        if (conn.app_tx_keys) |tx_keys| {
            const allow_send = conn.canSendUnderAmplification();

            // PHASE 42 PART 21: Enhanced amplification logging with timing context
            logger.debugPrint("[P42-21-ACK-AMPLIF] allow_send={s} rx_unval={d} tx_unval={d} validated={s} ratio={d:.2}\n", .{
                if (allow_send) "Y" else "N",
                conn.bytes_rx_unvalidated,
                conn.bytes_tx_unvalidated,
                if (conn.address_validated) "Y" else "N",
                if (conn.bytes_rx_unvalidated > 0)
                    @as(f64, @floatFromInt(conn.bytes_tx_unvalidated)) / @as(f64, @floatFromInt(conn.bytes_rx_unvalidated))
                else
                    0.0,
            });

            // Precompute ACK_ECN selection to keep consistent across branches
            var ack_ecn_common = conn.getAckEcn(.Application);
            if (ack_ecn_common == null) {
                if (ecn_bits) |e_cur| {
                    const bcur: u8 = e_cur & 0x03;
                    if (bcur != 0) {
                        ack_ecn_common = switch (bcur) {
                            0x01 => .{ .ect0 = 0, .ect1 = 1, .ce = 0 },
                            0x02 => .{ .ect0 = 1, .ect1 = 0, .ce = 0 },
                            0x03 => .{ .ect0 = 0, .ect1 = 0, .ce = 1 },
                            else => null,
                        };
                    }
                }
            }

            // If ECN observed and amplification blocks, mark pending
            if (ack_ecn_common != null and !allow_send) {
                conn.ecn_app_ack_pending = true;
            }

            if (allow_send) {
                // Emit immediate ACK_ECN if ECN observed
                if (ack_ecn_common != null) {
                    var ack_only = std.ArrayList(u8){};
                    defer ack_only.deinit(ack_ctx.allocator.*);
                    const wa = ack_only.writer(ack_ctx.allocator.*);
                    const ad = conn.buildAckApp();

                    if (ack_ctx.test_capture_enabled) {
                        logger.debugPrint("APP immediate ACK_ECN ce={d} ect0={d} ect1={d}\n", .{ ack_ecn_common.?.ce, ack_ecn_common.?.ect0, ack_ecn_common.?.ect1 });
                    }

                    const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
                    const ackf = frame.Frame{ .ack = .{ .largest = ad.largest, .ack_delay = ack_delay, .first_range = ad.first_range, .ranges = ad.ranges, .ecn = ack_ecn_common } };
                    _ = ackf.write(wa) catch 0;

                    const dcid_ack3 = if (conn.peer_initial_scid.len > 0)
                        conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)]
                    else
                        &[_]u8{};

                    const packet_storage = conn.packet_pool.checkout();
                    defer conn.packet_pool.release(packet_storage);
                    const pkt_len = packet.encodeShortProtectedInto(
                        packet_storage,
                        dcid_ack3,
                        @as(u32, @truncate(conn.pn_app_tx)),
                        2,
                        ack_only.items,
                        tx_keys,
                        conn.tx_key_phase,
                    ) catch 0;

                    if (pkt_len != 0) {
                        const pkt = packet_storage[0..pkt_len];
                        const send_start_ns = std.time.nanoTimestamp();
                        _ = ack_ctx.send_fn(ack_ctx.peer, pkt) catch {};
                        const send_end_ns = std.time.nanoTimestamp();
                        const send_duration_us = @as(u64, @intCast(@abs(send_end_ns - send_start_ns))) / 1000;
                        const total_delay_us = delay_since_rx_us + send_duration_us;

                        logger.debugPrint("[P42-21-ACK-SENT] ✅ ECN ACK sent: pkt_len={d}B largest={d} delay_rx_to_tx={d}us send_us={d}us total={d}us\n", .{
                            pkt.len,
                            ad.largest,
                            delay_since_rx_us,
                            send_duration_us,
                            total_delay_us,
                        });
                        conn.onShortHeaderPacketSent(pkt.len, false);
                    }
                    return; // Stop further processing
                } else {
                    // Build ACK with MAX_* frame piggybacking
                    var frames_buf = std.ArrayList(u8){};
                    defer frames_buf.deinit(ack_ctx.allocator.*);
                    const w = frames_buf.writer(ack_ctx.allocator.*);
                    const ack_desc = conn.buildAckApp();

                    if (ack_ctx.test_capture_enabled) {
                        logger.debugPrint("APP ACK (no ECN) allow_send\n", .{});
                    }

                    const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
                    const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = null } };
                    _ = ack.write(w) catch 0;

                    // Stream-level FC updates: emit only dirty streams to avoid full-map scans.
                    const fc_frames_sent = conn.appendDirtyMaxStreamDataFrames(w, 64);
                    if (fc_frames_sent > 0) {
                        logger.debugPrint("[P42-19-FC-SUMMARY] Sent {} MAX_STREAM_DATA frames in this ACK packet\n", .{fc_frames_sent});
                    }

                    if (conn.local_max_data > conn.last_sent_max_data) {
                        _ = (frame.Frame{ .max_data = .{ .max = conn.local_max_data } }).write(w) catch {};
                        conn.last_sent_max_data = conn.local_max_data;
                    }

                    if (conn.local_max_streams_bidi > conn.last_sent_max_streams_bidi) {
                        _ = (frame.Frame{ .max_streams_bidi = .{ .max = conn.local_max_streams_bidi } }).write(w) catch {};
                        conn.last_sent_max_streams_bidi = conn.local_max_streams_bidi;
                    }

                    // Append pending NEW_CONNECTION_ID frames
                    var any_pending = false;
                    {
                        var bi: usize = 0;
                        while (bi < conn.local_cids.len) : (bi += 1) {
                            if (conn.pending_new_cid.isSet(@intCast(bi))) {
                                any_pending = true;
                                break;
                            }
                        }
                    }
                    if (any_pending) {
                        _ = conn.writePendingNewConnectionIds(w, 2) catch 0;
                    }

                    const dcid_ack4 = if (conn.peer_initial_scid.len > 0)
                        conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                    else
                        &[_]u8{};

                    const packet_storage = conn.packet_pool.checkout();
                    defer conn.packet_pool.release(packet_storage);
                    const pkt_len = packet.encodeShortProtectedInto(
                        packet_storage,
                        dcid_ack4,
                        @as(u32, @truncate(conn.pn_app_tx)),
                        2,
                        frames_buf.items,
                        tx_keys,
                        conn.tx_key_phase,
                    ) catch 0;

                    if (pkt_len != 0) {
                        const pkt = packet_storage[0..pkt_len];
                        const send_start_ns = std.time.nanoTimestamp();
                        _ = ack_ctx.send_fn(ack_ctx.peer, pkt) catch {};
                        const send_end_ns = std.time.nanoTimestamp();
                        const send_duration_us = @as(u64, @intCast(@abs(send_end_ns - send_start_ns))) / 1000;
                        const total_delay_us = delay_since_rx_us + send_duration_us;

                        logger.debugPrint("[P42-21-ACK-SENT] ✅ Normal ACK sent: pkt_len={d}B largest={d} delay_rx_to_tx={d}us send_us={d}us total={d}us\n", .{
                            pkt.len,
                            ack_desc.largest,
                            delay_since_rx_us,
                            send_duration_us,
                            total_delay_us,
                        });
                        conn.onShortHeaderPacketSent(pkt.len, false);
                    }
                }
            } else {
                // RFC 9000 §8.1: Send ACK-only when under amplification limit
                logger.debugPrint("[P42-21-ACK-BLOCKED] ⚠️  ACK blocked by amplification limit\n", .{});
                var ack_only = std.ArrayList(u8){};
                defer ack_only.deinit(ack_ctx.allocator.*);
                const w2 = ack_only.writer(ack_ctx.allocator.*);
                const ack_desc2 = conn.buildAckApp();

                if (ack_ctx.test_capture_enabled) {
                    logger.debugPrint("APP ack-only branch\n", .{});
                    if (ack_ecn_common) |e2| {
                        logger.debugPrint("APP ACK_ECN ack-only ce={d} ect0={d} ect1={d}\n", .{ e2.ce, e2.ect0, e2.ect1 });
                    } else {
                        logger.debugPrint("APP ACK ack-only (no ECN)\n", .{});
                    }
                }

                const ack_delay2 = conn.getAckDelayEncoded(.Application, now_ns);
                const ack2 = frame.Frame{ .ack = .{ .largest = ack_desc2.largest, .ack_delay = ack_delay2, .first_range = ack_desc2.first_range, .ranges = ack_desc2.ranges, .ecn = ack_ecn_common } };
                _ = ack2.write(w2) catch 0;

                const dcid_ack5 = if (conn.peer_initial_scid.len > 0)
                    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                else
                    &[_]u8{};

                const packet_storage = conn.packet_pool.checkout();
                defer conn.packet_pool.release(packet_storage);
                const pkt_len = packet.encodeShortProtectedInto(
                    packet_storage,
                    dcid_ack5,
                    @as(u32, @truncate(conn.pn_app_tx)),
                    2,
                    ack_only.items,
                    tx_keys,
                    conn.tx_key_phase,
                ) catch 0;

                if (pkt_len != 0) {
                    const pkt = packet_storage[0..pkt_len];
                    _ = ack_ctx.send_fn(ack_ctx.peer, pkt) catch {};
                    // ACK-only is not ack-eliciting
                    conn.onShortHeaderPacketSent(pkt.len, false);
                }
            }
        }
    }
}

// =============================================================================
// Phase 4b.5 Session 3: Main processShortHeader() Coordinator
// =============================================================================

/// Process 1-RTT short header packet.
/// Extracted from endpoint.zig lines 1092-1671 (Phase 4b.5 Session 3).
///
/// This coordinator function integrates all extracted components:
/// 1. Connection lookup via peer address + DCID
/// 2. Decryption with DCID enumeration and key rotation
/// 3. Key promotion/demotion after successful decryption
/// 4. Packet number tracking
/// 5. Frame parsing and dispatch
/// 6. ACK generation and transmission
///
/// RFC 9000 §17.3: "Short header packets are used after the version and
/// 1-RTT keys are negotiated."
///
/// Parameters:
/// - ctx: RxContext with allocator, connections, config
/// - peer: Socket address of the peer
/// - bytes: Raw short header packet bytes
/// - ecn_bits: ECN bits from IP header (if available)
/// - send_fn: Function to send UDP datagrams
///
/// Returns: void (errors are logged but not propagated)
///
/// RFC 9000 §12: "QUIC packets are carried in UDP datagrams."
var g_app_decrypt_start: u64 = 0;
var g_app_decrypt_success: u64 = 0;
