const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const posix = std.posix;
const frame = @import("frame");
const lookup = @import("lookup");
const varint = @import("varint");
const shared = @import("shared.zig");
const incoming_b = @import("module_b.zig");
const incoming_b2 = @import("module_b2.zig");
const RxContext = shared.RxContext;
const SendFn = shared.SendFn;
const decryptShortHeaderWithKeyRotation = incoming_b.decryptShortHeaderWithKeyRotation;
const promoteToNextKeys = incoming_b.promoteToNextKeys;
const decrementPrevKeyAllowance = incoming_b.decrementPrevKeyAllowance;
const processFrames = incoming_b2.processFrames;
const generateAndSendAck = incoming_b2.generateAndSendAck;
const FrameProcessResult = incoming_b2.FrameProcessResult;
const AckContext = incoming_b2.AckContext;

pub const server_short_header_busy_conn_shedding_for_test = true;

var g_app_decrypt_start = std.atomic.Value(u64).init(0);
var g_app_decrypt_success = std.atomic.Value(u64).init(0);

fn shortHeaderDiagnosticsEnabled() bool {
    const raw = std.c.getenv("GEODE_QUIC_SHORT_HEADER_DIAGNOSTICS") orelse return false;
    const value = std.mem.span(raw);
    if (value.len == 0) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.ascii.eqlIgnoreCase(value, "false")) return false;
    if (std.ascii.eqlIgnoreCase(value, "no")) return false;
    if (std.ascii.eqlIgnoreCase(value, "off")) return false;
    return true;
}

fn peerPort(peer: conn_mod.SockAddr) u16 {
    return switch (peer.storage.family) {
        posix.AF.INET => blk: {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&peer.storage));
            break :blk std.mem.bigToNative(u16, sin.port);
        },
        posix.AF.INET6 => blk: {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&peer.storage));
            break :blk std.mem.bigToNative(u16, sin6.port);
        },
        else => 0,
    };
}

fn invalidSocket() posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) {
        return @ptrFromInt(~@as(usize, 0));
    } else {
        return -1;
    }
}

inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

inline fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

inline fn timingNsMonotonic() i128 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    if (rc != 0) return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

inline fn elapsedTimingNsSince(start_ns: i128) u64 {
    const end_ns = timingNsMonotonic();
    if (end_ns <= start_ns) return 0;
    return @intCast(end_ns - start_ns);
}

pub fn processShortHeader(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
    send_fn: SendFn,
) void {
    const lookup_result = lookup.findConnectionByDcid(
        ctx.conns,
        peer,
        bytes,
        null, // No path_changed_fn callback - NAT rebinding handled by caller
    );

    processShortHeaderResolved(ctx, peer, bytes, ecn_bits, send_fn, lookup_result);
}

// CANARY: REQ=REQ-QUIC-HC-112; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderFrameLockSplit; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
fn shortHeaderPayloadCanProcessWithoutRxSerial(payload: []const u8) bool {
    if (payload.len == 0) return false;

    var idx: usize = 0;
    while (idx < payload.len) {
        const decoded = frame.decodeOne(payload[idx..]) catch return false;
        if (decoded.n == 0) return false;

        switch (decoded.f) {
            .padding, .stream, .ack => {},
            else => return false,
        }

        idx += decoded.n;
    }

    return true;
}

// CANARY: REQ=REQ-QUIC-HC-049; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderLookupReuse; STATUS=TESTED; TEST=test_quic_short_header_reuses_endpoint_lookup; OWNER=transport; UPDATED=2026-05-26
pub fn processShortHeaderResolved(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
    send_fn: SendFn,
    lookup_result: lookup.LookupResult,
) void {
    // Phase 24 DEBUG: Unconditional logging to trace HANDSHAKE_DONE delivery
    logger.debugPrint("[processShortHeader] Called for {} bytes\n", .{bytes.len});

    // =============================================================================
    // STEP 1: Connection Lookup (RFC 9000 §5.2)
    // =============================================================================
    // The endpoint already performs this lookup to detect NAT rebinding. Reuse
    // that resolved result on the hot path so high-fanout application packets
    // do not pay for two DCID hash sweeps before decryption.

    const conn = lookup_result.conn orelse {
        // No connection found for this peer + DCID combination
        logger.debugPrint("[processShortHeader] No connection found for short header packet from peer\n", .{});
        if (shortHeaderDiagnosticsEnabled()) {
            std.debug.print(
                "short-header diag drop=lookup_miss peer_port={d} bytes={d} dcid_len={d}\n",
                .{ peerPort(peer), bytes.len, lookup_result.dcid_len },
            );
        }
        if (ctx.test_capture_enabled) {
            logger.debugPrint("No connection found for short header packet from peer\n", .{});
        }
        return;
    };

    const rx_serial_wait_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
    conn.endpoint_rx_serial_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    if (ctx.short_header_timing) |timing| {
        timing.rx_serial_wait_ns += elapsedTimingNsSince(rx_serial_wait_start_ns);
    }
    var rx_serial_locked = true;
    defer if (rx_serial_locked) conn.endpoint_rx_serial_mu.unlock(std.Io.Threaded.global_single_threaded.io());

    // RFC 9000 §10.2: Once a connection is closed, further packets MUST be
    // discarded. The connection will be removed from the tracking tables by
    // pruneClosed() at the end of the current poll() cycle.
    if (conn.closed) {
        logger.debugPrint("[processShortHeader] Dropping packet for closed connection\n", .{});
        if (shortHeaderDiagnosticsEnabled()) {
            std.debug.print(
                "short-header diag drop=closed peer_port={d} bytes={d} dcid_len={d}\n",
                .{ peerPort(peer), bytes.len, lookup_result.dcid_len },
            );
        }
        return;
    }

    logger.debugPrint("[processShortHeader] Found connection, role={s}, has_app_rx_keys={}\n", .{
        if (conn.role == .Server) "Server" else "Client",
        conn.app_rx_keys != null,
    });

    const dcid_len = lookup_result.dcid_len;

    if (ctx.test_capture_enabled) {
        logger.debugPrint("=== RECEIVED 1-RTT PACKET === size={}, dcid_len={}, has_app_rx={}, has_app_tx={}\n", .{
            bytes.len,
            dcid_len,
            conn.app_rx_keys != null,
            conn.app_tx_keys != null,
        });
    }

    // =============================================================================
    // STEP 2: ECN and Anti-Amplification Tracking (RFC 3168, RFC 9000 §8.1)
    // =============================================================================

    // Process ECN bits if provided (RFC 3168)
    if (ecn_bits) |e| conn.onEcnMark(.Application, e);

    // Track bytes received from unvalidated address for anti-amplification (RFC 9000 §8.1)
    conn.addRxUnvalidated(bytes.len);

    // Test-only debug: log short-header match and ECN bits/keys state
    if (ctx.test_capture_enabled) {
        const has_rx = (conn.app_rx_keys != null);
        const has_tx = (conn.app_tx_keys != null);
        const eb: u8 = if (ecn_bits) |e| (e & 0x03) else 0xff;
        logger.debugPrint("APP short: match dcid_len={d} rx_keys={s} tx_keys={s} ecn_bits=0x{x}\n", .{
            dcid_len,
            if (has_rx) "y" else "n",
            if (has_tx) "y" else "n",
            eb,
        });
    }

    // =============================================================================
    // STEP 3: DCID Length Caching and Key Check (Bug #6 fix)
    // =============================================================================

    const observed_dcid_len = dcid_len;
    const cached_dcid_len = conn.expected_rx_dcid_len;

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Will try decryption with observed_dcid_len={} cached_dcid_len={}\n", .{
            observed_dcid_len,
            if (cached_dcid_len) |c| c else 0xff,
        });
    }

    // Check if we have application-level RX keys
    if (conn.app_rx_keys == null) {
        logger.debugPrint("[APP-SHORT-NO-KEYS] dropping short header packet (pn tracking can't proceed)\n", .{});
        if (shortHeaderDiagnosticsEnabled()) {
            std.debug.print(
                "short-header diag drop=no_app_rx_keys peer_port={d} bytes={d} dcid_len={d} cached_dcid_len={d}\n",
                .{ peerPort(peer), bytes.len, lookup_result.dcid_len, conn.expected_rx_dcid_len orelse 0 },
            );
        }
        // No RX keys yet - handshake not complete
        if (ctx.test_capture_enabled) {
            logger.debugPrint("No app_rx_keys available, dropping packet\n", .{});
        }
        return;
    }

    // =============================================================================
    // STEP 4: Packet Decryption with Key Rotation (RFC 9001 §6)
    // =============================================================================

    if (ctx.test_capture_enabled) {
        logger.debugPrint("\n=== 1-RTT DECRYPT ATTEMPT ===\n", .{});
        logger.debugPrint("Packet first 32 bytes: ", .{});
        for (bytes[0..@min(32, bytes.len)]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nUsing RX keys (redacted)\n", .{});
    }

    // Use extracted decryption function with key rotation
    // Tries CURRENT → NEXT → PREV keys automatically
    // CANARY: REQ=REQ-QUIC-HC-116; FEATURE="High-Concurrency Requests"; ASPECT=ReleaseHotPathDiagnostics; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
    // Keep packet-level diagnostics off the ReleaseSafe receive path. The
    // logger call itself compiles away, but standalone scans and counters must
    // also sit behind the same compile-time guard.
    const debug_decrypt_attempt = if (comptime logger.enable_debug_prints)
        g_app_decrypt_start.fetchAdd(1, .monotonic) + 1
    else
        0;
    if (comptime logger.enable_debug_prints) {
        logger.debugPrint("[APP-DECRYPT-START] attempt={} dcid_len={} bytes={} cached={?}\n", .{ debug_decrypt_attempt, observed_dcid_len, bytes.len, conn.expected_rx_dcid_len });
    }
    const decrypt_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
    const decrypt_result = decryptShortHeaderWithKeyRotation(
        ctx.allocator.*,
        conn,
        bytes,
        @intCast(observed_dcid_len),
    ) catch |err| {
        if (shortHeaderDiagnosticsEnabled()) {
            std.debug.print(
                "short-header diag drop=decrypt err={s} peer_port={d} bytes={d} dcid_len={d} cached_dcid_len={d} largest_pn={d}\n",
                .{
                    @errorName(err),
                    peerPort(peer),
                    bytes.len,
                    observed_dcid_len,
                    conn.expected_rx_dcid_len orelse 0,
                    conn.pn_app.max,
                },
            );
        }
        if (err == error.StatelessReset) {
            if (ctx.test_capture_enabled) {
                logger.debugPrint("stateless-reset: closing connection\n", .{});
            }
            conn.markClosed();
        }
        return;
    };
    if (ctx.short_header_timing) |timing| {
        timing.decrypt_ns += elapsedTimingNsSince(decrypt_start_ns);
    }

    const dec_res = decrypt_result.decoded;
    const used_next = decrypt_result.used_next;
    const used_prev = decrypt_result.used_prev;
    if (comptime logger.enable_debug_prints) {
        const debug_decrypt_success = g_app_decrypt_success.fetchAdd(1, .monotonic) + 1;
        const debug_decrypt_total = g_app_decrypt_start.load(.monotonic);
        logger.debugPrint("[APP-DECRYPT-SUCCESS] attempt={} pn={} payload_len={} used_next={} used_prev={} rx_phase={} success_ratio={}/{}\n", .{ debug_decrypt_attempt, decrypt_result.decoded.packet_number, decrypt_result.decoded.payload.len, used_next, used_prev, conn.rx_key_phase, debug_decrypt_success, debug_decrypt_total });
        // Frame parsing diagnostics (actual processing occurs after packet-number tracking)
        logger.debugPrint("[APP-DISPATCH] Parsing 1-RTT frames payload_len={} pn={}\n", .{ dec_res.payload.len, dec_res.packet_number });
        if (dec_res.payload.len == 0) logger.debugPrint("[APP-DISPATCH] EMPTY-PAYLOAD pn={} suspect header protection/DCID length issue\n", .{dec_res.packet_number});
        // Fallback manual STREAM frame scan if decodeOne misses
        var scan_i: usize = 0;
        var stream_scan_hits: usize = 0;
        while (scan_i < dec_res.payload.len) : (scan_i += 1) {
            const b = dec_res.payload[scan_i];
            if ((b & 0xF8) == 0x08) { // STREAM frame type range
                stream_scan_hits += 1;
                logger.debugPrint("[APP-STREAM-SCAN] hit at offset={} type_byte=0x{X:0>2}\n", .{ scan_i, b });
                break; // only need first indication
            }
        }
        if (stream_scan_hits == 0 and dec_res.payload.len > 0) logger.debugPrint("[APP-STREAM-SCAN] no STREAM type bytes found in first {} bytes\n", .{dec_res.payload.len});
        // Hex dump first up to 64 bytes of decrypted payload for diagnostics
        const dump_len: usize = @min(dec_res.payload.len, 64);
        if (dump_len > 0) {
            logger.debugPrint("[APP-PAYLOAD-HEX] ", .{});
            var di: usize = 0;
            while (di < dump_len) : (di += 1) logger.debugPrint("{X:0>2} ", .{dec_res.payload[di]});
            logger.debugPrint("\n", .{});
        }
    }
    defer ctx.allocator.free(dec_res.payload);

    if (ctx.test_capture_enabled) {
        logger.debugPrint("✅ 1-RTT AEAD SUCCESS - payload_len={}, pn={}\n", .{
            dec_res.payload.len,
            dec_res.packet_number,
        });
    }

    // =============================================================================
    // STEP 5: NEXT Key Promotion (RFC 9001 §6.1)
    // =============================================================================

    // GAP-0200: Acquire conn.mu to protect PnWindow, ack_ranges_buf, key state,
    // and packet-number tracking from concurrent access by worker threads.
    // Released before processFrames() which calls pushStreamFrame() that acquires
    // conn.mu internally (Zig mutexes are non-recursive).
    //
    // CANARY: REQ=REQ-QUIC-HC-177; FEATURE="High-Concurrency Requests"; ASPECT=ServerShortHeaderBusyConnShedding; STATUS=IMPL; TEST=test_incoming_session3; OWNER=transport; UPDATED=2026-05-29
    //
    // On the server fan-in path, this mutex is also held by app writers sending
    // responses. Parking a poll worker here lets one busy connection monopolize
    // a UDP receive worker while thousands of unrelated request datagrams wait
    // in the socket FIFO. If the lock is busy, drop this packet before PN
    // tracking/ACK generation; the peer will retransmit because no ACK is sent.
    const pn_lock_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
    if (conn.role == .Server) {
        if (!conn.mu.tryLock()) {
            if (ctx.short_header_timing) |timing| {
                timing.conn_lock_wait_ns += elapsedTimingNsSince(pn_lock_start_ns);
            }
            if (shortHeaderDiagnosticsEnabled()) {
                std.debug.print(
                    "short-header diag drop=busy_conn peer_port={d} bytes={d} dcid_len={d} pn={d}\n",
                    .{ peerPort(peer), bytes.len, lookup_result.dcid_len, dec_res.packet_number },
                );
            }
            return;
        }
    } else {
        conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    }
    if (ctx.short_header_timing) |timing| {
        timing.conn_lock_wait_ns += elapsedTimingNsSince(pn_lock_start_ns);
    }

    // Handle key promotion if NEXT keys were used
    // RFC 9001 §6.1: "After receiving a packet encrypted with the next keys,
    // an endpoint MUST update to the next keys."
    if (used_next) {
        // PHASE 57 Part 5: Use pre-derived NEXT keys (already used for decryption)
        logger.debugPrint("[PHASE57-STEP5] 🔄 used_next=true, promoting pre-derived NEXT keys\n", .{});
        if (conn.app_rx_next_secret) |next_secret| {
            if (conn.app_rx_next_keys) |next_keys| {
                logger.debugPrint("[PHASE57-STEP5] Calling promoteToNextKeys()...\n", .{});
                promoteToNextKeys(conn, next_secret, next_keys);
                conn.syncTxKeysAfterRxUpdate();

                if (ctx.test_capture_enabled) {
                    logger.debugPrint("🔑 Promoted to NEXT keys after successful decryption\n", .{});
                }
            } else {
                logger.debugPrint("[PHASE57-STEP5] ⚠️ WARNING: used_next=true but no app_rx_next_keys!\n", .{});
            }
        } else {
            logger.debugPrint("[PHASE57-STEP5] ⚠️ WARNING: used_next=true but no app_rx_next_secret!\n", .{});
        }
    } else {
        logger.debugPrint("[PHASE57-STEP5] ✓ used_next=false, no key promotion needed\n", .{});
    }

    // =============================================================================
    // STEP 6: Packet Number Tracking (RFC 9000 §12.3)
    // =============================================================================

    // dec_res.packet_number is already expanded by decryptShortHeaderWithKeyRotation
    const pn_full: u64 = dec_res.packet_number;

    // PHASE 42 PART 20: Capture PN state BEFORE tracking for duplicate/gap detection
    const prev_largest_pn = conn.pn_app.max;
    const had_any_before = conn.pn_app.have_any;

    conn.trackRecvPnApp(pn_full);

    // PHASE 42 PART 20: Comprehensive packet number tracking debug logging
    // This helps identify duplicate PNs (AEAD failures) and packet loss (gaps)
    const is_duplicate = (pn_full <= prev_largest_pn and had_any_before);
    const has_gap = (pn_full > prev_largest_pn + 1 and had_any_before);
    const gap_size: i64 = if (has_gap) @as(i64, @intCast(pn_full)) - @as(i64, @intCast(prev_largest_pn)) - 1 else 0;

    if (is_duplicate) {
        logger.debugPrint("[P42-20-PN-DUP] ⚠️  DUPLICATE PN! pn={}, prev_largest={}, gap_from_largest={}\n", .{
            pn_full,
            prev_largest_pn,
            @as(i64, @intCast(prev_largest_pn)) - @as(i64, @intCast(pn_full)),
        });
    } else if (has_gap) {
        logger.debugPrint("[P42-20-PN-GAP] ⚠️  GAP DETECTED! pn={}, prev_largest={}, gap_size={} packets missing\n", .{
            pn_full,
            prev_largest_pn,
            gap_size,
        });
    } else {
        logger.debugPrint("[P42-20-PN-OK] ✓ Sequential PN received: pn={}, prev_largest={}\n", .{
            pn_full,
            prev_largest_pn,
        });
    }

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Tracked packet number: {}\n", .{pn_full});
    }

    // =============================================================================
    // STEP 7: PREV Key Cleanup (RFC 9001 §6.5)
    // =============================================================================

    // Handle previous key cleanup if they were used
    // RFC 9001 §6.5: "An endpoint MAY retain old keys for a short period
    // to allow it to decrypt packets that were delayed."
    if (used_prev) {
        decrementPrevKeyAllowance(conn);

        if (ctx.test_capture_enabled) {
            logger.debugPrint("🔓 Decremented PREV key allowance\n", .{});
        }
    }

    // =============================================================================
    // STEP 8: Frame Processing Integration (RFC 9000 §12.4)
    // =============================================================================

    const can_process_frames_without_rx_serial = shortHeaderPayloadCanProcessWithoutRxSerial(dec_res.payload);

    // GAP-0200: Release conn.mu before processFrames() because frame_handler
    // calls pushStreamFrame() which acquires conn.mu (non-recursive mutex).
    conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());

    // STREAM and ACK handlers already take the connection mutex around their
    // shared state. Releasing the endpoint RX serializer here lets poll workers
    // deliver application stream data for the same connection without queuing
    // behind ACK generation. Control frames stay serialized because several
    // handlers still mutate connection state directly.
    if (can_process_frames_without_rx_serial) {
        conn.endpoint_rx_serial_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        rx_serial_locked = false;
    }

    // Parse and process all frames from the decrypted payload
    const frame_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
    const frame_result = processFrames(
        ctx,
        conn,
        peer,
        dec_res.payload,
        send_fn,
    ) catch |err| {
        if (shortHeaderDiagnosticsEnabled()) {
            std.debug.print(
                "short-header diag drop=frame_process err={s} peer_port={d} payload={d} pn={d}\n",
                .{ @errorName(err), peerPort(peer), dec_res.payload.len, dec_res.packet_number },
            );
        }
        if (ctx.test_capture_enabled) {
            logger.debugPrint("Frame processing failed\n", .{});
        }
        return;
    };
    if (ctx.short_header_timing) |timing| {
        timing.frame_process_ns += elapsedTimingNsSince(frame_start_ns);
    }

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Frame processing result: saw_ack_eliciting={}, saw_handshake_done={}, saw_close={}\n", .{
            frame_result.saw_ack_eliciting,
            frame_result.saw_handshake_done,
            frame_result.saw_close,
        });
    }

    // GAP-0200: Re-acquire conn.mu for post-frame state mutations and ACK
    // generation (buildAckApp reads PnWindow / writes ack_ranges_buf).
    const post_lock_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
    conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    if (ctx.short_header_timing) |timing| {
        timing.conn_lock_wait_ns += elapsedTimingNsSince(post_lock_start_ns);
    }
    defer conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());

    // Handle HANDSHAKE_DONE frame (RFC 9000 §19.20)
    // Client: drop Handshake keys after HANDSHAKE_DONE (with conditions)
    if (frame_result.saw_handshake_done) {
        logger.debugPrint("[processShortHeader] CRITICAL: Setting handshake_done_seen=true for {s}\n", .{
            if (conn.role == .Server) "Server" else "Client",
        });
        conn.handshake_done_seen = true;

        // RFC 9001 §4.1.2: Only drop Handshake keys if safe to do so
        // Client (which receives HANDSHAKE_DONE): drop after first Handshake packet sent
        const can_drop_hs_keys = if (conn.role == .Client) conn.handshake_packet_sent else false;

        if (can_drop_hs_keys) {
            logger.debugPrint("[processShortHeader] {s}: Dropping Handshake keys after HANDSHAKE_DONE\n", .{
                if (conn.role == .Server) "Server" else "Client",
            });
            conn.hs_rx_keys = null;
            conn.hs_tx_keys = null;
            if (conn.crypto_retx_handshake) |buf| {
                conn.allocator.free(buf);
                conn.crypto_retx_handshake = null;
            }
            conn.crypto_retx_handshake_off = 0;
            conn.pto_handshake_active = false;
            conn.pto_handshake_id = 0;
            conn.pto_handshake_count = 0;

            if (ctx.test_capture_enabled) {
                logger.debugPrint("🤝 HANDSHAKE_DONE received, dropped Handshake keys\n", .{});
            }
        } else {
            logger.debugPrint("[processShortHeader] {s}: Deferring Handshake key drop (handshake_packet_sent={})\n", .{
                if (conn.role == .Server) "Server" else "Client",
                conn.handshake_packet_sent,
            });

            if (ctx.test_capture_enabled) {
                logger.debugPrint("🤝 HANDSHAKE_DONE received, deferring Handshake key drop\n", .{});
            }
        }
    }

    // Handle CONNECTION_CLOSE frame (RFC 9000 §10.2)
    if (frame_result.saw_close) {
        conn.markClosed();

        if (ctx.test_capture_enabled) {
            logger.debugPrint("❌ CONNECTION_CLOSE received, closing connection\n", .{});
        }
        return; // Stop processing further
    }

    // =============================================================================
    // STEP 9: ACK Generation (RFC 9000 §13.2)
    // =============================================================================

    // Record ack-eliciting frame receipt for ACK generation
    if (frame_result.saw_ack_eliciting) {
        const now_ns_ack: u64 = @intCast(blk: {
            var ts: std.os.linux.timespec = undefined;
            const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
            if (rc != 0) break :blk @as(i128, 0);
            break :blk @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
        });
        conn.recordAppAckElicitingRx(now_ns_ack);

        if (ctx.test_capture_enabled) {
            logger.debugPrint("📨 Recorded ack-eliciting frame receipt\n", .{});
        }
    }

    // RFC 9000 §13.2.1: ACK after at least two ack-eliciting packets, and
    // always within max_ack_delay. Server request/response traffic can defer
    // the first STREAM-only standalone ACK because writeStream() piggybacks
    // the pending ACK onto the response packet. ECN, control frames, clients,
    // and every second server STREAM packet still ACK immediately; a delayed
    // ACK timer covers upload-only users that do not produce a response.
    //
    // RFC 9000 §8.1: "A server MUST NOT send more than three times as many bytes
    // as the number of bytes it has received prior to validating the client address."
    if ((frame_result.saw_ack_eliciting or conn.ecn_app_ack_pending) and conn.app_tx_keys != null) {
        const ecn_present_or_pending = (ecn_bits != null) or conn.ecn_app_ack_pending;
        const send_immediate_ack = conn.shouldSendImmediateAppAck(
            frame_result.saw_stream,
            frame_result.saw_non_stream_ack_eliciting,
            ecn_present_or_pending,
        );
        if (!send_immediate_ack) {
            if (conn.app_ack_delay_timer_id == 0) {
                const delay_ms: u32 = @max(@as(u32, 1), @as(u32, conn.max_ack_delay_ms));
                conn.app_ack_delay_timer_id = ctx.schedule_timer_fn(conn, .AppAckDelay, delay_ms) catch 0;
            }
            return;
        }

        var ack_ctx = AckContext{
            .allocator = ctx.allocator,
            .conn = conn,
            .peer = peer,
            .send_fn = send_fn,
            .cfg = ctx.cfg,
            .test_capture_enabled = ctx.test_capture_enabled,
        };

        const ack_start_ns = if (ctx.short_header_timing != null) timingNsMonotonic() else 0;
        generateAndSendAck(&ack_ctx, frame_result, ecn_bits) catch {
            if (ctx.test_capture_enabled) {
                logger.debugPrint("Failed to generate/send ACK\n", .{});
            }
        };
        if (ctx.short_header_timing) |timing| {
            timing.ack_send_ns += elapsedTimingNsSince(ack_start_ns);
        }

        if (ctx.test_capture_enabled) {
            logger.debugPrint("📤 Sent ACK (ack_eliciting={}, ecn_pending={})\n", .{
                frame_result.saw_ack_eliciting,
                conn.ecn_app_ack_pending,
            });
        }
    }
}

/// Module marker for Phase 4b.5 Session 3 completion.
pub const session_3_complete = true;

/// Session 3 version for documentation
pub const session_3_version = "Phase 4b.5 Session 3 - Frame Processing and ACK Generation";

// =============================================================================
// Phase 4b.5 Session 5: Initial Packet Processing
// =============================================================================

/// Parsed Initial packet header information.
/// RFC 9000 §17.2.2: Initial Packet Format
pub const InitialHeaderInfo = struct {
    /// Destination Connection ID from packet header
    dcid: []const u8,
    /// Source Connection ID from packet header
    scid: []const u8,
    /// Token field (for address validation)
    token: []const u8,
    /// Packet number offset (protected, not yet decrypted)
    pn_offset: usize,
    /// Total length of packet from Length field
    packet_length: u64,
    /// Version field (already validated to be v1 or v2)
    version: u32,
};

/// Parse complete Initial packet header fields including Token and Length.
/// RFC 9000 §17.2.2: Initial Packet
///
/// This is a more complete version than parseInitialHeader(), which only extracts
/// DCID and SCID. This function additionally parses Token and Length fields.
///
/// Format:
/// ```
/// Initial Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2) = 0,
///   Reserved Bits (2),
///   Packet Number Length (2),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Token Length (i),
///   Token (..),
///   Length (i),
///   Packet Number (8..32),
///   Packet Payload (8..),
/// }
/// ```
///
/// Parameters:
/// - bytes: Raw packet bytes starting from first byte
/// - version: QUIC version from long header (already validated)
///
/// Returns:
/// - InitialHeaderInfo with parsed fields, or error if malformed
pub fn parseCompleteInitialHeader(bytes: []const u8, version: u32) !InitialHeaderInfo {
    // RFC 9000 §17.2.2: Initial packet structure
    //   byte 0: first byte (already validated as long header type 0)
    //   bytes 1-4: version (32-bit, already parsed)
    //   byte 5: DCID length
    //   bytes 6...: DCID, SCID, Token, Length, PN

    if (bytes.len < 6) return error.PacketTooShort;

    var i: usize = 5; // Start after version field (bytes 0-4)

    // Parse DCID length and value
    const dcid_len = bytes[i];
    i += 1;
    if (i + dcid_len > bytes.len) return error.InvalidDcidLength;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const scid_len = bytes[i];
    i += 1;
    if (i + scid_len > bytes.len) return error.InvalidScidLength;
    const scid = bytes[i .. i + scid_len];
    i += scid_len;

    // Parse Token Length (varint) and Token
    if (i >= bytes.len) return error.PacketTooShort;
    const token_len_result = varint.decode(bytes[i..]) catch return error.InvalidTokenLength;
    const token_len = token_len_result.value;
    i += token_len_result.n;

    if (i + token_len > bytes.len) return error.InvalidTokenLength;
    const token = bytes[i .. i + token_len];
    i += token_len;

    // Parse Length field (varint)
    if (i >= bytes.len) return error.PacketTooShort;
    const length_result = varint.decode(bytes[i..]) catch return error.InvalidLengthField;
    const packet_length = length_result.value;
    i += length_result.n;

    // Packet Number starts at current offset (still protected)
    const pn_offset = i;

    return InitialHeaderInfo{
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .pn_offset = pn_offset,
        .packet_length = packet_length,
        .version = version,
    };
}

/// Module marker for Phase 4b.5 Session 5 Initial packet parsing.
pub const session_5_initial_header_parsing = true;

/// Documentation skeleton for complete Initial packet processing (Sessions 5-6).
/// RFC 9000 §17.2.2: Initial Packet Processing
///
/// NOTE: This modular extraction is INCOMPLETE (Sessions 5-6 pending).
/// Production traffic uses the legacy path in incoming.zig.
/// Do not call processInitialSkeleton() -- it returns error.NotImplemented.
///
/// This skeleton documents the intended modular structure for Phase 4b.5
/// Sessions 5-6 extraction work.
///
/// Planned processing steps (RFC 9000 §7, §8.1):
/// 1. Parse Initial packet header (DCID, SCID, Token, Length) - DONE via parseCompleteInitialHeader()
/// 2. Validate token if present (RFC 9000 §8.1.4) - DONE via token.validateInitialToken()
/// 3. Decide whether to send Retry for address validation (RFC 9000 §8.1.2) - DONE via token.shouldSendRetry()
/// 4. Look up or create server connection - DONE via server.createServerConnection()
/// 5. Derive Initial keys from ODCID (RFC 9001 §5.2) - EXISTS as deriveInitialKeys()
/// 6. Decrypt Initial packet payload (PN + frames) - EXISTS as decryptInitialPacket()
/// 7. Process CRYPTO frame with TLS ClientHello - TBD Session 6
/// 8. Generate TLS ServerHello and Initial response - TBD Session 6
/// 9. Enqueue connection to accepted queue - DONE via server.pushAccepted()
///
/// Parameters (planned):
/// - allocator: Memory allocator
/// - bytes: Complete Initial packet bytes
/// - peer: Client socket address
/// - version: QUIC version
///
/// Returns:
/// - Success/failure status (specific return type TBD in Sessions 5-6)
pub fn processInitialSkeleton(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    peer: conn_mod.SockAddr,
    version: u32,
) !void {
    _ = allocator;
    _ = bytes;
    _ = peer;
    _ = version;

    // STEP 1: Parse Initial header (implemented)
    // const header = try parseCompleteInitialHeader(bytes, version);

    // STEP 2: Token validation (Session 5)
    // const token_valid = if (header.token.len > 0)
    //     token.validateInitialToken(header.token, peer, secret)
    // else
    //     false;

    // STEP 3: Retry decision (Session 5)
    // const should_retry = token.shouldSendRetry(
    //     header.token.len > 0,
    //     header.token,
    //     peer,
    //     secret,
    //     require_retry_policy
    // );
    // if (should_retry) {
    //     // Generate and send Retry packet
    //     const retry_token = try token.generateRetryToken(allocator, peer, header.dcid, secret, 120000);
    //     defer allocator.free(retry_token);
    //     // Send Retry packet via server.encodeRetryPacket()
    //     return;
    // }

    // STEP 4: Connection lookup/creation (Session 5)
    // const conn = try server.createServerConnection(allocator, sock_fd, peer, .{
    //     .version = version,
    //     .client_dcid = header.dcid,
    //     .client_scid = header.scid,
    //     ...
    // });

    // STEP 5: Key derivation (Session 6)
    // const initial_keys = deriveInitialKeys(conn, header.dcid, version);

    // STEP 6: Decrypt packet (Session 6)
    // const decrypted = try decryptInitialPacket(allocator, bytes, header.pn_offset, initial_keys, 0);

    // STEP 7: Process CRYPTO frame (Session 6)
    // Process TLS ClientHello via handshake_integration module

    // STEP 8: Generate response (Session 6)
    // Generate ServerHello, Handshake packets

    // STEP 9: Enqueue connection (Session 5)
    // server.pushAccepted(allocator, accepted_queue, conn);

    // NOTE: Full implementation will be completed in Sessions 5-6 extraction work
    return error.NotImplemented;
}

/// Module marker for Phase 4b.5 Session 5 processInitial skeleton.
pub const session_5_process_initial_skeleton = true;
