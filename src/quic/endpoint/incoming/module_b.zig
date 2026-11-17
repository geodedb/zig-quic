const std = @import("std");
const compat = @import("compat");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const posix = std.posix;
const key_schedule = @import("vendor_ztls_key_schedule");
const crypto = @import("crypto_quic");
const frame = @import("frame");
const frame_handler = @import("frame_handler");
const handshake_integration = @import("handshake_integration");
const lookup = @import("lookup");
const varint = @import("varint");
const shared = @import("shared.zig");
const key_update = @import("quic_key_update");
const incoming_a = @import("module_a.zig");
const enumerateDcidLength = incoming_a.enumerateDcidLength;
const RxContext = shared.RxContext;
const SendFn = shared.SendFn;

fn invalidSocket() posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) {
        return @ptrFromInt(~@as(usize, 0));
    } else {
        return -1;
    }
}

inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0); // fips-exempt: non-security — Wyhash connection-ID map key, not a FIPS algorithm.
    h.update(b);
    return h.final();
}

fn hashForSecret(secret: *const key_schedule.Secret) !key_schedule.Hash {
    return switch (secret.len) {
        32 => .sha256,
        48 => .sha384,
        else => error.InvalidSecretLength,
    };
}

inline fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

// CANARY: REQ=REQ-QUIC-HC-081; FEATURE="QUIC High-Concurrency Requests"; ASPECT=HandshakeSendAccounting; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
fn sendHandshakeDatagramFull(send_fn: SendFn, peer: conn_mod.SockAddr, data: []const u8, comptime label: []const u8) bool {
    const sent = send_fn(peer, data) catch |err| {
        logger.warn("{s} send failed: {s}", .{ label, @errorName(err) });
        return false;
    };
    if (sent != data.len) {
        logger.warn("{s} short send: sent={} expected={}", .{ label, sent, data.len });
        return false;
    }
    return true;
}

pub fn processHandshake(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    version: u32,
    ecn_bits: ?u8,
    send_fn: SendFn,
) void {
    _ = version; // Currently unused, but reserved for version negotiation

    // Parse Handshake header to extract DCID and SCID
    const header = parseHandshakeHeader(bytes) catch return;

    // Look up connection by peer hash + DCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(header.dcid) };

    logger.debugPrint("processHandshake: Looking up conn with peer_hash={X:0>16}, DCID len={}, DCID hash={X:0>16}\n", .{ ph, header.dcid.len, hashBytes(header.dcid) });

    var c_ptr = ctx.conns.getPtr(key);

    // Debug: Print all registered connections if lookup fails
    if (c_ptr == null) {
        logger.debugPrint("processHandshake: Connection not found. Registered connections:\n", .{});
        var iter = ctx.conns.iterator();
        while (iter.next()) |entry| {
            logger.debugPrint("  Key: peer_hash={X:0>16}, dcid_hash={X:0>16}, conn={*}\n", .{ entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash, entry.value_ptr.* });
        }
    }

    // Fallback: If lookup failed and DCID is empty, find connection by peer address alone
    // This handles the case where client sends empty DCID in Handshake packets
    if (c_ptr == null and header.dcid.len == 0) {
        var iter = ctx.conns.iterator();
        while (iter.next()) |entry| {
            if (entry.key_ptr.peer_hash == ph) {
                c_ptr = entry.value_ptr;
                break;
            }
        }
    }

    const conn = (if (c_ptr) |p| p.* else null) orelse {
        // No connection found - ignore packet
        logger.debugPrint("processHandshake: Connection not found for Handshake packet\n", .{});
        return;
    };

    processHandshakeResolvedWithHeader(ctx, peer, bytes, ecn_bits, send_fn, conn, header);
}

// CANARY: REQ=REQ-QUIC-HC-066; FEATURE="QUIC High-Concurrency Requests"; ASPECT=HandshakeLockSplit; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
pub fn processHandshakeResolved(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    version: u32,
    ecn_bits: ?u8,
    send_fn: SendFn,
    conn: *conn_mod.Connection,
) void {
    _ = version;
    const header = parseHandshakeHeader(bytes) catch return;
    processHandshakeResolvedWithHeader(ctx, peer, bytes, ecn_bits, send_fn, conn, header);
}

fn processHandshakeResolvedWithHeader(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
    send_fn: SendFn,
    conn: *conn_mod.Connection,
    header: HandshakeHeader,
) void {
    // GAP-0200: conn.mu is acquired in narrow scopes below around trackRecvPn*
    // and buildAck* calls only. Holding it for the entire function blocks worker
    // threads from writing to ANY stream on this connection for the duration of
    // handshake processing, causing stalls under multiplexed load.

    // Record ECN marking if present
    if (ecn_bits) |e| conn.*.onEcnMark(.Handshake, e);

    // Check if we have Handshake RX keys
    const rx_keys = conn.*.hs_rx_keys orelse {
        logger.debugPrint("processHandshake: No Handshake RX keys available for conn={*} role={s}\n", .{ conn, if (conn.*.role == .Client) "Client" else "Server" });
        return;
    };

    // Debug: Show packet info (never log key material)
    logger.debugPrint("processHandshake: Packet len={}, header offset={}, role={s}, conn_ptr={*}\n", .{ bytes.len, header.offset, if (conn.*.role == .Client) "Client" else "Server", conn });
    if (conn.*.hs_tx_keys != null) {
        logger.debugPrint("processHandshake: Handshake TX keys present\n", .{});
    }

    // Decrypt Handshake packet
    const decrypted = decryptHandshakePacket(
        ctx.allocator.*,
        bytes,
        header.offset,
        rx_keys,
        if (conn.*.pn_handshake.have_any) conn.*.pn_handshake.max else 0,
    ) catch |err| {
        logger.debugPrint("processHandshake: Decryption failed: {}\n", .{err});
        conn.*.onAeadAuthFailure();
        return;
    };
    defer ctx.allocator.free(decrypted.payload);

    // RFC 9001 §4.9.1:
    // - Server discards Initial keys after successfully processing first Handshake packet.
    // - Client discards Initial keys once Handshake sending starts (which follows here).
    // In practice, dropping here prevents stale Initial PTO probes during active Handshake.
    if (!conn.*.initial_keys_dropped) {
        conn.*.initial_keys_dropped = true;
        conn.*.initial_rx_keys = null;
        conn.*.initial_tx_keys = null;
        conn.*.discardSpaceRecovery(.Initial);
        conn.*.pto_initial_active = false;
        conn.*.pto_initial_id = 0;
        conn.*.pto_initial_count = 0;
        logger.debugPrint("processHandshake: Dropped Initial keys for conn={*} role={s}\n", .{
            conn,
            if (conn.*.role == .Client) "Client" else "Server",
        });
    }

    // Set connection context for TLS Context callbacks (Phase 21.2)
    handshake_integration.setCurrentConnection(if (@TypeOf(conn) == **conn_mod.Connection) conn.* else conn);
    defer handshake_integration.clearCurrentConnection();

    // Update packet number tracking (under conn.mu to prevent PnWindow race)
    conn.*.lockForEndpoint();
    conn.*.trackRecvPnHandshake(decrypted.packet_number);
    conn.*.mu.unlock(std.Io.Threaded.global_single_threaded.io());

    // RFC 9000 §8.1: Successfully authenticating a packet at the Handshake level
    // proves the client received the server's Initial (which provided handshake keys).
    // This validates the client's address for anti-amplification purposes.
    if (conn.*.role == .Server and !conn.*.address_validated) {
        logger.debugPrint("processHandshake: Validating client address after Handshake packet\n", .{});
        conn.*.address_validated = true;
        conn.*.bytes_rx_unvalidated = 0;
        conn.*.bytes_tx_unvalidated = 0;
    }

    // Process frames from decrypted payload
    var offset: usize = 0;
    var saw_crypto: bool = false;
    var saw_ack_eliciting: bool = false;
    const now_ns: u64 = @intCast(compat.nanoTimestamp());

    while (offset < decrypted.payload.len) {
        var fr = frame.decodeOne(decrypted.payload[offset..]) catch |err| {
            logger.debugPrint("processHandshake: Frame decode error at offset {}: {}\n", .{ offset, err });
            break;
        };
        // ACK ranges into this copy, not decodeOne's dead stack frame (SONNY-6673).
        fr.anchor();
        offset += fr.n;

        switch (fr.f) {
            .crypto => |cr| {
                // CRYPTO is ack-eliciting even when it carries duplicate bytes.
                saw_ack_eliciting = true;
                saw_crypto = true;

                // Process CRYPTO frame to advance TLS handshake
                logger.debugPrint("{s}: Received Handshake CRYPTO frame with {} bytes at offset {} (expected {})\n", .{
                    if (conn.*.role == .Server) "Server" else "Client",
                    cr.data.len,
                    cr.offset,
                    conn.*.crypto_rx_off_handshake,
                });

                const ack_needed = conn.*.handleHandshakeCrypto(
                    ctx.allocator,
                    cr.offset,
                    cr.data,
                ) catch |err| blk: {
                    conn.last_handshake_error = err;
                    logger.debugPrint("processHandshake: Failed to process CRYPTO: {}\n", .{err});
                    break :blk false;
                };

                if (conn.role == .Client and conn.pending_hs_send) {
                    if (ctx.mark_pending_hs_send_fn) |mark_pending| mark_pending(conn);
                }

                if (ack_needed) {
                    // Check if app keys are now ready (handshake complete)
                    if (conn.*.app_rx_keys != null and conn.*.app_tx_keys != null) {
                        logger.debugPrint("processHandshake: App keys ready - handshake complete\n", .{});
                        // Endpoint will handle closeStaleConnectionsForPeer via callback
                    }
                }
            },
            .ack => |a| {
                // Process ACK frame for PTO cancellation
                conn.*.onAckReceivedSpace(.Handshake, a.largest, a.first_range, a.ranges, a.ecn);

                // Cancel Handshake PTO timer
                conn.*.pto_handshake_count = 0;
                // Note: Actual timer cancellation requires endpoint access - handled by caller
            },
            .padding => {},
            .ping => {
                // PING frames are allowed in Handshake packets (RFC 9000 §19.2)
                // They're used for keepalive and connection validation
                saw_ack_eliciting = true;
                saw_crypto = true;
            },
            else => {
                // Other frames are unexpected in Handshake packets
                logger.debugPrint("processHandshake: Unexpected frame type in Handshake packet: {}\n", .{fr.f});
            },
        }
    }

    // Record ack-eliciting reception for ACK generation
    if (saw_ack_eliciting) {
        conn.*.recordAckElicitingRx(.Handshake, now_ns);
    }

    // Send pending Handshake CRYPTO data (e.g., server Finished, client Finished)
    if (conn.*.hs_tx_keys) |tx_keys| {
        // Poll TLS Context for Handshake-level CRYPTO data
        var crypto_data: ?[]const u8 = null;
        var owns_data = false;

        const tls_ctx = conn.tls_context orelse return; // No TLS Context, skip processing
        const hs_data = blk: {
            conn.tls_context_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer conn.tls_context_mu.unlock(std.Io.Threaded.global_single_threaded.io());

            // Set connection context for callbacks.
            handshake_integration.setCurrentConnection(conn);
            defer handshake_integration.clearCurrentConnection();

            // Poll for Handshake-level CRYPTO data.
            break :blk tls_ctx.pollCrypto(ctx.allocator.*, .Handshake) catch |err| err_blk: {
                // Unimplemented means no data available (expected).
                if (err != error.Unimplemented) {
                    logger.debugPrint("processHandshake: Context pollCrypto error: {}\n", .{err});
                }
                break :err_blk null;
            };
        };
        if (hs_data) |data| {
            crypto_data = data;
            owns_data = true;
        }

        if (crypto_data) |data| {
            defer if (owns_data) ctx.allocator.free(data);
            const n = data.len;
            // Fragment CRYPTO data across multiple packets if needed
            const max_crypto_per_packet: usize = 1100;
            var crypto_offset: usize = 0;
            const base_off = conn.*.crypto_tx_off_handshake;

            if (conn.*.crypto_retx_handshake) |old_buf| ctx.allocator.free(old_buf);
            const owned = ctx.allocator.alloc(u8, n) catch return;
            @memcpy(owned[0..n], data[0..n]);
            conn.*.crypto_retx_handshake = owned;
            conn.*.crypto_retx_handshake_off = base_off;

            while (crypto_offset < n) {
                const chunk_size = @min(max_crypto_per_packet, n - crypto_offset);
                const chunk = data[crypto_offset .. crypto_offset + chunk_size];

                var frames_buf: std.ArrayList(u8) = .empty;
                defer frames_buf.deinit(ctx.allocator.*);
                const w = @import("compat").arrayListWriter(&frames_buf, ctx.allocator.*);

                // Add CRYPTO frame
                const crypto_frame_offset = base_off + crypto_offset;
                _ = (frame.Frame{ .crypto = .{ .offset = crypto_frame_offset, .data = chunk } }).write(w) catch 0;

                // Use peer's SCID as DCID
                const hs_dcid = conn.*.peer_initial_scid.bytes[0..conn.*.peer_initial_scid.len];

                // Encode and send Handshake packet
                const pkt = packet.encodeHandshakeProtected(
                    ctx.allocator.*,
                    0x00000001, // QUIC v1
                    hs_dcid,
                    conn.*.our_scid.bytes[0..conn.*.our_scid.len],
                    @as(u32, @truncate(conn.*.pn_handshake_tx)),
                    2,
                    frames_buf.items,
                    tx_keys,
                ) catch null;

                if (pkt) |bytes_out| {
                    defer ctx.allocator.free(bytes_out);
                    if (!sendHandshakeDatagramFull(send_fn, peer, bytes_out, "Handshake CRYPTO")) return;
                    conn.*.onPacketSent(.Handshake, conn.*.pn_handshake_tx, bytes_out.len, true);
                    conn.*.pn_handshake_tx +%= 1;
                } else {
                    return;
                }

                crypto_offset += chunk_size;
            }

            conn.*.crypto_tx_off_handshake += n;

            // Attempt delayed 1-RTT key derivation after flushing TLS outbox
            conn.*.maybeDeriveAppKeysAfterFlush();
        }
    }

    // Send ACK for received Handshake packet
    if (saw_crypto) {
        if (conn.*.hs_tx_keys) |tx_keys| {
            var frames_buf: std.ArrayList(u8) = .empty;
            defer frames_buf.deinit(ctx.allocator.*);
            const w = @import("compat").arrayListWriter(&frames_buf, ctx.allocator.*);

            // GAP-0200: Lock conn.mu for ACK generation (reads PnWindow, writes ack_ranges_buf)
            conn.*.lockForEndpoint();
            const ack_desc = conn.*.buildAckHandshake();
            const ack_ecn = conn.*.getAckEcn(.Handshake);
            const ack_delay = conn.*.getAckDelayEncoded(.Handshake, now_ns);
            conn.*.mu.unlock(std.Io.Threaded.global_single_threaded.io());

            if (ack_desc.largest != 0xFFFFFFFFFFFFFFFF) {
                const ack_frame = frame.Frame{ .ack = .{
                    .largest = ack_desc.largest,
                    .ack_delay = ack_delay,
                    .first_range = ack_desc.first_range,
                    .ranges = ack_desc.ranges,
                    .ecn = ack_ecn,
                } };
                _ = ack_frame.write(w) catch 0;
            }

            // Use peer's SCID as DCID
            const hs_dcid = conn.*.peer_initial_scid.bytes[0..conn.*.peer_initial_scid.len];

            // Encode and send ACK packet
            const pkt = packet.encodeHandshakeProtected(
                ctx.allocator.*,
                0x00000001, // QUIC v1
                hs_dcid,
                conn.*.our_scid.bytes[0..conn.*.our_scid.len],
                @as(u32, @truncate(conn.*.pn_handshake_tx)),
                2,
                frames_buf.items,
                tx_keys,
            ) catch null;

            if (pkt) |bytes_out| {
                defer ctx.allocator.free(bytes_out);
                if (sendHandshakeDatagramFull(send_fn, peer, bytes_out, "Handshake ACK")) {
                    // ACK-only packet is not ack-eliciting
                    conn.*.pn_handshake_tx +%= 1;
                }
            }
        }
    }

    // RFC 9001 §4.9.3: Server MUST discard Handshake keys once HANDSHAKE_DONE is sent.
    // We do this after sending the Handshake ACK above so the client gets acknowledged.
    if (conn.*.role == .Server and conn.*.handshake_done_sent) {
        if (conn.*.hs_rx_keys != null or conn.*.hs_tx_keys != null or conn.*.crypto_retx_handshake != null or conn.*.pto_handshake_active) {
            conn.*.hs_rx_keys = null;
            conn.*.hs_tx_keys = null;
            conn.*.discardSpaceRecovery(.Handshake);
            if (conn.*.crypto_retx_handshake) |buf| {
                ctx.allocator.free(buf);
                conn.*.crypto_retx_handshake = null;
            }
            conn.*.crypto_retx_handshake_off = 0;
            conn.*.pto_handshake_active = false;
            conn.*.pto_handshake_id = 0;
            conn.*.pto_handshake_count = 0;
        }
    }

    // Loss/corruption interop resilience: if the server keeps receiving Handshake
    // traffic after 1-RTT keys are ready, resend HANDSHAKE_DONE in 1-RTT so the
    // client can complete confirmation when the original frame was lost/corrupted.
    if (conn.*.role == .Server and conn.*.peer_finished_verified and conn.*.app_tx_keys != null) {
        var done_frames: std.ArrayList(u8) = .empty;
        defer done_frames.deinit(ctx.allocator.*);
        const dw = @import("compat").arrayListWriter(&done_frames, ctx.allocator.*);
        _ = (frame.Frame{ .handshake_done = {} }).write(dw) catch 0;
        // A 1-RTT packet, sent while the application may already be sending
        // on this connection: under Connection.mu (SONNY-4379).
        conn.*.lockForEndpoint();
        defer conn.*.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        conn.*.sendControlFrames(done_frames.items);
    }
}

pub const HandshakeHeader = struct { dcid: []const u8, scid: []const u8, offset: usize };

/// Parse Handshake packet header.
/// Returns structure with DCID, SCID, and offset to payload+PN.
pub fn parseHandshakeHeader(bytes: []const u8) !HandshakeHeader {
    if (bytes.len < 5) return error.PacketTooShort;

    const first = bytes[0];
    const is_long = (first & 0x80) != 0;
    if (!is_long) return error.NotLongHeader;

    const pkt_type = (first & 0x30) >> 4;
    if (pkt_type != 2) return error.NotHandshakePacket; // Handshake = 2

    var i: usize = 5; // Skip first byte + 4-byte version

    // Parse DCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const dcid_len = bytes[i];
    i += 1;
    if (i + dcid_len > bytes.len) return error.PacketTooShort;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const scid_len = bytes[i];
    i += 1;
    if (i + scid_len > bytes.len) return error.PacketTooShort;
    const scid = bytes[i .. i + scid_len];
    i += scid_len;

    // Return offset pointing to length field (before PN + payload)
    return .{ .dcid = dcid, .scid = scid, .offset = i };
}

/// Decrypt Handshake packet using Handshake protection keys.
/// Similar to decryptInitialPacket but uses Handshake keys.
fn decryptHandshakePacket(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    length_offset: usize,
    rx_keys: packet.InitialKeys,
    largest_pn: u64,
) !struct { payload: []u8, packet_number: u64 } {
    var i = length_offset;
    const len_dec = varint.decode(bytes[i..]) catch return error.InvalidLength;
    i += len_dec.n;

    const end_total = i + @as(usize, @intCast(len_dec.value));
    if (end_total > bytes.len) return error.PacketTooShort;

    const first = bytes[0];
    const header_prefix = bytes[1..i];
    const full_pn_and_payload = bytes[i..end_total];

    // Minimum long-header protected body: 1-byte PN + 16-byte AEAD tag.
    if (full_pn_and_payload.len < 17) return error.PayloadTooShort;

    // Handshake packets use the same protection mechanics as Initial packets
    // (different keys, same header-protection + AEAD workflow).
    var pn_len_try: u3 = 1;
    while (pn_len_try <= 4) : (pn_len_try += 1) {
        if (@as(usize, pn_len_try) > full_pn_and_payload.len) break;

        const payload_cap = full_pn_and_payload.len - 16;
        const payload_buf = try allocator.alloc(u8, payload_cap);
        errdefer allocator.free(payload_buf);

        var header_first = first;
        var pn_masked: [4]u8 = [_]u8{0} ** 4;
        const avail = @min(@as(usize, 4), full_pn_and_payload.len);
        @memcpy(pn_masked[0..avail], full_pn_and_payload[0..avail]);

        const dec = crypto.unprotectInitialAutoSample(
            .aes_128_gcm,
            &rx_keys.key,
            &rx_keys.iv,
            &rx_keys.hp,
            &header_first,
            &pn_masked,
            header_prefix,
            full_pn_and_payload,
            payload_buf,
            largest_pn,
        ) catch {
            allocator.free(payload_buf);
            continue;
        };

        if (dec.payload_len > payload_buf.len) {
            allocator.free(payload_buf);
            return error.InvalidPacket;
        }
        const exact_payload = try allocator.alloc(u8, dec.payload_len);
        @memcpy(exact_payload, payload_buf[0..dec.payload_len]);
        allocator.free(payload_buf);

        return .{
            .payload = exact_payload,
            .packet_number = dec.packet_number,
        };
    }

    return error.AeadDecryptFailed;
}

// =============================================================================
// Phase 4b.5 Session 3: RX Short Header (1-RTT) Processing
// =============================================================================

/// Result of short header decryption with key rotation.
pub const ShortDecryptResult = struct {
    /// Decrypted payload and packet number
    decoded: packet.DecodedShort,
    /// Whether NEXT keys were used (requires key promotion)
    used_next: bool,
    /// Whether previous keys were used (requires allowance decrement)
    used_prev: bool,
    /// Actual DCID length discovered (may differ from input)
    dcid_len: u8,
};

/// Decrypt a 1-RTT (short header) packet: remove header protection once,
/// then open the packet with the one key set its key phase selects.
///
/// RFC 9000 §17.3.1: a short header does not carry the DCID length; the
/// receiver knows it, because the DCID is a connection ID it issued. The
/// lookup that found `conn` matched it, so `dcid_len` is authoritative.
///
/// RFC 9001 §6: "The header protection keys are not updated", so removing
/// header protection with the current HP key yields the real key phase bit
/// whatever key generation protects the packet. Key selection (§6.3, §6.5):
/// - key phase equal to the current receive phase: the current keys;
/// - otherwise, a packet number below the first one decrypted with the
///   current keys: the previous keys, while they are retained;
/// - otherwise: the next keys, pre-derived so that a key update costs no
///   more than any other packet (§6.3, §9.5).
///
/// One header protection removal and at most one AEAD open per packet, so
/// an off-path sender of undecryptable packets causes no more work than a
/// peer does. Each failed open counts toward the integrity limit (§6.6).
///
/// Returns:
/// - ShortDecryptResult with the decoded payload and which keys opened it
/// - error.AuthenticationFailed if the selected keys do not open the packet
/// - error.StatelessReset if the packet matches a stateless reset token
pub fn decryptShortHeaderWithKeyRotation(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    dcid_len: u8,
) !ShortDecryptResult {
    const rx_keys = conn.app_rx_keys orelse return error.NoApplicationKeys;

    // RFC 9000 Appendix A.3: Pass largest received PN for expansion
    const largest_pn: u64 = if (conn.pn_app.have_any) conn.pn_app.max else 0;

    // Ensure NEXT keys are always pre-derived so we can decode peer-initiated key updates
    if (conn.app_rx_next_keys == null and conn.app_rx_secret != null) {
        const cur_secret = conn.app_rx_secret.?;
        const hash = hashForSecret(&cur_secret) catch return error.InvalidSecretLength;
        const next_secret = try key_update.deriveNextTrafficSecret(hash, &cur_secret);
        const next_mat = key_schedule.deriveKeyIvHpHash(hash, &next_secret, conn.version_v2);
        conn.app_rx_next_secret = next_secret;
        conn.app_rx_next_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = next_mat.hp };
    }

    if (conn.looksLikeStatelessReset(bytes)) {
        return error.StatelessReset;
    }

    // RFC 9001 §6.5: old read keys are retained for no more than three PTOs
    // after the first packet opened with the new keys.
    if (conn.rx_prev_keys != null and nowMonotonicNs() >= conn.rx_prev_discard_ns) discardPrevRxKeys(conn);

    _ = conn.rx_short_decrypt_attempts.fetchAdd(1, .monotonic);
    const hp = rx_keys.hp;
    const peek = packet.peekShortHeader(bytes, dcid_len, hp, largest_pn) catch {
        conn.onAeadAuthFailure();
        return error.AuthenticationFailed;
    };

    const KeySet = enum { current, next, prev };
    const key_set: KeySet = if (peek.key_phase == conn.rx_key_phase)
        .current
    else if (peek.packet_number < conn.rx_key_gen_start_pn)
        .prev
    else
        .next;
    const keys: packet.AeadKeys = switch (key_set) {
        .current => rx_keys,
        .next => conn.app_rx_next_keys orelse {
            conn.onAeadAuthFailure();
            return error.AuthenticationFailed;
        },
        // RFC 9001 §6.5: once the previous keys are discarded (three PTOs
        // after the key update), packets protected with them are discarded
        // too.
        .prev => conn.rx_prev_keys orelse {
            conn.onAeadAuthFailure();
            return error.AuthenticationFailed;
        },
    };

    var decode_scratch: [4096]u8 = undefined;
    packet.phase57SetAttemptLabel(@tagName(key_set));
    const view = packet.decodeShortProtectedWithHpInto(bytes, dcid_len, hp, keys, largest_pn, decode_scratch[0..]) catch {
        conn.onAeadAuthFailure();
        return error.AuthenticationFailed;
    };
    if (view.payload.len > 0) {
        _ = frame.decodeOne(view.payload) catch return error.InvalidFrame;
    }
    const owned_payload = try allocator.alloc(u8, view.payload.len);
    @memcpy(owned_payload, view.payload);

    // Cache the DCID length for diagnostics (DCIDs may change post-handshake)
    conn.expected_rx_dcid_len = dcid_len;

    logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with {s} keys: pn={} key_phase={} conn_rx_kp={}\n", .{
        @tagName(key_set),
        view.packet_number,
        view.key_phase,
        conn.rx_key_phase,
    });

    return ShortDecryptResult{
        .decoded = .{
            .packet_number = view.packet_number,
            .packet_number_len = view.packet_number_len,
            .payload = owned_payload,
            .key_phase = view.key_phase,
        },
        .used_next = key_set == .next,
        .used_prev = key_set == .prev,
        .dcid_len = dcid_len,
    };
}

/// Promote connection to NEXT application keys after successful decryption.
/// Extracted from endpoint.zig lines 1289-1302 (Phase 4b.5 Session 3).
///
/// RFC 9001 §6: "Endpoints can use multiple packets to send data and can update
/// keys to improve forward secrecy and confidentiality."
///
/// When a packet is successfully decrypted with derived NEXT keys:
/// 1. Preserve current keys as previous (zeroize any older prev first)
/// 2. Install NEXT keys as current app_rx_keys
/// 3. Update app_rx_secret to NEXT secret
/// 4. Toggle rx_key_phase bit
/// 5. Retain the previous keys for three PTOs (RFC 9001 §6.5)
///
/// Parameters:
/// - conn: Connection to promote keys on
/// - next_secret: NEXT RX traffic secret
/// - next_keys: NEXT RX AEAD keys (key, iv, hp)
/// - first_pn: packet number of the packet that the NEXT keys opened, the
///   first of the new generation (RFC 9001 §6.3)
pub fn promoteToNextKeys(
    conn: *conn_mod.Connection,
    next_secret: key_schedule.Secret,
    next_keys: packet.AeadKeys,
    first_pn: u64,
) void {
    // PHASE 57: Log key promotion
    const old_key_phase = conn.rx_key_phase;
    const new_key_phase = !old_key_phase;
    logger.debugPrint("[PHASE57-KEY-PROMOTE] 🔑 Promoting to NEXT RX keys: rx_key_phase {} → {}\n", .{
        old_key_phase,
        new_key_phase,
    });

    // PHASE 57 Part 5: Re-derive NEXT keys from the current NEXT secret BEFORE promotion
    // This maintains the one-generation-ahead invariant (quic-go updatable_aead.go:120-123)
    // Derive NEXT from the NEXT secret (the one we're about to promote)
    const hash = hashForSecret(&next_secret) catch return;
    const new_next_secret = key_update.deriveNextTrafficSecret(hash, &next_secret) catch return;
    const new_next_mat = key_schedule.deriveKeyIvHpHash(hash, &new_next_secret, conn.version_v2);
    logger.debugPrint("[PHASE57-KEY-PROMOTE] 🔄 Pre-derived new NEXT keys before promotion\n", .{});

    // Preserve current keys as previous (zeroize any older prev first)
    if (conn.rx_prev_keys) |*old_prev| {
        // fips-exempt: non-security — key-material zeroization, not a FIPS algorithm.
        const sz = std.crypto.secureZero;
        sz(u8, &old_prev.key);
        sz(u8, &old_prev.iv);
        sz(u8, &old_prev.hp);
    }
    conn.rx_prev_keys = conn.app_rx_keys;
    // RFC 9001 §6.5: retain the old read keys "for no more than three times
    // the PTO after having received a packet protected using the new keys",
    // so that packets reordered across the update can still be opened.
    const pto_ns = conn.rec.rtt.computePtoNsWithBackoff(0, conn.rec.timer_granularity_ns);
    conn.rx_prev_discard_ns = nowMonotonicNs() +| (pto_ns *| 3);

    // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
    // Evidence: quic-go's rollKeys() only updates rcvAEAD/sendAEAD, NOT headerDecrypter/headerEncrypter
    const preserved_hp = conn.app_rx_keys.?.hp;

    // Install NEXT keys/secret as current (AEAD only, HP preserved)
    conn.app_rx_keys = .{ .key = next_keys.key, .iv = next_keys.iv, .hp = preserved_hp };
    conn.app_rx_secret = next_secret;
    conn.maybeEmitRxKeyUpdateLog(&next_secret);
    conn.rx_key_phase = !conn.rx_key_phase;
    conn.rx_key_gen += 1;
    conn.rx_key_gen_start_pn = first_pn;

    logger.debugPrint("[PHASE57-HP-PRESERVE] HP key preserved during promotion (not rotated per RFC 9001 §6)\n", .{});

    // Install the pre-derived NEXT keys/secret
    conn.app_rx_next_secret = new_next_secret;
    conn.app_rx_next_keys = .{ .key = new_next_mat.key, .iv = new_next_mat.iv, .hp = new_next_mat.hp };

    logger.debugPrint("[PHASE57-KEY-PROMOTE] ✅ Key promotion complete - ready for next packet\n", .{});
}

fn nowMonotonicNs() u64 {
    const t = compat.monotonicNanoTimestamp();
    return if (t > 0) @intCast(t) else 0;
}

/// Zeroize and drop the previous receive keys (RFC 9001 §6.5).
pub fn discardPrevRxKeys(conn: *conn_mod.Connection) void {
    if (conn.rx_prev_keys) |*to_zero| {
        // fips-exempt: non-security — key-material zeroization, not a FIPS algorithm.
        const sz = std.crypto.secureZero;
        sz(u8, &to_zero.key);
        sz(u8, &to_zero.iv);
        sz(u8, &to_zero.hp);
    }
    conn.rx_prev_keys = null;
}
