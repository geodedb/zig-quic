const std = @import("std");
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
const incoming_a = @import("module_a.zig");
const enumerateDcidLength = incoming_a.enumerateDcidLength;
const RxContext = shared.RxContext;
const SendFn = shared.SendFn;

fn addDcidCandidate(len: u8, list: []u8, count: *usize, max_len: u8) void {
    if (len > max_len) return;
    var idx: usize = 0;
    while (idx < count.*) : (idx += 1) {
        if (list[idx] == len) return;
    }
    list[count.*] = len;
    count.* += 1;
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

    // Update packet number tracking
    conn.*.trackRecvPnHandshake(decrypted.packet_number);

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
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    while (offset < decrypted.payload.len) {
        const fr = frame.decodeOne(decrypted.payload[offset..]) catch |err| {
            logger.debugPrint("processHandshake: Frame decode error at offset {}: {}\n", .{ offset, err });
            break;
        };
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
                    logger.debugPrint("processHandshake: Failed to process CRYPTO: {}\n", .{err});
                    break :blk false;
                };

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

        // Set connection context for callbacks
        handshake_integration.setCurrentConnection(conn);
        defer handshake_integration.clearCurrentConnection();

        // Poll for Handshake-level CRYPTO data
        const tls_ctx = conn.tls_context orelse return; // No TLS Context, skip processing
        const hs_data = tls_ctx.pollCrypto(ctx.allocator.*, .Handshake) catch |err| blk: {
            // Unimplemented means no data available (expected)
            if (err != error.Unimplemented) {
                logger.debugPrint("processHandshake: Context pollCrypto error: {}\n", .{err});
            }
            break :blk null;
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

            while (crypto_offset < n) {
                const chunk_size = @min(max_crypto_per_packet, n - crypto_offset);
                const chunk = data[crypto_offset .. crypto_offset + chunk_size];

                var frames_buf = std.ArrayList(u8){};
                defer frames_buf.deinit(ctx.allocator.*);
                const w = frames_buf.writer(ctx.allocator.*);

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
                    _ = send_fn(peer, bytes_out) catch |err| {
                        logger.warn("Handshake CRYPTO send failed: {s}", .{@errorName(err)});
                    };
                    conn.*.onPacketSent(.Handshake, conn.*.pn_handshake_tx, bytes_out.len, true);
                    conn.*.pn_handshake_tx +%= 1;
                }

                crypto_offset += chunk_size;
            }

            // Save retransmit buffer
            if (conn.*.crypto_retx_handshake) |old_buf| ctx.allocator.free(old_buf);
            const owned = ctx.allocator.alloc(u8, n) catch {
                conn.*.crypto_tx_off_handshake += n;
                return;
            };
            @memcpy(owned[0..n], data[0..n]);
            conn.*.crypto_retx_handshake = owned;
            conn.*.crypto_retx_handshake_off = base_off;
            conn.*.crypto_tx_off_handshake += n;

            // Attempt delayed 1-RTT key derivation after flushing TLS outbox
            conn.*.maybeDeriveAppKeysAfterFlush();
        }
    }

    // Send ACK for received Handshake packet
    if (saw_crypto) {
        if (conn.*.hs_tx_keys) |tx_keys| {
            var frames_buf = std.ArrayList(u8){};
            defer frames_buf.deinit(ctx.allocator.*);
            const w = frames_buf.writer(ctx.allocator.*);

            const ack_desc = conn.*.buildAckHandshake();
            const ack_ecn = conn.*.getAckEcn(.Handshake);
            const ack_delay = conn.*.getAckDelayEncoded(.Handshake, now_ns);

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
                _ = send_fn(peer, bytes_out) catch |err| {
                    logger.warn("Handshake ACK send failed: {s}", .{@errorName(err)});
                };
                // ACK-only packet is not ack-eliciting
                conn.*.pn_handshake_tx +%= 1;
            }
        }
    }

    // RFC 9001 §4.9.3: Server MUST discard Handshake keys once HANDSHAKE_DONE is sent.
    // We do this after sending the Handshake ACK above so the client gets acknowledged.
    if (conn.*.role == .Server and conn.*.handshake_done_sent) {
        if (conn.*.hs_rx_keys != null or conn.*.hs_tx_keys != null or conn.*.crypto_retx_handshake != null or conn.*.pto_handshake_active) {
            conn.*.hs_rx_keys = null;
            conn.*.hs_tx_keys = null;
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
        var done_frames = std.ArrayList(u8){};
        defer done_frames.deinit(ctx.allocator.*);
        const dw = done_frames.writer(ctx.allocator.*);
        _ = (frame.Frame{ .handshake_done = {} }).write(dw) catch 0;
        conn.*.sendControlFrames(done_frames.items);
    }
}

/// Parse Handshake packet header.
/// Returns structure with DCID, SCID, and offset to payload+PN.
fn parseHandshakeHeader(bytes: []const u8) !struct { dcid: []const u8, scid: []const u8, offset: usize } {
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

        const actual_pn_len: usize = @intCast(dec.pn_len);
        if (full_pn_and_payload.len < actual_pn_len + 16) {
            allocator.free(payload_buf);
            continue;
        }
        const actual_payload_len = full_pn_and_payload.len - actual_pn_len - 16;
        const resized = allocator.realloc(payload_buf, actual_payload_len) catch {
            allocator.free(payload_buf);
            return error.OutOfMemory;
        };

        return .{
            .payload = resized,
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

/// Decrypt short header packet with systematic DCID enumeration and key rotation.
/// Extracted from endpoint.zig lines 1198-1318 (Phase 4b.5 Session 3).
///
/// RFC 9000 §17.3: "Short headers do not include a length, so the DCID length
/// must be known through other means."
///
/// This function implements Bug #6 fix: systematic DCID length enumeration 0-20
/// to discover the actual DCID length when cached value fails.
///
/// RFC 9001 §6: "Endpoints can use multiple packets to send data and can update
/// keys to improve forward secrecy and confidentiality. Packets protected with
/// updated keys are sent with a different packet number space."
///
/// Key rotation strategy:
/// 1. Try current app_rx_keys with cached/heuristic DCID length
/// 2. On auth failure, try all DCID lengths 0-20 systematically
/// 3. On auth failure, derive NEXT keys and retry
/// 4. On auth failure, try previous keys (rx_prev_keys)
/// 5. Cache successful DCID length for future packets
/// 6. Promote to NEXT keys if decryption succeeded with them
///
/// Parameters:
/// - allocator: Memory allocator for decrypted payload
/// - conn: Connection with app_rx_keys, app_rx_secret, rx_prev_keys
/// - bytes: Raw 1-RTT packet bytes (short header)
/// - try_dcid_len: Initial DCID length to try (from cache or connection match)
///
/// Returns:
/// - ShortDecryptResult with decoded payload, key rotation flags, actual dcid_len
/// - error.AuthenticationFailed if all key attempts fail
/// - error.StatelessReset if packet matches stateless reset token
pub fn decryptShortHeaderWithKeyRotation(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    try_dcid_len: u8,
) !ShortDecryptResult {
    return decryptShortHeaderWithKeyRotationInternal(allocator, conn, bytes, try_dcid_len, false);
}

fn decryptShortHeaderWithKeyRotationInternal(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    try_dcid_len: u8,
    forced_attempted: bool,
) !ShortDecryptResult {
    const rx_keys = conn.app_rx_keys orelse return error.NoApplicationKeys;

    // RFC 9000 Appendix A.3: Pass largest received PN for expansion
    const largest_pn: u64 = if (conn.pn_app.have_any) conn.pn_app.max else 0;
    const should_log_attempts = largest_pn >= 80;

    // Ensure NEXT keys are always pre-derived so we can decode peer-initiated key updates
    if (conn.app_rx_next_keys == null and conn.app_rx_secret != null) {
        const cur_secret = conn.app_rx_secret.?;
        const hash = hashForSecret(&cur_secret) catch return error.InvalidSecretLength;
        const next_secret = key_schedule.updateQuicSecretHash(hash, &cur_secret);
        const next_mat = key_schedule.deriveKeyIvHpHash(hash, &next_secret, conn.version_v2);
        conn.app_rx_next_secret = next_secret;
        conn.app_rx_next_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = next_mat.hp };
    }

    var used_next = false;
    var used_prev = false;
    var actual_dcid_len = try_dcid_len;
    var decode_scratch: [4096]u8 = undefined;

    const adoptDecoded = struct {
        fn f(allocator_: std.mem.Allocator, view: packet.DecodedShortView) !packet.DecodedShort {
            const owned_payload = try allocator_.alloc(u8, view.payload.len);
            @memcpy(owned_payload, view.payload);
            return .{
                .packet_number = view.packet_number,
                .packet_number_len = view.packet_number_len,
                .payload = owned_payload,
                .key_phase = view.key_phase,
            };
        }
    }.f;

    // PHASE 57 PART 4 FIX: DCID×KeySet enumeration
    // RFC 9000 §17.2/§17.3: Short headers omit DCID length; RFC 9001 §6: KEY_PHASE toggles key generation
    // CRITICAL: Cannot trust KEY_PHASE bit until we find correct DCID length!
    // When DCID length is wrong, HP removal produces garbage, including garbage KEY_PHASE.
    // Solution: Try ALL key sets (CURRENT, NEXT, PREV) for EACH DCID length (0-20)

    // PHASE 57 Part 5: Use pre-derived NEXT keys (installed at handshake completion)
    // This avoids per-packet derivation and maintains one-generation-ahead invariant
    const next_keys_opt = conn.app_rx_next_keys;

    const decoded = blk_dec: {
        // Check for stateless reset before enumeration
        if (conn.looksLikeStatelessReset(bytes)) {
            return error.StatelessReset;
        }

        // PHASE 57 Part 7: DCID enumeration optimized per msquic reference
        // msquic uses a fixed, cached DCID length (forks/msquic/src/core/packet.c:146)
        // Strategy: Try cached length FIRST with all key sets, then enumerate as fallback

        const max_dcid_len: u8 = 20;
        var candidates: [max_dcid_len + 2]u8 = undefined;
        var cand_count: usize = 0;

        // PRIORITY 1: Cached DCID length (from previous successful decrypt)
        if (conn.expected_rx_dcid_len) |cached_len| {
            addDcidCandidate(cached_len, candidates[0..], &cand_count, max_dcid_len);
        }

        // PRIORITY 2: Observed DCID length (from packet structure)
        addDcidCandidate(try_dcid_len, candidates[0..], &cand_count, max_dcid_len);

        // PRIORITY 3: Enumerate all other lengths (fallback for edge cases)
        var len_iter: u8 = 0;
        while (len_iter <= max_dcid_len) : (len_iter += 1) {
            addDcidCandidate(len_iter, candidates[0..], &cand_count, max_dcid_len);
        }

        logger.debugPrint("[APP-PATH] Enter enumerateDcidLength (short header) bytes_len={} try_dcid_len={} largest_pn={} conn_set={}\n", .{ bytes.len, try_dcid_len, largest_pn, true });
        var cand_index: usize = 0;
        while (cand_index < cand_count) : (cand_index += 1) {
            const test_len = candidates[cand_index];

            if (should_log_attempts) {
                logger.debugPrint("[PHASE57-TRY] key_set=CURRENT dcid_len={} rx_phase={} largest={} forced={}\n", .{
                    test_len,
                    conn.rx_key_phase,
                    largest_pn,
                    forced_attempted,
                });
            }

            packet.phase57SetAttemptLabel("CURRENT");
            logger.debugPrint("[APP-DECODE] TRY CURRENT dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{ test_len, largest_pn, conn.rx_key_phase, bytes.len });
            if (packet.decodeShortProtectedInto(bytes, test_len, .{
                .key = rx_keys.key,
                .iv = rx_keys.iv,
                .hp = rx_keys.hp,
            }, largest_pn, decode_scratch[0..])) |result| {
                if (result.payload.len > 0) {
                    _ = frame.decodeOne(result.payload) catch {
                        continue;
                    };
                }
                const owned = adoptDecoded(allocator, result) catch continue;
                logger.debugPrint("[PHASE57] ✅ Decrypted with CURRENT keys: dcid_len={} pn={}\n", .{ test_len, result.packet_number });
                actual_dcid_len = test_len;
                break :blk_dec owned;
            } else |_| {
                if (next_keys_opt) |next_mat| {
                    packet.phase57SetAttemptLabel("HYBRID_CURRENT_NEXT");
                    if (packet.decodeShortProtectedWithHpInto(bytes, test_len, rx_keys.hp, .{
                        .key = next_mat.key,
                        .iv = next_mat.iv,
                        .hp = next_mat.hp,
                    }, largest_pn, decode_scratch[0..])) |hybrid| {
                        logger.debugPrint("[PHASE57-HYBRID] CURRENT hp + NEXT AEAD succeeded (dcid_len={})\n", .{test_len});
                        if (hybrid.payload.len > 0) {
                            _ = frame.decodeOne(hybrid.payload) catch {
                                continue;
                            };
                        }
                        const owned = adoptDecoded(allocator, hybrid) catch continue;
                        used_next = true;
                        actual_dcid_len = test_len;
                        break :blk_dec owned;
                    } else |_| {}
                }
            }

            if (next_keys_opt) |next_mat| {
                if (should_log_attempts) {
                    logger.debugPrint("[PHASE57-TRY] key_set=NEXT dcid_len={} rx_phase={} largest={} forced={}\n", .{
                        test_len,
                        conn.rx_key_phase,
                        largest_pn,
                        forced_attempted,
                    });
                }
                packet.phase57SetAttemptLabel("NEXT");
                logger.debugPrint("[APP-DECODE] TRY NEXT dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{ test_len, largest_pn, conn.rx_key_phase, bytes.len });
                if (packet.decodeShortProtectedInto(bytes, test_len, .{
                    .key = next_mat.key,
                    .iv = next_mat.iv,
                    .hp = next_mat.hp,
                }, largest_pn, decode_scratch[0..])) |result| {
                    if (result.payload.len > 0) {
                        _ = frame.decodeOne(result.payload) catch {
                            continue;
                        };
                    }
                    const owned = adoptDecoded(allocator, result) catch continue;
                    logger.debugPrint("[PHASE57] ✅ Decrypted with NEXT keys: dcid_len={} pn={} - will promote\n", .{ test_len, result.packet_number });
                    used_next = true;
                    actual_dcid_len = test_len;
                    break :blk_dec owned;
                } else |_| {}
            }

            if (conn.rx_prev_keys) |kp| {
                if (should_log_attempts) {
                    logger.debugPrint("[PHASE57-TRY] key_set=PREV dcid_len={} rx_phase={} largest={} forced={}\n", .{
                        test_len,
                        conn.rx_key_phase,
                        largest_pn,
                        forced_attempted,
                    });
                }
                packet.phase57SetAttemptLabel("PREV");
                logger.debugPrint("[APP-DECODE] TRY PREV dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{ test_len, largest_pn, conn.rx_key_phase, bytes.len });
                if (packet.decodeShortProtectedInto(bytes, test_len, .{
                    .key = kp.key,
                    .iv = kp.iv,
                    .hp = kp.hp,
                }, largest_pn, decode_scratch[0..])) |result| {
                    if (result.payload.len > 0) {
                        _ = frame.decodeOne(result.payload) catch {
                            continue;
                        };
                    }
                    const owned = adoptDecoded(allocator, result) catch continue;
                    logger.debugPrint("[PHASE57] ✅ Decrypted with PREV keys: dcid_len={} pn={}\n", .{ test_len, result.packet_number });
                    used_prev = true;
                    actual_dcid_len = test_len;
                    break :blk_dec owned;
                } else |_| {}
            }
        }

        // All combinations exhausted - attempt forced key update before giving up
        if (tryForceKeyUpdateAndDecrypt(allocator, conn, bytes, largest_pn)) |forced| {
            logger.debugPrint("[PHASE57] ⚠️ Forced key update derived from current secret (dcid_len={}, pn={})\n", .{
                forced.dcid_len,
                forced.decoded.packet_number,
            });
            used_next = true;
            actual_dcid_len = forced.dcid_len;
            break :blk_dec forced.decoded;
        }

        logger.debugPrint("[PHASE57] ❌ All DCID×KeySet combinations failed (0-20 × [CURRENT,NEXT,PREV])\n", .{});
        // PHASE 57 PART 9: Removed buggy force promotion that was flipping rx_key_phase prematurely.
        // Force promotion was promoting keys BEFORE successfully decrypting with NEXT keys,
        // causing rx_key_phase to match incoming key_phase and selecting wrong key generation.
        // The server should ONLY promote after successfully decrypting with NEXT keys.
        // See: PHASE57_PART8_SUMMARY.md - ACK decryption failures due to premature key promotion.
        //
        // if (!forced_attempted and conn.app_rx_next_secret != null and conn.app_rx_next_keys != null) {
        //     logger.debugPrint("[PHASE57] ⚠️ Forcing promotion to NEXT keys after repeated auth failures\n", .{});
        //     promoteToNextKeys(conn, conn.app_rx_next_secret.?, conn.app_rx_next_keys.?);
        //     return decryptShortHeaderWithKeyRotationInternal(allocator, conn, bytes, try_dcid_len, true);
        // }
        conn.onAeadAuthFailure();
        return error.AuthenticationFailed;
    };

    // Cache the successful DCID length for future packets (DCIDs may change post-handshake)
    conn.expected_rx_dcid_len = actual_dcid_len;

    // PHASE 57 PART 2: Check if packet KEY_PHASE differs from connection RX key phase
    // RFC 9001 §6: "Each packet contains a key phase bit that indicates which packet
    // protection keys are used to protect the packet."
    // If key_phase != rx_key_phase, peer has initiated key update (even if we successfully
    // decrypted with current keys, which shouldn't happen but handle defensively)
    if (!used_next and !used_prev and decoded.key_phase != conn.rx_key_phase) {
        logger.debugPrint("[PHASE57-KEY-UPDATE] 🔑 KEY_PHASE mismatch detected! packet_kp={} conn_rx_kp={} pn={}\n", .{
            decoded.key_phase,
            conn.rx_key_phase,
            decoded.packet_number,
        });
        logger.debugPrint("[PHASE57-KEY-UPDATE] Peer initiated key update - will promote to NEXT keys\n", .{});
        used_next = true; // Trigger key promotion in caller
    }

    // PHASE 57: Enhanced logging for key phase tracking
    if (used_next) {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with NEXT keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    } else if (used_prev) {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with PREV keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    } else {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with CURRENT keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    }

    return ShortDecryptResult{
        .decoded = decoded,
        .used_next = used_next,
        .used_prev = used_prev,
        .dcid_len = actual_dcid_len,
    };
}

fn tryForceKeyUpdateAndDecrypt(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    largest_pn: u64,
) ?ShortDecryptResult {
    const current_secret = conn.app_rx_secret orelse return null;
    _ = conn.app_rx_keys orelse return null;
    var decode_scratch: [4096]u8 = undefined;

    const next_keys_present = conn.app_rx_next_keys != null;
    const next_secret_present = conn.app_rx_next_secret != null;
    logger.debugPrint("[PHASE57] fallback invoked: rx_key_phase={} next_keys_present={} next_secret_present={} largest_pn={}\n", .{
        conn.rx_key_phase,
        next_keys_present,
        next_secret_present,
        largest_pn,
    });

    const hash = hashForSecret(&current_secret) catch return null;
    const forced_secret = key_schedule.updateQuicSecretHash(hash, &current_secret);
    const forced_mat = key_schedule.deriveKeyIvHpHash(hash, &forced_secret, conn.version_v2);

    logger.debugPrint("[PHASE57] Forced key derivation prepared (material redacted)\n", .{});

    var test_len: u8 = 0;
    while (test_len <= 20) : (test_len += 1) {
        packet.phase57SetAttemptLabel("FORCED");
        logger.debugPrint("[APP-DECODE] TRY FORCED dcid_len={} largest_pn={} bytes={}\n", .{ test_len, largest_pn, bytes.len });
        if (packet.decodeShortProtectedInto(bytes, test_len, .{
            .key = forced_mat.key,
            .iv = forced_mat.iv,
            .hp = forced_mat.hp,
        }, largest_pn, decode_scratch[0..])) |result| {
            if (result.payload.len > 0) {
                _ = frame.decodeOne(result.payload) catch {
                    continue;
                };
            }
            const owned_payload = allocator.alloc(u8, result.payload.len) catch return null;
            @memcpy(owned_payload, result.payload);

            conn.app_rx_next_secret = forced_secret;
            conn.app_rx_next_keys = .{
                .key = forced_mat.key,
                .iv = forced_mat.iv,
                .hp = forced_mat.hp,
            };

            return ShortDecryptResult{
                .decoded = .{
                    .packet_number = result.packet_number,
                    .packet_number_len = result.packet_number_len,
                    .payload = owned_payload,
                    .key_phase = result.key_phase,
                },
                .used_next = true,
                .used_prev = false,
                .dcid_len = test_len,
            };
        } else |_| {}
    }

    return null;
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
/// 5. Set rx_prev_allow window to 16 packets
///
/// Parameters:
/// - conn: Connection to promote keys on
/// - next_secret: NEXT RX traffic secret
/// - next_keys: NEXT RX AEAD keys (key, iv, hp)
pub fn promoteToNextKeys(
    conn: *conn_mod.Connection,
    next_secret: key_schedule.Secret,
    next_keys: packet.AeadKeys,
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
    const new_next_secret = key_schedule.updateQuicSecretHash(hash, &next_secret);
    const new_next_mat = key_schedule.deriveKeyIvHpHash(hash, &new_next_secret, conn.version_v2);
    logger.debugPrint("[PHASE57-KEY-PROMOTE] 🔄 Pre-derived new NEXT keys before promotion\n", .{});

    // Preserve current keys as previous (zeroize any older prev first)
    if (conn.rx_prev_keys) |*old_prev| {
        const sz = std.crypto.secureZero;
        sz(u8, &old_prev.key);
        sz(u8, &old_prev.iv);
        sz(u8, &old_prev.hp);
    }
    conn.rx_prev_keys = conn.app_rx_keys;
    conn.rx_prev_allow = 16; // bounded window for reordering

    // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
    // Evidence: quic-go's rollKeys() only updates rcvAEAD/sendAEAD, NOT headerDecrypter/headerEncrypter
    const preserved_hp = conn.app_rx_keys.?.hp;

    // Install NEXT keys/secret as current (AEAD only, HP preserved)
    conn.app_rx_keys = .{ .key = next_keys.key, .iv = next_keys.iv, .hp = preserved_hp };
    conn.app_rx_secret = next_secret;
    conn.maybeEmitRxKeyUpdateLog(&next_secret);
    conn.rx_key_phase = !conn.rx_key_phase;

    logger.debugPrint("[PHASE57-HP-PRESERVE] HP key preserved during promotion (not rotated per RFC 9001 §6)\n", .{});

    // Install the pre-derived NEXT keys/secret
    conn.app_rx_next_secret = new_next_secret;
    conn.app_rx_next_keys = .{ .key = new_next_mat.key, .iv = new_next_mat.iv, .hp = new_next_mat.hp };

    logger.debugPrint("[PHASE57-KEY-PROMOTE] ✅ Key promotion complete - ready for next packet\n", .{});
}

/// Decrement previous key allowance after using rx_prev_keys.
/// Extracted from endpoint.zig lines 1326-1346 (Phase 4b.5 Session 3).
///
/// RFC 9001 §6.5: "An endpoint MAY retain old keys for a short period to allow
/// decryption of packets that are reordered in the network."
///
/// When a packet is decrypted with previous keys:
/// 1. Decrement rx_prev_allow counter
/// 2. If counter reaches zero, zeroize and drop rx_prev_keys
/// 3. This prevents unbounded key retention
///
/// Parameters:
/// - conn: Connection with rx_prev_keys and rx_prev_allow
pub fn decrementPrevKeyAllowance(conn: *conn_mod.Connection) void {
    if (conn.rx_prev_allow > 0) {
        conn.rx_prev_allow -= 1;
        if (conn.rx_prev_allow == 0) {
            if (conn.rx_prev_keys) |*to_zero| {
                const sz = std.crypto.secureZero;
                sz(u8, &to_zero.key);
                sz(u8, &to_zero.iv);
                sz(u8, &to_zero.hp);
            }
            conn.rx_prev_keys = null;
        }
    } else {
        // Safety: if allowance already zero, drop prev immediately
        if (conn.rx_prev_keys) |*to_zero2| {
            const sz = std.crypto.secureZero;
            sz(u8, &to_zero2.key);
            sz(u8, &to_zero2.iv);
            sz(u8, &to_zero2.hp);
        }
        conn.rx_prev_keys = null;
    }
}
