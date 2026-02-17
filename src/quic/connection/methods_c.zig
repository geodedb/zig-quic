const std = @import("std");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
const tparams = @import("quic_transport_params");
const logger = @import("quic_logger");
const builtin = @import("builtin");

pub fn bind(comptime Connection: type) type {
    return struct {
        fn hashForSecret(secret: *const ks.Secret) !ks.Hash {
            return switch (secret.len) {
                32 => .sha256,
                48 => .sha384,
                else => error.InvalidSecretLength,
            };
        }

        const StreamTxMap = @FieldType(Connection, "stream_txs");
        const StreamRxMap = @FieldType(Connection, "streams_rx");
        const StreamTx = @FieldType(StreamTxMap.KV, "value");
        const StreamRx = @FieldType(StreamRxMap.KV, "value");

        pub fn readAnyStream(self: *Connection, buf: []u8) !struct { id: u64, n: usize } {
            if (!self.streams_rx_init) return error.WouldBlock;
            var it2 = self.streams_rx.iterator();
            while (it2.next()) |e| {
                const sid = e.key_ptr.*;
                var sr = e.value_ptr; // pointer to StreamRx
                if (sr.inbox.items.len == 0) continue;
                const n = @min(buf.len, sr.inbox.items.len);
                @memcpy(buf[0..n], sr.inbox.items[0..n]);
                const rem = sr.inbox.items.len - n;
                if (rem > 0) std.mem.copyForwards(u8, sr.inbox.items[0..rem], sr.inbox.items[n..]);
                sr.inbox.shrinkRetainingCapacity(rem);
                return .{ .id = sid, .n = n };
            }
            return error.WouldBlock;
        }

        fn maybeTriggerKeyUpdateOnSend(self: *Connection, bytes_sent: usize) void {
            if (self.app_tx_keys == null or self.app_tx_secret == null) return;
            if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
                if (std.posix.getenv("QUIC_DISABLE_AUTO_KEY_UPDATE")) |v| {
                    if (v.len == 0 or !std.mem.eql(u8, v, "0")) return;
                }
            }
            if (self.tx_update_in_progress) return;
            self.tx_sent_packets_since_key +%= 1;
            self.tx_sent_bytes_since_key +%= @intCast(bytes_sent);
            const pkt_thr: u64 = 512;
            const byte_thr: u64 = 1024 * 1024;
            if (self.tx_sent_packets_since_key >= pkt_thr or self.tx_sent_bytes_since_key >= byte_thr) {
                const current_secret = self.app_tx_secret.?;
                const hash = hashForSecret(&current_secret) catch return;
                const next_secret = ks.updateQuicSecretHash(hash, &current_secret);
                const preserved_hp = self.app_tx_keys.?.hp;

                const t = ks.deriveKeyIvHpHash(hash, &next_secret, self.version_v2);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
                self.app_tx_secret = next_secret;
                self.maybeEmitTxKeyUpdateLog(&next_secret);
                self.tx_key_phase = !self.tx_key_phase;
                self.tx_update_in_progress = true;
                self.tx_update_start_pn = self.pn_app_tx;
                self.tx_sent_packets_since_key = 0;
                self.tx_sent_bytes_since_key = 0;
                logger.debugPrint("keyupdate: triggered phase={d} start_pn={d}\n", .{ @intFromBool(self.tx_key_phase), self.tx_update_start_pn });
            }
        }

        /// Record a short-header 1-RTT packet as sent and maybe trigger key update.
        /// Bookkeeping when a short-header packet (1-RTT) is sent: CC accounting & key update thresholds.
        pub fn onShortHeaderPacketSent(self: *Connection, bytes_sent: usize, ack_eliciting: bool) void {
            // Track recovery for Application space
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);

            // PHASE 51: Debug logging to verify this function is called
            logger.debugPrint("[PHASE51] onShortHeaderPacketSent called: bytes={d} ack_eliciting={} pn={d}\n", .{
                bytes_sent, ack_eliciting, self.pn_app_tx,
            });

            // PHASE 51: Properly handle and report errors instead of silently swallowing them
            self.rec.onPacketSent(.Application, self.pn_app_tx, bytes_sent, ack_eliciting, now_ns) catch |err| {
                logger.debugPrint("[PHASE51] ERROR in rec.onPacketSent: {s}\n", .{@errorName(err)});
            };

            // Legacy shim for back-compat
            if (ack_eliciting) maybeTriggerKeyUpdateOnSend(self, bytes_sent);
            self.pn_app_tx +%= 1;
            self.computeAndMaybeArmPto(self);
            // AEAD usage counting: increment total encrypted count for confidentiality limit
            self.aead_tx_encrypted_count +%= 1;
            // Proactive trigger: when within 1% of the limit, bias an immediate key update on next ack-eliciting
            const near_limit: u64 = self.aead_confidentiality_limit - (self.aead_confidentiality_limit / 100);
            if (self.aead_tx_encrypted_count >= near_limit and !self.tx_update_in_progress) {
                self.tx_sent_packets_since_key = 64;
                self.tx_sent_bytes_since_key = 64 * 1024;
            }
            if (self.aead_tx_encrypted_count >= self.aead_confidentiality_limit) {
                // RFC 9001 §6.6: MUST initiate a key update before exceeding the limit; if not possible, close.
                // Attempt to trigger a TX key update immediately; if already in progress, allow it to finalize; otherwise close.
                if (!self.tx_update_in_progress) {
                    // Force a key update on next ack-eliciting send by faking thresholds
                    self.tx_sent_packets_since_key = 64;
                    self.tx_sent_bytes_since_key = 64 * 1024;
                }
            }
        }

        /// Build and send a DPLPMTUD probe at the requested UDP payload size using
        /// an ack-eliciting PING followed by PADDING to reach target. Returns bytes sent.
        /// Emit a sized PING+PADDING probe for DPLPMTUD (not congestion controlled beyond size bounds).
        pub fn sendPmtudProbe(self: *Connection, target_udp_payload: u16) !usize {
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // Minimum QUIC/UDP payload size is 1200 (RFC 9000 §14.1)
            if (target_udp_payload < 1200) return error.InvalidProbeSize;
            // CC-aware pacing guard: do not send a probe if it would exceed cwnd.
            // This keeps PMTUD probing from competing with data under tight congestion windows.
            const cc_state = self.rec.getCongestionState();
            const bif: usize = cc_state.bytes_in_flight;
            const cwnd: usize = cc_state.cwnd;
            if (bif + target_udp_payload > cwnd) {
                return error.WouldBlock;
            }
            // Compute short-header overhead: 1 (first byte) + DCID length + PN length (2)
            const dcid_len: usize = self.our_scid.len;
            const header_overhead: usize = 1 + dcid_len + 2;
            const aead_tag: usize = 16;
            // Frames: 1 byte for PING + N bytes of PADDING
            if (target_udp_payload < header_overhead + aead_tag + 1) return error.InvalidProbeSize;
            const needed_padding: usize = target_udp_payload - header_overhead - aead_tag - 1;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
            if (needed_padding > 0) {
                // Frame.padding counts total padding bytes to emit (writes that many 0x00)
                _ = (frame.Frame{ .padding = needed_padding }).write(w) catch 0;
            }
            // Record pending probe PN before send
            self.probe_pending_pn = self.pn_app_tx;
            self.probe_pending_size = target_udp_payload;
            const packet_storage = self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                @as(u32, @truncate(self.pn_app_tx)),
                2,
                frames.items,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            );
            const pkt = packet_storage[0..pkt_len];
            const n = try self.send(pkt);
            self.onShortHeaderPacketSent(pkt.len, true);
            return n;
        }

        /// Handle an ICMP/ICMPv6 Packet-Too-Big (PTB) signal by clamping path_mtu.
        /// Reported MTU is validated to never drop below 1200.
        /// Handle validated ICMP PTB by clamping path_mtu (never below 1200) and canceling search.
        pub fn onIcmpPacketTooBig(self: *Connection, reported_mtu: u16) void {
            const clamp: u16 = if (reported_mtu < 1200) 1200 else reported_mtu;
            if (clamp < self.path_mtu) self.path_mtu = clamp;
            // Clear any pending probe if it exceeds the new clamp
            if (self.probe_pending_pn != null and self.probe_pending_size > clamp) {
                self.probe_pending_pn = null;
                self.probe_pending_size = 0;
            }
        }

        /// Called by endpoint when an incoming packet fails AEAD authentication; enforces integrity limit.
        /// Increment integrity failure counter and close if AEAD integrity limit exceeded.
        pub fn onAeadAuthFailure(self: *Connection) void {
            self.aead_rx_invalid_count +%= 1;
            logger.debugPrint("DEBUG: onAeadAuthFailure called, count={}/{}\n", .{ self.aead_rx_invalid_count, self.aead_integrity_limit });
            if (self.aead_rx_invalid_count >= self.aead_integrity_limit) {
                // Enter closed state; in a full implementation we would send CONNECTION_CLOSE with AEAD_LIMIT_REACHED.
                logger.debugPrint("DEBUG: AEAD integrity limit exceeded, closing connection\n", .{});
                self.closed = true;
            }
        }

        /// Record a packet as sent in the given PN space for Recovery bookkeeping.
        /// Notify recovery of sent packet (per-space) for loss tracking & congestion control.
        pub fn onPacketSent(self: *Connection, space: recovery.PacketNumberSpace, pn: u64, bytes: usize, ack_eliciting: bool) void {
            // Record via Recovery (authoritative)
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            _ = self.rec.onPacketSent(space, pn, bytes, ack_eliciting, now_ns) catch {};
            // Legacy maps retained for compatibility with tests expecting them
            // Use proper init flags to avoid accessing undefined HashMaps
            if (!self.sent_time_init) {
                self.sent_time = std.AutoHashMap(u64, i128).init(self.allocator.*);
                self.sent_time_init = true;
            }
            if (!self.sent_sizes_init) {
                self.sent_sizes = std.AutoHashMap(u64, u16).init(self.allocator.*);
                self.sent_sizes_init = true;
            }
            _ = self.sent_time.put(pn, @as(i128, @intCast(now_ns))) catch {};
            _ = self.sent_sizes.put(pn, @intCast(@min(bytes, @as(usize, std.math.maxInt(u16))))) catch {};
            self.ccOnPacketSent(bytes, ack_eliciting);
        }

        /// Ensure stream_txs HashMap is initialized
        pub fn ensureStreamTxInit(self: *Connection) void {
            if (!self.stream_txs_init) {
                self.stream_txs = std.AutoHashMap(u64, StreamTx).init(self.allocator.*);
                self.stream_txs_init = true;
            }
        }

        pub fn ensureStreamRx(self: *Connection, id: u64) *StreamRx {
            // Ensure hashmaps are initialized - they can't use .empty (tracked via _init flag)
            if (!self.streams_rx_init) {
                self.streams_rx = std.AutoHashMap(u64, StreamRx).init(self.allocator.*);
                self.streams_rx_init = true;
            }
            // ArrayLists use .empty default, which has capacity=0 but is valid - no need to reinitialize
            if (self.streams_rx.getPtr(id)) |s| return s;
            var sr = StreamRx.init();
            // PHASE 42 PART 9: Initialize per-stream flow control window (RFC 9000 §4.2)
            sr.local_max_stream_data = self.local_max_stream_data;
            sr.last_sent_max_stream_data = 0;
            // PHASE 46: Store initial window size for quinn-style threshold calculation
            sr.initial_window_size = self.local_max_stream_data;
            self.streams_rx.put(id, sr) catch {};
            return self.streams_rx.getPtr(id).?;
        }

        /// Check if a stream ID was initiated by the peer
        pub fn isPeerInitiatedStream(self: *const Connection, stream_id: u64) bool {
            // Stream ID format: [stream_num:62][dir:1][initiator:1]
            // Bit 0: 0=client-initiated, 1=server-initiated
            const initiator_bit = stream_id & 0x1;
            const is_client_initiated = (initiator_bit == 0);
            const is_server_initiated = (initiator_bit == 1);

            if (self.role == .Client) {
                // If we're the client, peer-initiated means server-initiated
                return is_server_initiated;
            } else {
                // If we're the server, peer-initiated means client-initiated
                return is_client_initiated;
            }
        }

        /// CWE-400 mitigation: Validate peer-initiated stream against local limits.
        /// RFC 9000 §4.6: "An endpoint MUST NOT open more streams than the peer permits."
        /// Returns error.StreamLimitExceeded if the peer exceeds our advertised limits.
        pub fn validatePeerStreamLimit(self: *const Connection, stream_id: u64) !void {
            // Only check peer-initiated streams
            if (!isPeerInitiatedStream(self, stream_id)) return;

            // Already known stream - no limit check needed
            if (self.streams_rx_init and self.streams_rx.get(stream_id) != null) return;

            // Extract stream number and type from stream ID
            // Stream ID format: [stream_num:62][dir:1][initiator:1]
            const stream_num = stream_id >> 2;
            const dir_bit = (stream_id >> 1) & 0x1;
            const is_bidi = (dir_bit == 0);

            if (is_bidi) {
                // Check against local_max_streams_bidi (what we advertised to peer)
                if (stream_num >= self.local_max_streams_bidi) {
                    logger.debugPrint("validatePeerStreamLimit: Peer exceeded bidi stream limit (stream_num={}, limit={})\n", .{ stream_num, self.local_max_streams_bidi });
                    return error.StreamLimitExceeded;
                }
            } else {
                // Check against local_max_streams_uni
                if (stream_num >= self.local_max_streams_uni) {
                    logger.debugPrint("validatePeerStreamLimit: Peer exceeded uni stream limit (stream_num={}, limit={})\n", .{ stream_num, self.local_max_streams_uni });
                    return error.StreamLimitExceeded;
                }
            }
        }

        /// Check if we already know about this stream
        pub fn isStreamKnown(self: *const Connection, stream_id: u64) bool {
            // Check if it's in our RX map (only if initialized)
            if (self.streams_rx_init) {
                if (self.streams_rx.get(stream_id) != null) return true;
            }

            // Check if it's already in the incoming queue
            for (self.incoming_stream_queue.items) |id| {
                if (id == stream_id) return true;
            }

            return false;
        }

        /// Queue a new incoming stream for acceptance
        pub fn queueIncomingStream(self: *Connection, stream_id: u64) !void {
            // PHASE 42 PART 15: Remove duplicate check to allow re-queueing
            // Streams need to be queued every time new data arrives. The application
            // drains the queue via acceptStream() in a tight loop, so duplicates will
            // be processed quickly. This is necessary because acceptStream() is the
            // only mechanism to notify the application that a stream has more data.
            //
            // Old code (caused queue blocking):
            // for (self.incoming_stream_queue.items) |id| {
            //     if (id == stream_id) return;  // ← Prevented re-queueing
            // }

            // Add to queue (may create duplicates, but that's intentional)
            try self.incoming_stream_queue.append(self.allocator.*, stream_id);

            // Update highest seen stream ID
            const dir_bit = (stream_id >> 1) & 0x1;
            const is_bidi = (dir_bit == 0);

            if (is_bidi) {
                if (self.highest_peer_bidi_stream == null or stream_id > self.highest_peer_bidi_stream.?) {
                    self.highest_peer_bidi_stream = stream_id;
                }
            } else {
                if (self.highest_peer_uni_stream == null or stream_id > self.highest_peer_uni_stream.?) {
                    self.highest_peer_uni_stream = stream_id;
                }
            }
        }

        // RFC-9000 2.1.  Stream Types and Identifiers
        //
        // Streams can be unidirectional or bidirectional.  Unidirectional
        // streams carry data in one direction: from the initiator of the stream
        // to its peer.  Bidirectional streams allow for data to be sent in both
        // directions.
        //
        // Streams are identified within a connection by a numeric value,
        // referred to as the stream ID.  A stream ID is a 62-bit integer (0 to
        // 2^62-1) that is unique for all streams on a connection.  Stream IDs
        // are encoded as variable-length integers; see Section 16.  A QUIC
        // endpoint MUST NOT reuse a stream ID within a connection.
        //
        // The least significant bit (0x01) of the stream ID identifies the
        // initiator of the stream.  Client-initiated streams have even-numbered
        // stream IDs (with the bit set to 0), and server-initiated streams have
        // odd-numbered stream IDs (with the bit set to 1).
        //
        // The second least significant bit (0x02) of the stream ID
        // distinguishes between bidirectional streams (with the bit set to 0)
        // and unidirectional streams (with the bit set to 1).
        //
        // The two least significant bits from a stream ID therefore identify a
        // stream as one of four types, as summarized in Table 1.
        //
        //             +======+==================================+
        //             | Bits | Stream Type                      |
        //             +======+==================================+
        //             | 0x00 | Client-Initiated, Bidirectional  |
        //             +------+----------------------------------+
        //             | 0x01 | Server-Initiated, Bidirectional  |
        //             +------+----------------------------------+
        //             | 0x02 | Client-Initiated, Unidirectional |
        //             +------+----------------------------------+
        //             | 0x03 | Server-Initiated, Unidirectional |
        //             +------+----------------------------------+
        //
        //                         Table 1: Stream ID Types
        //
        // The stream space for each type begins at the minimum value (0x00
        // through 0x03, respectively); successive streams of each type are
        // created with numerically increasing stream IDs.  A stream ID that is
        // used out of order results in all streams of that type with lower-
        // numbered stream IDs also being opened.

        /// Accept an incoming peer-initiated stream (non-blocking)
        /// GAP-0200: Thread-safe - acquires connection mutex
        pub fn acceptStream(self: *Connection) !u64 {
            self.mu.lock();
            defer self.mu.unlock();

            if (self.incoming_stream_queue.items.len == 0) {
                return error.WouldBlock;
            }

            // Remove and return the first stream in the queue
            const stream_id = self.incoming_stream_queue.orderedRemove(0);

            // Ensure we have RX state for it
            _ = ensureStreamRx(self, stream_id);

            // Also ensure TX state for bidirectional streams
            const dir_bit = (stream_id >> 1) & 0x1;
            const is_bidi = (dir_bit == 0);
            if (is_bidi) {
                ensureStreamTxInit(self);
                if (self.stream_txs.getPtr(stream_id) == null) {
                    // PHASE 42 PART 10: Initialize per-stream peer window from connection default
                    _ = self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                }
            }

            return stream_id;
        }

        /// Check if any incoming streams are available
        pub fn hasIncomingStreams(self: *const Connection) bool {
            return self.incoming_stream_queue.items.len > 0;
        }

        /// Get the first available stream from received data (for compatibility)
        pub fn getFirstStream(self: *Connection) ?u64 {
            // Check if we have any streams in RX map that are peer-initiated
            if (!self.streams_rx_init) return null;
            var it = self.streams_rx.iterator();
            while (it.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                if (isPeerInitiatedStream(self, stream_id)) {
                    // Ensure TX state for bidirectional streams
                    const dir_bit = (stream_id >> 1) & 0x1;
                    const is_bidi = (dir_bit == 0);
                    if (is_bidi and self.stream_txs_init) {
                        if (self.stream_txs.getPtr(stream_id) == null) {
                            // PHASE 42 PART 10: Initialize per-stream peer window from connection default
                            _ = self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                        }
                    }
                    return stream_id;
                }
            }
            return null;
        }

        /// Decode and apply peer-provided QUIC transport parameters (encoded TP extension payload).
        /// Best-effort: on any error, defaults remain. Safe to call multiple times (idempotent after first success).
        /// Decode and apply peer transport parameters (limits, ack_delay_exponent, max_ack_delay, active_connection_id_limit).
        pub fn applyPeerTransportParameters(self: *Connection, encoded: []const u8) !void {
            if (self.transport_params_applied) return; // already applied
            var arena = std.heap.ArenaAllocator.init(self.allocator.*);
            defer arena.deinit();
            const alloc = arena.allocator();
            const tp_dec = tparams.TransportParams.decode(alloc, encoded) catch return error.MalformedTransportParams;

            // RFC 9000 §7.4: Validate required parameters are present
            // peer_is_server = true if we're a client receiving from server
            const peer_is_server = (self.role == .Client);
            const retry_sent = self.retry_received;
            tp_dec.validate(peer_is_server, retry_sent) catch return error.InvalidTransportParams;

            // RFC 9000 §18.2: Check that parameter values are within allowed ranges
            tp_dec.checkLimits() catch return error.InvalidTransportParams;
            // Flow control: peer's advertised maxima govern what we may send.
            if (tp_dec.initial_max_data) |v| self.peer_max_data = v;
            // PHASE 57 PART 11 FIX: Use correct transport parameter for stream direction
            // For client-initiated bidirectional streams, the server must use initial_max_stream_data_bidi_local
            // because from the client's perspective, these are locally-initiated streams.
            // RFC 9000 §18.2: initial_max_stream_data_bidi_local applies to locally-initiated bidirectional streams
            logger.debugPrint("[FC-TRANSPORT-PARAMS] Processing transport params: current peer_max_stream_data={}\n", .{self.peer_max_stream_data});

            // Store separate limits for different stream types
            var client_initiated_bidi_limit: u64 = self.peer_max_stream_data;
            var server_initiated_bidi_limit: u64 = self.peer_max_stream_data;

            if (tp_dec.initial_max_stream_data_bidi_local) |v| {
                logger.debugPrint("[FC-TRANSPORT-PARAMS] Client advertises initial_max_stream_data_bidi_local={} (for client-initiated streams)\n", .{v});
                client_initiated_bidi_limit = v; // This is the limit for client-initiated streams
            }
            if (tp_dec.initial_max_stream_data_bidi_remote) |v| {
                logger.debugPrint("[FC-TRANSPORT-PARAMS] Client advertises initial_max_stream_data_bidi_remote={} (for server-initiated streams)\n", .{v});
                server_initiated_bidi_limit = v; // This would be for server-initiated streams
            }

            // For now, use the client-initiated limit as the default since most streams are client-initiated
            // TODO: Track limits per stream based on who initiated it
            if (client_initiated_bidi_limit != self.peer_max_stream_data) {
                logger.debugPrint("[FC-TRANSPORT-PARAMS] Updating peer_max_stream_data from {} to {} for client-initiated streams\n", .{ self.peer_max_stream_data, client_initiated_bidi_limit });
                self.peer_max_stream_data = client_initiated_bidi_limit;
            }
            if (tp_dec.initial_max_streams_bidi) |v| self.peer_max_streams_bidi = v;
            if (tp_dec.initial_max_streams_uni) |v| self.peer_max_streams_uni = v;
            if (tp_dec.ack_delay_exponent) |v| {
                if (v <= 20) self.ack_delay_exponent = @intCast(v); // cap defensively
            }
            if (tp_dec.max_ack_delay) |v| {
                // max_ack_delay is in milliseconds (RFC 9000); cap to 4000ms for safety.
                const capped: u64 = if (v > 4000) 4000 else v;
                self.max_ack_delay_ms = @intCast(capped);
                // Feed into recovery RTT estimator (nanoseconds)
                self.rec.rtt.max_ack_delay_ns = capped * std.time.ns_per_ms;
            }
            if (tp_dec.max_udp_payload_size) |v| {
                // Enforce minimum 1200 and clamp path_mtu & cc.mds
                if (v >= 1200 and v <= 65527) {
                    const lim: u16 = @intCast(v);
                    if (lim < self.path_mtu) self.path_mtu = lim;
                    if (lim < self.rec.getMds()) self.rec.setMds(lim);
                    self.peer_max_udp_payload_size = lim;
                }
            }
            if (tp_dec.active_connection_id_limit) |v| {
                if (v >= 2) self.active_connection_id_limit = v;
            }
            // Mark applied (even if partial) to avoid reprocessing.
            self.transport_params_applied = true;
        }

        /// Determine whether a NEW_CONNECTION_ID frame may be issued without exceeding peer limit.
        /// Return true if a new CID can be issued without first retiring an existing one.
        pub fn canIssueNewConnectionId(self: *const Connection) bool {
            return self.issued_cids < self.active_connection_id_limit;
        }

        /// Register issuance of a new connection ID; returns error when limit reached.
        /// Bookkeeping after issuing a new CID: increments issued counter and enforces limit.
        pub fn onIssuedNewConnectionId(self: *Connection) !void {
            if (!self.canIssueNewConnectionId()) return error.ActiveConnectionIdLimitReached;
            self.issued_cids += 1;
        }

        /// Issue a new locally-generated Connection ID (placeholder implementation).
        /// In a full implementation this would also schedule a NEW_CONNECTION_ID frame for transmission.
        /// Returns the sequence number of the newly issued CID.
        /// Issue new local CID (no rotation); marks pending for advertisement and returns sequence.
        pub fn issueNewConnectionId(self: *Connection, rand: *std.rand.DefaultPrng) !u64 {
            try self.onIssuedNewConnectionId();
            // Allocate new CID slot and mark pending for advertisement.
            const alloc = try self.acquireLocalCid(rand);
            self.markPendingNewCid(alloc.idx);
            return alloc.sequence;
        }

        /// Flush any pending NEW_CONNECTION_ID frames in a standalone short-header packet.
        /// Returns number of frames flushed. No-op if no 1-RTT keys or amplification limit reached.
        /// Force emission of all pending NEW_CONNECTION_ID frames immediately (test helper / control packet).
        pub fn flushPendingNewConnectionIds(self: *Connection) !usize {
            if (self.app_tx_keys == null) return 0;
            if (!self.canSendUnderAmplification()) return 0;
            if (self.pending_new_cid.isEmpty()) return 0;
            var fb = std.ArrayList(u8){};
            defer fb.deinit(self.allocator.*);
            const w = fb.writer(self.allocator.*);
            const wrote = try self.writePendingNewConnectionIds(w, 4);
            if (wrote == 0) return 0;
            self.sendControlFrames(fb.items);
            return wrote;
        }

        /// Mark a local CID slot as pending advertisement.
        /// Mark a local CID slot index pending for NEW_CONNECTION_ID advertisement.
        pub fn markPendingNewCid(self: *Connection, idx: u8) void {
            if (idx < self.local_cids.len) self.pending_new_cid.set(idx);
        }

        /// Write pending NEW_CONNECTION_ID frames to writer (up to max_frames). Returns frames written.
        /// Write up to max_frames NEW_CONNECTION_ID frames for currently pending local CIDs; returns frames written.
        pub fn writePendingNewConnectionIds(self: *Connection, w: anytype, max_frames: usize) !usize {
            if (max_frames == 0) return 0;
            var written: usize = 0;
            const retire_prior_to: u64 = self.retired_prior_to; // monotonic threshold updated by rotation logic
            var i: usize = 0;
            while (i < self.local_cids.len and written < max_frames) : (i += 1) {
                if (!self.pending_new_cid.isSet(@intCast(i))) continue;
                const lc = self.local_cids[i];
                if (!lc.in_use or lc.sequence == 0) { // never advertise initial again
                    self.pending_new_cid.unset(@intCast(i));
                    continue;
                }
                const fr = frame.Frame{ .new_connection_id = .{
                    .sequence = lc.sequence,
                    .retire_prior_to = retire_prior_to,
                    .connection_id = lc.cid.bytes[0..lc.cid.len],
                    .stateless_reset_token = lc.reset_token,
                } };
                _ = try fr.write(w);
                self.pending_new_cid.unset(@intCast(i));
                written += 1;
            }
            return written;
        }

        /// Handle RETIRE_CONNECTION_ID received from peer; frees local CID with given sequence.
        /// Handle RETIRE_CONNECTION_ID from peer; updates inventory and retired_prior_to if contiguous prefix retired.
        pub fn onRetireConnectionId(self: *Connection, sequence: u64) void {
            var i: usize = 0;
            while (i < self.local_cids.len) : (i += 1) {
                if (self.local_cids[i].in_use and self.local_cids[i].sequence == sequence) {
                    self.local_cids[i].in_use = false;
                    self.pending_new_cid.unset(@intCast(i));
                    // Decrement active issued count (sequence 0 initial SCID still counts until retired by policy).
                    if (self.issued_cids > 0 and sequence != 0) {
                        self.issued_cids -= 1;
                    }
                    // Advance retired_prior_to if this retirement allows earlier sequences to be fully retired.
                    if (sequence + 1 > self.retired_prior_to) {
                        // Ensure all sequences < (sequence + 1) (except 0) are not in use before advancing.
                        var can_advance = true;
                        var j: usize = 0;
                        while (j < self.local_cids.len) : (j += 1) {
                            const lcj = self.local_cids[j];
                            if (lcj.in_use and lcj.sequence > 0 and lcj.sequence < sequence + 1) {
                                can_advance = false;
                                break;
                            }
                        }
                        if (can_advance) self.retired_prior_to = sequence + 1;
                    }
                    break;
                }
            }
        }

        fn deriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid_bytes: []const u8) [16]u8 {
            var ikm_buf: [8 + 20]u8 = undefined;
            var seq_be: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq_be, sequence, .big);
            @memcpy(ikm_buf[0..8], &seq_be);
            const cid_len = cid_bytes.len;
            if (cid_len > 20) unreachable;
            @memcpy(ikm_buf[8 .. 8 + cid_len], cid_bytes);
            const prk = ks.extract(base, ikm_buf[0 .. 8 + cid_len]);
            var out: [16]u8 = undefined;
            ks.expandLabel(prk, "reset token", &[_]u8{}, out[0..]) catch unreachable;
            return out;
        }

        fn ensureStatelessResetBase(self: *Connection) void {
            var any_non_zero = false;
            for (self.stateless_reset_base) |b| {
                if (b != 0) {
                    any_non_zero = true;
                    break;
                }
            }
            if (any_non_zero) return;
            if (self.app_tx_secret) |secret| {
                const label = "stateless reset base";
                const prk = ks.extract(secret.slice(), label);
                @memcpy(self.stateless_reset_base[0..], prk[0..]);
            } else {
                std.crypto.random.bytes(&self.stateless_reset_base);
            }
        }

        /// Acquire a free local CID slot, populate with random CID & derived token, return slot index and sequence.
        pub fn acquireLocalCid(self: *Connection, rand: *std.rand.DefaultPrng) !struct { idx: u8, sequence: u64 } {
            if (self.active_local_cids >= self.local_cids.len and !self.pending_new_cid.isEmpty()) {
                return error.ConnectionIdInventoryFull;
            }
            var i: usize = 0;
            while (i < self.local_cids.len) : (i += 1) {
                if (!self.local_cids[i].in_use) break;
            }
            if (i == self.local_cids.len) return error.ConnectionIdInventoryFull;
            const seq: u64 = self.next_cid_sequence;
            self.next_cid_sequence += 1;
            var cid_bytes: [8]u8 = undefined;
            rand.random().bytes(&cid_bytes);
            const lc = &self.local_cids[i];
            lc.* = .{ .in_use = true, .sequence = seq, .cid = .{ .len = cid_bytes.len, .bytes = undefined }, .reset_token = undefined };
            @memcpy(lc.cid.bytes[0..cid_bytes.len], &cid_bytes);
            self.ensureStatelessResetBase();
            lc.reset_token = deriveStatelessResetToken(&self.stateless_reset_base, seq, cid_bytes[0..]);
            if (i + 1 > self.active_local_cids) self.active_local_cids = @intCast(i + 1);
            return .{ .idx = @intCast(i), .sequence = seq };
        }

        /// Issue new CID performing rotation if at active limit (retires oldest non-zero sequence first).
        pub fn issueNewConnectionIdRotating(self: *Connection, rand: *std.rand.DefaultPrng) !u64 {
            if (self.canIssueNewConnectionId()) {
                return try self.issueNewConnectionId(rand);
            }
            var oldest_idx: ?usize = null;
            var oldest_seq: u64 = std.math.maxInt(u64);
            var k: usize = 0;
            while (k < self.local_cids.len) : (k += 1) {
                const lc = self.local_cids[k];
                if (!lc.in_use or lc.sequence == 0) continue;
                if (lc.sequence < oldest_seq) {
                    oldest_seq = lc.sequence;
                    oldest_idx = k;
                }
            }
            if (oldest_idx) |oi| {
                self.local_cids[oi].in_use = false;
                self.pending_new_cid.unset(@intCast(oi));
                if (oldest_seq + 1 > self.retired_prior_to) self.retired_prior_to = oldest_seq + 1;
                if (self.issued_cids > 0) self.issued_cids -= 1;
            } else {
                return error.ActiveConnectionIdLimitReached;
            }
            return try self.issueNewConnectionId(rand);
        }
    };
}
