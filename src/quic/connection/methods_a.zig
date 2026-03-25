const std = @import("std");
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
const logger = @import("quic_logger");

pub fn bind(comptime Connection: type) type {
    return struct {
        fn openAppendFile(path: []const u8) !std.fs.File {
            return std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch |err| switch (err) {
                error.FileNotFound => std.fs.cwd().createFile(path, .{ .truncate = false, .read = true }),
                else => err,
            };
        }

        fn currentClientRandom(self: *const Connection) ?[32]u8 {
            const tls_ctx = self.tls_context orelse return null;
            return tls_ctx.client_random;
        }

        fn appendKeyLogLine(
            self: *Connection,
            label: []const u8,
            client_random: *const [32]u8,
            secret: *const ks.Secret,
        ) bool {
            // SF-024: Compile out the entire keylog path in release builds.
            // Only Debug and test builds may export key material.
            if (comptime @import("builtin").mode != .Debug and !@import("builtin").is_test) return false;

            const keylog_path = std.process.getEnvVarOwned(self.allocator.*, "SSLKEYLOGFILE") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return false,
                else => {
                    logger.debugPrint("keylog: env lookup failed: {}\n", .{err});
                    return false;
                },
            };
            defer self.allocator.free(keylog_path);
            if (keylog_path.len == 0) return false;

            var file = openAppendFile(keylog_path) catch |err| {
                logger.debugPrint("keylog: open failed ({s}): {}\n", .{ keylog_path, err });
                return false;
            };
            defer file.close();
            file.seekFromEnd(0) catch |err| {
                logger.warn("keylog: seekFromEnd failed: {s}", .{@errorName(err)});
            };

            var line = std.ArrayList(u8){};
            defer line.deinit(self.allocator.*);
            const w = line.writer(self.allocator.*);
            w.print("{s} ", .{label}) catch return false;
            for (client_random) |b| {
                w.print("{X:0>2}", .{b}) catch return false;
            }
            w.writeByte(' ') catch return false;
            for (secret.slice()) |b| {
                w.print("{X:0>2}", .{b}) catch return false;
            }
            w.writeByte('\n') catch return false;

            file.writeAll(line.items) catch |err| {
                logger.debugPrint("keylog: write failed ({s}): {}\n", .{ label, err });
                return false;
            };
            return true;
        }

        fn emitTrafficSecretUpdate(self: *Connection, label_prefix: []const u8, epoch: *u32, secret: *const ks.Secret) void {
            if (!self.keylog_app_logged) return;
            const client_random = currentClientRandom(self) orelse return;
            const next_epoch = epoch.* + 1;

            var label_buf: [64]u8 = undefined;
            const label = std.fmt.bufPrint(&label_buf, "{s}_{d}", .{ label_prefix, next_epoch }) catch return;
            if (appendKeyLogLine(self, label, &client_random, secret)) {
                epoch.* = next_epoch;
            }
        }

        pub fn maybeEmitHandshakeKeyLog(
            self: *Connection,
            client_secret: *const ks.Secret,
            server_secret: *const ks.Secret,
        ) void {
            if (self.keylog_handshake_logged) return;
            const client_random = currentClientRandom(self) orelse return;
            const wrote_client = appendKeyLogLine(self, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", &client_random, client_secret);
            const wrote_server = appendKeyLogLine(self, "SERVER_HANDSHAKE_TRAFFIC_SECRET", &client_random, server_secret);
            if (wrote_client and wrote_server) {
                self.keylog_handshake_logged = true;
            }
        }

        pub fn maybeEmitApplicationKeyLog(
            self: *Connection,
            client_secret: *const ks.Secret,
            server_secret: *const ks.Secret,
        ) void {
            if (self.keylog_app_logged) return;
            const client_random = currentClientRandom(self) orelse return;
            const wrote_client = appendKeyLogLine(self, "CLIENT_TRAFFIC_SECRET_0", &client_random, client_secret);
            const wrote_server = appendKeyLogLine(self, "SERVER_TRAFFIC_SECRET_0", &client_random, server_secret);
            if (wrote_client and wrote_server) {
                self.keylog_client_traffic_epoch = 0;
                self.keylog_server_traffic_epoch = 0;
                self.keylog_app_logged = true;
            }
        }

        pub fn maybeEmitTxKeyUpdateLog(self: *Connection, secret: *const ks.Secret) void {
            if (self.role == .Client) {
                emitTrafficSecretUpdate(self, "CLIENT_TRAFFIC_SECRET", &self.keylog_client_traffic_epoch, secret);
            } else {
                emitTrafficSecretUpdate(self, "SERVER_TRAFFIC_SECRET", &self.keylog_server_traffic_epoch, secret);
            }
        }

        pub fn maybeEmitRxKeyUpdateLog(self: *Connection, secret: *const ks.Secret) void {
            if (self.role == .Client) {
                emitTrafficSecretUpdate(self, "SERVER_TRAFFIC_SECRET", &self.keylog_server_traffic_epoch, secret);
            } else {
                emitTrafficSecretUpdate(self, "CLIENT_TRAFFIC_SECRET", &self.keylog_client_traffic_epoch, secret);
            }
        }

        pub fn storeNegotiatedAlpn(self: *Connection, alpn: []const u8) !void {
            if (self.negotiated_alpn) |existing| {
                if (std.mem.eql(u8, existing, alpn)) return;
                self.allocator.free(existing);
            }
            const copy = try self.allocator.dupe(u8, alpn);
            self.negotiated_alpn = copy;
        }

        pub fn storePeerTransportParams(self: *Connection, encoded: []const u8) !void {
            if (self.peer_transport_params_raw) |existing| {
                if (std.mem.eql(u8, existing, encoded)) return;
                self.allocator.free(existing);
            }
            const copy = try self.allocator.dupe(u8, encoded);
            self.peer_transport_params_raw = copy;
        }

        pub fn storeLocalTransportParams(self: *Connection, encoded: []const u8) !void {
            if (self.local_transport_params_raw) |existing| {
                if (std.mem.eql(u8, existing, encoded)) return;
                self.allocator.free(existing);
            }
            const copy = try self.allocator.dupe(u8, encoded);
            self.local_transport_params_raw = copy;
        }

        /// Cache negotiated ALPN for outer layers (tests/interop helpers may call directly).
        pub fn cacheNegotiatedAlpn(self: *Connection, alpn: []const u8) !void {
            try storeNegotiatedAlpn(self, alpn);
        }

        /// Cache peer transport parameters (encoded form) for reuse outside TLS.
        pub fn cachePeerTransportParams(self: *Connection, encoded: []const u8) !void {
            try storePeerTransportParams(self, encoded);
        }

        /// Set locally advertised transport parameters on TLS and cache them for QUIC wiring.
        pub fn setLocalTransportParameters(self: *Connection, encoded: []const u8) !void {
            if (self.tls_context) |tls_ctx| {
                try tls_ctx.setTransportParameters(encoded);
            }
            try storeLocalTransportParams(self, encoded);
        }

        /// Returns true once the TLS stack has verified the peer's Finished and 1-RTT TX keys are ready.
        pub fn hasConfirmedAppTxKeys(self: *const Connection) bool {
            return self.peer_finished_verified and self.app_tx_keys != null;
        }

        pub fn updatePeerFinishedStatus(self: *Connection, verified: bool) void {
            if (self.peer_finished_verified == verified) return;
            self.peer_finished_verified = verified;
            if (self.peer_finished_verified) {
                logger.debugPrint("{s}: Peer Finished verified; short-header transmission unlocked\n", .{if (self.role == .Server) "Server" else "Client"});
                // NOTE: Do NOT drop Handshake keys here! maybeDropHandshakeKeys() will handle it safely
                // after we finish processing the current packet.
            } else {
                logger.debugPrint("{s}: Peer Finished verification revoked\n", .{if (self.role == .Server) "Server" else "Client"});
            }
        }

        /// Send bytes to peer using configured sender callback; if none, act as no-op that accounts amplification.
        /// Send bytes via installed sender callback (accounting amplification); in tests with no sender, acts as no-op success.
        pub fn send(self: *Connection, data: []const u8) !usize {
            // Amplification guard: if address not validated and we already exceeded 3x budget, refuse to send
            if (self.overAmplification()) return error.WouldBlock;

            // PHASE 48 REMOVED: The crude congestion control check was blocking legitimate sends.
            // The recovery module already handles congestion control properly via onPacketSent/onAckReceived.
            // Congestion control is enforced through:
            // 1. onShortHeaderPacketSent() -> rec.onPacketSent() tracking bytes_in_flight
            // 2. onAckReceivedSpace() -> rec.onAckReceivedWithEcn() updating cwnd
            // 3. Loss detection and retransmission in recovery module
            // This allows proper slow-start, congestion avoidance, and pacing.

            if (self.sender_fn) |f| {
                const ctx = self.sender_ctx orelse return data.len;
                const n = try f(ctx, self, data);
                if (data.len == 141) {
                    logger.debugPrint("sender_fn returned {} bytes for 141-byte packet\n", .{n});
                }
                self.addTxUnvalidated(n);
                return n;
            }
            // Test mode: no endpoint sender installed; pretend all bytes were sent.
            if (data.len == 141) {
                logger.debugPrint("No sender_fn, test mode - pretending 141 bytes sent\n", .{});
            }
            self.addTxUnvalidated(data.len);
            return data.len;
        }

        /// Send CRYPTO frame data in an Initial packet (Phase 24)
        pub fn sendInitialCrypto(self: *Connection, crypto_data: []const u8) !void {
            const tx = self.initial_tx_keys orelse return error.NoKeys;

            // Build CRYPTO frame
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            const crypto_frame = frame.Frame{ .crypto = .{
                .offset = self.crypto_tx_off_initial,
                .data = crypto_data,
            } };
            _ = crypto_frame.write(w) catch return;

            // RFC 9000 §14.1: client Initial datagrams MUST be at least 1200 bytes.
            // RFC 9000 §8.1.2: client must echo Retry token on subsequent Initial packets.
            const token = if (self.role == .Client) self.initial_token.items else &[_]u8{};

            // Encode Initial packet
            var out = packet.encodeInitialProtected(
                self.allocator.*,
                self.version,
                self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len],
                self.our_scid.bytes[0..self.our_scid.len],
                token,
                @as(u32, @truncate(self.pn_initial_tx)),
                2, // pn_len
                frames.items,
                tx,
            ) catch return;
            if (self.role == .Client and out.len < 1200) {
                const pad_needed = 1200 - out.len;
                self.allocator.free(out);
                frames.appendNTimes(self.allocator.*, @intFromEnum(frame.FrameType.PADDING), pad_needed) catch return;
                out = packet.encodeInitialProtected(
                    self.allocator.*,
                    self.version,
                    self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len],
                    self.our_scid.bytes[0..self.our_scid.len],
                    token,
                    @as(u32, @truncate(self.pn_initial_tx)),
                    2,
                    frames.items,
                    tx,
                ) catch return;
            }

            defer self.allocator.free(out);
            _ = self.send(out) catch |err| {
                logger.warn("sendInitialCrypto send failed: {s}", .{@errorName(err)});
            };

            // Update state
            self.crypto_tx_off_initial += crypto_data.len;
            self.onPacketSent(.Initial, self.pn_initial_tx, out.len, true);
            self.pn_initial_tx +%= 1;

            logger.debugPrint("[sendInitialCrypto] Sent {} bytes of CRYPTO in Initial packet\n", .{crypto_data.len});
        }

        /// Send CRYPTO frame data in a Handshake packet (Phase 24)
        pub fn sendHandshakeCrypto(self: *Connection, crypto_data: []const u8) !void {
            const tx = self.hs_tx_keys orelse return error.NoKeys;

            // Build CRYPTO frame
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            const crypto_frame = frame.Frame{ .crypto = .{
                .offset = self.crypto_tx_off_handshake,
                .data = crypto_data,
            } };
            _ = crypto_frame.write(w) catch return;

            // Encode Handshake packet
            const out = packet.encodeHandshakeProtected(
                self.allocator.*,
                self.version,
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
                self.our_scid.bytes[0..self.our_scid.len],
                @as(u32, @truncate(self.pn_handshake_tx)),
                2, // pn_len
                frames.items,
                tx,
            ) catch return;

            defer self.allocator.free(out);
            _ = self.send(out) catch |err| {
                logger.warn("sendHandshakeCrypto send failed: {s}", .{@errorName(err)});
            };

            // Update state
            self.crypto_tx_off_handshake += crypto_data.len;
            // Mark that at least one Handshake packet has been transmitted.
            // This gates RFC 9001 Handshake key discard on the client path.
            self.handshake_packet_sent = true;
            self.onPacketSent(.Handshake, self.pn_handshake_tx, out.len, true);
            self.pn_handshake_tx +%= 1;

            logger.debugPrint("[sendHandshakeCrypto] Sent {} bytes of CRYPTO in Handshake packet\n", .{crypto_data.len});
        }

        /// Feed received CRYPTO bytes to the TLS Context and derive keys when secrets become available.
        pub fn pushCrypto(self: *Connection, hs: []const u8) !void {
            const tls_ctx = self.tls_context orelse return; // No-op if TLS Context not initialized (test scenarios)

            // Determine encryption level based on which keys are installed.
            // NOTE: hs_rx_keys must be checked BEFORE app_rx_keys because the server
            // installs Application rx keys during Initial processing (via onSecretAvailable),
            // so when it later receives the client's Handshake Finished, both hs_rx_keys and
            // app_rx_keys are non-null. The correct level is Handshake — that is what the
            // caller (handleHandshakeCrypto) is processing.
            const level: tls13.EncryptionLevel = blk: {
                if (self.hs_rx_keys != null) break :blk .Handshake;
                if (self.app_rx_keys != null) break :blk .Application;
                break :blk .Initial;
            };

            logger.debugPrint("pushCrypto: role={s}, level={s}, hs_len={}\n", .{
                if (self.role == .Server) "Server" else "Client",
                @tagName(level),
                hs.len,
            });
            if (self.role == .Client and level == .Handshake) {
                const head_len: usize = if (hs.len < 16) hs.len else 16;
                logger.debugPrint("[TLS-HS-CLIENT] Handshake bytes head ({}): {any}\n", .{ head_len, hs[0..head_len] });
                if (hs.len > 96) {
                    const mid_start: usize = 80;
                    const mid_end: usize = if (hs.len < 112) hs.len else 112;
                    logger.debugPrint("[TLS-HS-CLIENT] Handshake bytes mid ({}..{}): {any}\n", .{ mid_start, mid_end, hs[mid_start..mid_end] });
                }
                var h = std.hash.Wyhash.init(0);
                h.update(hs);
                const hash = h.final();
                const tail_len: usize = if (hs.len < 16) hs.len else 16;
                logger.debugPrint("[TLS-HS-CLIENT] Handshake hash=0x{X:0>16}, tail ({}): {any}\n", .{
                    hash,
                    tail_len,
                    hs[hs.len - tail_len ..],
                });
            }

            // NOTE: Caller must set current connection context via handshake_integration.setCurrentConnection()
            // before calling this function for TLS Context callbacks to work properly

            // Process CRYPTO data through TLS Context
            tls_ctx.processCrypto(level, hs) catch |err| {
                logger.debugPrint("pushCrypto: processCrypto failed with error: {}\n", .{err});
                logger.debugPrint("  role={s}, level={s}, hs_len={}\n", .{
                    if (self.role == .Server) "Server" else "Client",
                    @tagName(level),
                    hs.len,
                });
                return err;
            };

            // Phase 24 FIX: Poll for client's Finished message after processing server's Finished
            // The server has separate code in handshake_integration.zig that sends its messages.
            // But the client needs to poll and send its Finished after verifying server's Finished.
            // Only poll at Handshake level when we're a CLIENT and just processed Handshake CRYPTO.
            if (self.role == .Client and level == .Handshake) {
                if (tls_ctx.pollCrypto(self.allocator.*, .Handshake)) |outgoing_crypto| {
                    defer self.allocator.free(outgoing_crypto);

                    logger.debugPrint("[pushCrypto] Client polled {} bytes of outgoing CRYPTO at Handshake level\n", .{outgoing_crypto.len});

                    // Send the client's Finished message in Handshake packet
                    if (outgoing_crypto.len > 0) {
                        try self.sendHandshakeCrypto(outgoing_crypto);

                        // CRITICAL: Mark that we sent our Finished message so TLS Context knows
                        // This allows Application key derivation to proceed (requires both
                        // peer_finished_verified AND local_finished_sent to be true)
                        try tls_ctx.markLocalFinished();
                        logger.debugPrint("[pushCrypto] Client marked local_finished_sent=true\n", .{});
                    }
                } else |err| {
                    // Unimplemented means no outgoing data
                    if (err != error.Unimplemented) {
                        logger.debugPrint("[pushCrypto] Error polling Handshake CRYPTO: {}\n", .{err});
                    }
                }
            }

            // Check for and install Handshake keys if now available
            if (self.hs_client == null or self.hs_server == null) {
                const client_slot = tls_ctx.secrets.slot(.Handshake, .send);
                const server_slot = tls_ctx.secrets.slot(.Handshake, .recv);

                if (client_slot.valid and server_slot.valid) {
                    logger.debugPrint("{s}: Handshake secrets available, installing keys\n", .{if (self.role == .Server) "Server" else "Client"});
                    self.hs_client = client_slot.value;
                    self.hs_server = server_slot.value;
                    self.deriveHandshakeKeys(self.version_v2);
                }
            }

            // Install 1-RTT keys when both Finished messages exchanged and CRYPTO outbox flushed
            logger.debugPrint("[pushCrypto] Checking if should derive Application keys: app_tx_keys={any}, conn={*}\n", .{ self.app_tx_keys != null, self });
            if (self.app_tx_keys == null) {
                const flags = tls_ctx.flags;
                // NOTE: Use Connection's peer_finished_verified (set by callback), not TLS Context's flag
                logger.debugPrint("[pushCrypto] Flags: conn={*}, conn.peer_finished_verified={}, flags.local_finished_sent={}\n", .{ self, self.peer_finished_verified, flags.local_finished_sent });
                if (self.peer_finished_verified and flags.local_finished_sent) {
                    // Check if Context has pending CRYPTO data to send
                    // Context manages outgoing CRYPTO via callbacks, so we check if secrets are ready
                    const send_slot = tls_ctx.secrets.slot(.Application, .send);
                    const recv_slot = tls_ctx.secrets.slot(.Application, .recv);

                    if (send_slot.valid and recv_slot.valid) {
                        // Phase 24 FIX: Slots are role-relative (.send/.recv depend on role)
                        // CLIENT: send=client secret, recv=server secret
                        // SERVER: send=server secret, recv=client secret
                        // But deriveAppKeys expects (client_secret, server_secret) regardless of role
                        const client_secret = if (self.role == .Client) send_slot.value else recv_slot.value;
                        const server_secret = if (self.role == .Client) recv_slot.value else send_slot.value;

                        logger.debugPrint("{s}: Deriving application secrets (both Finished exchanged)\n", .{if (self.role == .Server) "Server" else "Client"});
                        self.deriveAppKeys(client_secret, server_secret, self.version_v2);
                    }
                } else if (self.peer_finished_verified and !flags.local_finished_sent) {
                    logger.debugPrint("{s}: Deferring 1-RTT key derivation until our Finished is sent\n", .{if (self.role == .Server) "Server" else "Client"});
                }
            }

            // Server: Send HANDSHAKE_DONE if Application keys installed but not yet sent
            if (self.role == .Server and self.app_tx_keys != null and !self.handshake_done_sent and self.hasConfirmedAppTxKeys()) {
                logger.debugPrint("Server: Sending HANDSHAKE_DONE\n", .{});
                self.advertiseInitialFlowControl();
                self.initial_keys_dropped = true;
                self.initial_rx_keys = null;
                self.initial_tx_keys = null;

                // Build and send HANDSHAKE_DONE frame
                var frames_list = std.ArrayList(u8){};
                defer frames_list.deinit(self.allocator.*);
                const w = frames_list.writer(self.allocator.*);
                _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
                // FIXED: Do NOT send MAX_STREAM_DATA for stream 0 unconditionally.
                // _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_data = .{ .max = self.local_max_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(w) catch 0;

                logger.debugPrint("Server: Sending control frames ({} bytes):", .{frames_list.items.len});
                for (frames_list.items) |b| logger.debugPrint(" 0x{X:0>2}", .{b});
                logger.debugPrint("\n", .{});

                const tx = self.app_tx_keys.?;
                const packet_storage = try self.packet_pool.checkout();
                defer self.packet_pool.release(packet_storage);
                const pkt_len = packet.encodeShortProtectedInto(
                    packet_storage,
                    self.shortHeaderDcid(),
                    @as(u32, @truncate(self.pn_app_tx)),
                    2,
                    frames_list.items,
                    .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                    self.tx_key_phase,
                ) catch 0;
                if (pkt_len != 0) {
                    const pkt = packet_storage[0..pkt_len];
                    _ = self.send(pkt) catch |err| {
                        logger.warn("HANDSHAKE_DONE send failed: {s}", .{@errorName(err)});
                    };
                    self.onShortHeaderPacketSent(pkt.len, true);
                }
                self.handshake_done_sent = true;
            }

            // Apply peer transport parameters (once) when they first become available
            if (!self.transport_params_applied) {
                if (tls_ctx.peer_quic_transport_parameters) |peer_tp_bytes| {
                    self.applyPeerTransportParameters(peer_tp_bytes) catch {
                        // Ignore malformed transport parameters; retain defaults
                    };
                    storePeerTransportParams(self, peer_tp_bytes) catch |err| {
                        logger.err("storePeerTransportParams failed (OOM): {s}", .{@errorName(err)});
                    };
                }
            }

            // Store negotiated ALPN (ALPN validation removed - was incorrectly revoking peer_finished_verified)
            // Note: Applications should validate ALPN after handshake completion if needed
            if (tls_ctx.negotiatedAlpn()) |a| {
                storeNegotiatedAlpn(self, a) catch |err| {
                    logger.err("storeNegotiatedAlpn failed (OOM): {s}", .{@errorName(err)});
                };
                // REMOVED: ALPN mismatch should not revoke peer_finished_verified flag
                // The peer's Finished message was cryptographically verified by TLS
                // If ALPN validation is needed, it should be done at application level
                // and result in connection closure, not silent handshake stall
            }
        }

        pub fn afterInitialCryptoChunk(self: *Connection) void {
            _ = self;
        }

        pub fn processBufferedInitial(
            self: *Connection,
            allocator: *std.mem.Allocator,
        ) !void {
            // NOTE: Caller must set current connection context via handshake_integration.setCurrentConnection()
            // before calling this function for TLS Context to work properly (Phase 21.2)
            while (self.crypto_buffer_initial.getContiguous(self.crypto_rx_off_initial)) |fragments| {
                for (fragments) |frag| {
                    if (frag.data.len == 0) continue;
                    try self.pushCrypto(frag.data);
                    self.crypto_rx_off_initial += @intCast(frag.data.len);
                    afterInitialCryptoChunk(self);
                }

                self.crypto_buffer_initial.removeProcessed(fragments.len, allocator.*);
            }
        }

        pub fn processBufferedHandshake(
            self: *Connection,
            allocator: *std.mem.Allocator,
        ) !void {
            // NOTE: Caller must set current connection context via handshake_integration.setCurrentConnection()
            // before calling this function for TLS Context to work properly (Phase 21.2)
            while (self.crypto_buffer_handshake.getContiguous(self.crypto_rx_off_handshake)) |fragments| {
                for (fragments) |frag| {
                    if (frag.data.len == 0) continue;
                    try self.pushCrypto(frag.data);
                    self.crypto_rx_off_handshake += @intCast(frag.data.len);
                }

                self.crypto_buffer_handshake.removeProcessed(fragments.len, allocator.*);
            }
        }

        pub fn handleCryptoFrameGeneric(
            self: *Connection,
            allocator: *std.mem.Allocator,
            offset: u64,
            data: []const u8,
            expected_offset: *u64,
            buffer: anytype,
            after: anytype,
            continuation: anytype,
        ) !bool {
            var ack_eliciting = false;
            const expected = expected_offset.*;
            const is_handshake = expected_offset == &self.crypto_rx_off_handshake;
            if (self.role == .Client and is_handshake) {
                logger.debugPrint("[CRYPTO-HS-CLIENT] recv offset={} len={} expected={}\n", .{ offset, data.len, expected });
            }

            if (offset == expected) {
                if (data.len > 0) {
                    try self.pushCrypto(data);
                    expected_offset.* += @intCast(data.len);
                    ack_eliciting = true;
                    try after(self);
                }
                try continuation(self, allocator);
            } else if (offset > expected) {
                try buffer.add(offset, data, allocator.*);
                if (data.len > 0) ack_eliciting = true;
            } else {
                const overlap = expected - offset;
                if (overlap < data.len) {
                    const new_data = data[@intCast(overlap)..];
                    if (new_data.len > 0) {
                        try self.pushCrypto(new_data);
                        expected_offset.* += @intCast(new_data.len);
                        ack_eliciting = true;
                        try after(self);
                        try continuation(self, allocator);
                    }
                } else if (data.len > 0) {
                    // Full duplicate CRYPTO frame.
                    // Keep this ack-eliciting so the endpoint can emit ACKs and
                    // retransmit pending handshake flight data (e.g., lost HRR/SH).
                    ack_eliciting = true;
                }
            }

            return ack_eliciting;
        }

        pub fn afterInitialWrapper(self: *Connection) !void {
            afterInitialCryptoChunk(self);
        }

        pub fn afterHandshakeWrapper(self: *Connection) !void {
            _ = self;
            // no-op for handshake space
        }

        pub fn continueInitial(self: *Connection, allocator: *std.mem.Allocator) !void {
            try processBufferedInitial(self, allocator);
        }

        pub fn continueHandshake(self: *Connection, allocator: *std.mem.Allocator) !void {
            try processBufferedHandshake(self, allocator);
        }

        pub fn handleInitialCrypto(
            self: *Connection,
            allocator: *std.mem.Allocator,
            offset: u64,
            data: []const u8,
        ) !bool {
            return handleCryptoFrameGeneric(
                self,
                allocator,
                offset,
                data,
                &self.crypto_rx_off_initial,
                &self.crypto_buffer_initial,
                afterInitialWrapper,
                continueInitial,
            );
        }

        pub fn handleHandshakeCrypto(
            self: *Connection,
            allocator: *std.mem.Allocator,
            offset: u64,
            data: []const u8,
        ) !bool {
            return handleCryptoFrameGeneric(
                self,
                allocator,
                offset,
                data,
                &self.crypto_rx_off_handshake,
                &self.crypto_buffer_handshake,
                afterHandshakeWrapper,
                continueHandshake,
            );
        }

        /// Attempt to derive 1-RTT keys if both Finished messages have been exchanged.
        /// This is called after outgoing packets are sent to check if Application secrets are ready.
        pub fn maybeDeriveAppKeysAfterFlush(self: *Connection) void {
            if (self.app_tx_keys != null) return;

            const tls_ctx = self.tls_context orelse return;
            const flags = tls_ctx.flags;
            if (!(flags.peer_finished_verified and flags.local_finished_sent)) return;

            // Check if Application secrets are available
            const send_slot = tls_ctx.secrets.slot(.Application, .send);
            const recv_slot = tls_ctx.secrets.slot(.Application, .recv);

            if (send_slot.valid and recv_slot.valid) {
                // Phase 24 FIX: Slots are role-relative (.send/.recv depend on role)
                // CLIENT: send=client secret, recv=server secret
                // SERVER: send=server secret, recv=client secret
                // But deriveAppKeys expects (client_secret, server_secret) regardless of role
                const client_secret = if (self.role == .Client) send_slot.value else recv_slot.value;
                const server_secret = if (self.role == .Client) recv_slot.value else send_slot.value;

                logger.debugPrint("{s}: Deriving application secrets (maybeDeriveAppKeysAfterFlush)\n", .{if (self.role == .Server) "Server" else "Client"});
                self.deriveAppKeys(client_secret, server_secret, self.version_v2);
            }
        }

        /// Get negotiated ALPN if any.
        /// Return negotiated ALPN slice (if any) after handshake progression.
        pub fn getNegotiatedAlpn(self: *Connection) ?[]const u8 {
            if (self.negotiated_alpn) |alpn| return alpn;
            if (self.tls_context) |tls_ctx| {
                return tls_ctx.negotiatedAlpn();
            }
            return null;
        }

        /// Return cached peer transport parameters (encoded) if available.
        pub fn getPeerTransportParams(self: *Connection) ?[]const u8 {
            if (self.peer_transport_params_raw) |tp| return tp;
            if (self.tls_context) |tls_ctx| {
                return tls_ctx.peer_quic_transport_parameters;
            }
            return null;
        }

        /// Return locally advertised transport parameters (encoded) if cached.
        pub fn getLocalTransportParams(self: *Connection) ?[]const u8 {
            if (self.local_transport_params_raw) |tp| return tp;
            if (self.tls_context) |tls_ctx| {
                return tls_ctx.localTransportParameters();
            }
            return null;
        }

        /// Toggle congestion control (NewReno default, CUBIC optional).
        /// Switch congestion control mode between NewReno (false) and CUBIC (true).
        pub fn setUseCubic(self: *Connection, use: bool) void {
            self.use_cubic = use;
            self.rec.setCcMode(use);
        }

        /// Congestion control shim: record packet sent.
        pub fn ccOnPacketSent(self: *Connection, bytes: usize, ack_eliciting: bool) void {
            // Legacy shim retained for compatibility; Recovery.cc is authoritative for new paths.
            if (self.use_cubic) {
                self.cc_cubic.onPacketSent(bytes, ack_eliciting);
            } else {
                self.cc_nr.onPacketSent(bytes, ack_eliciting);
            }
        }

        /// Congestion control shim: on ACK.
        pub fn ccOnAck(self: *Connection, bytes_acked: usize) void {
            // Legacy shim retained for compatibility.
            if (self.use_cubic) {
                self.cc_cubic.onAck(bytes_acked);
            } else {
                self.cc_nr.onAck(bytes_acked);
            }
        }

        /// Congestion control shim: on loss.
        pub fn ccOnLoss(self: *Connection, bytes_lost: usize) void {
            // Legacy shim retained for compatibility.
            if (self.use_cubic) {
                self.cc_cubic.onLoss(bytes_lost);
            } else {
                self.cc_nr.onLoss(bytes_lost);
            }
        }

        /// Update peer Initial DCID/SCID (observed in Initial packet).
        /// Record peer's Initial DCID/SCID values observed to support VN/Retry logic.
        pub fn setPeerInitialCids(self: *Connection, dcid: []const u8, scid: []const u8) void {
            logger.debugPrint("setPeerInitialCids: ENTER - dcid.len={}, scid.len={}\n", .{ dcid.len, scid.len });
            self.peer_initial_dcid.len = @intCast(@min(dcid.len, self.peer_initial_dcid.bytes.len));
            if (self.peer_initial_dcid.len > 0) @memcpy(self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len], dcid[0..self.peer_initial_dcid.len]);
            // Capture original destination connection ID (ODCID) only once (first client Initial).
            if (self.original_dcid.len == 0) {
                self.original_dcid.len = self.peer_initial_dcid.len;
                if (self.original_dcid.len > 0) @memcpy(self.original_dcid.bytes[0..self.original_dcid.len], self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]);
            }
            logger.debugPrint("setPeerInitialCids: Before setting peer_initial_scid, current len={}\n", .{self.peer_initial_scid.len});
            self.peer_initial_scid.len = @intCast(@min(scid.len, self.peer_initial_scid.bytes.len));
            if (self.peer_initial_scid.len > 0) @memcpy(self.peer_initial_scid.bytes[0..self.peer_initial_scid.len], scid[0..self.peer_initial_scid.len]);

            // Reset any cached DCID length hint. The peer may shorten the DCID once
            // the handshake completes, so defer caching until we successfully
            // authenticate a 1-RTT packet and observe the actual length in use.
            self.expected_rx_dcid_len = null;

            logger.debugPrint("setPeerInitialCids: EXIT - peer_initial_dcid.len={}, peer_initial_scid.len={}\n", .{ self.peer_initial_dcid.len, self.peer_initial_scid.len });
        }

        /// Ingest a STREAM frame payload into the RX buffer for the stream with reassembly.
        /// Ingest STREAM frame data (copy + reassembly); updates flow-control windows heuristically.
        /// CWE-366 mitigation: Thread-safe - acquires connection mutex to protect stream maps.
        pub fn pushStreamFrame(self: *Connection, stream_id: u64, offset: u64, data: []const u8, fin: bool) !void {
            self.mu.lock();
            defer self.mu.unlock();

            logger.debugPrint("[CONN-PTR-PUSH] conn=0x{x} stream_id={}\n", .{ @intFromPtr(self), stream_id });
            logger.debugPrint("[STREAM-RX] id={} off={} len={} fin={} before recv_off={} inbox_len={} bufs={}\n", .{ stream_id, offset, data.len, fin, if (self.streams_rx.getPtr(stream_id)) |sr| sr.recv_off else 0, if (self.streams_rx.getPtr(stream_id)) |sr| sr.inbox.items.len else 0, if (self.streams_rx.getPtr(stream_id)) |sr| sr.bufs.items.len else 0 });
            if (self.stream_recv_aborted) return; // ignore further data after RESET_STREAM

            logger.debugPrint("\n=== PUSH_STREAM_FRAME ENTRY ===\n", .{});
            logger.debugPrint("stream_id={}, offset={}, len={}, fin={}, role={}\n", .{ stream_id, offset, data.len, fin, self.role });

            // CWE-400 mitigation: Validate peer-initiated streams don't exceed our limits.
            // RFC 9000 §4.6: Peers MUST NOT exceed our advertised MAX_STREAMS limits.
            // If exceeded, this is a STREAM_LIMIT_ERROR (0x04) per RFC 9000 §20.
            try self.validatePeerStreamLimit(stream_id);

            logger.debugPrint("Calling ensureStreamRx({})...\n", .{stream_id});
            const s = self.ensureStreamRx(stream_id);
            logger.debugPrint("After ensureStreamRx: streams_rx now has {} entries\n", .{self.streams_rx.count()});

            // PHASE 57 PART 6: Always re-queue streams when new data arrives
            // This matches the design intent from Phase 42 Part 15 (see queueIncomingStream comment)
            // The application drains the queue via acceptStream() in a tight loop, so duplicates
            // are processed quickly and provide notification that more data is available.

            if (fin) {
                const end_off: u64 = offset + @as(u64, data.len);
                s.fin_off = end_off;
                self.stream_recv_fin = true;
            }
            if (data.len > 0) {
                s.insert(self.allocator, offset, data);
                s.tryDrain(self.allocator);
                logger.debugPrint("[STREAM-RX-AFTER] id={} recv_off={} inbox_len={} bufs={} fin_off={?}\n", .{ stream_id, s.recv_off, s.inbox.items.len, s.bufs.items.len, s.fin_off });
            }

            // Queue stream every time new data arrives (not just first time)
            const is_peer_initiated = self.isPeerInitiatedStream(stream_id);
            const has_data_now = (s.inbox.items.len > 0);

            if (is_peer_initiated and has_data_now) {
                try self.queueIncomingStream(stream_id);
                logger.debugPrint("[P57-6-QUEUE] Stream {} queued ({} bytes in inbox, {} total in queue)\n", .{ stream_id, s.inbox.items.len, self.incoming_stream_queue.items.len });
            }

            // PHASE 57 PART 13: Send initial MAX_STREAM_DATA when stream receives first data
            // This ensures the peer knows the initial window size immediately, not just after first read
            // Note: Subsequent updates are sent in readStream() when application consumes data
            if (is_peer_initiated and s.last_sent_max_stream_data == 0 and self.hasConfirmedAppTxKeys()) {
                // Initialize local_max_stream_data to initial window size for new streams
                const receive_window = if (s.initial_window_size > 0) s.initial_window_size else self.local_max_stream_data;
                s.local_max_stream_data = receive_window; // bytes_consumed_total is 0 for new streams
                self.markStreamFlowControlDirty(stream_id);
                // Send initial MAX_STREAM_DATA to advertise the window
                self.advertiseInitialFlowControl();
            }
            // Auto-echo implementation DISABLED: This conflicts with application-level echo servers.
            // The auto-echo would send "Hello QUIC\n" (11 bytes) on stream 0 with offset=0 and FIN=true,
            // then the application would send its own response also with offset=0 and FIN=true,
            // causing FINAL_SIZE_ERROR because the client sees two different final sizes (11 vs actual).
            // Applications should handle their own echo logic (see cmd/quic-server.zig).
            _ = self.app_echo_sent; // Suppress unused field warning
            // Update connection RX accounting
            self.conn_recv_total +%= data.len;
            // PHASE 57 PART 11: Flow control is now handled in readStream() using quinn-style calculation
            // (max_stream_data = bytes_consumed + receive_window)
            // We no longer expand windows here based on recv_off, as that conflicts with the quinn approach.
            // Window updates are triggered when the application consumes data via readStream().
            // Connection-level flow control expansion is handled separately if needed.
        }

        /// Ingest a DATAGRAM frame payload (owned copy).
        /// Append an incoming DATAGRAM frame payload (owned copy) to inbox.
        pub fn pushDatagram(self: *Connection, data: []const u8) !void {
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            try self.dgram_inbox.append(self.allocator.*, owned);
        }

        /// Pop a DATAGRAM payload into buf; returns length copied or error if none.
        /// Pop next DATAGRAM payload into provided buffer; returns bytes copied or WouldBlock if none.
        /// Uses swapRemove for O(1) dequeue — datagram delivery order is not guaranteed.
        pub fn popDatagram(self: *Connection, buf: []u8) !usize {
            if (self.dgram_inbox.items.len == 0) return error.WouldBlock;
            const p = self.dgram_inbox.swapRemove(0);
            const n = @min(buf.len, p.len);
            @memcpy(buf[0..n], p[0..n]);
            self.allocator.free(p);
            return n;
        }

        /// No-op compatibility shim so Connection can be passed where an Endpoint is expected.
        /// This satisfies ep.scheduleConnPto(self, kind, delay_ms) used in some helpers.
        /// Compatibility shim for scheduling PTO timers when a Connection is used stand-alone in tests.
        pub fn scheduleConnPto(self: *Connection, _c: *Connection, kind: anytype, delay_ms: u32) !u64 {
            _ = self;
            _ = _c;
            _ = kind;
            _ = delay_ms;
            return 0;
        }

        /// PTO expiry hook for Initial space: clears active flag, increments per-space
        /// and global recovery PTO backoff counters, and schedules a PING probe packet
        /// (Initial keys) to elicit acknowledgment and re-establish RTT/loss timers.
        pub fn setPtoExpiredInitial(self: *Connection) void {
            if (!self.pto_initial_active) return;
            self.pto_initial_active = false;
            self.pto_initial_count +%= 1;
            // Increase recovery PTO backoff counter (shared across spaces) per RFC 9002.
            self.rec.pto_count +%= 1;
            self.sendPtoProbeInitial();
        }
        /// PTO expiry hook for Handshake space: clears active flag, increments counters
        /// and sends a Handshake PING probe to drive handshake completion under loss.
        pub fn setPtoExpiredHandshake(self: *Connection) void {
            if (!self.pto_handshake_active) return;
            self.pto_handshake_active = false;
            self.pto_handshake_count +%= 1;
            self.rec.pto_count +%= 1;
            self.sendPtoProbeHandshake();
        }
        /// PTO expiry hook for Application space: clears active flag, increments per-space
        /// and global recovery PTO counters, then sends a 1-RTT PING probe (with padding
        /// if needed) to re-arm loss detection and capture fresh RTT samples.
        pub fn setPtoExpiredApp(self: *Connection) void {
            if (!self.pto_app_active) return;
            self.pto_app_active = false;
            self.pto_app_count +%= 1;
            // Also bump recovery PTO backoff counter
            self.rec.pto_count +%= 1;
            self.sendPtoProbeApp();
        }

        /// Send a PATH_CHALLENGE on the 1-RTT path to validate current peer path.
        /// RFC 9000 §9.1/§9.3 require endpoints to probe a new path using
        /// PATH_CHALLENGE/RESPONSE pairs before migrating traffic; we mark
        /// validation pending until a matching PATH_RESPONSE arrives.
        pub fn sendPathChallenge(self: *Connection) void {
            if (!self.hasConfirmedAppTxKeys()) {
                // No confirmed 1-RTT keys yet (e.g. test setup); still mark validation pending and seed challenge data.
                std.crypto.random.bytes(&self.path_challenge_data);
                self.path_validation_pending = true;
                return;
            }
            const tx = self.app_tx_keys.?;
            // Generate opaque 8-byte data and remember for validation
            std.crypto.random.bytes(&self.path_challenge_data);
            self.path_validation_pending = true;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .path_challenge = self.path_challenge_data }).write(w) catch 0;

            const packet_storage = self.packet_pool.checkout() catch return;
            defer self.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                @as(u32, @truncate(self.pn_app_tx)),
                2,
                frames.items,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch 0;
            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                // Path validation probes should be sent immediately on address change.
                // Bypass pacing here so PATH_CHALLENGE is the first packet emitted
                // on the new path.
                const was_pacing_enabled = self.enable_pacing;
                self.enable_pacing = false;
                defer self.enable_pacing = was_pacing_enabled;
                _ = self.send(pkt) catch |err| {
                    logger.warn("PATH_CHALLENGE send failed: {s}", .{@errorName(err)});
                };
                self.onShortHeaderPacketSent(pkt.len, true);
            }
        }

        pub fn sendControlFrames(self: *Connection, frames_bytes: []const u8) void {
            if (!self.hasConfirmedAppTxKeys()) return;
            const tx = self.app_tx_keys.?;
            logger.debugPrint("{s}: Sending control frames ({d} bytes)\n", .{ if (self.role == .Server) "Server" else "Client", frames_bytes.len });
            const packet_storage = self.packet_pool.checkout() catch return;
            defer self.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                @as(u32, @truncate(self.pn_app_tx)),
                2,
                frames_bytes,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch 0;
            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                _ = self.send(pkt) catch |err| {
                    logger.warn("sendControlFrames send failed: {s}", .{@errorName(err)});
                };
                self.onShortHeaderPacketSent(pkt.len, true);
            }
        }

        /// Enable 0-RTT for this connection (client-side)
        pub fn enable0RTT(self: *Connection, ticket: []const u8, secret: [32]u8) void {
            self.session_ticket = ticket;
            self.resumption_secret = secret;
            self.zero_rtt_enabled = true;
            // Derive 0-RTT keys from resumption secret
            // This is a simplified implementation - full implementation would need proper key derivation
            const zero_rtt_secret = ks.deriveSecret(secret, "c e traffic", &[_]u8{});
            const keys = if (self.version_v2) ks.deriveKeyIvHpV2(zero_rtt_secret) else ks.deriveKeyIvHp(zero_rtt_secret);
            self.zero_rtt_keys = .{ .key = keys.key, .iv = keys.iv, .hp = keys.hp };
        }

        /// Accept 0-RTT data from the peer (server-side).
        ///
        /// When an anti-replay cache is attached (see `anti_replay_cache`), the
        /// peer's Initial DCID is hashed and checked against previously-seen
        /// values. If the hash was already recorded within the time window the
        /// 0-RTT data is rejected as a replay (RFC 8446 §8, RFC 9001 §9.2).
        ///
        /// When no cache is present (backwards-compatible path) the 0-RTT is
        /// accepted unconditionally and a warning is emitted.
        pub fn accept0RTT(self: *Connection) void {
            if (self.anti_replay_cache) |cache| {
                // Build a ticket fingerprint from the peer's Initial DCID.
                // This CID is chosen randomly by the client for each new
                // connection attempt so it uniquely identifies the 0-RTT
                // offer within the cache window.
                const ticket_hash = std.hash.Wyhash.hash(
                    0,
                    self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len],
                );

                const now_ns: u64 = @intCast(@max(0, std.time.nanoTimestamp()));

                const is_fresh = cache.checkAndRecord(ticket_hash, now_ns) catch {
                    // On allocation failure, reject 0-RTT to be safe.
                    logger.debugPrint("0-RTT rejected: anti-replay cache allocation failure\n", .{});
                    return;
                };

                if (!is_fresh) {
                    logger.debugPrint("0-RTT rejected: replay detected by anti-replay cache (RFC 8446 S8)\n", .{});
                    return;
                }

                logger.debugPrint("0-RTT accepted: anti-replay cache check passed\n", .{});
            } else {
                logger.debugPrint("WARNING: 0-RTT accepted without anti-replay protection\n", .{});
            }
            self.zero_rtt_accepted = true;
        }

        /// Mark initial flow-control limits for transmission (sets flags so MAX_* frames are sent).
        pub fn advertiseInitialFlowControl(self: *Connection) void {
            if (!self.hasConfirmedAppTxKeys()) return;
            if (!self.canSendUnderAmplification()) return;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            var wrote: bool = false;

            // PHASE 46: Quinn-style flow control with 1/8 threshold
            // Only send MAX_STREAM_DATA when increase is significant (at least 1/8 of window)
            if (self.streams_rx_init) {
                var it = self.streams_rx.iterator();
                while (it.next()) |entry| {
                    const stream_id = entry.key_ptr.*;
                    const stream_rx = entry.value_ptr;

                    // Calculate the increase amount
                    const increase = stream_rx.local_max_stream_data -| stream_rx.last_sent_max_stream_data;

                    // Calculate threshold (1/8 of initial window size to avoid division)
                    // Use initial_window_size if set, otherwise fall back to current window
                    const window = if (stream_rx.initial_window_size > 0)
                        stream_rx.initial_window_size
                    else
                        stream_rx.local_max_stream_data;
                    const threshold = window >> 3; // Divide by 8 using bit shift (256KB for 2MB window)

                    // PHASE 57 PART 12: Use minimum threshold to ensure frequent updates for small reads
                    // With 4KB reads, we need updates more frequently than every 256KB
                    // Use minimum of 1/8 window or 32KB to ensure updates happen at least every 8 reads
                    const min_threshold: u64 = 32 * 1024; // 32KB minimum
                    const effective_threshold = @min(threshold, min_threshold);

                    // Only send if increase is significant (at least threshold)
                    if (increase >= effective_threshold and increase > 0) {
                        _ = (frame.Frame{ .max_stream_data = .{ .stream_id = stream_id, .max = stream_rx.local_max_stream_data } }).write(w) catch 0;
                        stream_rx.last_sent_max_stream_data = stream_rx.local_max_stream_data;
                        wrote = true;
                        logger.debugPrint("[PHASE 46] Sending MAX_STREAM_DATA for stream {}: max={} (increase={}, threshold={})\n", .{ stream_id, stream_rx.local_max_stream_data, increase, effective_threshold });
                    }
                }
            }

            // Also handle the legacy stream 0 fields for backward compatibility
            if (self.local_max_stream_data > self.last_sent_max_stream_data) {
                // Only send for stream 0 if not already handled above
                if (!self.streams_rx_init or self.streams_rx.get(0) == null) {
                    // FIXED: Do NOT send MAX_STREAM_DATA for stream 0 in legacy block.
                    // _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
                    self.last_sent_max_stream_data = self.local_max_stream_data;
                    wrote = true;
                }
            }

            if (self.local_max_data > self.last_sent_max_data) {
                _ = (frame.Frame{ .max_data = .{ .max = self.local_max_data } }).write(w) catch 0;
                self.last_sent_max_data = self.local_max_data;
                wrote = true;
            }
            if (self.local_max_streams_bidi > self.last_sent_max_streams_bidi) {
                _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(w) catch 0;
                self.last_sent_max_streams_bidi = self.local_max_streams_bidi;
                wrote = true;
            }
            if (wrote) sendControlFrames(self, frames.items);
        }
    };
}
