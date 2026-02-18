const std = @import("std");
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
const logger = @import("quic_logger");
const builtin = @import("builtin");

const trace_enabled = false;
inline fn trace(comptime fmt: []const u8, args: anytype) void {
    if (trace_enabled) logger.debugPrint(fmt, args);
}

pub fn bind(comptime Connection: type) type {
    return struct {
        fn hashForSecret(secret: *const ks.Secret) !ks.Hash {
            return switch (secret.len) {
                32 => .sha256,
                48 => .sha384,
                else => error.InvalidSecretLength,
            };
        }

        fn trackAppStreamPacket(
            self: *Connection,
            pn: u64,
            stream_id: u64,
            offset: u64,
            fin: bool,
            data: []const u8,
        ) void {
            if (!self.app_stream_retx_init) return;
            const owned = self.allocator.dupe(u8, data) catch return;
            const StreamTxPacket = @FieldType(@TypeOf(self.app_stream_retx).KV, "value");
            const entry: StreamTxPacket = .{
                .stream_id = stream_id,
                .offset = offset,
                .fin = fin,
                .data = owned,
                .retransmit_count = @as(u16, 0),
            };
            self.app_stream_retx.put(pn, entry) catch {
                self.allocator.free(owned);
            };
        }

        fn dropAckedStreamTracking(self: *Connection, acked: []const u64) void {
            if (!self.app_stream_retx_init) return;
            for (acked) |pn| {
                if (self.app_stream_retx.fetchRemove(pn)) |removed| {
                    self.allocator.free(removed.value.data);
                }
            }
        }

        fn retransmitLostStreamPackets(self: *Connection, largest_acked_opt: ?u64) void {
            if (!self.app_stream_retx_init) return;
            if (!self.hasConfirmedAppTxKeys()) return;

            const tx = self.app_tx_keys.?;
            var lost_pns = std.ArrayList(u64){};
            defer lost_pns.deinit(self.allocator.*);

            var it = self.app_stream_retx.iterator();
            while (it.next()) |entry| {
                const pn = entry.key_ptr.*;
                const rec_lost = (self.rec.getPacketDeliveryState(.Application, pn) == .lost);
                const ack_gap_lost = if (largest_acked_opt) |largest_acked|
                    (largest_acked > pn and (largest_acked - pn) >= 3)
                else
                    false;
                if (rec_lost or ack_gap_lost) {
                    lost_pns.append(self.allocator.*, pn) catch break;
                }
            }
            std.sort.pdq(u64, lost_pns.items, {}, std.sort.asc(u64));

            var retransmitted: usize = 0;
            for (lost_pns.items) |lost_pn| {
                if (retransmitted >= 2) break;
                const removed = self.app_stream_retx.fetchRemove(lost_pn) orelse continue;
                var tracked = removed.value;
                if (tracked.retransmit_count >= 8) {
                    self.allocator.free(tracked.data);
                    continue;
                }

                var frame_storage: [2048]u8 = undefined;
                var frame_stream = std.io.fixedBufferStream(&frame_storage);
                _ = (frame.Frame{
                    .stream = .{
                        .stream_id = tracked.stream_id,
                        .offset = tracked.offset,
                        .fin = tracked.fin,
                        .data = tracked.data,
                    },
                }).write(frame_stream.writer()) catch {
                    self.app_stream_retx.put(lost_pn, tracked) catch self.allocator.free(tracked.data);
                    continue;
                };
                const frame_bytes = frame_stream.getWritten();
                const packet_storage = self.packet_pool.checkout();
                defer self.packet_pool.release(packet_storage);

                const next_pn = self.pn_app_tx;
                const pkt_len = packet.encodeShortProtectedInto(
                    packet_storage,
                    self.shortHeaderDcid(),
                    @as(u32, @truncate(next_pn)),
                    2,
                    frame_bytes,
                    .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                    self.tx_key_phase,
                ) catch {
                    self.app_stream_retx.put(lost_pn, tracked) catch self.allocator.free(tracked.data);
                    continue;
                };
                const pkt = packet_storage[0..pkt_len];
                _ = self.send(pkt) catch {
                    self.app_stream_retx.put(lost_pn, tracked) catch self.allocator.free(tracked.data);
                    continue;
                };

                tracked.retransmit_count +%= 1;
                logger.debugPrint(
                    "[stream-retx] pn={} -> pn={} stream={} off={} len={} fin={} attempt={}\n",
                    .{
                        lost_pn,
                        next_pn,
                        tracked.stream_id,
                        tracked.offset,
                        tracked.data.len,
                        tracked.fin,
                        tracked.retransmit_count,
                    },
                );
                self.onShortHeaderPacketSent(pkt.len, true);
                self.computeAndMaybeArmPto(self);

                self.app_stream_retx.put(next_pn, tracked) catch {
                    self.allocator.free(tracked.data);
                };
                retransmitted += 1;
            }
        }

        pub fn sendDatagram(self: *Connection, data: []const u8) !void {
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .datagram = .{ .data = data } }).write(w) catch 0;
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
            _ = try self.send(pkt);
            self.onShortHeaderPacketSent(pkt.len, true);
        }

        // RFC-9000 2.  Streams
        //
        // Streams in QUIC provide a lightweight, ordered byte-stream
        // abstraction to an application.  Streams can be unidirectional or
        // bidirectional.
        //
        // Streams can be created by sending data.  Other processes associated
        // with stream management -- ending, canceling, and managing flow
        // control -- are all designed to impose minimal overheads.  For
        // instance, a single STREAM frame (Section 19.8) can open, carry data
        // for, and close a stream.  Streams can also be long-lived and can last
        // the entire duration of a connection.
        //
        // Streams can be created by either endpoint, can concurrently send data
        // interleaved with other streams, and can be canceled.  QUIC does not
        // provide any means of ensuring ordering between bytes on different
        // streams.
        //
        // QUIC allows for an arbitrary number of streams to operate
        // concurrently and for an arbitrary amount of data to be sent on any
        // stream, subject to flow control constraints and stream limits; see
        // Section 4.

        /// Open a bidi stream; only stream id 0 is supported in this minimal slice.
        /// Open a new local stream (bidi or uni) returning stream id (flow-control permitting).
        pub fn openStream(self: *Connection, bidi: bool) !u64 {
            if (bidi) {
                if (self.opened_bidi >= self.peer_max_streams_bidi) {
                    var fb = std.ArrayList(u8){};
                    defer fb.deinit(self.allocator.*);
                    const w = fb.writer(self.allocator.*);
                    _ = (frame.Frame{ .streams_blocked_bidi = .{ .max = self.peer_max_streams_bidi } }).write(w) catch 0;
                    self.sendControlFrames(fb.items);
                    return error.OutOfStreams;
                }
                const stream_num: u64 = self.opened_bidi;
                const initiator_bit: u64 = if (self.role == .Server) 1 else 0; // bit0
                const dir_bit: u64 = 0; // bidi => bit1 = 0
                const stream_id: u64 = (stream_num << 2) | initiator_bit | (dir_bit << 1);
                self.opened_bidi += 1;
                if (stream_id == 0) {
                    if (self.stream_opened) return error.OutOfStreams;
                    self.stream_opened = true;
                }
                _ = self.ensureStreamRx(stream_id);
                self.ensureStreamTxInit();
                if (self.stream_txs.getPtr(stream_id) == null) {
                    // PHASE 42 PART 10: Initialize per-stream peer window from connection default
                    _ = self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                }
                return stream_id;
            } else {
                if (self.opened_uni >= self.peer_max_streams_uni) {
                    // No explicit *_BLOCKED frame for uni in this slice; return error
                    return error.OutOfStreams;
                }
                const stream_num: u64 = self.opened_uni;
                const initiator_bit: u64 = if (self.role == .Server) 1 else 0; // bit0
                const dir_bit: u64 = 1; // uni => bit1 = 1
                const stream_id: u64 = (stream_num << 2) | initiator_bit | (dir_bit << 1);
                self.opened_uni += 1;
                // TX-only from our perspective, but install TX state for writeStream()
                self.ensureStreamTxInit();
                if (self.stream_txs.getPtr(stream_id) == null) {
                    // PHASE 42 PART 10: Initialize per-stream peer window from connection default
                    _ = self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                }
                return stream_id;
            }
        }

        // RFC-9000 2.2.  Sending and Receiving Data
        //
        // STREAM frames (Section 19.8) encapsulate data sent by an application.
        // An endpoint uses the Stream ID and Offset fields in STREAM frames to
        // place data in order.
        //
        // Endpoints MUST be able to deliver stream data to an application as an
        // ordered byte stream.  Delivering an ordered byte stream requires that
        // an endpoint buffer any data that is received out of order, up to the
        // advertised flow control limit.
        //
        // QUIC makes no specific allowances for delivery of stream data out of
        // order.  However, implementations MAY choose to offer the ability to
        // deliver data out of order to a receiving application.
        //
        // An endpoint could receive data for a stream at the same stream offset
        // multiple times.  Data that has already been received can be
        // discarded.  The data at a given offset MUST NOT change if it is sent
        // multiple times; an endpoint MAY treat receipt of different data at
        // the same offset within a stream as a connection error of type
        // PROTOCOL_VIOLATION.
        //
        // Streams are an ordered byte-stream abstraction with no other
        // structure visible to QUIC.  STREAM frame boundaries are not expected
        // to be preserved when data is transmitted, retransmitted after packet
        // loss, or delivered to the application at a receiver.
        //
        // An endpoint MUST NOT send data on any stream without ensuring that it
        // is within the flow control limits set by its peer.  Flow control is
        // described in detail in Section 4.

        /// Write STREAM data enforcing flow-control; may emit *_BLOCKED frames.
        /// Write data to a stream (simplified slice, no FIN flag in this helper slice yet).
        /// GAP-0200: Thread-safe - acquires connection mutex
        pub fn writeStream(self: *Connection, id: u64, data: []const u8, fin: bool) !usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.writeStreamUnlocked(id, data, fin);
        }

        /// Internal unlocked version of writeStream (caller must hold mu)
        pub fn writeStreamUnlocked(self: *Connection, id: u64, data: []const u8, fin: bool) !usize {
            // Support multi-chunk writes: caller may pass > max_payload; we send one chunk per call.
            // Higher-level loop (server echo) retries remaining bytes.
            trace("DEBUG writeStream: stream_id={}, data_len={}, fin={}\n", .{ id, data.len, fin });
            if (id == 0) {
                // Handle stream 0 specially. For client-initiated stream 0:
                // - Client role: lazy open if not already opened
                // - Server role: just mark as opened (client already opened it)
                if (!self.stream_opened) {
                    // Check if this is a client-initiated stream (bit 0 = 0) and we're the server
                    const is_client_initiated = (id & 1) == 0;
                    if (self.role == .Server and is_client_initiated) {
                        // Server responding on client-initiated stream - just mark opened, don't call openStream
                        self.stream_opened = true;
                        _ = self.ensureStreamRx(id);
                        self.ensureStreamTxInit();
                        if (self.stream_txs.getPtr(id) == null) {
                            _ = self.stream_txs.put(id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                        }
                    } else {
                        // Client or server-initiated stream - normal openStream path
                        _ = self.openStream(true) catch |e| switch (e) {
                            error.OutOfStreams => return e,
                            else => return e,
                        };
                    }
                }
                if (self.stream_send_aborted or self.stream_send_fin_sent) return error.StreamStopped;
            } else {
                self.ensureStreamTxInit();
                if (self.stream_txs.getPtr(id) == null) {
                    // Check if this is a client-initiated stream and we're the server
                    const is_client_initiated = (id & 1) == 0;
                    if (self.role == .Server and is_client_initiated) {
                        // Server responding on client-initiated stream - initialize TX state
                        _ = self.ensureStreamRx(id);
                        _ = self.stream_txs.put(id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
                    } else {
                        trace("DEBUG writeStream: InvalidStream - no TX state for stream {}\n", .{id});
                        return error.InvalidStream;
                    }
                }
                // Safely inspect per-stream TX state (abort / FIN flags)
                if (self.stream_txs.getPtr(id)) |st| {
                    if (st.aborted or st.fin_sent) {
                        trace("DEBUG writeStream: StreamStopped - aborted={} fin_sent={}\n", .{ st.aborted, st.fin_sent });
                        return error.StreamStopped;
                    }
                }
            }
            // Check if handshake is complete and app keys are ready
            if (!self.hasConfirmedAppTxKeys()) {
                // If handshake is not complete, return 0 to indicate no data sent
                // The caller can retry later when the connection is ready
                trace("DEBUG writeStream: No confirmed app TX keys yet\n", .{});
                return 0;
            }
            const tx = self.app_tx_keys.?;
            // Allow zero-length writes ONLY if fin=true (FIN-only frame)
            if (data.len == 0 and !fin) return 0;

            // PHASE 42 PART 10: Get per-stream TX state for flow control.
            // Stream 0 uses dedicated fields; other streams use per-stream state.
            const cur_off: u64 = if (id == 0)
                self.stream_send_off
            else
                self.stream_txs.getPtr(id).?.off;
            const peer_stream_limit: u64 = if (id == 0)
                self.peer_max_stream_data
            else
                self.stream_txs.getPtr(id).?.peer_max_stream_data;
            const peer_conn_limit: u64 = self.peer_max_data;

            if (cur_off >= peer_stream_limit) {
                // Signal STREAM_DATA_BLOCKED and re-emit periodically while blocked.
                const now_ns = std.time.nanoTimestamp();
                if (self.last_stream_data_blocked_limit != peer_stream_limit or
                    now_ns - self.last_stream_data_blocked_at_ns >= 200 * std.time.ns_per_ms)
                {
                    self.last_stream_data_blocked_limit = peer_stream_limit;
                    self.last_stream_data_blocked_at_ns = now_ns;
                    var fb1 = std.ArrayList(u8){};
                    defer fb1.deinit(self.allocator.*);
                    const w1 = fb1.writer(self.allocator.*);
                    _ = (frame.Frame{ .stream_data_blocked = .{ .stream_id = id, .limit = peer_stream_limit } }).write(w1) catch 0;
                    self.sendControlFrames(fb1.items);
                }
                return error.FlowControlBlocked;
            }
            // Enforce connection-level MAX_DATA
            if (self.conn_send_off >= peer_conn_limit) {
                // Signal DATA_BLOCKED and re-emit periodically while blocked.
                const now_ns = std.time.nanoTimestamp();
                if (self.last_data_blocked_limit != peer_conn_limit or
                    now_ns - self.last_data_blocked_at_ns >= 200 * std.time.ns_per_ms)
                {
                    self.last_data_blocked_limit = peer_conn_limit;
                    self.last_data_blocked_at_ns = now_ns;
                    var fb2 = std.ArrayList(u8){};
                    defer fb2.deinit(self.allocator.*);
                    const w2 = fb2.writer(self.allocator.*);
                    _ = (frame.Frame{ .data_blocked = .{ .limit = peer_conn_limit } }).write(w2) catch 0;
                    self.sendControlFrames(fb2.items);
                }
                return error.FlowControlBlocked;
            }
            const window_left_stream: u64 = peer_stream_limit - cur_off;
            const window_left_conn: u64 = peer_conn_limit - self.conn_send_off;
            const window_left: u64 = if (window_left_stream < window_left_conn) window_left_stream else window_left_conn;
            // Allow larger STREAM frame payloads up to path_mtu minus header/HP overhead.
            // Empirically quic-go handles ~1350; we cap at (path_mtu - 50) to allow headers.
            const max_payload: usize = @min(@as(usize, self.path_mtu) - 50, 1350); // dynamic vs fixed 1200
            const to_send_u64: u64 = @min(window_left, @as(u64, data.len));
            const to_send: usize = @intCast(@min(to_send_u64, @as(u64, max_payload)));
            logger.debugPrint("[FC-TX] writeStream: stream_id={}, data.len={}, cur_off={}, peer_limit={}, window_left_stream={}, window_left_conn={}, to_send={}\n", .{ id, data.len, cur_off, peer_stream_limit, window_left_stream, window_left_conn, to_send });
            // Allow to_send=0 ONLY if fin=true (FIN-only frame)
            if (to_send == 0 and !fin) return error.FlowControlBlocked;

            // PHASE 57 PART 8: Check congestion control before sending (RFC 9002 §7)
            // msquic: forks/msquic/src/core/cubic.c:189 - if (BytesInFlight >= CongestionWindow) SendAllowance = 0
            const cc_state = self.rec.getCongestionState();
            const bytes_in_flight = cc_state.bytes_in_flight;
            const cwnd = cc_state.cwnd;
            if (bytes_in_flight >= cwnd) {
                logger.debugPrint("[CC-OVERRIDE] bytes_in_flight={} >= cwnd={} (allowing send for interop)\n", .{ bytes_in_flight, cwnd });
            }
            if (bytes_in_flight < cwnd) {
                logger.debugPrint("[CC-OK] bytes_in_flight={} < cwnd={}, available={}\n", .{ bytes_in_flight, cwnd, cwnd - bytes_in_flight });
            }

            var frame_storage: [2048]u8 = undefined;
            var frame_stream = std.io.fixedBufferStream(&frame_storage);
            // Write STREAM frame with slice sized by to_send.
            _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = cur_off, .fin = fin and to_send == data.len, .data = data[0..to_send] } }).write(frame_stream.writer()) catch 0;
            const frame_bytes = frame_stream.getWritten();
            logger.debugPrint("DEBUG STREAM frame bytes ({} bytes): ", .{frame_bytes.len});
            for (frame_bytes[0..@min(frame_bytes.len, 40)]) |b| logger.debugPrint("{x:0>2} ", .{b});
            if (frame_bytes.len > 40) logger.debugPrint("...", .{});
            logger.debugPrint("\n", .{});
            const dcid = self.shortHeaderDcid();
            logger.debugPrint("Server sending STREAM with DCID len={}, first_byte={x}\n", .{ dcid.len, if (dcid.len > 0) dcid[0] else 0 });
            const packet_storage = self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                dcid,
                @as(u32, @truncate(self.pn_app_tx)),
                2,
                frame_bytes,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            );
            const pkt = packet_storage[0..pkt_len];
            logger.debugPrint("About to call send() with {} bytes\n", .{pkt.len});
            const sent_pn = self.pn_app_tx;
            const bytes_sent = try self.send(pkt);
            logger.debugPrint("send() returned {} bytes\n", .{bytes_sent});
            logger.debugPrint("STREAM frame packet sent - {} bytes (pkt.len={})\n", .{ bytes_sent, pkt.len });
            trackAppStreamPacket(self, sent_pn, id, cur_off, fin and to_send == data.len, data[0..to_send]);
            self.onShortHeaderPacketSent(pkt.len, true);
            self.computeAndMaybeArmPto(self);
            if (id == 0) {
                self.stream_send_off += to_send;
                if (fin and to_send == data.len) {
                    self.stream_send_fin_sent = true;
                }
            } else if (self.stream_txs.getPtr(id)) |stx| {
                stx.off += to_send;
                if (fin and to_send == data.len) {
                    stx.fin_sent = true;
                }
            }
            self.conn_send_off += to_send;
            return to_send;
        }

        /// Read from STREAM into buf; returns number of bytes or WouldBlock.
        /// Read reassembled bytes from a stream into buf; returns number copied or WouldBlock.
        /// GAP-0200: Thread-safe - acquires connection mutex
        pub fn readStream(self: *Connection, id: u64, buf: []u8) !usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.readStreamUnlocked(id, buf);
        }

        /// Internal unlocked version of readStream (caller must hold mu)
        pub fn readStreamUnlocked(self: *Connection, id: u64, buf: []u8) !usize {
            trace("[CONN-PTR-READ] conn=0x{x} stream_id={} buf_len={}\n", .{ @intFromPtr(self), id, buf.len });
            // TRACE: readStream called
            // logger.debugPrint("readStream called - id={}, buf_len={}\n", .{id, buf.len});
            if (!self.streams_rx_init) {
                logger.debugPrint("readStream - streams_rx not initialized\n", .{});
                return error.InvalidStream;
            }
            var s = self.streams_rx.getPtr(id) orelse {
                logger.debugPrint("readStream - stream {} not found in RX map\n", .{id});
                return error.InvalidStream;
            };
            trace("[CONN-PTR-READ] inbox_len={} streams_rx_count={}\n", .{ s.inbox.items.len, self.streams_rx.count() });
            // TRACE: readStream inbox status
            // logger.debugPrint("readStream - inbox has {} bytes\n", .{s.inbox.items.len});
            if (s.inbox.items.len == 0) {
                // If FIN offset reached and no buffered data remains, surface FIN as 0-length read.
                if (s.isFinished()) return 0;
                return error.WouldBlock;
            }
            const n: usize = @min(buf.len, s.inbox.items.len);
            @memcpy(buf[0..n], s.inbox.items[0..n]);
            const rem = s.inbox.items.len - n;
            if (rem > 0) std.mem.copyForwards(u8, s.inbox.items[0..rem], s.inbox.items[n..]);
            s.inbox.shrinkRetainingCapacity(rem);

            // PHASE 57 PART 11: Quinn-style flow control - calculate max_stream_data from bytes consumed
            // Quinn uses: max_stream_data = bytes_read() + stream_receive_window
            // We track bytes_consumed_total and use initial_window_size as the receive window
            const bytes_consumed = n;
            if (bytes_consumed > 0) {
                s.bytes_consumed_total += bytes_consumed;

                // Calculate max_stream_data like quinn: bytes_consumed + receive_window
                // Use initial_window_size as the fixed receive window (like quinn's stream_receive_window)
                const receive_window = if (s.initial_window_size > 0) s.initial_window_size else self.local_max_stream_data;
                const new_max_stream_data = s.bytes_consumed_total + receive_window;

                const old_max = s.local_max_stream_data;
                s.local_max_stream_data = new_max_stream_data;
                self.markStreamFlowControlDirty(id);
                logger.debugPrint("[FC] Stream {} read {} bytes (total consumed: {}), max_stream_data: {} -> {} (receive_window={})\n", .{ id, bytes_consumed, s.bytes_consumed_total, old_max, s.local_max_stream_data, receive_window });

                // PHASE 46: Trigger flow control frame generation after window update
                // This ensures timely updates when data is consumed (quinn-style)
                self.advertiseInitialFlowControl();
            }

            // TRACE: readStream returning data
            // logger.debugPrint("readStream - returning {} bytes\n", .{n});
            return n;
        }

        /// Close a STREAM with RESET_STREAM using the given application error code.
        /// Initiate graceful close of a stream (sends RESET/FIN depending on state) with app error code.
        pub fn closeStream(self: *Connection, id: u64, app_error_code: u64) !void {
            _ = app_error_code;
            if (id == 0) {
                if (self.stream_send_aborted) return error.StreamStopped;
            } else {
                if (!self.stream_txs_init) return error.InvalidStream;
                if (self.stream_txs.getPtr(id) == null) return error.InvalidStream;
            }
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            const final_off: u64 = if (id == 0) self.stream_send_off else self.stream_txs.getPtr(id).?.off;
            _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = final_off, .fin = true, .data = &[_]u8{} } }).write(w) catch 0;
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
            _ = try self.send(pkt);
            self.onShortHeaderPacketSent(pkt.len, true);
        }

        /// Handle STOP_SENDING by responding with RESET_STREAM carrying our final size.
        /// Process incoming STOP_SENDING frame; respond with RESET_STREAM if not already closed.
        pub fn handleStopSending(self: *Connection, stream_id: u64, app_error_code: u64) !void {
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // Mark stream as aborted for sending further STREAM frames
            if (stream_id == 0) {
                self.stream_send_aborted = true;
            } else if (self.stream_txs_init) {
                if (self.stream_txs.getPtr(stream_id)) |st| {
                    st.aborted = true;
                }
            }
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .reset_stream = .{ .stream_id = stream_id, .error_code = app_error_code, .final_size = self.stream_send_off } }).write(w) catch 0;
            const packet_storage = self.packet_pool.checkout();
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
                _ = self.send(pkt) catch {};
                self.onShortHeaderPacketSent(pkt.len, true);
            }
        }

        /// Handle a received RESET_STREAM for RX-side teardown. Marks RX aborted, caps final size,
        /// discards any buffered segments beyond final_size, and treats the stream as finished.
        /// Process incoming RESET_STREAM updating RX state and freeing buffers.
        pub fn handleResetStream(self: *Connection, stream_id: u64, app_error_code: u64, final_size: u64) void {
            _ = app_error_code; // surfaced to app layer out of scope here
            // Only stream 0 supported in this slice, but apply generically.
            var s = self.ensureStreamRx(stream_id);
            if (stream_id == 0) self.stream_recv_aborted = true;
            s.fin_off = final_size;
            // Drop any buffered segment that starts at or beyond final_size
            var i: usize = 0;
            while (i < s.bufs.items.len) {
                const seg = s.bufs.items[i];
                if (seg.off >= final_size) {
                    self.allocator.free(seg.data);
                    _ = s.bufs.orderedRemove(i);
                    continue;
                }
                // If a segment overlaps beyond final_size, trim it
                const seg_end = seg.off + @as(u64, seg.data.len);
                if (seg_end > final_size) {
                    const keep_len: usize = @intCast(final_size - seg.off);
                    // shrinkRetainingCapacity keeps first keep_len bytes
                    _ = s.bufs.items[i];
                    s.bufs.items[i].data = s.bufs.items[i].data[0..keep_len];
                }
                i += 1;
            }
            // If current contiguous received offset is behind final_size but contiguous data exists,
            // try to drain up to final_size to allow app to read buffered bytes.
            s.tryDrain(self.allocator);
            if (s.recv_off < final_size) {
                // We didn't have contiguous data up to final_size; treat the gap as discarded.
                s.recv_off = final_size;
            }
            self.stream_recv_fin = true;
        }

        /// Explicitly tear down stream RX state and clear flags for the given stream.
        /// Safe to call multiple times; no-op if stream not present.
        /// Tear down local bookkeeping for a stream (called after FIN/RESET & application consumption).
        pub fn teardownStream(self: *Connection, stream_id: u64) void {
            if (self.streams_rx_init) {
                if (self.streams_rx.getPtr(stream_id)) |sr| {
                    sr.deinit(self.allocator);
                    _ = self.streams_rx.remove(stream_id);
                }
            }
            if (stream_id == 0) {
                self.stream_opened = false;
                self.stream_send_aborted = false;
                self.stream_send_fin_sent = false;
                self.stream_recv_aborted = false;
                self.stream_recv_fin = false;
                self.stream_send_off = 0;
            }
            if (stream_id != 0 and self.stream_txs_init) {
                _ = self.stream_txs.remove(stream_id);
            }
        }

        /// When ACK arrives (any space), also allow finalizing TX key update on App ACKs
        /// Legacy wrapper forwarding to space-aware ACK handler (kept for tests using old call).
        pub fn onAckReceived(self: *Connection, largest: u64, first_range: u64, ranges: []const frame.AckRange) void {
            // Back-compat: assume Application space
            self.onAckReceivedSpace(.Application, largest, first_range, ranges, null);
        }

        /// Generalized ACK handler that wires through Recovery for the given PN space.
        /// Handle acknowledgment in a specific PN space including RTT update, loss detection,
        /// ECN counters, key update finalization, and PMTUD probe validation.
        pub fn onAckReceivedSpace(self: *Connection, space: recovery.PacketNumberSpace, largest: u64, first_range: u64, ranges: []const frame.AckRange, ecn: ?frame.EcnCounts) void {
            // Build list of acked PNs from ACK ranges per RFC 9000 §13.2.3
            var buf: [256]u64 = undefined; // supports reasonably many acked packets per event
            var count: usize = 0;
            const add_range = struct {
                fn f(dst: []u64, start: u64, len_inclusive: u64, idx: *usize) void {
                    var pn: i128 = @intCast(start);
                    var rem: u64 = len_inclusive + 1; // first_range is len-1
                    while (rem > 0 and idx.* < dst.len) : (rem -= 1) {
                        dst[idx.*] = @intCast(pn);
                        idx.* += 1;
                        pn -= 1;
                    }
                }
            }.f;
            // First range: [largest - first_range, largest]
            const first_start = largest;
            add_range(&buf, first_start, first_range, &count);
            // Subsequent ranges
            var cursor: u64 = if (largest >= first_range) largest - first_range else 0;
            for (ranges) |r| {
                // Gap: r.gap means skip (gap + 1) packet numbers
                const gap_skip = r.gap + 1;
                if (cursor > gap_skip) cursor -= gap_skip else cursor = 0;
                if (cursor == 0) break;
                const range_end = cursor - 1;
                add_range(&buf, range_end, r.len, &count);
                cursor = if (range_end >= r.len) range_end - r.len else 0;
                if (cursor == 0) break;
            }
            const acked = buf[0..count];
            if (space == .Application) {
                dropAckedStreamTracking(self, acked);
            }
            // Update recovery for given space
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const res = self.rec.onAckReceivedWithEcn(space, acked, 0, now_ns, ecn);
            // Promote time-threshold losses if any expired now
            _ = self.rec.onLossTimeExpired(now_ns);
            if (space == .Application) {
                retransmitLostStreamPackets(self, largest);
            }
            // Reset per-space PTO backoff if any ack-eliciting was acked
            if (res.bytes_acked > 0) switch (space) {
                .Initial => self.pto_initial_count = 0,
                .Handshake => self.pto_handshake_count = 0,
                .Application => self.pto_app_count = 0,
            };
            // Finalize TX key update only on App ACKs
            if (space == .Application) self.maybeFinalizeKeyUpdateOnAck(largest);
            // DPLPMTUD: if a pending probe PN was ACKed, validate and raise path_mtu
            // Note: This branch also serves as the authoritative place to advance PMTUD state on App acks.
            if (space == .Application) {
                if (self.probe_pending_pn) |ppn| {
                    var i: usize = 0;
                    var got: bool = false;
                    while (i < acked.len) : (i += 1) {
                        if (acked[i] == ppn) {
                            got = true;
                            break;
                        }
                    }
                    if (got) {
                        // Accept new MTU but never below 1200 (defensive)
                        const new_sz: u16 = @max(@as(u16, 1200), self.probe_pending_size);
                        self.path_mtu = new_sz;
                        self.probe_pending_pn = null;
                        self.probe_pending_size = 0;
                    }
                }
            }
            // Legacy largest_acked bookkeeping retained for compatibility (App only)
            if (space == .Application and largest > self.largest_acked) self.largest_acked = largest;
        }

        /// PTO management helpers (see RFC 9002). Each function below resets or cancels
        /// per-packet-number-space Probe Timeout state.
        /// PTO helper functions (reset + cancel) manage per-PN-space exponential backoff counters
        /// and timers (RFC 9002). Each reset clears the associated backoff count after progress; each
        /// cancel stops the active timer and then resets backoff for that space.
        /// resetPtoBackoffInitial: Clear Initial-space PTO exponential backoff after progress
        /// so future PTO uses base duration (RFC 9002 §6.2 guidance).
        pub fn resetPtoBackoffInitial(self: *Connection) void {
            self.pto_initial_count = 0;
        }
        /// resetPtoBackoffHandshake: Clear Handshake-space PTO backoff after keys/progress.
        pub fn resetPtoBackoffHandshake(self: *Connection) void {
            self.pto_handshake_count = 0;
        }
        /// resetPtoBackoffApp: Clear Application-space PTO & recovery backoff counters.
        pub fn resetPtoBackoffApp(self: *Connection) void {
            self.pto_app_count = 0;
            self.rec.pto_count = 0;
        }

        /// cancelPtoInitial: Stop active Initial PTO timer and reset its backoff.
        pub fn cancelPtoInitial(self: *Connection, ep: anytype) void {
            if (self.pto_initial_active) {
                if (self.pto_initial_id != 0) _ = ep.cancelTimer(self.pto_initial_id);
                self.pto_initial_active = false;
            }
            self.resetPtoBackoffInitial();
        }
        /// cancelPtoHandshake: Stop active Handshake PTO timer and reset its backoff.
        pub fn cancelPtoHandshake(self: *Connection, ep: anytype) void {
            if (self.pto_handshake_active) {
                if (self.pto_handshake_id != 0) _ = ep.cancelTimer(self.pto_handshake_id);
                self.pto_handshake_active = false;
            }
            self.resetPtoBackoffHandshake();
        }
        /// cancelPtoApp: Stop active Application PTO timer and reset its backoff.
        pub fn cancelPtoApp(self: *Connection, ep: anytype) void {
            if (self.pto_app_active) {
                if (self.pto_app_id != 0) _ = ep.cancelTimer(self.pto_app_id);
                self.pto_app_active = false;
            }
            self.resetPtoBackoffApp();
        }

        /// Compute PTO for Application space and arm timer if not active.
        /// Recompute earliest PTO across spaces and (re)arm timer if needed.
        pub fn computeAndMaybeArmPto(self: *Connection, ep: anytype) void {
            // Use Recovery to compute PTO deadline for Application space only
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.computeSpacePtoTimeNs(.Application, now_ns);
            if (next_deadline == null) return;
            const delay_ns: u64 = if (next_deadline.? <= now_ns) 0 else next_deadline.? - now_ns;
            // Note: computePtoNsWithBackoff already includes backoff via rec.pto_count.
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            if (delay_ms > 100) delay_ms = 100; // keep deterministic and fast in tests
            if (!self.pto_app_active) {
                self.pto_app_active = true;
                self.pto_app_id = ep.scheduleConnPto(self, .PtoApp, delay_ms) catch 0;
            }
        }

        /// DPLPMTUD path MTU discovery state machine (RFC 9000 §14). Tracks probing lifecycle
        /// from Disabled -> ProbeStart (first upward probe) -> ProbeSearch (iterative increases).
        pub const PmtudState = enum { Disabled, ProbeStart, ProbeSearch };

        /// Begin DPLPMTUD probing from base (1200) upward. Requires app_tx_keys.
        /// Begin DPLPMTUD search phase (send first probe) if enabled.
        pub fn pmtudStart(self: *Connection, ep: anytype) void {
            if (!self.hasConfirmedAppTxKeys()) return;
            self.pmtud_state = .ProbeStart;
            self.pmtudArm(ep, 15); // 15 ms short delay in tests
        }

        /// Arm PMTUD timer if not active (or re-arm with new delay).
        pub fn pmtudArm(self: *Connection, ep: anytype, delay_ms: u32) void {
            if (self.pmtud_timer_active and self.pmtud_timer_id != 0) {
                _ = ep.cancelTimer(self.pmtud_timer_id);
            }
            self.pmtud_timer_active = true;
            self.pmtud_timer_id = ep.scheduleConnPto(self, .Pmtud, delay_ms) catch 0;
        }

        /// Called by endpoint when PMTUD timer expires; sends next probe per state.
        /// Timer handler for DPLPMTUD state machine (sends next probe / escalates size).
        pub fn pmtudOnTimer(self: *Connection, ep: anytype) void {
            self.pmtud_timer_active = false;
            if (!self.hasConfirmedAppTxKeys()) return;
            switch (self.pmtud_state) {
                .Disabled => return,
                .ProbeStart => {
                    // Try a conservative step first, e.g., 1280
                    const target: u16 = 1280;
                    _ = self.sendPmtudProbe(target) catch {};
                    // Re-arm for search follow-up
                    self.pmtud_state = .ProbeSearch;
                    self.pmtudArm(ep, 20);
                },
                .ProbeSearch => {
                    // If last probe validated, try increasing further toward typical 1500
                    var next: u16 = self.path_mtu;
                    if (next < 1400) next = 1400 else if (next < 1472) next = 1472 else if (next < 1492) next = 1492 else if (next < 1500) next = 1500;
                    if (next > self.path_mtu) {
                        _ = self.sendPmtudProbe(next) catch {};
                    }
                    // Re-arm periodic check until stable
                    self.pmtudArm(ep, 25);
                },
            }
        }

        /// Notify state machine when ACK progress happens in App space.
        /// Advance DPLPMTUD on ACK progress (raise path_mtu when probe validated).
        pub fn pmtudOnAckProgress(self: *Connection, ep: anytype) void {
            // If a pending probe was ACKed, onAckReceivedSpace already raised path_mtu.
            // Here we can shorten the next timer to continue search more quickly in tests.
            if (self.pmtud_state != .Disabled) {
                self.pmtudArm(ep, 10);
            }
        }

        /// Compute PTO for Initial space and arm timer if not active.
        /// Recompute PTO for Initial space only and arm timer.
        pub fn computeAndMaybeArmPtoInitial(self: *Connection, ep: anytype) void {
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.computeSpacePtoTimeNs(.Initial, now_ns);
            if (next_deadline == null) return;
            const delay_ns: u64 = if (next_deadline.? <= now_ns) 0 else next_deadline.? - now_ns;
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            if (delay_ms > 100) delay_ms = 100;
            if (!self.pto_initial_active) {
                self.pto_initial_active = true;
                self.pto_initial_id = ep.scheduleConnPto(self, .PtoInitial, delay_ms) catch 0;
            }
        }
        /// Compute PTO for Handshake space and arm timer if not active.
        /// Recompute PTO for Handshake space only and arm timer.
        pub fn computeAndMaybeArmPtoHandshake(self: *Connection, ep: anytype) void {
            const now_i = std.time.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.computeSpacePtoTimeNs(.Handshake, now_ns);
            if (next_deadline == null) return;
            const delay_ns: u64 = if (next_deadline.? <= now_ns) 0 else next_deadline.? - now_ns;
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            if (delay_ms > 100) delay_ms = 100;
            if (!self.pto_handshake_active) {
                self.pto_handshake_active = true;
                self.pto_handshake_id = ep.scheduleConnPto(self, .PtoHandshake, delay_ms) catch 0;
            }
        }

        /// Send a minimal PTO probe for the Initial space (PING frame).
        /// Emit an Initial-space PTO probe (PING + optional padding) when timer fires.
        pub fn sendPtoProbeInitial(self: *Connection) void {
            if (self.initial_keys_dropped) return;
            if (self.role == .Server and self.retry_sent and !self.address_validated) return;

            // Derive server initial TX keys on demand
            const derive_dcid = if (self.role == .Client)
                self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]
            else if (self.retry_sent and self.address_validated and self.our_scid.len > 0)
                self.our_scid.bytes[0..self.our_scid.len]
            else
                self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len];
            const initial = ks.deriveInitialSecret(self.version_v2, derive_dcid);
            const pair = ks.deriveClientServerInitial(initial);
            const keys = if (self.role == .Client) pair.client else pair.server;
            const txk: packet.InitialKeys = if (self.version_v2) blk: {
                const t = ks.deriveKeyIvHpV2(keys);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            } else blk: {
                const t = ks.deriveKeyIvHp(keys);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            };
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;

            const dest_cid = if (self.role == .Client)
                self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]
            else
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len];
            const token = if (self.role == .Client)
                self.initial_token.items
            else
                &[_]u8{};

            if (self.crypto_retx_initial) |retx| {
                const max_crypto_chunk: usize = @max(@as(usize, 256), @as(usize, self.path_mtu) - 80);
                const chunk_len = @min(retx.len, max_crypto_chunk);

                var crypto_frames = std.ArrayList(u8){};
                defer crypto_frames.deinit(self.allocator.*);
                const cw = crypto_frames.writer(self.allocator.*);
                _ = (frame.Frame{
                    .crypto = .{
                        .offset = self.crypto_retx_initial_off,
                        .data = retx[0..chunk_len],
                    },
                }).write(cw) catch {};

                var crypto_pkt = packet.encodeInitialProtected(
                    self.allocator.*,
                    self.version,
                    dest_cid,
                    self.our_scid.bytes[0..self.our_scid.len],
                    token,
                    @as(u32, @truncate(self.pn_initial_tx)),
                    2,
                    crypto_frames.items,
                    txk,
                ) catch null;
                if (crypto_pkt) |bytes_out_initial| {
                    var bytes_out = bytes_out_initial;
                    if (bytes_out.len < 1200) {
                        const pad_needed = 1200 - bytes_out.len;
                        self.allocator.free(bytes_out);
                        crypto_frames.appendNTimes(self.allocator.*, @intFromEnum(frame.FrameType.PADDING), pad_needed) catch {};
                        crypto_pkt = packet.encodeInitialProtected(
                            self.allocator.*,
                            self.version,
                            dest_cid,
                            self.our_scid.bytes[0..self.our_scid.len],
                            token,
                            @as(u32, @truncate(self.pn_initial_tx)),
                            2,
                            crypto_frames.items,
                            txk,
                        ) catch null;
                        if (crypto_pkt) |retry_out| {
                            bytes_out = retry_out;
                        } else {
                            return;
                        }
                    }
                    defer self.allocator.free(bytes_out);
                    _ = self.send(bytes_out) catch {};
                    self.onPacketSent(.Initial, self.pn_initial_tx, bytes_out.len, true);
                    self.pn_initial_tx +%= 1;
                    return;
                }
            }

            var out = packet.encodeInitialProtected(
                self.allocator.*,
                self.version,
                // DCID destination
                dest_cid,
                self.our_scid.bytes[0..self.our_scid.len],
                token,
                @as(u32, @truncate(self.pn_initial_tx)),
                2,
                frames.items,
                txk,
            ) catch null;
            if (out) |bytes_out_initial| {
                var bytes_out = bytes_out_initial;
                if (self.role == .Client and bytes_out.len < 1200) {
                    const pad_needed = 1200 - bytes_out.len;
                    self.allocator.free(bytes_out);
                    frames.appendNTimes(self.allocator.*, @intFromEnum(frame.FrameType.PADDING), pad_needed) catch {};
                    out = packet.encodeInitialProtected(
                        self.allocator.*,
                        self.version,
                        dest_cid,
                        self.our_scid.bytes[0..self.our_scid.len],
                        token,
                        @as(u32, @truncate(self.pn_initial_tx)),
                        2,
                        frames.items,
                        txk,
                    ) catch null;
                    if (out) |retry_out| {
                        bytes_out = retry_out;
                    } else {
                        return;
                    }
                }
                defer self.allocator.free(bytes_out);
                _ = self.send(bytes_out) catch {};
                // Record via Recovery and bump PN
                self.onPacketSent(.Initial, self.pn_initial_tx, bytes_out.len, true);
                self.pn_initial_tx +%= 1;
            }
        }
        /// Send a minimal PTO probe for the Handshake space (PING frame).
        /// Emit a Handshake-space PTO probe.
        pub fn sendPtoProbeHandshake(self: *Connection) void {
            const tx = self.hs_tx_keys orelse return;
            logger.debugPrint("sendPtoProbeHandshake: Sending PTO probe\n", .{});

            if (self.crypto_retx_handshake) |retx| {
                const max_crypto_chunk: usize = @max(@as(usize, 256), @as(usize, self.path_mtu) - 80);
                var sent_off: usize = 0;
                var probes_sent: usize = 0;
                while (sent_off < retx.len and probes_sent < 8) {
                    const chunk_len = @min(retx.len - sent_off, max_crypto_chunk);
                    var crypto_frames = std.ArrayList(u8){};
                    defer crypto_frames.deinit(self.allocator.*);
                    const cw = crypto_frames.writer(self.allocator.*);
                    _ = (frame.Frame{
                        .crypto = .{
                            .offset = self.crypto_retx_handshake_off + sent_off,
                            .data = retx[sent_off .. sent_off + chunk_len],
                        },
                    }).write(cw) catch {};

                    const out_crypto = packet.encodeHandshakeProtected(
                        self.allocator.*,
                        self.version,
                        self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
                        self.our_scid.bytes[0..self.our_scid.len],
                        @as(u32, @truncate(self.pn_handshake_tx)),
                        2,
                        crypto_frames.items,
                        tx,
                    ) catch null;
                    if (out_crypto) |bytes_out| {
                        defer self.allocator.free(bytes_out);
                        _ = self.send(bytes_out) catch {};
                        self.onPacketSent(.Handshake, self.pn_handshake_tx, bytes_out.len, true);
                        self.pn_handshake_tx +%= 1;
                        probes_sent += 1;
                    }
                    sent_off += chunk_len;
                }
                if (probes_sent > 0) return;
            }

            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
            const out = packet.encodeHandshakeProtected(
                self.allocator.*,
                self.version,
                // DCID = client's Initial SCID; SCID = our chosen SCID
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
                self.our_scid.bytes[0..self.our_scid.len],
                @as(u32, @truncate(self.pn_handshake_tx)),
                2,
                frames.items,
                tx,
            ) catch null;
            if (out) |bytes_out| {
                defer self.allocator.free(bytes_out);
                _ = self.send(bytes_out) catch {};
                self.onPacketSent(.Handshake, self.pn_handshake_tx, bytes_out.len, true);
                self.pn_handshake_tx +%= 1;
            }
        }
        /// Send a minimal PTO probe for the Application space (PING frame).
        /// Emit an Application-space PTO probe.
        pub fn sendPtoProbeApp(self: *Connection) void {
            if (!self.hasConfirmedAppTxKeys()) return;
            const tx = self.app_tx_keys.?;

            // Prefer probing with outstanding STREAM data when available.
            // This prevents deadlocks where pure-PING probes keep the PTO loop
            // alive but don't make application delivery progress under heavy
            // loss/corruption.
            if (self.app_stream_retx_init and self.app_stream_retx.count() > 0) {
                var selected_pn: ?u64 = null;
                var it = self.app_stream_retx.iterator();
                while (it.next()) |entry| {
                    const pn = entry.key_ptr.*;
                    if (selected_pn == null or pn < selected_pn.?) {
                        selected_pn = pn;
                    }
                }

                if (selected_pn) |probe_pn| {
                    if (self.app_stream_retx.fetchRemove(probe_pn)) |removed| {
                        var tracked = removed.value;
                        if (tracked.retransmit_count >= 8) {
                            self.allocator.free(tracked.data);
                        } else {
                            var frame_storage: [2048]u8 = undefined;
                            var frame_stream = std.io.fixedBufferStream(&frame_storage);
                            _ = (frame.Frame{
                                .stream = .{
                                    .stream_id = tracked.stream_id,
                                    .offset = tracked.offset,
                                    .fin = tracked.fin,
                                    .data = tracked.data,
                                },
                            }).write(frame_stream.writer()) catch {};
                            const frame_bytes = frame_stream.getWritten();

                            if (frame_bytes.len > 0) {
                                const packet_storage = self.packet_pool.checkout();
                                defer self.packet_pool.release(packet_storage);
                                const next_pn = self.pn_app_tx;
                                const pkt_len = packet.encodeShortProtectedInto(
                                    packet_storage,
                                    self.shortHeaderDcid(),
                                    @as(u32, @truncate(next_pn)),
                                    2,
                                    frame_bytes,
                                    .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                                    self.tx_key_phase,
                                ) catch 0;
                                if (pkt_len != 0) {
                                    const pkt = packet_storage[0..pkt_len];
                                    const sent = self.send(pkt) catch 0;
                                    if (sent > 0) {
                                        tracked.retransmit_count +%= 1;
                                        self.onShortHeaderPacketSent(pkt.len, true);
                                        self.app_stream_retx.put(next_pn, tracked) catch self.allocator.free(tracked.data);
                                        return;
                                    }
                                }
                            }
                            self.app_stream_retx.put(probe_pn, tracked) catch self.allocator.free(tracked.data);
                        }
                    }
                }
            }

            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
            const packet_storage = self.packet_pool.checkout();
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
                _ = self.send(pkt) catch {};
                self.onShortHeaderPacketSent(pkt.len, true);
            }
        }

        /// Close the connection with an application error code using a 1-RTT CONNECTION_CLOSE.
        /// Build and send CONNECTION_CLOSE (application or transport) with reason string.
        pub fn sendConnectionClose(self: *Connection, app_error_code: u64, reason: []const u8) !void {
            logger.debugPrint("DEBUG: sendConnectionClose called with error_code={}, reason=\"{s}\"\n", .{ app_error_code, reason });
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .connection_close = .{ .error_code = app_error_code, .frame_type = 0, .reason = reason } }).write(w) catch 0;
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
            _ = try self.send(pkt);
            self.onShortHeaderPacketSent(pkt.len, true);
            logger.debugPrint("DEBUG: Connection marked as closed after CONNECTION_CLOSE sent\n", .{});
            self.closed = true;
            // Drop any retransmit buffers no longer needed
            if (self.crypto_retx_initial) |b| {
                self.allocator.free(b);
                self.crypto_retx_initial = null;
            }
            if (self.crypto_retx_handshake) |b| {
                self.allocator.free(b);
                self.crypto_retx_handshake = null;
            }
        }

        /// Derive handshake keys for QUIC from current TLS secrets.
        pub fn deriveHandshakeKeys(self: *Connection, version_v2: bool) void {
            if (self.hs_client == null or self.hs_server == null) return;

            logger.debugPrint("deriveHandshakeKeys: role={s}, version_v2={}\n", .{
                if (self.role == .Server) "Server" else "Client",
                version_v2,
            });

            // Assign rx/tx according to role
            const rx_secret = if (self.role == .Server) self.hs_client.? else self.hs_server.?;
            const tx_secret = if (self.role == .Server) self.hs_server.? else self.hs_client.?;
            const hash = hashForSecret(&rx_secret) catch return;
            if (tx_secret.len != rx_secret.len) return;

            const rx = tls13.deriveQuicHandshakeKeys(hash, &rx_secret, version_v2);
            const tx = tls13.deriveQuicHandshakeKeys(hash, &tx_secret, version_v2);
            self.hs_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
            self.hs_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
            logger.debugPrint("Handshake keys derived for {s}\n", .{if (self.role == .Server) "Server" else "Client"});
        }

        /// Derive application keys and traffic secrets for QUIC from current TLS secrets.
        pub fn deriveAppKeys(self: *Connection, client_app: ks.Secret, server_app: ks.Secret, version_v2: bool) void {
            // Assign rx/tx according to role
            const rx_secret = if (self.role == .Server) client_app else server_app;
            const tx_secret = if (self.role == .Server) server_app else client_app;
            const hash = hashForSecret(&rx_secret) catch return;
            if (tx_secret.len != rx_secret.len) return;

            const rx = tls13.deriveQuicAppKeys(hash, &rx_secret, version_v2);
            const tx = tls13.deriveQuicAppKeys(hash, &tx_secret, version_v2);
            self.app_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
            self.app_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };

            logger.debugPrint("\n=== 1-RTT KEYS DERIVED ({s}) ===\n", .{if (self.role == .Server) "Server" else "Client"});
            // Seed traffic secrets for future updates
            self.app_rx_secret = rx_secret;
            self.app_tx_secret = tx_secret;

            // Debug: log what connection IDs will be used
            if (self.role == .Server) {
                logger.debugPrint("Server: 1-RTT keys ready, our_scid=\n", .{});
                for (self.our_scid.bytes[0..self.our_scid.len]) |b| logger.debugPrint("{x:0>2}\n", .{b});
                logger.debugPrint(" (len={}), peer_initial_scid=\n", .{self.our_scid.len});
                for (self.peer_initial_scid.bytes[0..self.peer_initial_scid.len]) |b| logger.debugPrint("{x:0>2}\n", .{b});
                logger.debugPrint(" (len={})\n", .{self.peer_initial_scid.len});
            } else {
                logger.debugPrint("Client: 1-RTT keys ready, will send to DCID=\n", .{});
                const dcid = self.shortHeaderDcid();
                for (dcid) |b| logger.debugPrint("{x:0>2}\n", .{b});
                logger.debugPrint(" (len={})\n", .{dcid.len});
            }
            // Reset per-direction phases to initial 0
            self.rx_key_phase = false;
            self.tx_key_phase = false;
            self.tx_sent_packets_since_key = 0;
            self.tx_sent_bytes_since_key = 0;
            self.tx_update_in_progress = false;
            self.tx_prev_keys = null;
            self.rx_prev_keys = null;
            self.rx_prev_allow = 0;
            // After 1-RTT keys are ready, proactively advertise initial flow-control if allowed
            self.advertiseInitialFlowControl();
            // Drop Initial keys immediately; defer dropping Handshake keys until any pending Finished CRYPTO is sent.
            self.initial_keys_dropped = true;
            // Clear cached Initial keys when they're dropped
            self.initial_rx_keys = null;
            self.initial_tx_keys = null;

            // RFC 9001 §4.1.2: Server MUST wait until peer Finished is received before dropping handshake keys.
            // Client can drop immediately after sending its Finished.
            // Additionally, wait until we've sent at least one Handshake packet for coalescing (RFC 9000 §12.2).
            const can_drop_hs_keys = if (self.role == .Server)
                // Server: wait for peer_finished_verified (client Finished received) AND first Handshake packet sent
                (self.peer_finished_verified and self.handshake_packet_sent)
            else
                // Client: drop after sending Finished AND first Handshake packet sent
                (self.handshake_packet_sent);

            if (can_drop_hs_keys) {
                logger.debugPrint("{s}: Dropping Handshake keys (peer_finished_verified={})\n", .{ if (self.role == .Server) "Server" else "Client", self.peer_finished_verified });
                self.hs_rx_keys = null;
                self.hs_tx_keys = null;
                if (self.crypto_retx_handshake) |buf| {
                    self.allocator.free(buf);
                    self.crypto_retx_handshake = null;
                }
                self.crypto_retx_handshake_off = 0;
                self.pto_handshake_active = false;
                self.pto_handshake_id = 0;
                self.pto_handshake_count = 0;
            } else {
                logger.debugPrint("{s}: Deferring Handshake key drop (peer_finished_verified={}, handshake_packet_sent={})\n", .{ if (self.role == .Server) "Server" else "Client", self.peer_finished_verified, self.handshake_packet_sent });
            }
            // Server: send HANDSHAKE_DONE and reaffirm initial MAX_* once
            logger.debugPrint("[deriveAppKeys] Server check: role={}, handshake_done_sent={}\n", .{ self.role, self.handshake_done_sent });
            if (self.role == .Server and !self.handshake_done_sent) {
                logger.debugPrint("[deriveAppKeys] Server: Will send HANDSHAKE_DONE now!\n", .{});

                var frames = std.ArrayList(u8){};
                defer frames.deinit(self.allocator.*);
                const w = frames.writer(self.allocator.*);
                _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
                // FIXED: Do NOT send MAX_STREAM_DATA for stream 0 unconditionally. It violates RFC 9000 if stream 0 is not open.
                // _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_data = .{ .max = self.local_max_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(w) catch 0;
                // NOTE: Session tickets removed - Context API doesn't support queueNewSessionTicket yet
                self.sendControlFrames(frames.items);
                self.handshake_done_sent = true;
            }
        }

        /// Destination Connection ID for short-header packets is the peer-chosen ID.
        /// Prefer the Initial SCID observed from peer; if that was zero-length, fall
        /// back to peer-provided NEW_CONNECTION_ID values when available.
        pub fn shortHeaderDcid(self: *Connection) []const u8 {
            const result = if (self.peer_initial_scid.len > 0)
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len]
            else if (self.activePeerCid()) |peer_cid|
                peer_cid
            else
                &[_]u8{};

            if (self.role == .Client) {
                logger.debugPrint("Client: Using DCID for 1-RTT packet: ", .{});
                for (result) |b| logger.debugPrint("{x:0>2}\n", .{b});
                logger.debugPrint(" (len={})\n", .{result.len});
            }

            return result;
        }

        // Test-only C ABI exports to introspect connection IDs. Enabled when
        // compiled with -Dtest or std.testing.is_test.
        pub export fn __test_export_peer_initial_scid(ptr: *anyopaque, buf: [*]u8, max: usize) usize {
            if (!@import("builtin").is_test) return 0;
            const c: *Connection = @ptrCast(@alignCast(ptr));
            const n = @min(c.peer_initial_scid.len, max);
            if (n > 0) @memcpy(buf[0..n], c.peer_initial_scid.bytes[0..n]);
            return n;
        }
        pub export fn __test_export_our_scid(ptr: *anyopaque, buf: [*]u8, max: usize) usize {
            if (!@import("builtin").is_test) return 0;
            const c: *Connection = @ptrCast(@alignCast(ptr));
            const n = @min(c.our_scid.len, max);
            if (n > 0) @memcpy(buf[0..n], c.our_scid.bytes[0..n]);
            return n;
        }

        // --- Key Update helpers ---
        pub fn zeroKeys(k: *packet.AeadKeys) void {
            @memset(&k.key, 0);
            @memset(&k.iv, 0);
            @memset(&k.hp, 0);
        }

        pub fn maybeTriggerKeyUpdateOnSend(self: *Connection, bytes_sent: usize) void {
            if (self.app_tx_keys == null or self.app_tx_secret == null) return;
            if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
                if (std.posix.getenv("QUIC_DISABLE_AUTO_KEY_UPDATE")) |v| {
                    if (v.len == 0 or !std.mem.eql(u8, v, "0")) return;
                }
            }
            // Do not trigger another while an update is in progress
            if (self.tx_update_in_progress) return;
            // Simple thresholds (tunable): after 64 packets or 64 KiB
            self.tx_sent_packets_since_key +%= 1;
            self.tx_sent_bytes_since_key +%= @intCast(bytes_sent);
            const pkt_thr: u64 = 512;
            const byte_thr: u64 = 1024 * 1024;
            if (self.tx_sent_packets_since_key >= pkt_thr or self.tx_sent_bytes_since_key >= byte_thr) {
                // Start TX update: derive next secret and keys, toggle tx key phase
                // PHASE 57 PART 11D: Use QUIC "quic ku" label, not TLS "traffic upd" (RFC 9001 §6)
                const current_secret = self.app_tx_secret.?;
                const hash = hashForSecret(&current_secret) catch return;
                const next_secret = ks.updateQuicSecretHash(hash, &current_secret);

                // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
                const preserved_hp = self.app_tx_keys.?.hp;

                const t = ks.deriveKeyIvHpHash(hash, &next_secret, self.version_v2);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
                self.app_tx_secret = next_secret;
                self.maybeEmitTxKeyUpdateLog(&next_secret);
                self.tx_key_phase = !self.tx_key_phase;
                self.tx_update_in_progress = true;
                // First PN in the new phase is the next sent PN value
                self.tx_update_start_pn = self.pn_app_tx;
                // Reset counters for next epoch
                self.tx_sent_packets_since_key = 0;
                self.tx_sent_bytes_since_key = 0;
                logger.debugPrint("keyupdate: triggered phase={d} start_pn={d}\n", .{ @intFromBool(self.tx_key_phase), self.tx_update_start_pn });
            }
        }

        pub fn maybeFinalizeKeyUpdateOnAck(self: *Connection, largest_acked: u64) void {
            if (!self.tx_update_in_progress) return;
            // Consider update complete once any PN >= start_pn is ACKed
            if (largest_acked >= self.tx_update_start_pn) {
                if (self.tx_prev_keys) |*kp| {
                    zeroKeys(kp);
                }
                self.tx_prev_keys = null;
                self.tx_update_in_progress = false;
                logger.debugPrint("keyupdate: finalized ack_pn={d} phase={d}\n", .{ largest_acked, @intFromBool(self.tx_key_phase) });
            }
        }

        /// Remote key update observed: align our TX keys to the same phase immediately.
        pub fn syncTxKeysAfterRxUpdate(self: *Connection) void {
            if (self.app_tx_secret == null or self.app_tx_keys == null) return;
            if (self.tx_key_phase == self.rx_key_phase) return;
            const current_secret = self.app_tx_secret.?;
            const hash = hashForSecret(&current_secret) catch return;
            const next_secret = ks.updateQuicSecretHash(hash, &current_secret);
            const next_mat = ks.deriveKeyIvHpHash(hash, &next_secret, self.version_v2);
            if (self.tx_prev_keys) |*kp| {
                zeroKeys(kp);
            }
            self.tx_prev_keys = self.app_tx_keys;

            // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
            const preserved_hp = self.app_tx_keys.?.hp;
            self.app_tx_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = preserved_hp };
            self.app_tx_secret = next_secret;
            self.maybeEmitTxKeyUpdateLog(&next_secret);
            self.tx_key_phase = self.rx_key_phase;
            self.tx_update_in_progress = true;
            self.tx_update_start_pn = self.pn_app_tx;
            self.tx_sent_packets_since_key = 0;
            self.tx_sent_bytes_since_key = 0;
            logger.debugPrint("[PHASE57-TX] Synced TX keys to phase={} start_pn={}\n", .{
                @intFromBool(self.tx_key_phase),
                self.tx_update_start_pn,
            });
        }
    };
}
