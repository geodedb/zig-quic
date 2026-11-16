const std = @import("std");
const compat = @import("compat");
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
const logger = @import("quic_logger");
const builtin = @import("builtin");
const crypto_utils = @import("crypto_utils.zig");
const stream_mod = @import("stream.zig");
const key_update = @import("quic_key_update");

/// Compile-time toggle for verbose method-level tracing in connection helpers.
/// Set to `true` and rebuild (`zig build`) to emit detailed debug prints via
/// `logger.debugPrint`. Requires recompilation; has no effect at runtime.
const trace_enabled = false;
inline fn trace(comptime fmt: []const u8, args: anytype) void {
    if (trace_enabled) logger.debugPrint(fmt, args);
}

pub fn bind(comptime Connection: type) type {
    return struct {
        const hashForSecret = crypto_utils.hashForSecret;
        const frame_ack_max_ranges = 64; // frame/ack.zig max_ack_ranges

        fn trackAppStreamPacket(
            self: *Connection,
            pn: u64,
            stream_id: u64,
            offset: u64,
            fin: bool,
            data: []const u8,
        ) void {
            if (!self.app_stream_retx_init) return;
            self.retx_diag.noteSent(self.allocator.*, pn, stream_id, offset, data.len, fin);
            const owned = self.allocator.dupe(u8, data) catch return;
            if (putAppStreamRetx(self, pn, .{
                .stream_id = stream_id,
                .offset = offset,
                .fin = fin,
                .data = owned,
                .retransmit_count = @as(u16, 0),
            })) self.noteStreamPacketTracked(stream_id);
        }

        /// Re-track `entry` under a new packet number after retransmitting
        /// it. If tracking fails the data is gone; account for it so the
        /// stream does not wait for an acknowledgement that cannot come.
        fn retrackAppStreamRetx(self: *Connection, pn: u64, entry: RetxEntry(Connection)) void {
            const stream_id = entry.stream_id;
            if (!putAppStreamRetx(self, pn, entry)) self.noteStreamPacketReleased(stream_id);
        }

        fn RetxEntry(comptime C: type) type {
            return @FieldType(@FieldType(C, "app_stream_retx").KV, "value");
        }

        /// Index of the first element of ascending `pns` that is >= `pn`.
        fn lowerBoundPn(pns: []const u64, pn: u64) usize {
            var lo: usize = 0;
            var hi: usize = pns.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (pns[mid] < pn) lo = mid + 1 else hi = mid;
            }
            return lo;
        }

        /// Live (not yet pruned) part of the ascending retransmit PN order.
        fn retxOrder(self: *Connection) []u64 {
            return self.app_stream_retx_order.items[self.app_stream_retx_head..];
        }

        /// Track `entry` under `pn` in the retransmit map and its PN order.
        /// Takes ownership of `entry.data`; frees it and returns false if
        /// tracking fails.
        fn putAppStreamRetx(self: *Connection, pn: u64, entry: RetxEntry(Connection)) bool {
            const order = retxOrder(self);
            const at = lowerBoundPn(order, pn);
            const in_order = at < order.len and order[at] == pn;
            if (!in_order) {
                self.app_stream_retx_order.ensureUnusedCapacity(self.allocator.*, 1) catch {
                    self.allocator.free(entry.data);
                    return false;
                };
            }
            // QUAL-08: getOrPut so a packet-number collision (e.g. PTO/probe
            // paths reusing retransmission tracking) frees the displaced entry's
            // buffer instead of leaking it.
            const gop = self.app_stream_retx.getOrPut(pn) catch {
                self.allocator.free(entry.data);
                return false;
            };
            if (gop.found_existing) {
                const displaced = gop.value_ptr.stream_id;
                self.allocator.free(gop.value_ptr.data);
                self.noteStreamPacketReleased(displaced);
            }
            gop.value_ptr.* = entry;
            if (!in_order) {
                // New packet numbers are the largest so far: an append.
                self.app_stream_retx_order.insertAssumeCapacity(self.app_stream_retx_head + at, pn);
            }
            return true;
        }

        /// Drop PNs whose entry is gone from the front of the order, and
        /// compact the order once it is mostly dead space. Amortized O(1)
        /// per tracked packet.
        fn pruneAppStreamRetxOrder(self: *Connection) void {
            const order = &self.app_stream_retx_order;
            while (self.app_stream_retx_head < order.items.len and
                !self.app_stream_retx.contains(order.items[self.app_stream_retx_head]))
            {
                self.app_stream_retx_head += 1;
            }
            const live = order.items.len - self.app_stream_retx_head;
            const stale = live -| self.app_stream_retx.count();
            if (stale > 64 and stale > self.app_stream_retx.count()) {
                // Out-of-band removals left dead PNs mid-order; filter them.
                var w: usize = 0;
                for (order.items[self.app_stream_retx_head..]) |pn| {
                    if (!self.app_stream_retx.contains(pn)) continue;
                    order.items[w] = pn;
                    w += 1;
                }
                order.items.len = w;
                self.app_stream_retx_head = 0;
            } else if (self.app_stream_retx_head > 64 and self.app_stream_retx_head * 2 >= order.items.len) {
                std.mem.copyForwards(u64, order.items[0..live], order.items[self.app_stream_retx_head..]);
                order.items.len = live;
                self.app_stream_retx_head = 0;
            }
        }

        /// Oldest packet number still tracked for STREAM retransmission.
        fn oldestAppStreamRetxPn(self: *Connection) ?u64 {
            pruneAppStreamRetxOrder(self);
            const order = retxOrder(self);
            return if (order.len == 0) null else order[0];
        }

        /// Inclusive packet-number interval acknowledged by one ACK range.
        const AckedInterval = recovery.Recovery.AckedRange;

        /// Decode an ACK frame's ranges (RFC 9000 §19.3.1) into inclusive
        /// [lo, hi] intervals, newest first. Unlike enumerating packet
        /// numbers, this is not bounded by how many packets are acknowledged:
        /// one interval per range, bounded by the frame's range count.
        fn ackedIntervals(largest: u64, first_range: u64, ranges: []const frame.AckRange, out: []AckedInterval) []AckedInterval {
            if (out.len == 0) return out[0..0];
            var n: usize = 0;
            const first_lo = if (largest >= first_range) largest - first_range else 0;
            out[n] = .{ .lo = first_lo, .hi = largest };
            n += 1;
            var smallest = first_lo;
            for (ranges) |r| {
                if (n >= out.len) break;
                // Next range's largest = smallest - gap - 2.
                const step = r.gap +| 2;
                if (smallest < step) break;
                const hi = smallest - step;
                const lo = if (hi >= r.len) hi - r.len else 0;
                out[n] = .{ .lo = lo, .hi = hi };
                n += 1;
                smallest = lo;
                if (smallest == 0) break;
            }
            return out[0..n];
        }

        fn pnInAckedIntervals(intervals: []const AckedInterval, pn: u64) bool {
            for (intervals) |iv| {
                if (pn > iv.hi) return false; // intervals are descending
                if (pn >= iv.lo) return true;
            }
            return false;
        }

        /// Drop retransmission state for every tracked STREAM packet the
        /// peer's ACK frame covers.
        ///
        /// Each interval is located in the ascending PN order by binary
        /// search and only the tracked packets inside it are visited and
        /// removed (SONNY-6434: this used to walk the whole map on every
        /// ACK). Exact removal by range membership is what lets every entry
        /// still tracked below the largest acknowledged PN be treated as
        /// unacknowledged data.
        fn dropAckedStreamTracking(self: *Connection, intervals: []const AckedInterval) void {
            if (!self.app_stream_retx_init) return;
            self.retx_diag.noteAck(self.allocator.*, intervals);
            for (intervals) |iv| {
                const order = retxOrder(self);
                if (order.len == 0) break;
                if (iv.hi < order[0] or iv.lo > order[order.len - 1]) continue;
                const a = lowerBoundPn(order, iv.lo);
                const b = if (iv.hi == std.math.maxInt(u64)) order.len else lowerBoundPn(order, iv.hi + 1);
                if (a == b) continue;
                for (order[a..b]) |pn| {
                    self.ack_retx_entries_visited +%= 1;
                    if (self.app_stream_retx.fetchRemove(pn)) |removed| {
                        self.allocator.free(removed.value.data);
                        // May retire the stream (RFC 9000 §3.1 Data Recvd).
                        self.noteStreamPacketReleased(removed.value.stream_id);
                    }
                }
                // Splice [a, b) out of the order (usually a prefix).
                const base = self.app_stream_retx_head;
                const list = &self.app_stream_retx_order;
                if (a == 0) {
                    self.app_stream_retx_head += b;
                } else {
                    std.mem.copyForwards(u64, list.items[base + a ..], list.items[base + b ..]);
                    list.items.len -= b - a;
                }
            }
            dropAckedRetxAliases(self, intervals);
            pruneAppStreamRetxOrder(self);
        }

        /// Remember that the data tracked under `old_pn` now lives under
        /// `new_pn`, so an ACK that covers `old_pn` still acknowledges it.
        fn noteRekey(self: *Connection, old_pn: u64, new_pn: u64) void {
            self.app_stream_retx_alias.put(self.allocator.*, old_pn, new_pn) catch return;
            // Aliases of entries since acknowledged or dropped are dead;
            // drop them once they outnumber the live entries.
            if (self.app_stream_retx_alias.count() > 64 + 2 * self.app_stream_retx.count()) pruneRetxAliases(self);
        }

        /// The current key of the data first sent as `pn`, if still tracked.
        fn resolveRetxAlias(self: *Connection, pn: u64) ?u64 {
            var cur = pn;
            var hops: usize = 0;
            while (self.app_stream_retx_alias.get(cur)) |next| : (hops += 1) {
                if (hops >= 64) return null;
                if (self.app_stream_retx.contains(next)) return next;
                cur = next;
            }
            return null;
        }

        fn pruneRetxAliases(self: *Connection) void {
            var dead: std.ArrayList(u64) = .empty;
            defer dead.deinit(self.allocator.*);
            var it = self.app_stream_retx_alias.keyIterator();
            while (it.next()) |k| {
                if (resolveRetxAlias(self, k.*) == null) dead.append(self.allocator.*, k.*) catch return;
            }
            for (dead.items) |k| _ = self.app_stream_retx_alias.remove(k);
        }

        /// ACKs covering an earlier packet number of re-sent data release
        /// the data where it lives now. Without this, data re-sent by a PTO
        /// whose original packet was then acknowledged stayed tracked and
        /// was sent again if the re-sent copy was lost (SONNY-6478).
        fn dropAckedRetxAliases(self: *Connection, intervals: []const AckedInterval) void {
            if (self.app_stream_retx_alias.count() == 0) return;
            var acked_old: std.ArrayList(u64) = .empty;
            defer acked_old.deinit(self.allocator.*);
            // Work is min(packet numbers the ACK covers, aliases), never
            // proportional to both (SONNY-6434: ACK work stays bounded).
            const n_alias: u64 = self.app_stream_retx_alias.count();
            var span: u64 = 0;
            for (intervals) |iv| span +|= (iv.hi - iv.lo) +| 1;
            if (span <= n_alias) {
                for (intervals) |iv| {
                    var pn = iv.lo;
                    while (true) : (pn += 1) {
                        if (self.app_stream_retx_alias.contains(pn)) acked_old.append(self.allocator.*, pn) catch return;
                        if (pn == iv.hi) break;
                    }
                }
            } else {
                var it = self.app_stream_retx_alias.keyIterator();
                while (it.next()) |k| {
                    for (intervals) |iv| {
                        if (k.* >= iv.lo and k.* <= iv.hi) {
                            acked_old.append(self.allocator.*, k.*) catch return;
                            break;
                        }
                    }
                }
            }
            for (acked_old.items) |old| {
                if (resolveRetxAlias(self, old)) |cur| {
                    if (self.app_stream_retx.fetchRemove(cur)) |removed| {
                        self.allocator.free(removed.value.data);
                        self.noteStreamPacketReleased(removed.value.stream_id);
                    }
                }
                _ = self.app_stream_retx_alias.remove(old);
            }
        }

        fn recordAppStreamRetransmitAttempt(tracked: anytype) void {
            if (tracked.retransmit_count < std.math.maxInt(u16)) {
                tracked.retransmit_count += 1;
            }
        }

        /// Encode and send `tracked` as a STREAM frame in a new 1-RTT packet
        /// numbered `self.pn_app_tx`. Returns the packet length if the whole
        /// datagram was sent; on any failure nothing was sent.
        ///
        /// The send keys are read here, with the key phase: the previous
        /// retransmission's onShortHeaderPacketSent can start a key update,
        /// and a packet protected with the old keys but carrying the new key
        /// phase cannot be decrypted (RFC 9001 §6; SONNY-6649).
        fn sendStreamRetransmission(self: *Connection, tracked: RetxEntry(Connection)) ?usize {
            const tx = self.app_tx_keys orelse return null;
            var frame_storage: [2048]u8 = undefined;
            var frame_stream = @import("compat").fixedBufWriter(&frame_storage);
            _ = (frame.Frame{
                .stream = .{
                    .stream_id = tracked.stream_id,
                    .offset = tracked.offset,
                    .fin = tracked.fin,
                    .data = tracked.data,
                },
            }).write(frame_stream.writer()) catch return null;
            const frame_bytes = frame_storage[0..frame_stream.pos];
            const packet_storage = self.packet_pool.checkout() catch return null;
            defer self.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                frame_bytes,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch return null;
            const pkt = packet_storage[0..pkt_len];
            const sent = self.send(pkt) catch return null;
            if (sent != pkt.len) return null;
            return pkt.len;
        }

        /// Largest STREAM payload one packet carries, as in writeStream().
        fn maxStreamPayload(self: *const Connection) usize {
            return @min(@as(usize, self.path_mtu) - 50, 1350);
        }

        /// Whether the tracked packet `pn` is lost on an ACK whose largest
        /// acknowledged PN is `largest_acked`; see retransmitLostStreamPackets.
        fn trackedPacketLost(pn: u64, largest_acked: u64, recovery_reported_loss: bool) bool {
            if (pn >= largest_acked) return false;
            return (largest_acked - pn) >= 3 or recovery_reported_loss;
        }

        /// A run of lost tracked packets, in PN order from `order[first]`
        /// to `order[last]`, whose STREAM data is contiguous on one stream
        /// and fits one packet. `count` live entries (dead PNs in between
        /// are skipped); `len` bytes; `fin` if the last one carries the FIN.
        const LostRun = struct { last: usize, count: usize, len: usize, fin: bool };

        /// Extend the lost packet at `order[first]` with the lost packets
        /// after it that continue its stream's data (RFC 9000 §13.3: lost
        /// data is sent again in new frames, which need not have the
        /// original frame boundaries).
        fn lostRunFrom(self: *Connection, order: []const u64, first: usize, largest_acked: u64, recovery_reported_loss: bool) LostRun {
            const head = self.app_stream_retx.getPtr(order[first]).?;
            var run: LostRun = .{ .last = first, .count = 1, .len = head.data.len, .fin = head.fin };
            const max_len = maxStreamPayload(self);
            var end = head.offset + head.data.len;
            var j = first + 1;
            while (!run.fin and j < order.len) : (j += 1) {
                const pn = order[j];
                const e = self.app_stream_retx.getPtr(pn) orelse continue;
                if (!trackedPacketLost(pn, largest_acked, recovery_reported_loss)) break;
                if (e.stream_id != head.stream_id or e.offset != end) break;
                if (run.len + e.data.len > max_len) break;
                end += e.data.len;
                run = .{ .last = j, .count = run.count + 1, .len = run.len + e.data.len, .fin = e.fin };
            }
            return run;
        }

        /// One tracked entry holding the data of every packet in `run`.
        /// The caller owns the returned data.
        fn coalesceLostRun(self: *Connection, order: []const u64, first: usize, run: LostRun) ?RetxEntry(Connection) {
            const head = self.app_stream_retx.getPtr(order[first]).?;
            const data = self.allocator.alloc(u8, run.len) catch return null;
            var at: usize = 0;
            var attempts: u16 = 0;
            for (order[first .. run.last + 1]) |pn| {
                const e = self.app_stream_retx.getPtr(pn) orelse continue;
                @memcpy(data[at..][0..e.data.len], e.data);
                at += e.data.len;
                attempts = @max(attempts, e.retransmit_count);
            }
            return .{ .stream_id = head.stream_id, .offset = head.offset, .fin = run.fin, .data = data, .retransmit_count = attempts };
        }

        const RunOutcome = enum { sent, send_failed, no_memory };

        /// Send the data of every packet in `run` in one new packet, which
        /// then replaces them in the retransmission tracking. On failure
        /// nothing was sent and they stay tracked.
        fn retransmitLostRun(self: *Connection, order: []const u64, first: usize, run: LostRun) RunOutcome {
            var merged = coalesceLostRun(self, order, first, run) orelse return .no_memory;
            const next_pn = self.pn_app_tx;
            const pkt_len = sendStreamRetransmission(self, merged) orelse {
                self.allocator.free(merged.data);
                return .send_failed;
            };
            self.retx_diag.noteRetransmit(merged.stream_id, merged.offset, merged.data.len, merged.fin);
            self.retx_diag.noteSent(self.allocator.*, next_pn, merged.stream_id, merged.offset, merged.data.len, merged.fin);
            for (order[first .. run.last + 1]) |pn| {
                const removed = self.app_stream_retx.fetchRemove(pn) orelse continue;
                self.allocator.free(removed.value.data);
            }
            recordAppStreamRetransmitAttempt(&merged);
            self.stream_retx_packets +%= 1;
            logger.debugPrint(
                "[stream-retx] pn={}..{} ({} packets) -> pn={} stream={} off={} len={} fin={} attempt={}\n",
                .{ order[first], order[run.last], run.count, next_pn, merged.stream_id, merged.offset, merged.data.len, merged.fin, merged.retransmit_count },
            );
            self.onShortHeaderPacketSent(pkt_len, true);
            // The new packet counts once in the stream's outstanding packets,
            // where the run counted `count` times. Released after it is
            // tracked, so the stream cannot look fully acknowledged between.
            const stream_id = merged.stream_id;
            retrackAppStreamRetx(self, next_pn, merged);
            for (1..run.count) |_| self.noteStreamPacketReleased(stream_id);
            // No alias from the old packet numbers: an ACK for one of them
            // acknowledges only that packet's part of this data.
            return .sent;
        }

        /// Retransmit STREAM data lost below the largest acknowledged PN,
        /// oldest first, at most two packets per ACK.
        ///
        /// Lost packets whose data continues on the same stream go out
        /// together, up to a full packet (SONNY-6649). One small STREAM
        /// frame per packet used to be retransmitted as one packet each:
        /// after a burst loss of N such packets, recovery took N packets
        /// and N/2 ACKs, minutes for a long blackout on a loaded host.
        ///
        /// A tracked packet below `largest_acked` is lost once it is
        /// kPacketThreshold (3) packets older (RFC 9002 §6.1.1), or as soon
        /// as recovery reported loss on this ACK (time threshold, §6.1.2:
        /// recovery compacts lost packets away, so their state is no longer
        /// queryable here). Acknowledged packets were already removed by
        /// dropAckedStreamTracking(), and packets above the largest
        /// acknowledged are never lost on an ACK (§6.1) -- they are left to
        /// later ACKs or the PTO (§6.2).
        ///
        /// Walking the ascending PN order means both conditions hold for a
        /// prefix of it, so the walk stops at the first entry that is not
        /// lost and visits O(budget) entries (SONNY-6434: it used to scan the
        /// whole map and query recovery for every entry, each query a
        /// linear scan of the sent packets when the packet was untracked).
        fn retransmitLostStreamPackets(self: *Connection, largest_acked_opt: ?u64, recovery_reported_loss: bool) void {
            if (!self.app_stream_retx_init) return;
            if (!self.hasConfirmedAppTxKeys()) return;
            const largest_acked = largest_acked_opt orelse return;

            var retransmitted: usize = 0;
            var i: usize = 0;
            while (retransmitted < 2) : (i += 1) {
                const order = retxOrder(self);
                if (i >= order.len) break;
                const lost_pn = order[i];
                self.ack_retx_entries_visited +%= 1;
                const tracked_ptr = self.app_stream_retx.getPtr(lost_pn) orelse continue;
                // CANARY: REQ=REQ-QUIC-HC-138; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AppStreamTimeLossRetx; STATUS=TESTED; TEST=app_ack_time_threshold_loss_retransmits_retained_STREAM_data; OWNER=transport; UPDATED=2026-05-28
                //
                // Recovery compacts packets as soon as they are acked or
                // declared lost. For time-threshold loss with only one or two
                // newer packets ACKed, packet-threshold detection does not
                // fire, and getPacketDeliveryState() can already return
                // unknown by the time app STREAM retransmission runs. If
                // recovery reported app loss on this ACK, any retained STREAM
                // packet older than the largest ACK is still unacked
                // application data and must be retransmitted.
                if (!trackedPacketLost(lost_pn, largest_acked, recovery_reported_loss)) break;

                const run = lostRunFrom(self, order, i, largest_acked, recovery_reported_loss);
                if (run.count > 1) switch (retransmitLostRun(self, order, i, run)) {
                    .sent => {
                        i = run.last;
                        retransmitted += 1;
                        continue;
                    },
                    .send_failed => break,
                    // Out of memory to coalesce: send the first one alone.
                    .no_memory => {},
                };

                const next_pn = self.pn_app_tx;
                // A failed send (WouldBlock, pool exhausted) leaves the entry
                // tracked for the next ACK or PTO. Stop rather than re-encode
                // every remaining lost packet against a full socket.
                const pkt_len = sendStreamRetransmission(self, tracked_ptr.*) orelse break;
                self.retx_diag.noteRetransmit(tracked_ptr.stream_id, tracked_ptr.offset, tracked_ptr.data.len, tracked_ptr.fin);
                self.retx_diag.noteSent(self.allocator.*, next_pn, tracked_ptr.stream_id, tracked_ptr.offset, tracked_ptr.data.len, tracked_ptr.fin);
                var tracked = self.app_stream_retx.fetchRemove(lost_pn).?.value;
                recordAppStreamRetransmitAttempt(&tracked);
                self.stream_retx_packets +%= 1;
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
                self.onShortHeaderPacketSent(pkt_len, true);
                retrackAppStreamRetx(self, next_pn, tracked);
                noteRekey(self, lost_pn, next_pn);
                retransmitted += 1;
            }
            pruneAppStreamRetxOrder(self);

            // No cumulative "prune below largest" pass here. Recovery compacts
            // a packet away as soon as it is declared lost, so a lost packet
            // and an acknowledged one both report `.unknown` from
            // getPacketDeliveryState(). The old prune could not tell them
            // apart and freed lost STREAM data that the 2-per-ACK budget above
            // had not reached yet; after a burst of receive-buffer drops the
            // stream was left with a permanent hole and stalled. Acknowledged
            // packets are now removed exactly by dropAckedStreamTracking()
            // (ACK range membership), so the map stays bounded by unacked data.
        }

        pub fn sendDatagram(self: *Connection, data: []const u8) !void {
            // Every 1-RTT packet is sent under Connection.mu (SONNY-4379).
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // #163: stack buffer replaces per-call ArrayList assembly.
            var frame_buf: [2048]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .datagram = .{ .data = data } }).write(w) catch 0;
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                fbs.getWritten(),
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
        /// Open a stream. Takes Connection.mu: when the stream limit is
        /// reached it sends STREAMS_BLOCKED, a 1-RTT packet (SONNY-4379).
        pub fn openStream(self: *Connection, bidi: bool) !u64 {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            return self.openStreamUnlocked(bidi);
        }

        /// openStream for callers that hold Connection.mu.
        pub fn openStreamUnlocked(self: *Connection, bidi: bool) !u64 {
            if (bidi) {
                if (self.opened_bidi >= self.peer_max_streams_bidi) {
                    // #163: stack buffer for single STREAMS_BLOCKED_BIDI frame (< 16 bytes).
                    var frame_buf: [64]u8 = undefined;
                    var fbs = @import("compat").fixedBufWriter(&frame_buf);
                    const w = fbs.writer();
                    _ = (frame.Frame{ .streams_blocked_bidi = .{ .max = self.peer_max_streams_bidi } }).write(w) catch 0;
                    self.sendControlFrames(fbs.getWritten());
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
                    // Propagate OOM -- callers already handle errors from openStream.
                    _ = try self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data });
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
                    // Propagate OOM -- callers already handle errors from openStream.
                    _ = try self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data });
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
            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
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
                            // Propagate OOM -- writeStream already returns errors.
                            _ = try self.stream_txs.put(id, .{ .peer_max_stream_data = self.peer_max_stream_data });
                        }
                    } else {
                        // Client or server-initiated stream - normal openStream path
                        _ = self.openStreamUnlocked(true) catch |e| switch (e) {
                            error.OutOfStreams => return e,
                            else => return e,
                        };
                    }
                }
                if (!self.stream_send_state.canWrite() or self.stream_send_aborted or self.stream_send_fin_sent) return error.StreamStopped;
            } else {
                self.ensureStreamTxInit();
                if (self.stream_txs.getPtr(id) == null) {
                    // A retired stream finished both directions (SONNY-6478).
                    if (self.isStreamRetired(id)) return error.StreamStopped;
                    // Check if this is a client-initiated stream and we're the server
                    const is_client_initiated = (id & 1) == 0;
                    if (self.role == .Server and is_client_initiated) {
                        // Server responding on client-initiated stream - initialize TX state
                        _ = self.ensureStreamRx(id);
                        // Propagate OOM -- writeStream already returns errors.
                        _ = try self.stream_txs.put(id, .{ .peer_max_stream_data = self.peer_max_stream_data });
                    } else {
                        trace("DEBUG writeStream: InvalidStream - no TX state for stream {}\n", .{id});
                        return error.InvalidStream;
                    }
                }
                // Safely inspect per-stream TX state (abort / FIN flags)
                if (self.stream_txs.getPtr(id)) |st| {
                    if (st.canWrite()) |_| {} else |err| {
                        trace("DEBUG writeStream: StreamStopped - aborted={} fin_sent={}\n", .{ st.aborted, st.fin_sent });
                        return err;
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
                const now_ns = compat.nanoTimestamp();
                if (self.last_stream_data_blocked_limit != peer_stream_limit or
                    now_ns - self.last_stream_data_blocked_at_ns >= 200 * std.time.ns_per_ms)
                {
                    self.last_stream_data_blocked_limit = peer_stream_limit;
                    self.last_stream_data_blocked_at_ns = now_ns;
                    // #163: stack buffer for single STREAM_DATA_BLOCKED frame (< 24 bytes).
                    var frame_buf: [64]u8 = undefined;
                    var fbs1 = @import("compat").fixedBufWriter(&frame_buf);
                    const w1 = fbs1.writer();
                    _ = (frame.Frame{ .stream_data_blocked = .{ .stream_id = id, .limit = peer_stream_limit } }).write(w1) catch 0;
                    self.sendControlFrames(fbs1.getWritten());
                }
                return error.FlowControlBlocked;
            }
            // Enforce connection-level MAX_DATA
            if (self.conn_send_off >= peer_conn_limit) {
                // Signal DATA_BLOCKED and re-emit periodically while blocked.
                const now_ns = compat.nanoTimestamp();
                if (self.last_data_blocked_limit != peer_conn_limit or
                    now_ns - self.last_data_blocked_at_ns >= 200 * std.time.ns_per_ms)
                {
                    self.last_data_blocked_limit = peer_conn_limit;
                    self.last_data_blocked_at_ns = now_ns;
                    // #163: stack buffer for single DATA_BLOCKED frame (< 16 bytes).
                    var frame_buf: [64]u8 = undefined;
                    var fbs2 = @import("compat").fixedBufWriter(&frame_buf);
                    const w2 = fbs2.writer();
                    _ = (frame.Frame{ .data_blocked = .{ .limit = peer_conn_limit } }).write(w2) catch 0;
                    self.sendControlFrames(fbs2.getWritten());
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

            // SF-025 / RFC 9002 §7: Enforce congestion window before sending.
            // msquic: forks/msquic/src/core/cubic.c:189 - if (BytesInFlight >= CongestionWindow) SendAllowance = 0
            const cc_state = self.rec.getCongestionState();
            const bytes_in_flight = cc_state.bytes_in_flight;
            const cwnd = cc_state.cwnd;
            // CANARY: REQ=REQ-QUIC-HC-125; FEATURE="QUIC High-Concurrency Requests"; ASPECT=TrustedLocalCwndBypass; STATUS=TESTED; TEST=localhost_cwnd_exemption_allows_stream_write_when_congestion_window_is_full; OWNER=transport; UPDATED=2026-05-28
            // Loopback endpoints already opt into a trusted-localhost
            // amplification exemption. Apply the same scoped policy to this
            // pre-send congestion gate so high-fanout local clients can drain
            // small response bursts instead of wedging every writer behind a
            // recovery window that only those responses would unblock.
            const localhost_cwnd_exempt = self.exempt_localhost and self.isLocalhost();
            if (!localhost_cwnd_exempt and bytes_in_flight >= cwnd) {
                logger.debugPrint("[CC-BLOCKED] bytes_in_flight={} >= cwnd={}, deferring send\n", .{ bytes_in_flight, cwnd });
                return 0;
            }
            logger.debugPrint("[CC-OK] bytes_in_flight={} cwnd={} localhost_exempt={} available={}\n", .{
                bytes_in_flight,
                cwnd,
                localhost_cwnd_exempt,
                if (bytes_in_flight < cwnd) cwnd - bytes_in_flight else 0,
            });

            var frame_storage: [2048]u8 = undefined;
            var frame_stream = @import("compat").fixedBufWriter(&frame_storage);
            // RFC 9000 S13.2.1: Piggyback an ACK frame into STREAM packets when
            // we have received app-space packets to acknowledge.  This reduces
            // standalone ACK-only datagrams and speeds peer-side loss recovery.
            // The ACK is written first because non-ack-eliciting frames (ACK)
            // should precede ack-eliciting frames (STREAM) per convention.
            //
            // #109 closure note (within-packet coalescing): we already coalesce
            // ACK + STREAM here; the 2 KiB `frame_storage` buffer easily fits
            // both a 4-range ACK (~50 B) and a 1300 B max-payload STREAM frame.
            // GSO-style multi-packet batching is provided by the paced-send
            // flush in `endpoint.processExpiredTimers` (#165/#183 closure)
            // which collects up to 16 paced datagrams per `sendmmsg` call.
            // Cross-stream coalescing (multiple STREAM frames from different
            // streams in one packet) is a future enhancement — the frame
            // builder already supports it, but `writeStream` currently emits
            // exactly one STREAM frame per call. See PERF_GAP_ANALYSIS for
            // the next step.
            const include_app_ack = self.pn_app.have_any;
            if (include_app_ack) {
                const now_ns: u64 = @intCast(compat.nanoTimestamp());
                const ad = self.buildAckApp();
                const ack_delay = self.getAckDelayEncoded(.Application, now_ns);
                const ack_ecn = self.getAckEcn(.Application);
                _ = (frame.Frame{ .ack = .{
                    .largest = ad.largest,
                    .ack_delay = ack_delay,
                    .first_range = ad.first_range,
                    .ranges = ad.ranges,
                    .ecn = ack_ecn,
                } }).write(frame_stream.writer()) catch 0;
            }
            // Write STREAM frame with slice sized by to_send.
            _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = cur_off, .fin = fin and to_send == data.len, .data = data[0..to_send] } }).write(frame_stream.writer()) catch 0;
            const frame_bytes = frame_storage[0..frame_stream.pos];
            logger.debugPrint("DEBUG STREAM frame bytes ({} bytes): ", .{frame_bytes.len});
            for (frame_bytes[0..@min(frame_bytes.len, 40)]) |b| logger.debugPrint("{x:0>2} ", .{b});
            if (frame_bytes.len > 40) logger.debugPrint("...", .{});
            logger.debugPrint("\n", .{});
            const dcid = self.shortHeaderDcid();
            logger.debugPrint("Server sending STREAM with DCID len={}, first_byte={x}\n", .{ dcid.len, if (dcid.len > 0) dcid[0] else 0 });
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                dcid,
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
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
            if (include_app_ack) self.markAppAckSent();
            if (id == 0) {
                self.stream_send_off +%= to_send;
                if (fin and to_send == data.len) {
                    self.stream_send_fin_sent = true;
                    self.stream_send_state = .DataSent;
                } else if (to_send > 0) {
                    self.stream_send_state = .Send;
                }
            } else if (self.stream_txs.getPtr(id)) |stx| {
                try stx.recordDataSent(@intCast(to_send), fin and to_send == data.len);
            }
            self.conn_send_off += to_send;
            return to_send;
        }

        /// Read from STREAM into buf; returns number of bytes or WouldBlock.
        /// Read reassembled bytes from a stream into buf; returns number copied or WouldBlock.
        /// GAP-0200: Thread-safe - acquires connection mutex
        pub fn readStream(self: *Connection, id: u64, buf: []u8) !usize {
            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
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
                // A retired stream was read to its end (SONNY-6478).
                if (self.isStreamRetired(id)) return 0;
                logger.debugPrint("readStream - stream {} not found in RX map\n", .{id});
                return error.InvalidStream;
            };
            trace("[CONN-PTR-READ] inbox_len={} streams_rx_count={}\n", .{ s.available(), self.streams_rx.count() });
            // TRACE: readStream inbox status
            // logger.debugPrint("readStream - inbox has {} bytes\n", .{s.inbox.items.len});
            if (s.available() == 0) {
                // If FIN offset reached and no buffered data remains, surface FIN as 0-length read.
                if (s.isFinished()) return 0;
                return error.WouldBlock;
            }
            const n = s.readInto(buf);
            if (id == 0) {
                self.stream_recv_state = s.state;
                self.stream_recv_fin = s.isFinished();
            }

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

                // Connection-level flow control: update local_max_data as data is consumed.
                // RFC 9000 §4.1: The receiver MUST send MAX_DATA frames to allow the
                // sender to continue sending. Without this, the peer gets DATA_BLOCKED
                // after sending initial_max_data bytes and the connection stalls/resets.
                // Quinn-style: local_max_data = conn_recv_total + connection_receive_window
                const conn_receive_window: u64 = 10 * 1024 * 1024; // 10MB connection window
                const new_max_data = self.conn_recv_total + conn_receive_window;
                if (new_max_data > self.local_max_data) {
                    self.local_max_data = new_max_data;
                }

                // PHASE 46: Trigger flow control frame generation after window update
                // This ensures timely updates when data is consumed (quinn-style)
                self.advertiseInitialFlowControl();
                // Everything delivered (RFC 9000 §3.2 Data Read): release the
                // stream if its send side is finished too.
                self.maybeRetireStream(id);
            }

            // TRACE: readStream returning data
            // logger.debugPrint("readStream - returning {} bytes\n", .{n});
            return n;
        }

        /// Gracefully close a stream by sending a STREAM frame with FIN.
        ///
        /// RFC 9000 §3.3: Signals the peer that no more data will be sent on this
        /// stream. For abrupt termination with an error code, use `resetStream`.
        pub fn closeStream(self: *Connection, id: u64, app_error_code: u64) !void {
            // SONNY-4776: share the writer's critical section through packet
            // emission and PN advancement; a reused PN also reuses the AEAD nonce.
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            _ = app_error_code;
            if (id == 0) {
                if (!self.stream_send_state.canWrite() or self.stream_send_aborted) return error.StreamStopped;
            } else {
                if (!self.stream_txs_init) return error.InvalidStream;
                const st = self.stream_txs.getPtr(id) orelse {
                    if (self.isStreamRetired(id)) return error.StreamStopped;
                    return error.InvalidStream;
                };
                try st.canWrite();
            }
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            var frame_buf: [64]u8 = undefined;
            var frame_w: std.Io.Writer = .fixed(&frame_buf);
            const final_off: u64 = if (id == 0) self.stream_send_off else self.stream_txs.getPtr(id).?.off;
            _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = final_off, .fin = true, .data = &[_]u8{} } }).write(&frame_w) catch 0;
            const frame_bytes = frame_buf[0..frame_w.end];
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                frame_bytes,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            );
            const pkt = packet_storage[0..pkt_len];
            const sent_pn = self.pn_app_tx;
            _ = try self.send(pkt);
            // Track the FIN like any STREAM frame: it is retransmitted if lost
            // and its acknowledgement completes the send side (SONNY-6478).
            trackAppStreamPacket(self, sent_pn, id, final_off, true, &[_]u8{});
            self.onShortHeaderPacketSent(pkt.len, true);
            if (id == 0) {
                self.stream_send_fin_sent = true;
                self.stream_send_state = .DataSent;
            } else if (self.stream_txs.getPtr(id)) |st| {
                try st.recordFinSent();
            }
        }

        /// Abort a stream by sending RESET_STREAM with the given application error code.
        ///
        /// RFC 9000 §19.4: RESET_STREAM terminates sending on a stream, signalling
        /// the peer that any data beyond `final_size` will never arrive. Unlike
        /// `closeStream` (which sends a graceful FIN), this immediately marks the
        /// stream TX as aborted so no further STREAM frames will be emitted.
        ///
        /// QUIC-H3-001: Public API for HTTP/3 adapters to reset streams on error.
        pub fn resetStream(self: *Connection, id: u64, app_error_code: u64) !void {
            // Serialize terminal state and packet emission with writes and FINs.
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            // Validate stream exists
            if (id == 0) {
                if (!self.stream_send_state.canWrite() or self.stream_send_aborted) return error.StreamStopped;
            } else {
                if (!self.stream_txs_init) return error.InvalidStream;
                const st = self.stream_txs.getPtr(id) orelse {
                    if (self.isStreamRetired(id)) return error.StreamStopped;
                    return error.InvalidStream;
                };
                try st.canWrite();
            }
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // Mark stream as aborted
            if (id == 0) {
                self.stream_send_state = .ResetSent;
                self.stream_send_aborted = true;
            } else {
                if (self.stream_txs.getPtr(id)) |st| {
                    try st.recordResetSent();
                }
            }
            // Use per-stream offset as final_size
            const final_size: u64 = if (id == 0) self.stream_send_off else self.stream_txs.getPtr(id).?.off;
            // #163: stack buffer for single RESET_STREAM frame (< 40 bytes).
            var frame_buf: [64]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .reset_stream = .{
                .stream_id = id,
                .error_code = app_error_code,
                .final_size = final_size,
            } }).write(w) catch 0;
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                fbs.getWritten(),
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            );
            const pkt = packet_storage[0..pkt_len];
            const sent_pn = self.pn_app_tx;
            _ = try self.send(pkt);
            // Sent again until acknowledged (RFC 9000 §13.3; SONNY-6486).
            self.noteControlPacket(sent_pn, fbs.getWritten());
            self.onShortHeaderPacketSent(pkt.len, true);
            self.maybeRetireStream(id);
        }

        /// Handle STOP_SENDING by responding with RESET_STREAM carrying our final size.
        /// Process incoming STOP_SENDING frame; respond with RESET_STREAM if not already closed.
        pub fn handleStopSending(self: *Connection, stream_id: u64, app_error_code: u64) !void {
            // SONNY-4776 / SONNY-4379: frame dispatch releases mu before
            // calling here; protect this RESET_STREAM packet like explicit resets.
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // Nothing left to stop on a retired stream (SONNY-6478).
            if (self.isStreamRetired(stream_id)) return;
            // RFC 9000 §19.5: STOP_SENDING for a receive-only stream is
            // STREAM_STATE_ERROR (SONNY-6486).
            if (self.isPeerInitiatedStream(stream_id) and (stream_id & 0x2) != 0) return error.StreamStateError;
            // Mark stream as aborted for sending further STREAM frames
            if (stream_id == 0) {
                if (!self.stream_send_state.canWrite()) return error.StreamStopped;
                self.stream_send_state = .ResetSent;
                self.stream_send_aborted = true;
            } else if (self.stream_txs_init) {
                if (self.stream_txs.getPtr(stream_id)) |st| {
                    try st.recordResetSent();
                }
            }
            // Use per-stream offset as final_size (not always stream 0's offset)
            // Nothing sent on a stream without send state: final size 0 (it
            // used to report stream 0's offset).
            const final_size: u64 = if (stream_id == 0)
                self.stream_send_off
            else if (self.stream_txs_init and self.stream_txs.getPtr(stream_id) != null)
                self.stream_txs.getPtr(stream_id).?.off
            else
                0;
            // #163: stack buffer for single RESET_STREAM frame (< 40 bytes).
            var frame_buf: [64]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .reset_stream = .{ .stream_id = stream_id, .error_code = app_error_code, .final_size = final_size } }).write(w) catch 0;
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                fbs.getWritten(),
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch 0;
            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                const sent_pn = self.pn_app_tx;
                _ = self.send(pkt) catch |err| {
                    logger.warn("send STOP_SENDING response failed: {s}", .{@errorName(err)});
                };
                self.noteControlPacket(sent_pn, fbs.getWritten());
                self.onShortHeaderPacketSent(pkt.len, true);
            }
            self.maybeRetireStream(stream_id);
        }

        /// Handle a received RESET_STREAM for RX-side teardown. Marks RX aborted, caps final size,
        /// discards any buffered segments beyond final_size, and treats the stream as finished.
        /// Process incoming RESET_STREAM updating RX state and freeing buffers.
        pub fn handleResetStream(self: *Connection, stream_id: u64, app_error_code: u64, final_size: u64) error{ FinalSizeError, FlowControlError, StreamLimitExceeded, StreamStateError }!void {
            _ = app_error_code; // surfaced to app layer out of scope here
            // Frame dispatch releases mu; take it like pushStreamFrame does.
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mu.lockUncancelable(io);
            defer self.mu.unlock(io);
            // RFC 9000 §19.4: RESET_STREAM on a send-only stream, or on a
            // locally initiated stream not yet opened, is STREAM_STATE_ERROR;
            // a peer stream beyond our limit is STREAM_LIMIT_ERROR (§4.6).
            // The limit check also bounds the implicitly opened ids that
            // admitStream records (SONNY-6486).
            if (!self.isPeerInitiatedStream(stream_id)) {
                if ((stream_id & 0x2) != 0) return error.StreamStateError;
                if ((stream_id >> 2) >= self.opened_bidi) return error.StreamStateError;
            }
            try self.validatePeerStreamLimit(stream_id);
            // A retired stream already finished (SONNY-6478).
            if (!self.admitStream(stream_id)) return;
            // Only stream 0 supported in this slice, but apply generically.
            var s = self.ensureStreamRx(stream_id);
            // Validate the final size BEFORE mutating receive state (RFC 9000
            // §4.5). A FINAL_SIZE_ERROR aborts the connection; the dispatcher
            // maps the returned error to CONNECTION_CLOSE 0x06.
            try s.recordReset(final_size);
            // §4.5: the final size counts against flow control like data.
            if (final_size > s.highest_off) {
                const stream_window: u64 = if (s.initial_window_size > 0) s.initial_window_size else self.local_max_stream_data;
                const stream_limit = @max(@max(s.local_max_stream_data, s.last_sent_max_stream_data), stream_window);
                const delta = final_size - s.highest_off;
                if (final_size > stream_limit or self.conn_recv_highest_total + delta > self.local_max_data) return error.FlowControlError;
                self.conn_recv_highest_total += delta;
                s.highest_off = final_size;
            }
            if (stream_id == 0) {
                self.stream_recv_aborted = true;
                self.stream_recv_state = .ResetRead;
            }
            // Drop any buffered segment that starts at or beyond final_size
            var i: usize = 0;
            while (i < s.bufs.items.len) {
                const seg = s.bufs.items[i];
                if (seg.off >= final_size) {
                    stream_mod.freeSegment(self.allocator.*, seg);
                    s.buffered_bytes -|= seg.data.len;
                    // Keep the segments sorted by offset (tryDrain relies on it).
                    _ = s.bufs.orderedRemove(i);
                    continue;
                }
                // A segment overlapping final_size cannot pass recordReset()
                // (final_size >= highest received). Trim defensively anyway,
                // into an allocation of exactly the kept length: segment data
                // is always freed with its own length (SONNY-6486: the slice
                // used to be shortened in place, then freed short).
                const seg_end = seg.off + @as(u64, seg.data.len);
                if (seg_end > final_size) {
                    const keep_len: usize = @intCast(final_size - seg.off);
                    const kept = self.allocator.dupe(u8, seg.data[0..keep_len]) catch {
                        stream_mod.freeSegment(self.allocator.*, seg);
                        s.buffered_bytes -|= seg.data.len;
                        _ = s.bufs.orderedRemove(i);
                        continue;
                    };
                    stream_mod.freeSegment(self.allocator.*, seg);
                    s.buffered_bytes -|= seg.data.len - keep_len;
                    s.bufs.items[i] = .{ .off = seg.off, .data = kept };
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
            if (stream_id == 0) self.stream_recv_fin = true;
            self.maybeRetireStream(stream_id);
        }

        /// Explicitly tear down stream RX state and clear flags for the given stream.
        /// Safe to call multiple times; no-op if stream not present.
        /// Tear down local bookkeeping for a stream (called after FIN/RESET & application consumption).
        ///
        /// Not needed for streams that finish normally: those are retired
        /// automatically once both directions are done (SONNY-6478). This
        /// releases the state at once, retires the id (later frames for it are
        /// ignored) and, for a peer-initiated stream, returns its stream-count
        /// credit.
        pub fn teardownStream(self: *Connection, stream_id: u64) void {
            self.releaseStreamState(stream_id);
            if (stream_id == 0) {
                self.stream_opened = false;
                self.stream_send_aborted = false;
                self.stream_send_fin_sent = false;
                self.stream_recv_aborted = false;
                self.stream_recv_fin = false;
                self.stream_send_state = .Ready;
                self.stream_recv_state = .Recv;
                self.stream_send_off = 0;
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
            self.markPtoDirty(); // #182: notify endpoint dirty-set
            // ACK ranges per RFC 9000 §19.3.1, as inclusive intervals. Passing
            // ranges (not an enumeration of packet numbers, formerly capped at
            // 256) lets recovery acknowledge every packet the frame covers.
            var interval_buf: [frame_ack_max_ranges + 1]AckedInterval = undefined;
            const intervals = ackedIntervals(largest, first_range, ranges, &interval_buf);
            if (space == .Application) {
                dropAckedStreamTracking(self, intervals);
            }
            // Update recovery for given space
            const now_i = compat.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const res = self.rec.onAckRangesReceivedWithEcn(space, intervals, 0, now_ns, ecn);
            if (res.bytes_acked > 0) {
                _ = self.tx_credit_generation.fetchAdd(1, .release);
                std.Io.Threaded.global_single_threaded.io().futexWake(u32, &self.tx_credit_generation.raw, std.math.maxInt(u32));
            }
            // Promote time-threshold losses if any expired now
            _ = self.rec.onLossTimeExpired(now_ns);
            if (space == .Application) {
                retransmitLostStreamPackets(self, largest, res.bytes_lost > 0);
                self.onAckControlFrames(intervals, largest, res.bytes_lost > 0);
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
                    if (pnInAckedIntervals(intervals, ppn)) {
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
            self.markPtoDirty(); // #182: notify endpoint dirty-set
            if (self.pto_initial_active) {
                if (self.pto_initial_id != 0) _ = ep.cancelTimer(self.pto_initial_id);
                self.pto_initial_active = false;
            }
            self.resetPtoBackoffInitial();
        }
        /// cancelPtoHandshake: Stop active Handshake PTO timer and reset its backoff.
        pub fn cancelPtoHandshake(self: *Connection, ep: anytype) void {
            self.markPtoDirty(); // #182: notify endpoint dirty-set
            if (self.pto_handshake_active) {
                if (self.pto_handshake_id != 0) _ = ep.cancelTimer(self.pto_handshake_id);
                self.pto_handshake_active = false;
            }
            self.resetPtoBackoffHandshake();
        }
        /// cancelPtoApp: Stop active Application PTO timer and reset its backoff.
        pub fn cancelPtoApp(self: *Connection, ep: anytype) void {
            self.markPtoDirty(); // #182: notify endpoint dirty-set
            if (self.pto_app_active) {
                if (self.pto_app_id != 0) _ = ep.cancelTimer(self.pto_app_id);
                self.pto_app_active = false;
            }
            self.resetPtoBackoffApp();
        }

        /// Keys for the Initial or Handshake space were discarded (RFC 9001
        /// §4.9): drop that space's loss recovery state and stop its PTO
        /// (RFC 9002 §6.4). Without this its packets stayed in flight for
        /// ever, and the PTO backoff their probes raised (shared with the
        /// application space) was never reset.
        pub fn discardSpaceRecovery(self: *Connection, space: recovery.PacketNumberSpace) void {
            self.rec.discardSpace(space);
            switch (space) {
                .Initial => {
                    self.pto_initial_active = false;
                    self.pto_initial_count = 0;
                },
                .Handshake => {
                    self.pto_handshake_active = false;
                    self.pto_handshake_count = 0;
                },
                .Application => unreachable,
            }
            self.markPtoDirty();
        }

        /// Compute PTO for Application space and arm timer if not active.
        /// Recompute earliest PTO across spaces and (re)arm timer if needed.
        pub fn computeAndMaybeArmPto(self: *Connection, ep: anytype) void {
            // Fast path: skip syscall + computation if timer already armed
            if (self.pto_app_active) return;
            // RFC 9002 §6.2.1: the deadline counts from the most recent
            // ack-eliciting packet and includes the exponential backoff
            // (rec.pto_count); no timer while nothing ack-eliciting is in
            // flight.
            const now_i = compat.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.ptoDeadlineNs(.Application) orelse return;
            const delay_ns: u64 = if (next_deadline <= now_ns) 0 else next_deadline - now_ns;
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            // The timer wakes at least every 100 ms. appPtoDue() decides on
            // expiry whether the deadline has really passed, so this bounds
            // the wake-up interval without shortening the PTO (SONNY-6454).
            if (delay_ms > 100) delay_ms = 100;
            self.pto_app_active = true;
            self.pto_app_id = ep.scheduleConnPto(self, .PtoApp, delay_ms) catch 0;
        }

        /// Whether an expired Application PTO timer should send a probe
        /// (RFC 9002 §6.2.1). The timer is armed once and not moved on every
        /// send or ACK, so on expiry it may be stale: everything it covered
        /// may have been acknowledged, or newer packets moved the deadline.
        /// Probing then would resend delivered data or send a PING loop on an
        /// idle connection (SONNY-6478). Lost STREAM data still waiting to be
        /// retransmitted with nothing in flight is always probed for.
        pub fn appPtoDue(self: *Connection, now_ns: u64) bool {
            const deadline = self.rec.ptoDeadlineNs(.Application) orelse
                return self.app_stream_retx_init and self.app_stream_retx.count() > 0;
            // Timer resolution is 1 ms; treat a deadline within it as passed.
            return now_ns +| self.rec.timer_granularity_ns >= deadline;
        }

        /// Whether an expired Initial or Handshake PTO timer should send a
        /// probe: its RFC 9002 §6.2.1 deadline (last ack-eliciting packet
        /// in the space plus the backed-off PTO) has passed. The timers
        /// wake at least every 100 ms; probing on every wake-up raised the
        /// backoff shared with application data ten times a second
        /// (NEWGAP-10). No probe when nothing ack-eliciting is in flight.
        pub fn handshakePtoDue(self: *Connection, space: recovery.PacketNumberSpace, now_ns: u64) bool {
            std.debug.assert(space != .Application);
            const deadline = self.rec.ptoDeadlineNs(space) orelse return false;
            return now_ns +| self.rec.timer_granularity_ns >= deadline;
        }

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
                    _ = self.sendPmtudProbe(target) catch |err| {
                        logger.warn("PMTUD probe (start) failed: {s}", .{@errorName(err)});
                    };
                    // Re-arm for search follow-up
                    self.pmtud_state = .ProbeSearch;
                    self.pmtudArm(ep, 20);
                },
                .ProbeSearch => {
                    // If last probe validated, try increasing further toward typical 1500
                    var next: u16 = self.path_mtu;
                    if (next < 1400) next = 1400 else if (next < 1472) next = 1472 else if (next < 1492) next = 1492 else if (next < 1500) next = 1500;
                    if (next > self.path_mtu) {
                        _ = self.sendPmtudProbe(next) catch |err| {
                            logger.warn("PMTUD probe (search) failed: {s}", .{@errorName(err)});
                        };
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
            // Fast path: skip syscall + computation if already armed or keys dropped
            if (self.pto_initial_active or self.initial_keys_dropped) return;
            const now_i = compat.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.computeSpacePtoTimeNs(.Initial, now_ns);
            if (next_deadline == null) return;
            const delay_ns: u64 = if (next_deadline.? <= now_ns) 0 else next_deadline.? - now_ns;
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            if (delay_ms > 100) delay_ms = 100;
            self.pto_initial_active = true;
            self.pto_initial_id = ep.scheduleConnPto(self, .PtoInitial, delay_ms) catch 0;
        }
        /// Compute PTO for Handshake space and arm timer if not active.
        /// Recompute PTO for Handshake space only and arm timer.
        pub fn computeAndMaybeArmPtoHandshake(self: *Connection, ep: anytype) void {
            // Fast path: skip syscall + computation if already armed or handshake keys gone
            if (self.pto_handshake_active) return;
            // Skip if handshake TX keys are already dropped (connection is established)
            if (self.hs_tx_keys == null and self.app_tx_keys != null) return;
            const now_i = compat.nanoTimestamp();
            const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
            const next_deadline = self.rec.computeSpacePtoTimeNs(.Handshake, now_ns);
            if (next_deadline == null) return;
            const delay_ns: u64 = if (next_deadline.? <= now_ns) 0 else next_deadline.? - now_ns;
            var delay_ms: u32 = @intCast(@min(delay_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(u32))));
            if (delay_ms == 0) delay_ms = 1;
            if (delay_ms > 100) delay_ms = 100;
            self.pto_handshake_active = true;
            self.pto_handshake_id = ep.scheduleConnPto(self, .PtoHandshake, delay_ms) catch 0;
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
            // #163: stack buffer for PING+PADDING (fallback path, up to 1200 B).
            var frame_buf: [2048]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;

            const dest_cid = if (self.role == .Client)
                self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]
            else
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len];
            const token = if (self.role == .Client)
                self.initial_token.items
            else
                &[_]u8{};

            // CANARY: REQ=REQ-QUIC-HC-081; FEATURE="QUIC High-Concurrency Requests"; ASPECT=HandshakeSendAccounting; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
            //
            // Initial/Handshake PTO probes are recovery state. Under high
            // parallelism, a transient sender failure must not consume packet
            // numbers or mark bytes in flight.
            if (self.crypto_retx_initial) |retx| {
                const max_crypto_chunk: usize = @max(@as(usize, 256), @as(usize, self.path_mtu) - 80);
                const chunk_len = @min(retx.len, max_crypto_chunk);

                // #163: stack buffer for CRYPTO + PADDING up to 1200 B.
                var crypto_frame_buf: [2048]u8 = undefined;
                var cfbs = @import("compat").fixedBufWriter(&crypto_frame_buf);
                const cw = cfbs.writer();
                _ = (frame.Frame{
                    .crypto = .{
                        .offset = self.crypto_retx_initial_off,
                        .data = retx[0..chunk_len],
                    },
                }).write(cw) catch |err| {
                    logger.err("PTO Initial CRYPTO frame write failed: {s}", .{@errorName(err)});
                };

                var crypto_pkt = packet.encodeInitialProtected(
                    self.allocator.*,
                    self.version,
                    dest_cid,
                    self.our_scid.bytes[0..self.our_scid.len],
                    token,
                    @as(u32, @truncate(self.pn_initial_tx)),
                    2,
                    cfbs.getWritten(),
                    txk,
                ) catch null;
                if (crypto_pkt) |bytes_out_initial| {
                    var bytes_out = bytes_out_initial;
                    if (bytes_out.len < 1200) {
                        const pad_needed = 1200 - bytes_out.len;
                        self.allocator.free(bytes_out);
                        cw.writeByteNTimes(@intFromEnum(frame.FrameType.PADDING), pad_needed) catch |err| {
                            logger.err("PTO Initial padding append failed: {s}", .{@errorName(err)});
                            return;
                        };
                        crypto_pkt = packet.encodeInitialProtected(
                            self.allocator.*,
                            self.version,
                            dest_cid,
                            self.our_scid.bytes[0..self.our_scid.len],
                            token,
                            @as(u32, @truncate(self.pn_initial_tx)),
                            2,
                            cfbs.getWritten(),
                            txk,
                        ) catch null;
                        if (crypto_pkt) |retry_out| {
                            bytes_out = retry_out;
                        } else {
                            return;
                        }
                    }
                    defer self.allocator.free(bytes_out);
                    const sent = self.send(bytes_out) catch |err| {
                        logger.warn("PTO Initial CRYPTO retx send failed: {s}", .{@errorName(err)});
                        return;
                    };
                    if (sent != bytes_out.len) {
                        logger.warn("PTO Initial CRYPTO retx short send: sent={} expected={}", .{ sent, bytes_out.len });
                        return;
                    }
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
                fbs.getWritten(),
                txk,
            ) catch null;
            if (out) |bytes_out_initial| {
                var bytes_out = bytes_out_initial;
                if (self.role == .Client and bytes_out.len < 1200) {
                    const pad_needed = 1200 - bytes_out.len;
                    self.allocator.free(bytes_out);
                    w.writeByteNTimes(@intFromEnum(frame.FrameType.PADDING), pad_needed) catch |err| {
                        logger.err("PTO Initial padding append failed: {s}", .{@errorName(err)});
                        return;
                    };
                    out = packet.encodeInitialProtected(
                        self.allocator.*,
                        self.version,
                        dest_cid,
                        self.our_scid.bytes[0..self.our_scid.len],
                        token,
                        @as(u32, @truncate(self.pn_initial_tx)),
                        2,
                        fbs.getWritten(),
                        txk,
                    ) catch null;
                    if (out) |retry_out| {
                        bytes_out = retry_out;
                    } else {
                        return;
                    }
                }
                defer self.allocator.free(bytes_out);
                const sent = self.send(bytes_out) catch |err| {
                    logger.warn("PTO Initial send failed: {s}", .{@errorName(err)});
                    return;
                };
                if (sent != bytes_out.len) {
                    logger.warn("PTO Initial short send: sent={} expected={}", .{ sent, bytes_out.len });
                    return;
                }
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
                    // #163: stack buffer for CRYPTO chunk.
                    var crypto_frame_buf: [2048]u8 = undefined;
                    var cfbs = @import("compat").fixedBufWriter(&crypto_frame_buf);
                    const cw = cfbs.writer();
                    _ = (frame.Frame{
                        .crypto = .{
                            .offset = self.crypto_retx_handshake_off + sent_off,
                            .data = retx[sent_off .. sent_off + chunk_len],
                        },
                    }).write(cw) catch |err| {
                        logger.err("PTO Handshake CRYPTO frame write failed: {s}", .{@errorName(err)});
                    };

                    const out_crypto = packet.encodeHandshakeProtected(
                        self.allocator.*,
                        self.version,
                        self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
                        self.our_scid.bytes[0..self.our_scid.len],
                        @as(u32, @truncate(self.pn_handshake_tx)),
                        2,
                        cfbs.getWritten(),
                        tx,
                    ) catch null;
                    if (out_crypto) |bytes_out| {
                        defer self.allocator.free(bytes_out);
                        const sent = self.send(bytes_out) catch |err| {
                            logger.warn("PTO Handshake CRYPTO retx send failed: {s}", .{@errorName(err)});
                            return;
                        };
                        if (sent != bytes_out.len) {
                            logger.warn("PTO Handshake CRYPTO retx short send: sent={} expected={}", .{ sent, bytes_out.len });
                            return;
                        }
                        self.onPacketSent(.Handshake, self.pn_handshake_tx, bytes_out.len, true);
                        self.pn_handshake_tx +%= 1;
                        probes_sent += 1;
                    } else {
                        return;
                    }
                    sent_off += chunk_len;
                }
                if (probes_sent > 0) return;
            }

            // #163: stack buffer for single PING frame.
            var frame_buf: [64]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
            const out = packet.encodeHandshakeProtected(
                self.allocator.*,
                self.version,
                // DCID = client's Initial SCID; SCID = our chosen SCID
                self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
                self.our_scid.bytes[0..self.our_scid.len],
                @as(u32, @truncate(self.pn_handshake_tx)),
                2,
                fbs.getWritten(),
                tx,
            ) catch null;
            if (out) |bytes_out| {
                defer self.allocator.free(bytes_out);
                const sent = self.send(bytes_out) catch |err| {
                    logger.warn("PTO Handshake send failed: {s}", .{@errorName(err)});
                    return;
                };
                if (sent != bytes_out.len) {
                    logger.warn("PTO Handshake short send: sent={} expected={}", .{ sent, bytes_out.len });
                    return;
                }
                self.onPacketSent(.Handshake, self.pn_handshake_tx, bytes_out.len, true);
                self.pn_handshake_tx +%= 1;
            }
        }
        /// Send a minimal PTO probe for the Application space (PING frame).
        /// Emit an Application-space PTO probe.
        pub fn sendPtoProbeApp(self: *Connection) void {
            if (!self.hasConfirmedAppTxKeys()) return;
            const tx = self.app_tx_keys.?;

            // CANARY: REQ=REQ-QUIC-HC-079; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AppPtoSendAccounting; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
            //
            // App PTO recovery runs during high-fanout request bursts when the
            // server socket can drop client STREAM datagrams. Do not advance the
            // retransmit PN, packet-number accounting, or recovery bytes-in-flight
            // unless the probe datagram was fully accepted by the UDP sender.
            // A WouldBlock/short-send must keep the original tracking entry so the
            // next PTO can retry the same application bytes.
            // CANARY: REQ=REQ-QUIC-HC-080; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ReliableAppPtoRetxRetention; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
            //
            // STREAM retransmit buffers are reliability state, not a best-effort
            // retry queue. Keep unacked application data until ACK or connection
            // teardown; an 8-attempt cap can silently abandon client requests
            // during synchronized high-concurrency bursts.
            // Prefer probing with outstanding STREAM data when available.
            // This prevents deadlocks where pure-PING probes keep the PTO loop
            // alive but don't make application delivery progress under heavy
            // loss/corruption.
            if (self.app_stream_retx_init and self.app_stream_retx.count() > 0) {
                if (oldestAppStreamRetxPn(self)) |probe_pn| {
                    if (self.app_stream_retx.fetchRemove(probe_pn)) |removed| {
                        var tracked = removed.value;
                        var frame_storage: [2048]u8 = undefined;
                        var frame_stream = @import("compat").fixedBufWriter(&frame_storage);
                        _ = (frame.Frame{
                            .stream = .{
                                .stream_id = tracked.stream_id,
                                .offset = tracked.offset,
                                .fin = tracked.fin,
                                .data = tracked.data,
                            },
                        }).write(frame_stream.writer()) catch |err| {
                            logger.err("PTO App STREAM frame write failed: {s}", .{@errorName(err)});
                            retrackAppStreamRetx(self, probe_pn, tracked);
                            self.markPtoDirty();
                            return;
                        };
                        const frame_bytes = frame_storage[0..frame_stream.pos];

                        if (frame_bytes.len > 0) {
                            const packet_storage = self.packet_pool.checkout() catch {
                                retrackAppStreamRetx(self, probe_pn, tracked);
                                self.markPtoDirty();
                                return;
                            };
                            defer self.packet_pool.release(packet_storage);
                            const next_pn = self.pn_app_tx;
                            const pkt_len = packet.encodeShortProtectedInto(
                                packet_storage,
                                self.shortHeaderDcid(),
                                next_pn,
                                self.appPacketNumberLen(next_pn),
                                frame_bytes,
                                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                                self.tx_key_phase,
                            ) catch 0;
                            if (pkt_len != 0) {
                                const pkt = packet_storage[0..pkt_len];
                                const sent = self.send(pkt) catch 0;
                                if (sent == pkt.len) {
                                    self.retx_diag.noteRetransmit(tracked.stream_id, tracked.offset, tracked.data.len, tracked.fin);
                                    self.retx_diag.noteSent(self.allocator.*, next_pn, tracked.stream_id, tracked.offset, tracked.data.len, tracked.fin);
                                    recordAppStreamRetransmitAttempt(&tracked);
                                    self.stream_retx_packets +%= 1;
                                    self.onShortHeaderPacketSent(pkt.len, true);
                                    retrackAppStreamRetx(self, next_pn, tracked);
                                    noteRekey(self, probe_pn, next_pn);
                                    return;
                                }
                            }
                        }
                        // CANARY: REQ=REQ-QUIC-HC-139; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AppPtoSendFailureRearm; STATUS=TESTED; TEST=app_PTO_send_failure_rearms_retransmission_timer; OWNER=transport; UPDATED=2026-05-28
                        //
                        // A nonblocking UDP WouldBlock/short-send during PTO
                        // must not leave retained STREAM data without a future
                        // timer. No packet was recorded via
                        // onShortHeaderPacketSent(), so explicitly dirty the
                        // connection after restoring the retransmit entry.
                        retrackAppStreamRetx(self, probe_pn, tracked);
                        self.markPtoDirty();
                    }
                }
            }

            // #163: stack buffer for single PING frame.
            var frame_buf: [64]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
            const packet_storage = self.packet_pool.checkout() catch {
                self.markPtoDirty();
                return;
            };
            defer self.packet_pool.release(packet_storage);
            const pkt_len = packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                fbs.getWritten(),
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch 0;
            if (pkt_len != 0) {
                const pkt = packet_storage[0..pkt_len];
                const sent = self.send(pkt) catch |err| {
                    logger.warn("PTO App send failed: {s}", .{@errorName(err)});
                    self.markPtoDirty();
                    return;
                };
                if (sent == pkt.len) {
                    self.onShortHeaderPacketSent(pkt.len, true);
                } else {
                    self.markPtoDirty();
                }
            } else {
                self.markPtoDirty();
            }
        }

        /// Close the connection with an application error code using a 1-RTT CONNECTION_CLOSE.
        /// Build and send CONNECTION_CLOSE (application or transport) with reason string.
        pub fn sendConnectionClose(self: *Connection, app_error_code: u64, reason: []const u8) !void {
            logger.debugPrint("DEBUG: sendConnectionClose called with error_code={}, reason=\"{s}\"\n", .{ app_error_code, reason });
            if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
            const tx = self.app_tx_keys.?;
            // #163: stack buffer for single CONNECTION_CLOSE frame. Reason string
            // is unbounded in the protocol but practically capped; 2048 B covers
            // typical reasons plus a hard error.NoSpaceLeft guard for unusually long ones.
            var frame_buf: [2048]u8 = undefined;
            var fbs = @import("compat").fixedBufWriter(&frame_buf);
            const w = fbs.writer();
            _ = (frame.Frame{ .connection_close = .{ .error_code = app_error_code, .frame_type = 0, .reason = reason } }).write(w) catch 0;
            const packet_storage = try self.packet_pool.checkout();
            defer self.packet_pool.release(packet_storage);
            const pkt_len = try packet.encodeShortProtectedInto(
                packet_storage,
                self.shortHeaderDcid(),
                self.pn_app_tx,
                self.appPacketNumberLen(self.pn_app_tx),
                fbs.getWritten(),
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            );
            const pkt = packet_storage[0..pkt_len];
            _ = try self.send(pkt);
            self.onShortHeaderPacketSent(pkt.len, true);
            logger.debugPrint("DEBUG: Connection marked as closed after CONNECTION_CLOSE sent\n", .{});
            self.markClosed();
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
            self.tx_key_gen = 0;
            self.rx_key_gen = 0;
            self.rx_key_gen_start_pn = 0;
            self.tx_sent_packets_since_key = 0;
            self.tx_sent_bytes_since_key = 0;
            self.tx_update_in_progress = false;
            self.tx_prev_keys = null;
            self.rx_prev_keys = null;
            self.rx_prev_discard_ns = 0;
            // After 1-RTT keys are ready, proactively advertise initial flow-control if allowed
            self.advertiseInitialFlowControl();
            // Drop Initial keys immediately; defer dropping Handshake keys until any pending Finished CRYPTO is sent.
            self.initial_keys_dropped = true;
            // Clear cached Initial keys when they're dropped
            self.initial_rx_keys = null;
            self.initial_tx_keys = null;
            self.discardSpaceRecovery(.Initial);

            // RFC 9001 §4.1.2: Server MUST wait until peer Finished is received before dropping handshake keys.
            // Client can drop immediately after sending its Finished.
            // Additionally, wait until we've sent at least one Handshake packet for coalescing (RFC 9000 §12.2).
            const can_drop_hs_keys = if (self.role == .Server)
                // Server: wait for peer_finished_verified (client Finished received) AND first Handshake packet sent
                (self.peer_finished_verified and self.handshake_packet_sent)
            else
                // Client: never here. RFC 9001 §4.9.2: the client keeps its Handshake
                // keys (and the Finished retransmission buffer) until the handshake is
                // CONFIRMED, i.e. HANDSHAKE_DONE arrives (processShortHeader drops them).
                // Dropping them on 1-RTT key install made a lost client Finished
                // unrecoverable: the server never got 1-RTT keys and dropped every
                // request packet the client sent.
                false;

            if (can_drop_hs_keys) {
                logger.debugPrint("{s}: Dropping Handshake keys (peer_finished_verified={})\n", .{ if (self.role == .Server) "Server" else "Client", self.peer_finished_verified });
                self.hs_rx_keys = null;
                self.hs_tx_keys = null;
                self.discardSpaceRecovery(.Handshake);
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

                // #163: stack buffer for HANDSHAKE_DONE + MAX_DATA + MAX_STREAMS_BIDI (< 64 B total).
                var frame_buf: [128]u8 = undefined;
                var fbs = @import("compat").fixedBufWriter(&frame_buf);
                const w = fbs.writer();
                _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
                // FIXED: Do NOT send MAX_STREAM_DATA for stream 0 unconditionally. It violates RFC 9000 if stream 0 is not open.
                // _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_data = .{ .max = self.local_max_data } }).write(w) catch 0;
                _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(w) catch 0;
                // NOTE: Session tickets removed - Context API doesn't support queueNewSessionTicket yet
                const sent_pn = self.pn_app_tx;
                self.sendControlFrames(fbs.getWritten());
                if (self.pn_app_tx != sent_pn) self.handshake_done_pn = sent_pn;
                self.handshake_done_sent = true;
            }
        }

        /// Destination Connection ID for short-header packets is the peer-chosen ID.
        /// Prefer the Initial SCID observed from peer, including the valid
        /// zero-length case. Peer-provided NEW_CONNECTION_ID values are a fallback
        /// only before the Initial SCID has been latched.
        pub fn shortHeaderDcid(self: *Connection) []const u8 {
            const result = if (self.peer_initial_scid_set or self.peer_initial_scid.len > 0)
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
            // Use secureZero to prevent compiler from eliding the wipe.
            const sz = std.crypto.secureZero; // fips-exempt: non-security — memory zeroization helper, not a FIPS algorithm.
            sz(u8, &k.key);
            sz(u8, &k.iv);
            sz(u8, &k.hp);
        }

        pub fn maybeTriggerKeyUpdateOnSend(self: *Connection, bytes_sent: usize) void {
            if (self.app_tx_keys == null or self.app_tx_secret == null) return;
            if (self.disable_auto_key_update) return;
            // RFC 9001 §6.1: "An endpoint MUST NOT initiate a key update
            // prior to having confirmed the handshake (Section 4.1.2)." A
            // server confirms it when the handshake completes, a client when
            // it receives HANDSHAKE_DONE (§4.1.2). hasConfirmedAppTxKeys()
            // is handshake completion, which a client reaches earlier.
            const confirmed = switch (self.role) {
                .Server => self.peer_finished_verified,
                .Client => self.handshake_done_seen,
            };
            if (!confirmed) return;
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
                const next_secret = key_update.deriveNextTrafficSecret(hash, &current_secret) catch return;

                // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
                const preserved_hp = self.app_tx_keys.?.hp;

                const t = ks.deriveKeyIvHpHash(hash, &next_secret, self.version_v2);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
                self.app_tx_secret = next_secret;
                self.maybeEmitTxKeyUpdateLog(&next_secret);
                self.tx_key_phase = !self.tx_key_phase;
                self.tx_key_gen += 1;
                self.tx_update_in_progress = true;
                // First PN in the new phase is the next sent PN value. The
                // caller must have counted the packet that triggered the
                // update already (onShortHeaderPacketSent increments
                // pn_app_tx first): that packet went out with the old keys,
                // and an ACK for it must not complete this update.
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

        /// Remote key update observed: update our send keys to the peer's
        /// generation before acknowledging (RFC 9001 §6.2).
        ///
        /// Compare generations, not key phase bits: when our own update is
        /// already ahead of what we receive (we initiated it, the peer has
        /// not responded yet), the phases differ although the send keys
        /// must not move. Moving them anyway skipped a generation the peer
        /// never saw, and it could decrypt nothing more (SONNY-6522).
        pub fn syncTxKeysAfterRxUpdate(self: *Connection) void {
            if (self.app_tx_secret == null or self.app_tx_keys == null) return;
            while (self.tx_key_gen < self.rx_key_gen) {
                if (!advanceTxKeysOnce(self)) return;
            }
        }

        fn advanceTxKeysOnce(self: *Connection) bool {
            const current_secret = self.app_tx_secret.?;
            const hash = hashForSecret(&current_secret) catch return false;
            const next_secret = key_update.deriveNextTrafficSecret(hash, &current_secret) catch return false;
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
            self.tx_key_phase = !self.tx_key_phase;
            self.tx_key_gen += 1;
            self.tx_update_in_progress = true;
            self.tx_update_start_pn = self.pn_app_tx;
            self.tx_sent_packets_since_key = 0;
            self.tx_sent_bytes_since_key = 0;
            logger.debugPrint("[PHASE57-TX] Synced TX keys to phase={} start_pn={}\n", .{
                @intFromBool(self.tx_key_phase),
                self.tx_update_start_pn,
            });
            return true;
        }
    };
}
