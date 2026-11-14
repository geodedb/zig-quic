// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Stream retirement (RFC 9000 §3, §4.6; SONNY-6478).
//!
//! A stream's state is released once both directions are finished: the send
//! side has every byte and the FIN acknowledged ("Data Recvd", §3.1) or was
//! reset, and the receive side has delivered everything to the application
//! ("Data Read", §3.2) or was reset. Retiring a peer-initiated stream returns
//! one unit of stream-count credit (MAX_STREAMS, §4.6) to the peer.
//!
//! Retired streams leave no per-stream state behind. Whether a stream id is
//! retired is derived from what remains:
//! - a locally initiated stream below the opened count with no state;
//! - a peer-initiated stream below the highest one seen, with no state, that
//!   is not an implicitly opened stream the peer has not used yet (§3.2: a
//!   frame for stream N opens every lower-numbered stream of its type).
//! Only those not-yet-used ids are kept, so the bookkeeping is bounded by the
//! stream-count limit, not by how many streams a connection has completed.
//!
//! Callers hold `Connection.mu`.

const std = @import("std");
const frame = @import("quic_frame");
const logger = @import("quic_logger");

pub fn bind(comptime Connection: type) type {
    return struct {
        fn isUni(id: u64) bool {
            return (id & 0x2) != 0;
        }

        fn typeIdx(id: u64) usize {
            return if (isUni(id)) 1 else 0;
        }

        fn hasStreamState(self: *const Connection, id: u64) bool {
            if (self.streams_rx_init and self.streams_rx.contains(id)) return true;
            if (self.stream_txs_init and self.stream_txs.contains(id)) return true;
            return false;
        }

        /// True if `id` was used and its state has since been released.
        /// Frames for a retired stream are ignored (RFC 9000 §3.2/§3.5: an
        /// endpoint may discard data for a closed stream); reads report the
        /// end of the stream and writes fail with StreamStopped.
        pub fn isStreamRetired(self: *const Connection, id: u64) bool {
            if (hasStreamState(self, id)) return false;
            const num = id >> 2;
            if (!self.isPeerInitiatedStream(id)) {
                const opened = if (isUni(id)) self.opened_uni else self.opened_bidi;
                return num < opened;
            }
            if (num >= self.peer_stream_next[typeIdx(id)]) return false;
            return !self.peer_stream_gaps.contains(id);
        }

        /// Record that a peer-initiated stream is about to get state. Opening
        /// stream N implicitly opens every lower-numbered stream of its type
        /// (RFC 9000 §3.2); those are remembered until used. Returns false if
        /// `id` is retired, in which case no state must be created for it.
        /// Locally initiated ids are left to their own open/close paths.
        pub fn admitStream(self: *Connection, id: u64) bool {
            if (!self.isPeerInitiatedStream(id)) return !isStreamRetired(self, id);
            if (hasStreamState(self, id)) return true;
            const t = typeIdx(id);
            const num = id >> 2;
            const next = self.peer_stream_next[t];
            if (num >= next) {
                // validatePeerStreamLimit() bounds `num` by our stream limit,
                // so this records at most that many implicitly opened ids.
                var n = next;
                while (n < num) : (n += 1) {
                    self.peer_stream_gaps.put(self.allocator.*, (n << 2) | (id & 0x3), {}) catch |err| {
                        logger.err("peer_stream_gaps.put failed (OOM): {s}", .{@errorName(err)});
                    };
                }
                self.peer_stream_next[t] = num + 1;
                return true;
            }
            if (self.peer_stream_gaps.remove(id)) return true;
            return false;
        }

        fn sendSideFinished(self: *Connection, id: u64) bool {
            if (self.isPeerInitiatedStream(id) and isUni(id)) return true; // receive-only
            if (!self.stream_txs_init) return false;
            // No send state yet: the application has not started this side.
            const stx = self.stream_txs.getPtr(id) orelse return false;
            if (id == 0) {
                // Stream 0 keeps its send flags in dedicated connection fields.
                if (self.stream_send_aborted) return true;
                return self.stream_send_fin_sent and stx.retx_outstanding == 0;
            }
            return stx.sendTerminal();
        }

        fn recvSideFinished(self: *Connection, id: u64) bool {
            if (!self.isPeerInitiatedStream(id) and isUni(id)) return true; // send-only
            if (!self.streams_rx_init) return false;
            const srx = self.streams_rx.getPtr(id) orelse return false;
            return srx.state.terminal();
        }

        /// Release `id`'s state if both directions are finished.
        pub fn maybeRetireStream(self: *Connection, id: u64) void {
            if (!hasStreamState(self, id)) return;
            if (!sendSideFinished(self, id)) return;
            if (!recvSideFinished(self, id)) return;
            releaseStreamState(self, id);
        }

        /// Drop every piece of per-stream state for `id` and, for a
        /// peer-initiated stream, return its stream-count credit.
        pub fn releaseStreamState(self: *Connection, id: u64) void {
            const had_state = hasStreamState(self, id);
            if (self.streams_rx_init) {
                if (self.streams_rx.fetchRemove(id)) |kv| {
                    var rx = kv.value;
                    rx.deinit(self.allocator);
                }
            }
            if (self.stream_txs_init) _ = self.stream_txs.remove(id);
            if (!had_state) return;
            self.streams_retired +%= 1;
            if (!self.isPeerInitiatedStream(id)) return;
            // RFC 9000 §4.6: a closed peer-initiated stream frees a slot.
            const t = typeIdx(id);
            self.peer_streams_retired[t] +%= 1;
            if (t == 1) {
                self.local_max_streams_uni +|= 1;
            } else {
                self.local_max_streams_bidi +|= 1;
            }
            maybeSendMaxStreams(self, false);
        }

        /// A STREAM packet for `stream_id` is now tracked for retransmission.
        pub fn noteStreamPacketTracked(self: *Connection, stream_id: u64) void {
            if (!self.stream_txs_init) return;
            const stx = self.stream_txs.getPtr(stream_id) orelse return;
            stx.retx_outstanding +|= 1;
        }

        /// A tracked STREAM packet for `stream_id` left retransmission
        /// tracking: acknowledged, or (on allocation failure) dropped.
        pub fn noteStreamPacketReleased(self: *Connection, stream_id: u64) void {
            if (!self.stream_txs_init) return;
            const stx = self.stream_txs.getPtr(stream_id) orelse return;
            stx.retx_outstanding -|= 1;
            if (stx.retx_outstanding == 0) maybeRetireStream(self, stream_id);
        }

        /// Stream-count credit the peer has used up since our last
        /// MAX_STREAMS, per direction. Sent once half of the initial limit
        /// has been returned (so the peer never waits for it while it has
        /// streams left), when the peer reports it is blocked, or when
        /// another frame is going out anyway (`force`).
        pub fn maybeSendMaxStreams(self: *Connection, force: bool) void {
            var buf: [32]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            var send_bidi: ?u64 = null;
            var send_uni: ?u64 = null;
            if (creditDue(self.local_max_streams_bidi, self.last_sent_max_streams_bidi, self.peer_streams_retired[0], force)) {
                _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(&w) catch return;
                send_bidi = self.local_max_streams_bidi;
            }
            if (creditDue(self.local_max_streams_uni, self.last_sent_max_streams_uni, self.peer_streams_retired[1], force)) {
                _ = (frame.Frame{ .max_streams_uni = .{ .max = self.local_max_streams_uni } }).write(&w) catch return;
                send_uni = self.local_max_streams_uni;
            }
            if (w.end == 0) return;
            if (!self.hasConfirmedAppTxKeys()) return;
            self.sendControlFrames(buf[0..w.end]);
            if (send_bidi) |v| self.last_sent_max_streams_bidi = v;
            if (send_uni) |v| self.last_sent_max_streams_uni = v;
        }

        fn creditDue(local: u64, last_sent: u64, retired: u64, force: bool) bool {
            if (local <= last_sent) return false;
            if (force) return true;
            // The initial limit is what remains after the credit returned.
            const initial = local -| retired;
            return local - last_sent >= @max(@as(u64, 1), initial / 2);
        }
    };
}
