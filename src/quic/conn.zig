// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC connection orchestration and socket helpers (thread-safe).
//!
//! GAP-0200: This module now supports concurrent access from multiple threads.
//! Each Connection has a mutex (mu) protecting its internal state. The endpoint
//! should hold the endpoint mutex when looking up connections, then acquire the
//! connection mutex for operations on that connection.
//!
//! This module owns the end-to-end connection state machine defined by RFC 9000
//! (§§2–7), integrates TLS 1.3 per RFC 9001 §4, and drives loss detection per
//! RFC 9002 §5. Inline comments call out the specific sections where behaviour
//! matches normative spec requirements (e.g., packet number handling, ACK logic).
// QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
// Import transport parameters module (registered as quic_transport_params in build.zig)
const tparams = @import("quic_transport_params");
const logger = @import("quic_logger");
const byteorder = @import("byteorder");
const reset_token = @import("connection/reset_token.zig");

// Connection ID (RFC-9000):  An identifier that is used to identify a QUIC
//     connection at an endpoint.  Each endpoint selects one or more
//     connection IDs for its peer to include in packets sent towards the
//     endpoint.  This value is opaque to the peer.
//
// This is tracked in the code as a `cid` `dcid` and `scid`
// cid = Connection ID
// dcid = Destination Connection ID
// scid = Source Connection ID
//
// Stream (RFC-9000):  A unidirectional or bidirectional channel of ordered bytes
//     within a QUIC connection.  A QUIC connection can carry multiple
//     simultaneous streams.

/// Buffer for reassembling out-of-order CRYPTO frames.
///
/// RFC 9000 §4.9.2 requires endpoints to handle out-of-order CRYPTO data until
/// it becomes contiguous. This helper keeps fragments sorted so handshake
/// processing can consume them in order without reallocation churn.
const CryptoBuffer = struct {
    const Fragment = struct {
        offset: u64,
        data: []u8,
    };

    // Static array to avoid allocations - max 8 out-of-order fragments
    fragments: [8]?Fragment = [_]?Fragment{null} ** 8,
    count: usize = 0,
    // Result buffer to avoid returning stack-allocated memory
    result_buffer: [8]Fragment = undefined,

    /// Add a fragment to the buffer
    pub fn add(self: *CryptoBuffer, offset: u64, data: []const u8, allocator: std.mem.Allocator) !void {
        // If buffer is full, skip adding this fragment to prevent memory corruption
        // In normal operation with in-order CRYPTO frames, this should never happen
        if (self.count >= self.fragments.len) {
            logger.debugPrint("WARNING: CryptoBuffer full (count={}, max={}), skipping fragment at offset {}\n", .{ self.count, self.fragments.len, offset });
            return error.BufferFull;
        }

        // Copy data
        const data_copy = try allocator.alloc(u8, data.len);
        @memcpy(data_copy, data);

        // Find the correct position to insert (sorted by offset)
        var insert_pos: usize = 0;
        var found_pos = false;

        // Find first null slot or position where offset should be inserted
        var i: usize = 0;
        while (i < self.fragments.len) : (i += 1) {
            if (self.fragments[i]) |frag| {
                if (frag.offset > offset) {
                    insert_pos = i;
                    found_pos = true;
                    break;
                }
            } else {
                // Found a null slot, we can use this
                if (!found_pos) {
                    insert_pos = i;
                    found_pos = true;
                }
            }
        }

        // If no position found, use the first available null slot
        if (!found_pos) {
            i = 0;
            while (i < self.fragments.len) : (i += 1) {
                if (self.fragments[i] == null) {
                    insert_pos = i;
                    break;
                }
            }
        }

        // If we need to shift elements right, do so
        if (self.fragments[insert_pos] != null) {
            // Find first null slot after insert_pos
            var null_pos: ?usize = null;
            i = insert_pos;
            while (i < self.fragments.len) : (i += 1) {
                if (self.fragments[i] == null) {
                    null_pos = i;
                    break;
                }
            }

            // Shift elements right to make room
            if (null_pos) |np| {
                i = np;
                while (i > insert_pos) : (i -= 1) {
                    self.fragments[i] = self.fragments[i - 1];
                }
            }
        }

        self.fragments[insert_pos] = Fragment{ .offset = offset, .data = data_copy };
        self.count += 1;
    }

    /// Check if we have contiguous data starting from the given offset
    /// Returns the fragments that can be processed
    pub fn getContiguous(self: *CryptoBuffer, start_offset: u64) ?[]const Fragment {
        var result_count: usize = 0;
        var expected_offset = start_offset;

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                if (frag.offset == expected_offset) {
                    self.result_buffer[result_count] = frag;
                    expected_offset += frag.data.len;
                    result_count += 1;
                } else if (frag.offset < expected_offset) {
                    // Overlapping or duplicate fragment - skip
                    continue;
                } else {
                    // Gap found
                    break;
                }
            }
        }

        if (result_count == 0) return null;

        // Return slice of contiguous fragments
        return self.result_buffer[0..result_count];
    }

    /// Remove processed fragments
    pub fn removeProcessed(self: *CryptoBuffer, count: usize, allocator: std.mem.Allocator) void {
        // Free memory for processed fragments
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                allocator.free(frag.data);
                self.fragments[i] = null;
            }
        }

        // Shift remaining fragments left
        i = 0;
        while (i < self.count - count) : (i += 1) {
            self.fragments[i] = self.fragments[i + count];
            self.fragments[i + count] = null;
        }

        self.count -= count;
    }

    /// Clear all buffered fragments
    pub fn clear(self: *CryptoBuffer, allocator: std.mem.Allocator) void {
        // Only iterate up to count, not the full array length
        // This avoids attempting to free already-freed fragments
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                // Only free non-empty allocations
                if (frag.data.len > 0) {
                    allocator.free(frag.data);
                }
                self.fragments[i] = null;
            }
        }
        self.count = 0;
    }
};

/// Role of this endpoint for a connection.
pub const Role = enum { Client, Server };

/// Portable socket address wrapper used by endpoint/connection.
pub const SockAddr = struct {
    storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage), // CRITICAL FIX: Zero-initialize to avoid undefined behavior
    len: u32 = 0,

    /// Initialize from a POSIX addrinfo entry.
    /// Initialize a SockAddr from a POSIX addrinfo entry (copies raw bytes).
    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    /// Return address family (AF.INET/AF.INET6).
    /// Return address family (AF.INET or AF.INET6).
    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

    /// Compare two socket addresses for byte-wise equality.
    /// Compare two SockAddr values for byte-wise equality.
    pub fn eq(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.len != b.len) return false;
        if (a.storage.family != b.storage.family) return false;
        const pa = @as([*]const u8, @ptrCast(&a.storage))[0..a.len];
        const pb = @as([*]const u8, @ptrCast(&b.storage))[0..b.len];
        return std.mem.eql(u8, pa, pb);
    }

    /// Helper to build an IPv4 sockaddr for tests.
    /// Build an IPv4 SockAddr from octets and host-order port (test helper).
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port_host: u16) SockAddr {
        var s: SockAddr = .{};
        // CRITICAL FIX: Zero-initialize the entire storage first to avoid garbage data
        s.storage = std.mem.zeroes(posix.sockaddr.storage);
        var sin: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = byteorder.toEndian(u16, .big, port_host),
            .addr = byteorder.toEndian(u32, .big, (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d)),
            .zero = .{0} ** 8,
        };
        s.len = @intCast(@sizeOf(posix.sockaddr.in));
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..s.len], @as([*]const u8, @ptrCast(&sin))[0..s.len]);
        return s;
    }

    /// Extract IP address bytes for token validation (RFC 9000 §8.1).
    /// Returns a slice pointing to the IP address portion of the sockaddr structure.
    /// For IPv4: 4 bytes, For IPv6: 16 bytes.
    pub fn getIpBytes(self: *const SockAddr) []const u8 {
        const storage_bytes = @as([*]const u8, @ptrCast(&self.storage));
        if (self.family() == posix.AF.INET) {
            // IPv4: addr is at offset 4 (after family:u16 + port:u16)
            return storage_bytes[4..8];
        } else if (self.family() == posix.AF.INET6) {
            // IPv6: addr is at offset 8 (after family:u16 + port:u16 + flowinfo:u32)
            return storage_bytes[8..24];
        }
        return &[_]u8{};
    }
};

/// Fixed-size Connection ID used in tests/internals.
pub const Cid = struct {
    len: u8 = 0,
    bytes: [20]u8 = [_]u8{0} ** 20, // Initialize to zeros to avoid undefined behavior
};

/// Sender callback used by Endpoint to provide paced sending.
pub const SendFn = *const fn (ctx: *anyopaque, c: *Connection, data: []const u8) anyerror!usize;

/// Sliding ACK tracking window constrained to the most recent 256 packet
/// numbers. RFC 9000 §13.2 recommends maintaining acknowledgement state per
/// packet number space, while §19.3 defines how ACK ranges are encoded. This
/// helper maps received packet numbers into the limited ACK range encoding
/// window used by the connection object.
const PnWindow = struct {
    max: u64 = 0,
    have_any: bool = false,
    win: std.bit_set.IntegerBitSet(256) = std.bit_set.IntegerBitSet(256).initEmpty(),

    fn track(this: *PnWindow, pn: u64) void {
        const span: u64 = 256;
        const had_any = this.have_any;
        const prev_max = this.max;
        const prev_base: u64 = if (had_any and prev_max + 1 >= span) prev_max + 1 - span else 0;

        if (!had_any or pn > this.max) {
            this.max = pn;
            this.have_any = true;
        }

        const new_max = this.max;
        const new_base: u64 = if (this.have_any and new_max + 1 >= span) new_max + 1 - span else 0;

        if (!had_any) {
            this.win = std.bit_set.IntegerBitSet(256).initEmpty();
        } else if (new_base != prev_base) {
            var new_win = std.bit_set.IntegerBitSet(256).initEmpty();
            var idx: usize = 0;
            while (idx < span) : (idx += 1) {
                if (this.win.isSet(@intCast(idx))) {
                    const pn_val: u64 = prev_base + idx;
                    if (pn_val >= new_base) {
                        const shifted: u64 = pn_val - new_base;
                        if (shifted < span) {
                            new_win.set(@intCast(shifted));
                        }
                    }
                }
            }
            this.win = new_win;
        }

        if (pn < new_base) {
            // RFC 9000 §13.2 allows omitting acknowledgements that fall outside
            // the tracked ranges; we simply drop packet numbers that are older
            // than the sliding window permits.
            return;
        }

        const offset: u64 = pn - new_base;
        if (offset >= span) return;
        const idx: u8 = @intCast(offset);
        this.win.set(idx);
    }

    fn buildAckRanges(this: *const PnWindow, out_buf: []frame.AckRange) struct { first_range: u64, ranges_len: usize } {
        if (!this.have_any) return .{ .first_range = 0, .ranges_len = 0 };
        const largest: u64 = this.max;
        const span: u64 = 256;
        const base: u64 = if (largest + 1 >= span) largest + 1 - span else 0;
        const largest_idx: usize = @intCast(largest - base);
        // RFC 9000 §19.3: first_range encodes the number of contiguous packet
        // numbers (minus one) acknowledged up to Largest Acknowledged.
        var first_len: u64 = 0;
        var i_desc: i64 = @intCast(largest_idx);
        while (i_desc >= 0) : (i_desc -= 1) {
            if (this.win.isSet(@intCast(i_desc))) first_len += 1 else break;
        }
        const first_range: u64 = if (first_len == 0) 0 else (first_len - 1);
        var out_len: usize = 0;
        var pos: i64 = i_desc;
        while (pos >= 0 and out_len < out_buf.len) {
            var zeros: u64 = 0;
            while (pos >= 0 and !this.win.isSet(@intCast(pos))) : (pos -= 1) zeros += 1;
            if (pos < 0) break;
            var ones: u64 = 0;
            while (pos >= 0 and this.win.isSet(@intCast(pos))) : (pos -= 1) ones += 1;
            // RFC 9000 §19.3: gap encodes the number of missing packet numbers
            // between ACK ranges minus one, and len encodes the size of the
            // following contiguous ACK range minus one.
            const gap_val: u64 = if (zeros == 0) 0 else (zeros - 1);
            const len_val: u64 = if (ones == 0) 0 else (ones - 1);
            out_buf[out_len] = .{ .gap = gap_val, .len = len_val };
            out_len += 1;
        }
        return .{ .first_range = first_range, .ranges_len = out_len };
    }
};

fn expandTruncatedPn(trunc_val: u64, pn_len: u3, expected: u64) u64 {
    // RFC 9000 §12.3. Avoid under/overflow for edge cases.
    const nbits: u6 = @as(u6, pn_len) * 8;
    const pn_win: u64 = @as(u64, 1) << nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;
    var candidate: u64 = (expected & ~pn_mask) | trunc_val;

    // If no history, return truncation as-is (expected == 0), matching first-packet semantics.
    if (expected == 0) return trunc_val;

    // Compare using thresholds to avoid overflow in candidate + pn_hwin and expected + pn_hwin
    var threshold_low: u64 = 0;
    const em1: u64 = expected - 1; // safe because expected > 0 here
    if (em1 >= pn_hwin) {
        threshold_low = em1 - pn_hwin;
    } else {
        threshold_low = 0;
    }

    if (candidate <= threshold_low) {
        candidate += pn_win;
    } else {
        const max_u64: u64 = std.math.maxInt(u64);
        const threshold_high: u64 = if (expected > max_u64 - pn_hwin) max_u64 else expected + pn_hwin;
        if (candidate > threshold_high) {
            candidate -= pn_win;
        }
    }
    return candidate;
}

const AckDesc = struct { largest: u64, first_range: u64, ranges: []const frame.AckRange };

// Reassembly support
const Segment = struct { off: u64, data: []u8 };
pub const StreamRx = struct {
    recv_off: u64 = 0,
    inbox: std.ArrayList(u8),
    bufs: std.ArrayList(Segment),
    fin_off: ?u64 = null,
    // PHASE 42 PART 9: Per-stream flow control tracking (RFC 9000 §4.2)
    local_max_stream_data: u64 = 0, // Current receive window limit for this stream
    last_sent_max_stream_data: u64 = 0, // Last MAX_STREAM_DATA value sent to peer
    // PHASE 42 PART 18: RTT-based autotuning (RFC 9000 §4.3, quiche flowcontrol.rs)
    last_window_update_time_us: u64 = 0, // Timestamp of last window expansion (microseconds)
    // PHASE 46: Quinn-style flow control tracking
    initial_window_size: u64 = 0, // Initial window size for threshold calculation
    // PHASE 57 PART 11: Track bytes consumed by application (like quinn's assembler.bytes_read())
    bytes_consumed_total: u64 = 0, // Total bytes consumed by application via readStream()
    // Flow-control bookkeeping: stream needs MAX_STREAM_DATA emission.
    fc_dirty: bool = false,

    pub fn init() StreamRx {
        return .{
            .recv_off = 0,
            .inbox = std.ArrayList(u8){},
            .bufs = std.ArrayList(Segment){},
            .fin_off = null,
            .local_max_stream_data = 0,
            .last_sent_max_stream_data = 0,
            .last_window_update_time_us = 0,
            .initial_window_size = 0,
            .bytes_consumed_total = 0,
            .fc_dirty = false,
        };
    }
    pub fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| alloc.free(seg.data);
        self.bufs.deinit(alloc.*);
        self.inbox.deinit(alloc.*);
    }

    pub fn insert(self: *StreamRx, alloc: *std.mem.Allocator, off: u64, data: []const u8) void {
        // store a copy of segment
        const owned = alloc.alloc(u8, data.len) catch return;
        @memcpy(owned, data);
        self.bufs.append(alloc.*, .{ .off = off, .data = owned }) catch {
            alloc.free(owned);
            return;
        };
    }

    pub fn tryDrain(self: *StreamRx, alloc: *std.mem.Allocator) void {
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.bufs.items.len) {
                const seg = self.bufs.items[i];
                if (seg.off == self.recv_off) {
                    // append to inbox and advance
                    _ = self.inbox.appendSlice(alloc.*, seg.data) catch {};
                    self.recv_off +%= seg.data.len;
                    alloc.free(seg.data);
                    _ = self.bufs.orderedRemove(i);
                    progressed = true;
                    // restart scan
                    i = 0;
                    continue;
                }
                i += 1;
            }
        }
    }

    pub fn isFinished(self: *const StreamRx) bool {
        return if (self.fin_off) |f| self.recv_off >= f else false;
    }
};

// Per-space ECN counters for ACK_ECN emission
const EcnCounter = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,
    seen_any: bool = false,
};

const trace_enabled = false;
inline fn trace(comptime fmt: []const u8, args: anytype) void {
    if (trace_enabled) logger.debugPrint(fmt, args);
}

// Per-stream transmit bookkeeping (offset + flags) for multi-stream support.
pub const StreamTx = struct {
    off: u64 = 0,
    fin_sent: bool = false,
    aborted: bool = false,
    // PHASE 42 PART 10: Per-stream send-side flow control (RFC 9000 §4.2)
    peer_max_stream_data: u64 = 0, // Peer's receive window limit for this stream
};

pub const StreamTxPacket = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8,
    retransmit_count: u16 = 0,
};

const PacketBufferPool = struct {
    const slot_count: usize = 4;
    const slot_size: usize = 4096;

    slots: [slot_count][slot_size]u8 = undefined,
    in_use: [slot_count]bool = [_]bool{false} ** slot_count,
    next_slot: usize = 0,

    pub fn checkout(self: *PacketBufferPool) []u8 {
        var i: usize = 0;
        while (i < slot_count) : (i += 1) {
            const idx = (self.next_slot + i) % slot_count;
            if (!self.in_use[idx]) {
                self.in_use[idx] = true;
                self.next_slot = (idx + 1) % slot_count;
                return self.slots[idx][0..];
            }
        }
        // Fallback under contention: reuse a slot deterministically.
        const idx = self.next_slot;
        self.next_slot = (idx + 1) % slot_count;
        self.in_use[idx] = true;
        return self.slots[idx][0..];
    }

    pub fn release(self: *PacketBufferPool, buf: []u8) void {
        var i: usize = 0;
        while (i < slot_count) : (i += 1) {
            if (buf.ptr == self.slots[i][0..].ptr) {
                self.in_use[i] = false;
                return;
            }
        }
    }
};

const PmtudState = enum { Disabled, ProbeStart, ProbeSearch };

/// Connection state and helpers for QUIC handshake, recovery, and 1-RTT.
/// GAP-0200: Thread-safe - each connection has its own mutex for concurrent access.
pub const Connection = struct {
    // GAP-0200: Per-connection mutex for thread-safe access to connection state
    // This protects all mutable state in this connection: streams, keys, flow control, etc.
    // Lock ordering: endpoint.mu -> connection.mu (never reverse)
    mu: std.Thread.Mutex = .{},

    id: u64,
    role: Role,
    sock_fd: isize,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    /// TLS 1.3 Context for QUIC handshake and encryption (vendor/ztls)
    /// Optional to allow tests that don't need TLS; production code should always initialize via client/server modules
    tls_context: ?*tls13.Context = null,
    allocator: *std.mem.Allocator,
    // Allowed ALPNs configured on endpoint
    allowed_alpns: []const []const u8 = &[_][]const u8{},
    /// Negotiated ALPN cached for outer layers (owned slice, may be null prior to EncryptedExtensions)
    negotiated_alpn: ?[]u8 = null,
    /// Server name (SNI) expected by the client for certificate validation (owned slice).
    server_name: ?[]u8 = null,
    /// Locally advertised QUIC transport parameters (encoded) cached for reuse.
    local_transport_params_raw: ?[]u8 = null,
    /// Peer-provided QUIC transport parameters (encoded) cached after validation.
    peer_transport_params_raw: ?[]u8 = null,
    // Optional pacing flag (from endpoint cfg)
    enable_pacing: bool = false,
    // Optional sender callback (set by Endpoint) for paced sending
    sender_ctx: ?*anyopaque = null,
    sender_fn: ?SendFn = null,
    // Derived handshake traffic secrets (once both hellos present)
    hs_client: ?ks.Secret = null,
    hs_server: ?ks.Secret = null,
    // Cached QUIC Handshake keys for RX/TX once derived
    hs_rx_keys: ?packet.InitialKeys = null,
    hs_tx_keys: ?packet.InitialKeys = null,
    // 1-RTT application keys
    app_rx_keys: ?packet.AeadKeys = null,
    app_tx_keys: ?packet.AeadKeys = null,
    // Track current TLS application traffic secrets for RX/TX to support Key Update
    app_rx_secret: ?ks.Secret = null,
    app_tx_secret: ?ks.Secret = null,
    // Optional NSS-style keylog state (used by interop test harnesses via SSLKEYLOGFILE).
    keylog_handshake_logged: bool = false,
    keylog_app_logged: bool = false,
    keylog_client_traffic_epoch: u32 = 0,
    keylog_server_traffic_epoch: u32 = 0,
    // PHASE 57 Part 5: Pre-derived NEXT generation keys (RFC 9001 §6)
    // These are derived when CURRENT keys are installed and updated when keys are promoted
    // This avoids per-packet derivation and maintains the one-generation-ahead invariant
    app_rx_next_secret: ?ks.Secret = null,
    app_rx_next_keys: ?packet.AeadKeys = null,
    // Short header key phase tracking (false = phase 0, true = phase 1)
    rx_key_phase: bool = false,
    tx_key_phase: bool = false,
    // RX dual-phase support during transition
    rx_prev_keys: ?packet.AeadKeys = null,
    rx_prev_allow: u32 = 0,
    // TX update in-progress bookkeeping
    tx_prev_keys: ?packet.AeadKeys = null,
    tx_update_in_progress: bool = false,
    tx_update_start_pn: u64 = 0,
    tx_sent_packets_since_key: u64 = 0,
    /// Coalesce sustained *_BLOCKED noise: remember last advertised limits we signaled
    last_stream_data_blocked_limit: u64 = 0,
    last_data_blocked_limit: u64 = 0,
    last_stream_data_blocked_at_ns: i128 = 0,
    last_data_blocked_at_ns: i128 = 0,
    /// Pace MAX_* emission: remember last maxima we sent
    last_sent_max_stream_data: u64 = 0,
    last_sent_max_data: u64 = 0,
    tx_sent_bytes_since_key: u64 = 0,
    // Lifecycle flags
    handshake_done_sent: bool = false,
    handshake_done_seen: bool = false,
    // Temporary demo flag: whether server auto-echo response on stream 0 was sent
    app_echo_sent: bool = false,
    /// Tracks when the TLS engine has verified the peer's Finished, enabling short-header traffic.
    peer_finished_verified: bool = false,
    server_hello_sent: bool = false,
    /// Track whether we've sent at least one Handshake packet (for key drop timing)
    handshake_packet_sent: bool = false,
    session_ticket_sent: bool = false,
    // 0-RTT state
    zero_rtt_keys: ?struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } = null,
    zero_rtt_enabled: bool = false,
    zero_rtt_accepted: bool = false,
    // Session resumption
    session_ticket: ?[]const u8 = null,
    resumption_secret: ?[32]u8 = null,
    // Connection close state
    closed: bool = false,
    // Server-side: whether this connection has been enqueued for accept()
    accepted_enqueued: bool = false,
    // Guard flag to keep deinit idempotent across layered cleanup paths.
    deinit_called: bool = false,

    // --- Missing transport/runtime state used by endpoint/tests ---
    // Packet number spaces: next PN to send in each space (RFC 9000 §12.3: MUST start at 0)
    pn_initial_tx: u64 = 0,
    initial_debug_alloc: ?[]u8 = null,
    pn_handshake_tx: u64 = 0,
    pn_app_tx: u64 = 0,
    // Version negotiation/bookkeeping
    version: u32 = 0,
    version_v2: bool = false,
    initial_version: u32 = 0,
    initial_keys_dropped: bool = false,
    // Cached Initial AEAD keys (derived once, reused for all Initial packets)
    initial_rx_keys: ?packet.InitialKeys = null,
    initial_tx_keys: ?packet.InitialKeys = null,
    // Connection IDs used during Initial/transport
    peer_initial_dcid: Cid = .{},
    // Original Destination Connection ID chosen by client (ODCID).
    // Used for Retry integrity validation/TP signaling (RFC 9001 §5.8, RFC 9000 §18.2).
    original_dcid: Cid = .{},
    peer_initial_scid: Cid = .{},
    our_scid: Cid = .{},
    // Expected DCID length in incoming 1-RTT packets (learned from negotiation)
    // Initially matches our_scid.len, but may be updated based on successful decryption
    expected_rx_dcid_len: ?u8 = null,
    // Received PN tracking windows for ACK generation
    pn_initial: PnWindow = .{},
    pn_handshake: PnWindow = .{},
    pn_app: PnWindow = .{},
    // Recovery integration: RFC 9002 RTT/loss/CC/PTO
    rec: recovery.Recovery = undefined,
    // Legacy send-time/size tracking (kept for backward-compat; no longer used for loss)
    // Note: HashMaps need explicit init() before use - tracked via _init flags
    sent_time: std.AutoHashMap(u64, i128) = undefined,
    sent_time_init: bool = false,
    sent_sizes: std.AutoHashMap(u64, u16) = undefined,
    sent_sizes_init: bool = false,
    largest_acked: u64 = 0,
    // RTT estimators per space (deprecated by rec.rtt for App)
    rtt_initial: recovery.RttState = .{},
    rtt_handshake: recovery.RttState = .{},
    rtt_app: recovery.RttState = .{},
    // PTO state
    timer_granularity_ns: u64 = std.time.ns_per_ms,
    pto_initial_active: bool = false,
    pto_handshake_active: bool = false,
    pto_app_active: bool = false,
    pto_initial_id: u64 = 0,
    pto_handshake_id: u64 = 0,
    pto_app_id: u64 = 0,
    pto_initial_count: u32 = 0,
    pto_handshake_count: u32 = 0,
    pto_app_count: u32 = 0,
    // DATAGRAM inbox - use .empty for safe default (Zig 0.15 ArrayListUnmanaged)
    dgram_inbox: std.ArrayList([]u8) = .empty,
    // Streams RX map and simple stream-0 TX counters
    // Note: HashMaps need explicit init() before use - tracked via _init flags
    streams_rx: std.AutoHashMap(u64, StreamRx) = undefined,
    streams_rx_init: bool = false,
    stream_opened: bool = false,
    stream_send_off: u64 = 0,
    // Multi-stream TX state map (extended): track offset/flags per stream id
    stream_txs: std.AutoHashMap(u64, StreamTx) = undefined,
    stream_txs_init: bool = false,
    // STREAM frames tracked by packet number for loss-triggered retransmission.
    app_stream_retx: std.AutoHashMap(u64, StreamTxPacket) = undefined,
    app_stream_retx_init: bool = false,
    // Queue of incoming peer-initiated streams waiting to be accepted
    incoming_stream_queue: std.ArrayList(u64) = .empty,
    // Streams needing MAX_STREAM_DATA emission; avoids full-map scans on ACK assembly.
    pending_fc_streams: std.ArrayList(u64) = .empty,
    // Track highest peer-initiated stream ID seen (for each type)
    highest_peer_bidi_stream: ?u64 = null,
    highest_peer_uni_stream: ?u64 = null,
    // Stream state flags (stream 0 in this slice)
    stream_send_aborted: bool = false,
    stream_send_fin_sent: bool = false,
    stream_recv_aborted: bool = false,
    stream_recv_fin: bool = false,
    // Flow-control windows (connection and per-stream)
    // Start with conservative windows; grow adaptively.
    // Increased initial flow control windows to avoid 1MB+ stall during streaming tests.
    // RFC 9000 §4.2 allows large initial_max_data/stream values; quic-go/quiche default to multi-MB.
    local_max_stream_data: u64 = 2 * 1024 * 1024,
    peer_max_stream_data: u64 = 2 * 1024 * 1024,
    local_max_data: u64 = 10 * 1024 * 1024,
    peer_max_data: u64 = 10 * 1024 * 1024,
    peer_max_streams_bidi: u64 = 4096,
    peer_max_streams_uni: u64 = 4096,
    opened_bidi: u64 = 0,
    local_max_streams_bidi: u64 = 1000,
    local_max_streams_uni: u64 = 1000,
    last_sent_max_streams_bidi: u64 = 0,
    opened_uni: u64 = 0,
    conn_send_off: u64 = 0,
    conn_recv_total: u64 = 0,
    // Address validation / anti-amplification
    address_validated: bool = false,
    bytes_rx_unvalidated: u64 = 0,
    bytes_tx_unvalidated: u64 = 0,
    // Retry token buffer - use .empty for safe default (Zig 0.15 ArrayListUnmanaged)
    initial_token: std.ArrayList(u8) = .empty,
    // Retry tracking (RFC 9000 §7.4.1 / RFC 9001 §5.8).
    retry_sent: bool = false,
    retry_received: bool = false,
    retry_packets_observed: u32 = 0,
    retry_apply_count: u32 = 0,
    retry_reject_integrity: u32 = 0,
    retry_reject_post_handshake: u32 = 0,
    retry_reject_duplicate: u32 = 0,
    // Simple path validation & tokens
    /// PATH_CHALLENGE validation state per RFC 9000 §9; true until a matching
    /// PATH_RESPONSE arrives for the outstanding challenge data.
    path_validation_pending: bool = false,
    /// Last PATH_CHALLENGE payload issued (8 bytes, §19.17).
    path_challenge_data: [8]u8 = .{0} ** 8,
    /// Track NEW_TOKEN issuance per RFC 9000 §19.7 (servers advertise address validation tokens).
    new_token_pending: bool = false,
    new_token_sent: bool = false,
    // Stateless reset tokens advertised by peer via NEW_CONNECTION_ID
    /// Peer-advertised stateless reset tokens (RFC 9000 §10.3, §19.15).
    reset_tokens: std.ArrayList([16]u8) = .empty,
    // Congestion controllers and selection flag (legacy; Recovery.cc is authoritative)
    use_cubic: bool = false,
    cc_nr: recovery.NewReno = .{},
    cc_cubic: recovery.Cubic = .{},

    // Temporary buffer for building ACK ranges
    ack_ranges_buf: [32]frame.AckRange = undefined,
    // Reusable packet assembly buffers for hot-path send operations.
    packet_pool: PacketBufferPool = .{},

    // --- ECN accounting (per packet number space) ---
    ecn_initial: EcnCounter = .{},
    ecn_handshake: EcnCounter = .{},
    ecn_app: EcnCounter = .{},
    // Pending ACK_ECN emission hint for Application space
    ecn_app_ack_pending: bool = false,

    // --- CRYPTO stream offsets (Initial and Handshake) ---
    crypto_tx_off_initial: u64 = 0,
    crypto_tx_off_handshake: u64 = 0,
    crypto_rx_off_initial: u64 = 0,
    crypto_rx_off_handshake: u64 = 0,
    crypto_retx_initial: ?[]u8 = null,
    crypto_retx_initial_off: u64 = 0,
    crypto_retx_handshake: ?[]u8 = null,
    crypto_retx_handshake_off: u64 = 0,

    // Pending Handshake-level TLS messages (EncryptedExtensions, Certificate, Finished)
    // that were popped from TLS but haven't been sent yet (waiting for Handshake keys)
    pending_hs_messages: ?[]u8 = null,

    // Pending Initial packet for coalescing with Handshake packet (RFC 9000 §12.2)
    pending_initial_packet: ?[]u8 = null,

    // CRYPTO frame reassembly buffers for out-of-order frames
    crypto_buffer_initial: CryptoBuffer = .{},
    crypto_buffer_handshake: CryptoBuffer = .{},

    // --- DPLPMTUD (RFC 9000 §14.2–§14.4) minimal state ---
    /// Current believed path MTU (UDP payload size), never below 1200. RFC 9000
    /// §14.1 mandates a minimum of 1200 bytes for Initials and recommends
    /// probing larger sizes via DPLPMTUD.
    /// PHASE 57 PART 17: Increased from 1200 to 1500 (Ethernet MTU) to fix slow flush rate
    path_mtu: u16 = 1500,
    /// Pending probe PN (Application space) awaiting ACK to validate path MTU
    /// per RFC 9000 §14.3.
    probe_pending_pn: ?u64 = null,
    /// Target size of the pending probe (UDP payload size).
    probe_pending_size: u16 = 0,
    /// DPLPMTUD phase and timer (RFC 9000 §14.4, RFC 8899).
    pmtud_state: PmtudState = .Disabled,
    pmtud_timer_active: bool = false,
    pmtud_timer_id: u64 = 0,

    // --- AEAD usage limits (RFC 9001 §6.6) ---
    /// Total number of 1-RTT packets encrypted with current TX keys (RFC 9001 §6.6 confidentiality limit).
    aead_tx_encrypted_count: u64 = 0,
    /// Total number of packets that failed authentication on RX (integrity limit counter per §6.6).
    aead_rx_invalid_count: u64 = 0,
    /// Applied limits (derived from cipher suite and optionally overridden by config).
    aead_confidentiality_limit: u64 = (1 << 23), // AES-GCM default
    aead_integrity_limit: u64 = (1 << 52),

    // --- Negotiated transport parameters (peer provided) ---
    transport_params_applied: bool = false,
    ack_delay_exponent: u8 = 3, // RFC 9000 default when absent
    max_ack_delay_ms: u16 = 25, // RFC 9000 default (25 ms)
    peer_max_udp_payload_size: u16 = 1200, // enforce <= path_mtu
    active_connection_id_limit: u64 = 2, // minimum permitted (RFC 9000 §18.2)
    // Count of locally issued connection IDs (includes initial our_scid as 1)
    issued_cids: u64 = 1,
    /// Active locally issued Connection IDs currently valid for use by peer (sequence space starts at 0).
    /// Index 0 corresponds to the original Source Connection ID (our_scid) used in Initial.
    local_cids: [8]LocalCid = [_]LocalCid{.{}} ** 8,
    /// Peer-advertised destination Connection IDs received via NEW_CONNECTION_ID.
    peer_cids: [8]PeerCid = [_]PeerCid{.{}} ** 8,
    /// Number of entries in local_cids that are considered active (<= active_connection_id_limit, <= local_cids.len).
    active_local_cids: u8 = 1,
    /// Sequence number of currently preferred peer CID for short-header packets.
    active_peer_cid_sequence: ?u64 = null,
    /// Next sequence number to allocate when issuing a new CID (monotonic, may exceed local_cids.len — older entries retired first).
    next_cid_sequence: u64 = 1,
    /// Pending NEW_CONNECTION_ID indices (into local_cids) waiting to be sent to peer.
    pending_new_cid: std.bit_set.IntegerBitSet(8) = std.bit_set.IntegerBitSet(8).initEmpty(),
    /// Secret used to derive stateless reset tokens (HKDF extraction of initial secret, set during handshake). Placeholder until integrated.
    stateless_reset_base: [32]u8 = [_]u8{0} ** 32,
    /// Highest retire_prior_to value we have advertised (monotonic). Used when emitting NEW_CONNECTION_ID.
    retired_prior_to: u64 = 0,

    // --- ACK delay measurement (per space) ---
    last_ack_eliciting_rx_initial_ns: u64 = 0,
    last_ack_eliciting_rx_handshake_ns: u64 = 0,
    last_ack_eliciting_rx_app_ns: u64 = 0,

    /// recordAckElicitingRx: Timestamp most recent ack-eliciting RX in the given PN space.
    /// RFC 9000 §13.2.1 defines ack-eliciting packets and requires endpoints to
    /// track time since such packets to schedule ACKs and encode ACK Delay.
    pub fn recordAckElicitingRx(self: *Connection, space: recovery.PacketNumberSpace, now_ns: u64) void {
        switch (space) {
            .Initial => self.last_ack_eliciting_rx_initial_ns = now_ns,
            .Handshake => self.last_ack_eliciting_rx_handshake_ns = now_ns,
            .Application => self.last_ack_eliciting_rx_app_ns = now_ns,
        }
    }

    /// getAckDelayEncoded: Encode ACK delay per RFC 9000 §19.3 using ack_delay_exponent and max_ack_delay cap.
    /// The ACK Delay field stores the delay in microseconds divided by
    /// 2^ack_delay_exponent (§18.2) and clamped to peer-advertised
    /// max_ack_delay.
    pub fn getAckDelayEncoded(self: *const Connection, space: recovery.PacketNumberSpace, now_ns: u64) u64 {
        const origin_ns: u64 = switch (space) {
            .Initial => self.last_ack_eliciting_rx_initial_ns,
            .Handshake => self.last_ack_eliciting_rx_handshake_ns,
            .Application => self.last_ack_eliciting_rx_app_ns,
        };
        if (origin_ns == 0 or now_ns <= origin_ns) return 0;
        const delta_ns: u64 = now_ns - origin_ns;
        var delay_us: u64 = delta_ns / 1000;
        const max_us: u64 = @as(u64, self.max_ack_delay_ms) * 1000;
        if (delay_us > max_us) delay_us = max_us;
        const shift: u6 = @intCast(self.ack_delay_exponent);
        return delay_us >> shift;
    }

    /// Return whether a new Connection ID can be issued without rotation. This checks
    /// the current `issued_cids` count against the peer's negotiated
    /// `active_connection_id_limit` (minimum 2 per RFC 9000 §18.2). Rotation helpers
    /// may still retire an existing non-zero sequence CID to free a slot when this
    /// returns false.
    /// Expand a truncated PN in Initial space using expected next PN.
    /// Expand truncated Initial-space packet number using expected next PN (RFC 9000 §12.3).
    pub fn expandPnInitial(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_initial.have_any) self.pn_initial.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }
    /// Expand a truncated PN in Handshake space using expected next PN.
    /// Expand truncated Handshake-space packet number using expected next PN.
    pub fn expandPnHandshake(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_handshake.have_any) self.pn_handshake.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }
    /// Expand a truncated PN in 1-RTT App space using expected next PN.
    /// Expand truncated Application-space packet number using expected next PN.
    pub fn expandPnApp(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_app.have_any) self.pn_app.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }

    /// Track a received PN in Initial space for ACK generation.
    /// RFC 9000 §13.2 requires endpoints to maintain separate ACK tracking for
    /// each packet number space; this feeds the Initial-space ACK encoder.
    pub fn trackRecvPnInitial(self: *Connection, pn_full: u64) void {
        self.pn_initial.track(pn_full);
    }
    /// Track a received PN in Handshake space for ACK generation. See RFC 9000
    /// §13.2 for per-space ACK maintenance rules.
    pub fn trackRecvPnHandshake(self: *Connection, pn_full: u64) void {
        self.pn_handshake.track(pn_full);
    }
    /// Track a received PN in App space for ACK generation. RFC 9000 §13.2
    /// requires independent ACK state for the Application packet number space.
    pub fn trackRecvPnApp(self: *Connection, pn_full: u64) void {
        self.pn_app.track(pn_full);
    }

    /// Build ACK ranges for Initial/Handshake/App space using the sliding window.
    /// Emits ACK metadata following RFC 9000 §19.3 semantics.
    /// Build ACK descriptor (largest + ranges) for Initial space using sliding window.
    pub fn buildAckInitial(self: *Connection) AckDesc {
        const d = self.pn_initial.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_initial.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Handshake space.
    /// Build ACK descriptor for Handshake space per RFC 9000 §19.3.
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        const d = self.pn_handshake.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_handshake.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Application space.
    /// Build ACK descriptor for Application (1-RTT) space per RFC 9000 §19.3.
    pub fn buildAckApp(self: *Connection) AckDesc {
        const d = self.pn_app.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_app.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }

    /// Return true when the receive side of the stream has reached FIN.
    pub fn isStreamFinished(self: *Connection, id: u64) bool {
        if (!self.streams_rx_init) return false;
        if (self.streams_rx.getPtr(id)) |rx| {
            return rx.isFinished();
        }
        return false;
    }

    /// Mark stream for deferred MAX_STREAM_DATA emission without scanning all streams.
    pub fn markStreamFlowControlDirty(self: *Connection, stream_id: u64) void {
        if (!self.streams_rx_init) return;
        if (self.streams_rx.getPtr(stream_id)) |stream| {
            if (stream.fc_dirty) return;
            stream.fc_dirty = true;
            self.pending_fc_streams.append(self.allocator.*, stream_id) catch {
                stream.fc_dirty = false;
            };
        }
    }

    /// Append MAX_STREAM_DATA frames for dirty streams only.
    /// Returns the number of stream-level FC frames appended.
    pub fn appendDirtyMaxStreamDataFrames(self: *Connection, w: anytype, max_frames: usize) u32 {
        var sent: u32 = 0;
        while (self.pending_fc_streams.items.len > 0 and sent < max_frames) {
            const stream_id = self.pending_fc_streams.swapRemove(self.pending_fc_streams.items.len - 1);
            if (!self.streams_rx_init) continue;
            if (self.streams_rx.getPtr(stream_id)) |stream| {
                if (!stream.fc_dirty) continue;
                if (stream.local_max_stream_data > stream.last_sent_max_stream_data) {
                    _ = (frame.Frame{
                        .max_stream_data = .{
                            .stream_id = stream_id,
                            .max = stream.local_max_stream_data,
                        },
                    }).write(w) catch {
                        // No room in current packet; keep dirty for next attempt.
                        self.pending_fc_streams.append(self.allocator.*, stream_id) catch {};
                        break;
                    };
                    stream.last_sent_max_stream_data = stream.local_max_stream_data;
                    sent += 1;
                }
                stream.fc_dirty = false;
            }
        }
        return sent;
    }

    /// Initialize a Connection in the given role bound to a socket and peer address.
    /// Initialize connection object with allocator, role, socket fd, and peer address; sets defaults.
    pub fn init(self: *Connection, alloc: *std.mem.Allocator, role: Role, sock_fd: isize, peer: SockAddr) void {
        self.id = 0;
        self.role = role;
        self.sock_fd = sock_fd;
        self.peer = peer;
        self.tls_inbox = std.ArrayList(u8){};
        // NOTE: tls_context must be initialized by caller (client/server modules)
        // Connection.init() no longer manages TLS initialization
        self.tls_context = null;
        self.allocator = alloc;
        self.allowed_alpns = &[_][]const u8{};
        self.negotiated_alpn = null;
        self.server_name = null;
        self.local_transport_params_raw = null;
        self.peer_transport_params_raw = null;
        self.enable_pacing = false;
        self.sender_ctx = null;
        self.sender_fn = null;
        self.hs_client = null;
        self.hs_server = null;
        self.hs_rx_keys = null;
        self.hs_tx_keys = null;
        self.app_rx_keys = null;
        self.app_tx_keys = null;
        self.pn_initial_tx = 0;
        self.pn_handshake_tx = 0;
        self.pn_app_tx = 0;
        self.peer_initial_dcid = .{};
        self.peer_initial_scid = .{};
        // Explicitly zero original_dcid (was left uninitialized when reusing a Connection object
        // before this field was added, leading to bogus large lengths and panics when slicing).
        self.original_dcid = .{};
        self.our_scid = .{};
        self.expected_rx_dcid_len = null;
        self.version = 0;
        self.version_v2 = false;
        self.initial_version = 0;
        self.initial_keys_dropped = false;
        // CRITICAL: Initialize cached Initial key fields to null
        // Without this, allocator.create() leaves them as undefined memory (0xAA pattern)
        self.initial_rx_keys = null;
        self.initial_tx_keys = null;
        self.pn_initial = .{};
        self.pn_handshake = .{};
        self.pn_app = .{};
        self.rec = recovery.Recovery.init(alloc.*);
        self.sent_time = std.AutoHashMap(u64, i128).init(alloc.*);
        self.sent_sizes = std.AutoHashMap(u64, u16).init(alloc.*);
        self.largest_acked = 0;
        // Initialize PTO state deterministically
        self.pto_initial_active = false;
        self.pto_handshake_active = false;
        self.pto_app_active = false;
        self.pto_initial_id = 0;
        self.pto_handshake_id = 0;
        self.pto_app_id = 0;
        self.pto_initial_count = 0;
        self.pto_handshake_count = 0;
        self.pto_app_count = 0;
        self.timer_granularity_ns = std.time.ns_per_ms;
        // Init DATAGRAM inbox - use .empty for Zig 0.15 ArrayListUnmanaged
        self.dgram_inbox = .empty;
        // Init streams map
        self.streams_rx = std.AutoHashMap(u64, StreamRx).init(alloc.*);
        self.streams_rx_init = true;
        self.stream_opened = false;
        self.stream_send_off = 0;
        self.stream_txs = std.AutoHashMap(u64, StreamTx).init(alloc.*);
        self.stream_txs_init = true;
        self.app_stream_retx = std.AutoHashMap(u64, StreamTxPacket).init(alloc.*);
        self.app_stream_retx_init = true;
        self.stream_send_aborted = false;
        self.stream_send_fin_sent = false;
        self.stream_recv_aborted = false;
        // Init incoming stream queue - use .empty for Zig 0.15 ArrayListUnmanaged
        self.incoming_stream_queue = .empty;
        self.pending_fc_streams = .empty;
        self.highest_peer_bidi_stream = null;
        self.highest_peer_uni_stream = null;
        self.stream_recv_fin = false;
        // Initialize ECN counters
        self.ecn_initial = .{};
        self.ecn_handshake = .{};
        self.ecn_app = .{};
        self.ecn_app_ack_pending = false;
        // Flow-control connection-level defaults already set via field initializers
        self.path_validation_pending = false;
        self.path_challenge_data = .{0} ** 8;
        self.new_token_pending = false;
        self.new_token_sent = false;
        self.reset_tokens = .empty;
        // CC default to NewReno; endpoint can flip use_cubic
        self.use_cubic = false;
        self.cc_nr = .{};
        self.cc_cubic = .{};
        // ensure recovery knows CC mode
        self.rec.setCcMode(false);
        // Initialize retry token buffer to match deinit symmetry - use .empty for Zig 0.15
        self.initial_token = .empty;
        // Explicitly initialize crypto retransmit buffers (field defaults not applied on reuse)
        self.crypto_retx_initial = null;
        self.crypto_retx_handshake = null;
        self.pending_hs_messages = null;
        self.pending_initial_packet = null;
        // Initialize ack_ranges_buf array
        self.ack_ranges_buf = undefined;
        // Initialize other fields that have defaults but might not be set
        self.app_rx_secret = null;
        self.app_tx_secret = null;
        self.keylog_handshake_logged = false;
        self.keylog_app_logged = false;
        self.keylog_client_traffic_epoch = 0;
        self.keylog_server_traffic_epoch = 0;
        self.rx_key_phase = false;
        self.tx_key_phase = false;
        self.rx_prev_keys = null;
        self.rx_prev_allow = 0;
        self.tx_prev_keys = null;
        self.tx_update_in_progress = false;
        self.tx_update_start_pn = 0;
        self.tx_sent_packets_since_key = 0;
        self.last_stream_data_blocked_limit = 0;
        self.last_data_blocked_limit = 0;
        self.last_stream_data_blocked_at_ns = 0;
        self.last_data_blocked_at_ns = 0;
        self.last_sent_max_stream_data = 0;
        self.last_sent_max_data = 0;
        self.last_sent_max_streams_bidi = 0;
        self.tx_sent_bytes_since_key = 0;
        self.handshake_done_sent = false;
        self.peer_finished_verified = false;
        self.server_hello_sent = false;
        self.handshake_packet_sent = false;
        self.closed = false;
        self.accepted_enqueued = false;
        self.deinit_called = false;
        self.app_echo_sent = false;
        // Initialize connection ID management
        self.local_cids = [_]LocalCid{.{}} ** 8;
        self.peer_cids = [_]PeerCid{.{}} ** 8;
        self.active_local_cids = 1;
        self.active_peer_cid_sequence = null;
        self.next_cid_sequence = 1;
        self.pending_new_cid = std.bit_set.IntegerBitSet(8).initEmpty();
        self.stateless_reset_base = [_]u8{0} ** 32;
        self.retired_prior_to = 0;
        self.issued_cids = 1;
        // Initialize flow control defaults (aligned with quinn's defaults for good performance)
        // Quinn uses: stream_receive_window = 1.25MB, receive_window = VarInt::MAX (essentially unlimited)
        // This ensures large transfers (1MB+) don't get flow-control blocked
        self.local_max_stream_data = 2 * 1024 * 1024; // 2MB per stream (vs quinn's 1.25MB)
        self.peer_max_stream_data = 2 * 1024 * 1024; // 2MB per stream
        self.local_max_data = 10 * 1024 * 1024; // 10MB connection-level (vs quinn's VarInt::MAX)
        self.peer_max_data = 10 * 1024 * 1024; // 10MB connection-level
        self.peer_max_streams_bidi = 4096;
        self.peer_max_streams_uni = 4096;
        self.opened_bidi = 0;
        self.local_max_streams_bidi = 1000;
        self.local_max_streams_uni = 1000;
        self.opened_uni = 0;
        self.conn_send_off = 0;
        self.conn_recv_total = 0;
        self.address_validated = (role == .Client); // Clients don't need address validation
        self.bytes_rx_unvalidated = 0;
        self.bytes_tx_unvalidated = 0;
        self.retry_sent = false;
        self.retry_received = false;
        self.retry_packets_observed = 0;
        self.retry_apply_count = 0;
        self.retry_reject_integrity = 0;
        self.retry_reject_post_handshake = 0;
        self.retry_reject_duplicate = 0;
        // Initialize crypto offsets
        self.crypto_tx_off_initial = 0;
        self.crypto_tx_off_handshake = 0;
        self.crypto_rx_off_initial = 0;
        self.crypto_rx_off_handshake = 0;
        self.crypto_retx_initial_off = 0;
        self.crypto_retx_handshake_off = 0;
        // Initialize crypto reassembly buffers
        self.crypto_buffer_initial = .{};
        self.crypto_buffer_handshake = .{};
        // Initialize PMTUD state
        // PHASE 57 PART 17: Use 1500 (Ethernet MTU) instead of 1200 (IPv6 minimum)
        self.path_mtu = 1500;
        self.probe_pending_pn = null;
        self.probe_pending_size = 0;
        self.pmtud_state = .Disabled;
        self.pmtud_timer_active = false;
        self.pmtud_timer_id = 0;
        // Initialize AEAD limits
        self.aead_tx_encrypted_count = 0;
        self.aead_rx_invalid_count = 0;
        self.aead_confidentiality_limit = (1 << 23);
        self.aead_integrity_limit = (1 << 52);
        // Initialize transport params
        self.transport_params_applied = false;
        self.ack_delay_exponent = 3;
        self.max_ack_delay_ms = 25;
        self.peer_max_udp_payload_size = 1200;
        self.active_connection_id_limit = 2;
        // Initialize ACK timing
        self.last_ack_eliciting_rx_initial_ns = 0;
        self.last_ack_eliciting_rx_handshake_ns = 0;
        self.last_ack_eliciting_rx_app_ns = 0;
    }

    /// Set the expected server name (SNI) for TLS certificate validation on client connections.
    /// This updates the TLS context so ClientHello includes SNI and hostname checks run.
    pub fn setServerName(self: *Connection, server_name: []const u8) !void {
        if (server_name.len == 0) return;
        if (self.server_name) |old| {
            self.allocator.free(old);
        }
        const owned = try self.allocator.dupe(u8, server_name);
        self.server_name = owned;
        if (self.tls_context) |tls_ctx| {
            tls_ctx.config.server_name = owned;
        }
    }

    /// Release resources held by this Connection (payloads, maps, TLS state).
    /// Free dynamic resources (lists, maps, TLS engine) owned by the connection.
    pub fn deinit(self: *Connection) void {
        if (self.deinit_called) return;
        self.deinit_called = true;
        if (self.negotiated_alpn) |alpn| self.allocator.free(alpn);
        if (self.server_name) |name| self.allocator.free(name);
        if (self.local_transport_params_raw) |tp| self.allocator.free(tp);
        if (self.peer_transport_params_raw) |tp| self.allocator.free(tp);
        self.negotiated_alpn = null;
        self.local_transport_params_raw = null;
        self.peer_transport_params_raw = null;
        self.tls_inbox.deinit(self.allocator.*);
        // Free the TLS Context if present (allocated by client/server modules)
        if (self.tls_context) |tls_ctx| {
            tls_ctx.deinit(); // Clean up Context internals (ArrayLists, etc.)
            self.allocator.destroy(tls_ctx);
        }
        self.rec.deinit();
        if (self.sent_time_init) self.sent_time.deinit();
        if (self.sent_sizes_init) self.sent_sizes.deinit();
        // Free inbox payloads
        if (self.crypto_retx_initial) |b| self.allocator.free(b);
        if (self.crypto_retx_handshake) |b| self.allocator.free(b);
        if (self.pending_hs_messages) |b| self.allocator.free(b);
        if (self.pending_initial_packet) |b| self.allocator.free(b);
        while (self.dgram_inbox.items.len > 0) {
            const p = self.dgram_inbox.orderedRemove(0);
            self.allocator.free(p);
        }
        self.dgram_inbox.deinit(self.allocator.*);
        // Deinit all streams (only if initialized)
        if (self.streams_rx_init) {
            var it = self.streams_rx.iterator();
            while (it.next()) |e| {
                var s = e.value_ptr.*;
                s.deinit(self.allocator);
            }
            self.streams_rx.deinit();
        }
        if (self.stream_txs_init) self.stream_txs.deinit();
        if (self.app_stream_retx_init) {
            var retx_it = self.app_stream_retx.iterator();
            while (retx_it.next()) |entry| {
                self.allocator.free(entry.value_ptr.data);
            }
            self.app_stream_retx.deinit();
        }
        // Free incoming stream queue
        if (self.incoming_stream_queue.capacity != 0) self.incoming_stream_queue.deinit(self.allocator.*);
        if (self.pending_fc_streams.capacity != 0) self.pending_fc_streams.deinit(self.allocator.*);
        // Free reset tokens / initial token buffers once (previous code double-deinited)
        if (self.reset_tokens.capacity != 0) self.reset_tokens.deinit(self.allocator.*);
        if (self.initial_token.capacity != 0) self.initial_token.deinit(self.allocator.*);
        // Clear CRYPTO reassembly buffers
        self.crypto_buffer_initial.clear(self.allocator.*);
        self.crypto_buffer_handshake.clear(self.allocator.*);
    }

    /// Update peer address (used for NAT rebinding / migration detection).
    /// Update peer remote address (e.g., after observing NAT rebinding) without altering validation state.
    pub fn setPeer(self: *Connection, peer: SockAddr) void {
        self.peer = peer;
    }

    /// Update/reset stateless reset tokens based on NEW_CONNECTION_ID retire_prior_to.
    /// Install/retire peer-advertised stateless reset tokens based on NEW_CONNECTION_ID frame sequencing.
    pub fn onNewConnectionId(self: *Connection, sequence: u64, retire_prior_to: u64, connection_id: []const u8, stateless_reset_token: [16]u8) void {
        // Retire tokens with index < retire_prior_to
        var i: usize = 0;
        while (i < self.reset_tokens.items.len) {
            if (@as(u64, @intCast(i)) < retire_prior_to) {
                _ = self.reset_tokens.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        // Ensure capacity up to sequence index and store/replace
        if (sequence >= self.reset_tokens.items.len) {
            const need = sequence + 1 - self.reset_tokens.items.len;
            var k: usize = 0;
            while (k < need) : (k += 1) self.reset_tokens.append(self.allocator.*, .{0} ** 16) catch break;
        }
        if (sequence < self.reset_tokens.items.len) self.reset_tokens.items[@intCast(sequence)] = stateless_reset_token;

        // Retire peer CIDs below retire_prior_to.
        i = 0;
        while (i < self.peer_cids.len) : (i += 1) {
            if (self.peer_cids[i].in_use and self.peer_cids[i].sequence < retire_prior_to) {
                self.peer_cids[i] = .{};
            }
        }

        const cid_len = @min(connection_id.len, self.peer_cids[0].cid.bytes.len);
        if (cid_len > 0) {
            var slot: ?usize = null;
            var free_slot: ?usize = null;
            var oldest_slot: usize = 0;
            var oldest_seq: u64 = std.math.maxInt(u64);

            i = 0;
            while (i < self.peer_cids.len) : (i += 1) {
                const entry = self.peer_cids[i];
                if (entry.in_use) {
                    if (entry.sequence == sequence) {
                        slot = i;
                        break;
                    }
                    if (entry.sequence < oldest_seq) {
                        oldest_seq = entry.sequence;
                        oldest_slot = i;
                    }
                } else if (free_slot == null) {
                    free_slot = i;
                }
            }

            const idx = slot orelse free_slot orelse oldest_slot;
            var entry = &self.peer_cids[idx];
            entry.in_use = true;
            entry.sequence = sequence;
            entry.cid.len = @intCast(cid_len);
            @memcpy(entry.cid.bytes[0..cid_len], connection_id[0..cid_len]);
            if (cid_len < entry.cid.bytes.len) {
                @memset(entry.cid.bytes[cid_len..], 0);
            }

            if (self.active_peer_cid_sequence == null or sequence >= self.active_peer_cid_sequence.?) {
                self.active_peer_cid_sequence = sequence;
            }
        }

        // Ensure active peer CID points at a live entry; prefer highest sequence.
        if (self.active_peer_cid_sequence) |active_seq| {
            var found_active = false;
            i = 0;
            while (i < self.peer_cids.len) : (i += 1) {
                const entry = self.peer_cids[i];
                if (entry.in_use and entry.cid.len > 0 and entry.sequence == active_seq) {
                    found_active = true;
                    break;
                }
            }
            if (!found_active) self.active_peer_cid_sequence = null;
        }

        if (self.active_peer_cid_sequence == null) {
            var best_seq: u64 = 0;
            var have_best = false;
            i = 0;
            while (i < self.peer_cids.len) : (i += 1) {
                const entry = self.peer_cids[i];
                if (!entry.in_use or entry.cid.len == 0) continue;
                if (!have_best or entry.sequence > best_seq) {
                    best_seq = entry.sequence;
                    have_best = true;
                }
            }
            if (have_best) self.active_peer_cid_sequence = best_seq;
        }
    }

    /// Returns the currently active peer-provided CID (NEW_CONNECTION_ID) if available.
    pub fn activePeerCid(self: *const Connection) ?[]const u8 {
        if (self.active_peer_cid_sequence) |seq| {
            var i: usize = 0;
            while (i < self.peer_cids.len) : (i += 1) {
                const entry = self.peer_cids[i];
                if (entry.in_use and entry.sequence == seq and entry.cid.len > 0) {
                    return entry.cid.bytes[0..entry.cid.len];
                }
            }
        }
        return null;
    }

    /// Check if a trailing 16-byte token matches any known stateless reset token.
    /// Heuristic detection of stateless reset (short header random body + 16-byte trailing token).
    pub fn looksLikeStatelessReset(self: *const Connection, pkt: []const u8) bool {
        if (pkt.len < 5 + 16) return false; // need at least short header + token
        // Per RFC 9000 §10.3, stateless reset is short header with random looking body and 16-byte token at end
        const tail = pkt[pkt.len - 16 ..];
        var i: usize = 0;
        while (i < self.reset_tokens.items.len) : (i += 1) {
            if (std.mem.eql(u8, &self.reset_tokens.items[i], tail)) return true;
        }
        return false;
    }

    /// Record an ECN mark observed on an incoming datagram for the given PN space.
    /// ecn_bits: least-significant two bits of the IP ECN field (00=Not-ECT, 10=ECT(0), 01=ECT(1), 11=CE).
    /// Incorporate observed ECN bits for a received datagram into per-space counters for ACK_ECN emission.
    pub fn onEcnMark(self: *Connection, space: recovery.PacketNumberSpace, ecn_bits: u8) void {
        const b: u8 = ecn_bits & 0x03;
        var ctr: *EcnCounter = switch (space) {
            .Initial => &self.ecn_initial,
            .Handshake => &self.ecn_handshake,
            .Application => &self.ecn_app,
        };
        switch (b) {
            0x01 => ctr.ect1 +%= 1, // ECT(1)
            0x02 => ctr.ect0 +%= 1, // ECT(0)
            0x03 => ctr.ce +%= 1, // CE
            else => {},
        }
        if (b != 0) ctr.seen_any = true;
        if (space == .Application and b != 0) {
            self.ecn_app_ack_pending = true;
        }
    }

    /// Return ECN counts for ACK_ECN emission in the given PN space if any ECN
    /// marks were observed; otherwise return null to emit a plain ACK.
    /// Retrieve ECN counters for given PN space or null if none observed (emit ACK vs ACK_ECN).
    pub fn getAckEcn(self: *const Connection, space: recovery.PacketNumberSpace) ?frame.EcnCounts {
        const ctr: *const EcnCounter = switch (space) {
            .Initial => &self.ecn_initial,
            .Handshake => &self.ecn_handshake,
            .Application => &self.ecn_app,
        };
        // Emit ACK_ECN only when at least one ECN mark was observed in this space.
        // Use counters directly to avoid relying on the seen_any latch in edge-ordering cases.
        if (ctr.ect0 == 0 and ctr.ect1 == 0 and ctr.ce == 0) return null;
        return .{ .ect0 = ctr.ect0, .ect1 = ctr.ect1, .ce = ctr.ce };
    }

    /// Install a custom sender callback (typically provided by Endpoint) for paced sending.
    /// Install sender callback (paced) used by endpoint for actual datagram emission.
    pub fn setSender(self: *Connection, ctx: *anyopaque, f: SendFn) void {
        self.sender_ctx = ctx;
        self.sender_fn = f;
    }

    /// Configure AEAD usage limits based on endpoint config (optional overrides).
    /// Configure optional AEAD usage limits overriding cipher defaults (tests / policy tuning).
    pub fn setAeadUsageLimits(self: *Connection, conf_limit: ?u64, integ_limit: ?u64) void {
        if (conf_limit) |v| self.aead_confidentiality_limit = v;
        if (integ_limit) |v| self.aead_integrity_limit = v;
    }

    /// Return true if sending is allowed under the anti-amplification limit.
    /// RFC 9000 §8.1 caps a server's response to three times the amount of data
    /// received before the client address is validated. Uses division (tx/3 <=
    /// rx) to avoid overflow for very large counters.
    /// Return true if anti-amplification budget permits sending (server before validation). Uses division to avoid overflow.
    pub fn canSendUnderAmplification(self: *const Connection) bool {
        const validated = self.address_validated;
        const is_local = self.isLocalhost();
        const result = if (validated) true else (self.bytes_tx_unvalidated / 3) <= self.bytes_rx_unvalidated;

        logger.debugPrint("[AMPLIFICATION] validated={} isLocalhost={} rx={} tx={} tx/3={} allow={}\n", .{
            validated,
            is_local,
            self.bytes_rx_unvalidated,
            self.bytes_tx_unvalidated,
            self.bytes_tx_unvalidated / 3,
            result,
        });

        if (validated) return true;
        return (self.bytes_tx_unvalidated / 3) <= self.bytes_rx_unvalidated;
    }

    /// Check if the peer address is localhost (127.0.0.1 or ::1)
    pub fn isLocalhost(self: *const Connection) bool {
        // Check IPv4 localhost (127.0.0.1)
        if (self.peer.storage.family == posix.AF.INET) {
            const addr_bytes = @as([*]const u8, @ptrCast(&self.peer.storage));
            // IPv4 sockaddr_in structure: family(2) + port(2) + addr(4)
            // Check if address bytes are 127.0.0.1
            if (self.peer.len >= 8) {
                const is_127 = addr_bytes[4] == 127 and addr_bytes[5] == 0 and
                    addr_bytes[6] == 0 and addr_bytes[7] == 1;
                logger.debugPrint("[LOCALHOST] IPv4 check: {}.{}.{}.{} -> {}\n", .{
                    addr_bytes[4],
                    addr_bytes[5],
                    addr_bytes[6],
                    addr_bytes[7],
                    is_127,
                });
                return is_127;
            }
        }

        // Check IPv6 localhost (::1)
        if (self.peer.storage.family == posix.AF.INET6) {
            const addr_bytes = @as([*]const u8, @ptrCast(&self.peer.storage));
            // IPv6 sockaddr_in6 structure: family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4)
            // Check if address is ::1 (all zeros except last byte = 1)
            if (self.peer.len >= 24) {
                // Address starts at offset 8
                var i: usize = 8;
                while (i < 23) : (i += 1) {
                    if (addr_bytes[i] != 0) return false;
                }
                return addr_bytes[23] == 1;
            }
        }

        return false;
    }

    /// Return true if we are currently over the anti-amplification limit.
    /// RFC 9000 §8.1 states that an endpoint must limit the data it sends to
    /// thrice the amount received until validation, unless exempt (e.g.,
    /// localhost in our implementation-specific carve-out).
    /// Return true if currently exceeding allowed 3x amplification limit.
    pub fn overAmplification(self: *const Connection) bool {
        if (std.posix.getenv("QUIC_DISABLE_AMPLIFICATION_LIMIT")) |v| {
            if (v.len == 0 or !std.mem.eql(u8, v, "0")) return false;
        }
        if (self.address_validated) return false;

        // CANARY: REQ=REQ-TRANSPORT-001; FEATURE="AmplificationProtection"; ASPECT=LocalhostExemption; STATUS=IMPLEMENTED; OWNER=transport; UPDATED=2025-10-15
        // Exempt localhost connections from amplification protection
        // This is safe because localhost connections have no amplification risk
        if (self.isLocalhost()) return false;

        // Apply standard amplification protection for non-localhost connections
        return (self.bytes_tx_unvalidated / 3) > self.bytes_rx_unvalidated;
    }

    /// Saturating add to RX unvalidated counter to avoid wrap.
    /// RFC 9000 §8.1 requires accurate accounting of unvalidated bytes; we
    /// saturate to stay within u64 bounds.
    /// Saturating add to unvalidated RX byte counter (pre-validation address accounting).
    pub fn addRxUnvalidated(self: *Connection, n: usize) void {
        if (self.address_validated or n == 0) return;
        const max = std.math.maxInt(u64);
        const add: u64 = @intCast(n);
        if (self.bytes_rx_unvalidated > max - add) {
            self.bytes_rx_unvalidated = max;
        } else {
            self.bytes_rx_unvalidated += add;
        }
    }

    /// Saturating add to TX unvalidated counter to avoid wrap.
    /// RFC 9000 §8.1 likewise constrains transmission prior to validation, so
    /// we track unvalidated TX with saturation.
    /// Saturating add to unvalidated TX byte counter used for amplification gating.
    pub fn addTxUnvalidated(self: *Connection, n: usize) void {
        if (self.address_validated or n == 0) return;
        const max = std.math.maxInt(u64);
        const add: u64 = @intCast(n);
        if (self.bytes_tx_unvalidated > max - add) {
            self.bytes_tx_unvalidated = max;
        } else {
            self.bytes_tx_unvalidated += add;
        }
    }

    // Extracted method groups for staged modularization (#75)
    const methods_a = @import("connection/methods_a.zig").bind(@This());
    const methods_b = @import("connection/methods_b.zig").bind(@This());
    const methods_c = @import("connection/methods_c.zig").bind(@This());

    pub const storeNegotiatedAlpn = methods_a.storeNegotiatedAlpn;
    pub const storePeerTransportParams = methods_a.storePeerTransportParams;
    pub const storeLocalTransportParams = methods_a.storeLocalTransportParams;
    pub const cacheNegotiatedAlpn = methods_a.cacheNegotiatedAlpn;
    pub const cachePeerTransportParams = methods_a.cachePeerTransportParams;
    pub const setLocalTransportParameters = methods_a.setLocalTransportParameters;
    pub const hasConfirmedAppTxKeys = methods_a.hasConfirmedAppTxKeys;
    pub const updatePeerFinishedStatus = methods_a.updatePeerFinishedStatus;
    pub const send = methods_a.send;
    pub const sendInitialCrypto = methods_a.sendInitialCrypto;
    pub const sendHandshakeCrypto = methods_a.sendHandshakeCrypto;
    pub const pushCrypto = methods_a.pushCrypto;
    pub const afterInitialCryptoChunk = methods_a.afterInitialCryptoChunk;
    pub const processBufferedInitial = methods_a.processBufferedInitial;
    pub const processBufferedHandshake = methods_a.processBufferedHandshake;
    pub const handleCryptoFrameGeneric = methods_a.handleCryptoFrameGeneric;
    pub const afterInitialWrapper = methods_a.afterInitialWrapper;
    pub const afterHandshakeWrapper = methods_a.afterHandshakeWrapper;
    pub const continueInitial = methods_a.continueInitial;
    pub const continueHandshake = methods_a.continueHandshake;
    pub const handleInitialCrypto = methods_a.handleInitialCrypto;
    pub const handleHandshakeCrypto = methods_a.handleHandshakeCrypto;
    pub const maybeDeriveAppKeysAfterFlush = methods_a.maybeDeriveAppKeysAfterFlush;
    pub const getNegotiatedAlpn = methods_a.getNegotiatedAlpn;
    pub const getPeerTransportParams = methods_a.getPeerTransportParams;
    pub const getLocalTransportParams = methods_a.getLocalTransportParams;
    pub const setUseCubic = methods_a.setUseCubic;
    pub const ccOnPacketSent = methods_a.ccOnPacketSent;
    pub const ccOnAck = methods_a.ccOnAck;
    pub const ccOnLoss = methods_a.ccOnLoss;
    pub const setPeerInitialCids = methods_a.setPeerInitialCids;
    pub const pushStreamFrame = methods_a.pushStreamFrame;
    pub const pushDatagram = methods_a.pushDatagram;
    pub const popDatagram = methods_a.popDatagram;
    pub const scheduleConnPto = methods_a.scheduleConnPto;
    pub const setPtoExpiredInitial = methods_a.setPtoExpiredInitial;
    pub const setPtoExpiredHandshake = methods_a.setPtoExpiredHandshake;
    pub const setPtoExpiredApp = methods_a.setPtoExpiredApp;
    pub const sendPathChallenge = methods_a.sendPathChallenge;
    pub const sendControlFrames = methods_a.sendControlFrames;
    pub const enable0RTT = methods_a.enable0RTT;
    pub const accept0RTT = methods_a.accept0RTT;
    pub const advertiseInitialFlowControl = methods_a.advertiseInitialFlowControl;
    pub const maybeEmitHandshakeKeyLog = methods_a.maybeEmitHandshakeKeyLog;
    pub const maybeEmitApplicationKeyLog = methods_a.maybeEmitApplicationKeyLog;
    pub const maybeEmitTxKeyUpdateLog = methods_a.maybeEmitTxKeyUpdateLog;
    pub const maybeEmitRxKeyUpdateLog = methods_a.maybeEmitRxKeyUpdateLog;

    pub const sendDatagram = methods_b.sendDatagram;
    pub const openStream = methods_b.openStream;
    pub const writeStream = methods_b.writeStream;
    pub const writeStreamUnlocked = methods_b.writeStreamUnlocked;
    pub const readStream = methods_b.readStream;
    pub const readStreamUnlocked = methods_b.readStreamUnlocked;
    pub const closeStream = methods_b.closeStream;
    pub const handleStopSending = methods_b.handleStopSending;
    pub const handleResetStream = methods_b.handleResetStream;
    pub const teardownStream = methods_b.teardownStream;
    pub const onAckReceived = methods_b.onAckReceived;
    pub const onAckReceivedSpace = methods_b.onAckReceivedSpace;
    pub const resetPtoBackoffInitial = methods_b.resetPtoBackoffInitial;
    pub const resetPtoBackoffHandshake = methods_b.resetPtoBackoffHandshake;
    pub const resetPtoBackoffApp = methods_b.resetPtoBackoffApp;
    pub const cancelPtoInitial = methods_b.cancelPtoInitial;
    pub const cancelPtoHandshake = methods_b.cancelPtoHandshake;
    pub const cancelPtoApp = methods_b.cancelPtoApp;
    pub const computeAndMaybeArmPto = methods_b.computeAndMaybeArmPto;
    pub const pmtudStart = methods_b.pmtudStart;
    pub const pmtudArm = methods_b.pmtudArm;
    pub const pmtudOnTimer = methods_b.pmtudOnTimer;
    pub const pmtudOnAckProgress = methods_b.pmtudOnAckProgress;
    pub const computeAndMaybeArmPtoInitial = methods_b.computeAndMaybeArmPtoInitial;
    pub const computeAndMaybeArmPtoHandshake = methods_b.computeAndMaybeArmPtoHandshake;
    pub const sendPtoProbeInitial = methods_b.sendPtoProbeInitial;
    pub const sendPtoProbeHandshake = methods_b.sendPtoProbeHandshake;
    pub const sendPtoProbeApp = methods_b.sendPtoProbeApp;
    pub const sendConnectionClose = methods_b.sendConnectionClose;
    pub const deriveHandshakeKeys = methods_b.deriveHandshakeKeys;
    pub const deriveAppKeys = methods_b.deriveAppKeys;
    pub const shortHeaderDcid = methods_b.shortHeaderDcid;
    pub const zeroKeys = methods_b.zeroKeys;
    pub const maybeTriggerKeyUpdateOnSend = methods_b.maybeTriggerKeyUpdateOnSend;
    pub const maybeFinalizeKeyUpdateOnAck = methods_b.maybeFinalizeKeyUpdateOnAck;
    pub const syncTxKeysAfterRxUpdate = methods_b.syncTxKeysAfterRxUpdate;

    pub const readAnyStream = methods_c.readAnyStream;
    pub const onShortHeaderPacketSent = methods_c.onShortHeaderPacketSent;
    pub const sendPmtudProbe = methods_c.sendPmtudProbe;
    pub const onIcmpPacketTooBig = methods_c.onIcmpPacketTooBig;
    pub const onAeadAuthFailure = methods_c.onAeadAuthFailure;
    pub const onPacketSent = methods_c.onPacketSent;
    pub const ensureStreamTxInit = methods_c.ensureStreamTxInit;
    pub const ensureStreamRx = methods_c.ensureStreamRx;
    pub const isPeerInitiatedStream = methods_c.isPeerInitiatedStream;
    pub const validatePeerStreamLimit = methods_c.validatePeerStreamLimit;
    pub const isStreamKnown = methods_c.isStreamKnown;
    pub const queueIncomingStream = methods_c.queueIncomingStream;
    pub const acceptStream = methods_c.acceptStream;
    pub const hasIncomingStreams = methods_c.hasIncomingStreams;
    pub const getFirstStream = methods_c.getFirstStream;
    pub const applyPeerTransportParameters = methods_c.applyPeerTransportParameters;
    pub const canIssueNewConnectionId = methods_c.canIssueNewConnectionId;
    pub const onIssuedNewConnectionId = methods_c.onIssuedNewConnectionId;
    pub const issueNewConnectionId = methods_c.issueNewConnectionId;
    pub const flushPendingNewConnectionIds = methods_c.flushPendingNewConnectionIds;
    pub const markPendingNewCid = methods_c.markPendingNewCid;
    pub const writePendingNewConnectionIds = methods_c.writePendingNewConnectionIds;
    pub const onRetireConnectionId = methods_c.onRetireConnectionId;
    pub const acquireLocalCid = methods_c.acquireLocalCid;
    pub const issueNewConnectionIdRotating = methods_c.issueNewConnectionIdRotating;
};

/// Local CID entry (minimal for now). Will be expanded with expiration/retire markers.
const LocalCid = struct {
    in_use: bool = false,
    sequence: u64 = 0,
    cid: Cid = .{},
    reset_token: [16]u8 = [_]u8{0} ** 16,
};

const PeerCid = struct {
    in_use: bool = false,
    sequence: u64 = 0,
    cid: Cid = .{},
};

const deriveStatelessResetToken = reset_token.deriveStatelessResetToken;
pub const testDeriveStatelessResetToken = reset_token.testDeriveStatelessResetToken;
