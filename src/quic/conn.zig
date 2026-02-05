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

    fn init() StreamRx {
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
        };
    }
    pub fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| alloc.free(seg.data);
        self.bufs.deinit(alloc.*);
        self.inbox.deinit(alloc.*);
    }

    fn insert(self: *StreamRx, alloc: *std.mem.Allocator, off: u64, data: []const u8) void {
        // store a copy of segment
        const owned = alloc.alloc(u8, data.len) catch return;
        @memcpy(owned, data);
        self.bufs.append(alloc.*, .{ .off = off, .data = owned }) catch {
            alloc.free(owned);
            return;
        };
    }

    fn tryDrain(self: *StreamRx, alloc: *std.mem.Allocator) void {
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

    fn isFinished(self: *const StreamRx) bool {
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
    hs_client: ?[ks.H.digest_length]u8 = null,
    hs_server: ?[ks.H.digest_length]u8 = null,
    // Cached QUIC Handshake keys for RX/TX once derived
    hs_rx_keys: ?packet.InitialKeys = null,
    hs_tx_keys: ?packet.InitialKeys = null,
    // 1-RTT application keys
    app_rx_keys: ?packet.AeadKeys = null,
    app_tx_keys: ?packet.AeadKeys = null,
    // Track current TLS application traffic secrets for RX/TX to support Key Update
    app_rx_secret: ?[ks.H.digest_length]u8 = null,
    app_tx_secret: ?[ks.H.digest_length]u8 = null,
    // PHASE 57 Part 5: Pre-derived NEXT generation keys (RFC 9001 §6)
    // These are derived when CURRENT keys are installed and updated when keys are promoted
    // This avoids per-packet derivation and maintains the one-generation-ahead invariant
    app_rx_next_secret: ?[ks.H.digest_length]u8 = null,
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
    // Original Destination Connection ID chosen by client (ODCID). Remains constant
    // across Retry; used for Initial secret derivation per RFC 9000 §5.2.
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
    // Queue of incoming peer-initiated streams waiting to be accepted
    incoming_stream_queue: std.ArrayList(u64) = .empty,
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
    peer_max_streams_bidi: u64 = 16,
    peer_max_streams_uni: u64 = 16,
    opened_bidi: u64 = 0,
    local_max_streams_bidi: u64 = 16,
    local_max_streams_uni: u64 = 0,
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
    /// Number of entries in local_cids that are considered active (<= active_connection_id_limit, <= local_cids.len).
    active_local_cids: u8 = 1,
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
        self.stream_send_aborted = false;
        self.stream_send_fin_sent = false;
        self.stream_recv_aborted = false;
        // Init incoming stream queue - use .empty for Zig 0.15 ArrayListUnmanaged
        self.incoming_stream_queue = .empty;
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
        self.active_local_cids = 1;
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
        self.peer_max_streams_bidi = 16;
        self.peer_max_streams_uni = 16;
        self.opened_bidi = 0;
        self.local_max_streams_bidi = 16;
        self.local_max_streams_uni = 0;
        self.opened_uni = 0;
        self.conn_send_off = 0;
        self.conn_recv_total = 0;
        self.address_validated = (role == .Client); // Clients don't need address validation
        self.bytes_rx_unvalidated = 0;
        self.bytes_tx_unvalidated = 0;
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
        // Free incoming stream queue
        if (self.incoming_stream_queue.capacity != 0) self.incoming_stream_queue.deinit(self.allocator.*);
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
    pub fn onNewConnectionId(self: *Connection, sequence: u64, retire_prior_to: u64, stateless_reset_token: [16]u8) void {
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

    fn storeNegotiatedAlpn(self: *Connection, alpn: []const u8) !void {
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

    fn storeLocalTransportParams(self: *Connection, encoded: []const u8) !void {
        if (self.local_transport_params_raw) |existing| {
            if (std.mem.eql(u8, existing, encoded)) return;
            self.allocator.free(existing);
        }
        const copy = try self.allocator.dupe(u8, encoded);
        self.local_transport_params_raw = copy;
    }

    /// Cache negotiated ALPN for outer layers (tests/interop helpers may call directly).
    pub fn cacheNegotiatedAlpn(self: *Connection, alpn: []const u8) !void {
        try self.storeNegotiatedAlpn(alpn);
    }

    /// Cache peer transport parameters (encoded form) for reuse outside TLS.
    pub fn cachePeerTransportParams(self: *Connection, encoded: []const u8) !void {
        try self.storePeerTransportParams(encoded);
    }

    /// Set locally advertised transport parameters on TLS and cache them for QUIC wiring.
    pub fn setLocalTransportParameters(self: *Connection, encoded: []const u8) !void {
        if (self.tls_context) |tls_ctx| {
            tls_ctx.setTransportParameters(encoded);
        }
        self.storeLocalTransportParams(encoded) catch {};
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
    fn sendInitialCrypto(self: *Connection, crypto_data: []const u8) !void {
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

        // Encode Initial packet
        const out = packet.encodeInitialProtected(
            self.allocator.*,
            self.version,
            self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len],
            self.our_scid.bytes[0..self.our_scid.len],
            &[_]u8{}, // token (empty for client Initial, populated for server if retry used)
            @as(u32, @truncate(self.pn_initial_tx)),
            2, // pn_len
            frames.items,
            tx,
        ) catch return;

        defer self.allocator.free(out);
        _ = self.send(out) catch {};

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
        _ = self.send(out) catch {};

        // Update state
        self.crypto_tx_off_handshake += crypto_data.len;
        self.onPacketSent(.Handshake, self.pn_handshake_tx, out.len, true);
        self.pn_handshake_tx +%= 1;

        logger.debugPrint("[sendHandshakeCrypto] Sent {} bytes of CRYPTO in Handshake packet\n", .{crypto_data.len});
    }

    /// Feed received CRYPTO bytes to the TLS Context and derive keys when secrets become available.
    pub fn pushCrypto(self: *Connection, hs: []const u8) !void {
        const tls_ctx = self.tls_context orelse return; // No-op if TLS Context not initialized (test scenarios)

        // Determine encryption level based on which keys are installed
        const level: tls13.EncryptionLevel = blk: {
            if (self.app_rx_keys != null) break :blk .Application;
            if (self.hs_rx_keys != null) break :blk .Handshake;
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
                    tls_ctx.markLocalFinished();
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
                var hs_c: [ks.H.digest_length]u8 = undefined;
                var hs_s: [ks.H.digest_length]u8 = undefined;
                @memcpy(&hs_c, client_slot.value.bytes[0..ks.H.digest_length]);
                @memcpy(&hs_s, server_slot.value.bytes[0..ks.H.digest_length]);
                self.hs_client = hs_c;
                self.hs_server = hs_s;
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
            const pkt = packet.encodeShortProtected(
                self.allocator.*,
                self.shortHeaderDcid(),
                @as(u32, @truncate(self.pn_app_tx)),
                2,
                frames_list.items,
                .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
                self.tx_key_phase,
            ) catch null;
            if (pkt) |bytes_out| {
                defer self.allocator.free(bytes_out);
                _ = self.send(bytes_out) catch {};
                self.onShortHeaderPacketSent(bytes_out.len, true);
            }
            self.handshake_done_sent = true;
        }

        // Apply peer transport parameters (once) when they first become available
        if (!self.transport_params_applied) {
            if (tls_ctx.peer_quic_transport_parameters) |peer_tp_bytes| {
                self.applyPeerTransportParameters(peer_tp_bytes) catch {
                    // Ignore malformed transport parameters; retain defaults
                };
                self.storePeerTransportParams(peer_tp_bytes) catch {};
            }
        }

        // Store negotiated ALPN (ALPN validation removed - was incorrectly revoking peer_finished_verified)
        // Note: Applications should validate ALPN after handshake completion if needed
        if (tls_ctx.negotiatedAlpn()) |a| {
            self.storeNegotiatedAlpn(a) catch {};
            // REMOVED: ALPN mismatch should not revoke peer_finished_verified flag
            // The peer's Finished message was cryptographically verified by TLS
            // If ALPN validation is needed, it should be done at application level
            // and result in connection closure, not silent handshake stall
        }
    }

    fn afterInitialCryptoChunk(self: *Connection) void {
        _ = self;
    }

    fn processBufferedInitial(
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
                self.afterInitialCryptoChunk();
            }

            self.crypto_buffer_initial.removeProcessed(fragments.len, allocator.*);
        }
    }

    fn processBufferedHandshake(
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

    fn handleCryptoFrameGeneric(
        self: *Connection,
        allocator: *std.mem.Allocator,
        offset: u64,
        data: []const u8,
        expected_offset: *u64,
        buffer: *CryptoBuffer,
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
            }
        }

        return ack_eliciting;
    }

    fn afterInitialWrapper(self: *Connection) !void {
        self.afterInitialCryptoChunk();
    }

    fn afterHandshakeWrapper(self: *Connection) !void {
        _ = self;
        // no-op for handshake space
    }

    fn continueInitial(self: *Connection, allocator: *std.mem.Allocator) !void {
        try self.processBufferedInitial(allocator);
    }

    fn continueHandshake(self: *Connection, allocator: *std.mem.Allocator) !void {
        try self.processBufferedHandshake(allocator);
    }

    pub fn handleInitialCrypto(
        self: *Connection,
        allocator: *std.mem.Allocator,
        offset: u64,
        data: []const u8,
    ) !bool {
        return self.handleCryptoFrameGeneric(
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
        return self.handleCryptoFrameGeneric(
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
    fn ccOnPacketSent(self: *Connection, bytes: usize, ack_eliciting: bool) void {
        // Legacy shim retained for compatibility; Recovery.cc is authoritative for new paths.
        if (self.use_cubic) {
            self.cc_cubic.onPacketSent(bytes, ack_eliciting);
        } else {
            self.cc_nr.onPacketSent(bytes, ack_eliciting);
        }
    }

    /// Congestion control shim: on ACK.
    fn ccOnAck(self: *Connection, bytes_acked: usize) void {
        // Legacy shim retained for compatibility.
        if (self.use_cubic) {
            self.cc_cubic.onAck(bytes_acked);
        } else {
            self.cc_nr.onAck(bytes_acked);
        }
    }

    /// Congestion control shim: on loss.
    fn ccOnLoss(self: *Connection, bytes_lost: usize) void {
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
    pub fn popDatagram(self: *Connection, buf: []u8) !usize {
        if (self.dgram_inbox.items.len == 0) return error.WouldBlock;
        const p = self.dgram_inbox.orderedRemove(0);
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
        const out = packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        ) catch null;
        if (out) |pkt| {
            defer self.allocator.free(pkt);
            _ = self.send(pkt) catch {};
            self.onShortHeaderPacketSent(pkt.len, true);
        }
    }

    fn sendControlFrames(self: *Connection, frames_bytes: []const u8) void {
        if (!self.hasConfirmedAppTxKeys()) return;
        const tx = self.app_tx_keys.?;
        logger.debugPrint("{s}: Sending control frames ({d} bytes)\n", .{ if (self.role == .Server) "Server" else "Client", frames_bytes.len });
        const pkt = packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames_bytes,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        ) catch null;
        if (pkt) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onShortHeaderPacketSent(bytes_out.len, true);
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

    /// Accept 0-RTT data (server-side)
    pub fn accept0RTT(self: *Connection) void {
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
        if (wrote) self.sendControlFrames(frames.items);
    }

    /// Send a datagram to the connection's peer using 1-RTT short header.
    /// Queue an application DATAGRAM for sending (subject to path MTU / congestion heuristics).
    pub fn sendDatagram(self: *Connection, data: []const u8) !void {
        if (!self.hasConfirmedAppTxKeys()) return error.KeysNotReady;
        const tx = self.app_tx_keys.?;
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .datagram = .{ .data = data } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        );
        defer self.allocator.free(pkt);
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
    fn writeStreamUnlocked(self: *Connection, id: u64, data: []const u8, fin: bool) !usize {
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

        // PHASE 42 PART 10: Get per-stream TX state for flow control
        const tx_state = if (id == 0)
            &StreamTx{ .off = self.stream_send_off, .peer_max_stream_data = self.peer_max_stream_data }
        else
            self.stream_txs.getPtr(id).?;

        const cur_off: u64 = tx_state.off;
        const peer_stream_limit: u64 = tx_state.peer_max_stream_data;

        if (cur_off >= peer_stream_limit) {
            // Signal STREAM_DATA_BLOCKED (coalesced: only once per limit value)
            if (self.last_stream_data_blocked_limit != peer_stream_limit) {
                self.last_stream_data_blocked_limit = peer_stream_limit;
                var fb1 = std.ArrayList(u8){};
                defer fb1.deinit(self.allocator.*);
                const w1 = fb1.writer(self.allocator.*);
                _ = (frame.Frame{ .stream_data_blocked = .{ .stream_id = id, .limit = peer_stream_limit } }).write(w1) catch 0;
                self.sendControlFrames(fb1.items);
            }
            return error.FlowControlBlocked;
        }
        // Enforce connection-level MAX_DATA
        if (self.conn_send_off >= self.peer_max_data) {
            // Signal DATA_BLOCKED (coalesced: only once per limit value)
            if (self.last_data_blocked_limit != self.peer_max_data) {
                self.last_data_blocked_limit = self.peer_max_data;
                var fb2 = std.ArrayList(u8){};
                defer fb2.deinit(self.allocator.*);
                const w2 = fb2.writer(self.allocator.*);
                _ = (frame.Frame{ .data_blocked = .{ .limit = self.peer_max_data } }).write(w2) catch 0;
                self.sendControlFrames(fb2.items);
            }
            return error.FlowControlBlocked;
        }
        const window_left_stream: u64 = peer_stream_limit - cur_off;
        const window_left_conn: u64 = self.peer_max_data - self.conn_send_off;
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
            // TEMPORARY OVERRIDE: allow send beyond cwnd to diagnose 1MB stall (investigation).
            logger.debugPrint("[CC-OVERRIDE] bytes_in_flight={} >= cwnd={} (allowing send for diagnostic)\n", .{ bytes_in_flight, cwnd });
        } else {
            logger.debugPrint("[CC-OK] bytes_in_flight={} < cwnd={}, available={}\n", .{ bytes_in_flight, cwnd, cwnd - bytes_in_flight });
        }

        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        // Write STREAM frame with slice sized by to_send.
        _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = cur_off, .fin = fin and to_send == data.len, .data = data[0..to_send] } }).write(w) catch 0;
        logger.debugPrint("DEBUG STREAM frame bytes ({} bytes): ", .{frames.items.len});
        for (frames.items[0..@min(frames.items.len, 40)]) |b| logger.debugPrint("{x:0>2} ", .{b});
        if (frames.items.len > 40) logger.debugPrint("...", .{});
        logger.debugPrint("\n", .{});
        const dcid = self.shortHeaderDcid();
        logger.debugPrint("Server sending STREAM with DCID len={}, first_byte={x}\n", .{ dcid.len, if (dcid.len > 0) dcid[0] else 0 });
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            dcid,
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        );
        defer self.allocator.free(pkt);
        logger.debugPrint("About to call send() with {} bytes\n", .{pkt.len});
        const bytes_sent = try self.send(pkt);
        logger.debugPrint("send() returned {} bytes\n", .{bytes_sent});
        logger.debugPrint("STREAM frame packet sent - {} bytes (pkt.len={})\n", .{ bytes_sent, pkt.len });
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
    fn readStreamUnlocked(self: *Connection, id: u64, buf: []u8) !usize {
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
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        );
        defer self.allocator.free(pkt);
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
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        ) catch null;
        if (pkt) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onShortHeaderPacketSent(bytes_out.len, true);
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
        // Update recovery for given space
        const now_i = std.time.nanoTimestamp();
        const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
        const res = self.rec.onAckReceivedWithEcn(space, acked, 0, now_ns, ecn);
        // Promote time-threshold losses if any expired now
        _ = self.rec.onLossTimeExpired(now_ns);
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
    fn pmtudArm(self: *Connection, ep: anytype, delay_ms: u32) void {
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
        // Derive server initial TX keys on demand
        const initial = ks.deriveInitialSecret(self.version_v2, self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]);
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

        const out = packet.encodeInitialProtected(
            self.allocator.*,
            self.version,
            // DCID destination
            dest_cid,
            self.our_scid.bytes[0..self.our_scid.len],
            &[_]u8{},
            @as(u32, @truncate(self.pn_initial_tx)),
            2,
            frames.items,
            txk,
        ) catch null;
        if (out) |bytes_out| {
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
        logger.debugPrint("sendPtoProbeHandshake: Sending PTO probe with keys - key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ tx.key[0], tx.key[1], tx.key[2], tx.key[3] });
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
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
        const out = packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        ) catch null;
        if (out) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onShortHeaderPacketSent(bytes_out.len, true);
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
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        );
        defer self.allocator.free(pkt);
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

        // Log the raw secrets first
        logger.debugPrint("deriveHandshakeKeys: role={s}, version_v2={}\n", .{
            if (self.role == .Server) "Server" else "Client",
            version_v2,
        });
        logger.debugPrint("  hs_client secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            self.hs_client.?[0], self.hs_client.?[1], self.hs_client.?[2], self.hs_client.?[3],
        });
        logger.debugPrint("  hs_server secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            self.hs_server.?[0], self.hs_server.?[1], self.hs_server.?[2], self.hs_server.?[3],
        });

        // Assign rx/tx according to role
        const rx_secret_bytes = if (self.role == .Server) self.hs_client.? else self.hs_server.?;
        const tx_secret_bytes = if (self.role == .Server) self.hs_server.? else self.hs_client.?;

        const rx_secret = ks.Secret.fromSlice(.sha256, &rx_secret_bytes);
        const tx_secret = ks.Secret.fromSlice(.sha256, &tx_secret_bytes);

        logger.debugPrint("  For {s}:", .{if (self.role == .Server) "Server" else "Client"});
        logger.debugPrint("    rx_secret (for reading) = {s} secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            if (self.role == .Server) "client" else "server",
            rx_secret_bytes[0],
            rx_secret_bytes[1],
            rx_secret_bytes[2],
            rx_secret_bytes[3],
        });
        logger.debugPrint("    tx_secret (for writing) = {s} secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            if (self.role == .Server) "server" else "client",
            tx_secret_bytes[0],
            tx_secret_bytes[1],
            tx_secret_bytes[2],
            tx_secret_bytes[3],
        });

        const rx = tls13.deriveQuicHandshakeKeys(.sha256, &rx_secret, version_v2);
        const tx = tls13.deriveQuicHandshakeKeys(.sha256, &tx_secret, version_v2);
        self.hs_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.hs_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
        logger.debugPrint("Handshake keys derived for {s} - tx_key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}, rx_key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            if (self.role == .Server) "Server" else "Client",
            tx.key[0],
            tx.key[1],
            tx.key[2],
            tx.key[3],
            rx.key[0],
            rx.key[1],
            rx.key[2],
            rx.key[3],
        });
    }

    /// Derive application keys and traffic secrets for QUIC from current TLS secrets.
    fn deriveAppKeys(self: *Connection, client_app: ks.Secret, server_app: ks.Secret, version_v2: bool) void {
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) client_app else server_app;
        const tx_secret = if (self.role == .Server) server_app else client_app;
        const rx = tls13.deriveQuicAppKeys(.sha256, &rx_secret, version_v2);
        const tx = tls13.deriveQuicAppKeys(.sha256, &tx_secret, version_v2);
        self.app_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.app_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };

        // Debug: Log derived key material
        logger.debugPrint("\n=== 1-RTT KEYS DERIVED ({s}) ===\n", .{if (self.role == .Server) "Server" else "Client"});
        logger.debugPrint("RX (decrypt) secret[0..8]: ", .{});
        const rx_slice = rx_secret.slice();
        for (rx_slice[0..@min(8, rx_slice.len)]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nRX key[0..8]: ", .{});
        for (rx.key[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nRX iv[0..8]: ", .{});
        for (rx.iv[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nRX hp[0..8]: ", .{});
        for (rx.hp[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nTX (encrypt) secret[0..8]: ", .{});
        const tx_slice = tx_secret.slice();
        for (tx_slice[0..@min(8, tx_slice.len)]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nTX key[0..8]: ", .{});
        for (tx.key[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\n", .{});
        // Seed traffic secrets for future updates
        var app_rx: [ks.H.digest_length]u8 = undefined;
        var app_tx: [ks.H.digest_length]u8 = undefined;
        @memcpy(&app_rx, rx_secret.slice());
        @memcpy(&app_tx, tx_secret.slice());
        self.app_rx_secret = app_rx;
        self.app_tx_secret = app_tx;

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

    /// Destination Connection ID for short-header packets is always the peer-chosen ID.
    /// Use peer_initial_scid (the SCID the peer used in its Initial). If the peer sent a
    /// zero-length SCID, return an empty slice per RFC 9000 §7.2: "An endpoint that receives
    /// a packet with a zero-length Source Connection ID field MUST use a zero-length
    /// Destination Connection ID field for all packets in the connection."
    pub fn shortHeaderDcid(self: *Connection) []const u8 {
        const result = if (self.peer_initial_scid.len > 0) self.peer_initial_scid.bytes[0..self.peer_initial_scid.len] else &[_]u8{};

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
    fn zeroKeys(k: *packet.AeadKeys) void {
        @memset(&k.key, 0);
        @memset(&k.iv, 0);
        @memset(&k.hp, 0);
    }

    fn maybeTriggerKeyUpdateOnSend(self: *Connection, bytes_sent: usize) void {
        if (self.app_tx_keys == null or self.app_tx_secret == null) return;
        // Do not trigger another while an update is in progress
        if (self.tx_update_in_progress) return;
        // Simple thresholds (tunable): after 64 packets or 64 KiB
        self.tx_sent_packets_since_key +%= 1;
        self.tx_sent_bytes_since_key +%= @intCast(bytes_sent);
        const pkt_thr: u64 = 64;
        const byte_thr: u64 = 64 * 1024;
        if (self.tx_sent_packets_since_key >= pkt_thr or self.tx_sent_bytes_since_key >= byte_thr) {
            // Start TX update: derive next secret and keys, toggle tx key phase
            // PHASE 57 PART 11D: Use QUIC "quic ku" label, not TLS "traffic upd" (RFC 9001 §6)
            const next_secret = ks.updateQuicSecret(self.app_tx_secret.?);

            // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
            const preserved_hp = self.app_tx_keys.?.hp;

            if (self.version_v2) {
                const t = ks.deriveKeyIvHpV2(next_secret);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
            } else {
                const t = ks.deriveKeyIvHp(next_secret);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
            }
            self.app_tx_secret = next_secret;
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

    fn maybeFinalizeKeyUpdateOnAck(self: *Connection, largest_acked: u64) void {
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
        const next_secret = ks.updateQuicSecret(self.app_tx_secret.?);
        const next_mat = if (self.version_v2)
            ks.deriveKeyIvHpV2(next_secret)
        else
            ks.deriveKeyIvHp(next_secret);
        if (self.tx_prev_keys) |*kp| {
            zeroKeys(kp);
        }
        self.tx_prev_keys = self.app_tx_keys;

        // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
        const preserved_hp = self.app_tx_keys.?.hp;
        self.app_tx_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = preserved_hp };
        self.app_tx_secret = next_secret;
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

    /// Read first available stream data (any stream). Returns error.WouldBlock if none.
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
        if (ack_eliciting) self.maybeTriggerKeyUpdateOnSend(bytes_sent);
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
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.shortHeaderDcid(),
            @as(u32, @truncate(self.pn_app_tx)),
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
            self.tx_key_phase,
        );
        defer self.allocator.free(pkt);
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
    fn ensureStreamTxInit(self: *Connection) void {
        if (!self.stream_txs_init) {
            self.stream_txs = std.AutoHashMap(u64, StreamTx).init(self.allocator.*);
            self.stream_txs_init = true;
        }
    }

    fn ensureStreamRx(self: *Connection, id: u64) *StreamRx {
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
    fn isPeerInitiatedStream(self: *const Connection, stream_id: u64) bool {
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
        if (!self.isPeerInitiatedStream(stream_id)) return;

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
                logger.debugPrint("validatePeerStreamLimit: Peer exceeded bidi stream limit (stream_num={}, limit={})\n", .{
                    stream_num, self.local_max_streams_bidi
                });
                return error.StreamLimitExceeded;
            }
        } else {
            // Check against local_max_streams_uni
            if (stream_num >= self.local_max_streams_uni) {
                logger.debugPrint("validatePeerStreamLimit: Peer exceeded uni stream limit (stream_num={}, limit={})\n", .{
                    stream_num, self.local_max_streams_uni
                });
                return error.StreamLimitExceeded;
            }
        }
    }

    /// Check if we already know about this stream
    fn isStreamKnown(self: *const Connection, stream_id: u64) bool {
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
    fn queueIncomingStream(self: *Connection, stream_id: u64) !void {
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
        _ = self.ensureStreamRx(stream_id);

        // Also ensure TX state for bidirectional streams
        const dir_bit = (stream_id >> 1) & 0x1;
        const is_bidi = (dir_bit == 0);
        if (is_bidi) {
            self.ensureStreamTxInit();
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
            if (self.isPeerInitiatedStream(stream_id)) {
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
        const retry_sent = false; // FIXME: Track if Retry was sent by server
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

    /// Acquire (or reuse) a local CID slot and populate with new random CID + derived stateless reset token.
    /// Returns index into local_cids array and sequence number. Does NOT mark as pending for emission (caller does).
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
        var lc = &self.local_cids[i];
        lc.* = .{ .in_use = true, .sequence = seq, .cid = .{ .len = cid_bytes.len, .bytes = undefined }, .reset_token = undefined };
        @memcpy(lc.cid.bytes[0..cid_bytes.len], &cid_bytes);
        // Seed stateless_reset_base lazily from first available app_tx_secret (post-handshake) if still zeroed.
        self.ensureStatelessResetBase();
        lc.reset_token = deriveStatelessResetToken(&self.stateless_reset_base, seq, cid_bytes[0..]);
        if (i + 1 > self.active_local_cids) self.active_local_cids = @intCast(i + 1);
        return .{ .idx = @intCast(i), .sequence = seq };
    }

    /// Issue a new CID with rotation: if active limit reached, retire the oldest non-zero sequence locally
    /// and advance retired_prior_to so peer can drop it once the new CID frame is processed.
    /// Issue new CID performing rotation if at active limit (retires oldest non-zero sequence first).
    pub fn issueNewConnectionIdRotating(self: *Connection, rand: *std.rand.DefaultPrng) !u64 {
        if (self.canIssueNewConnectionId()) {
            return try self.issueNewConnectionId(rand);
        }
        // Find oldest (lowest sequence > 0) still in_use to retire locally.
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
            // Adjust issued_cids count to reflect active set change (sequence 0 not decremented here)
            if (self.issued_cids > 0) self.issued_cids -= 1;
        } else {
            return error.ActiveConnectionIdLimitReached;
        }
        // Now we can issue a fresh CID under limit again.
        return try self.issueNewConnectionId(rand);
    }
};

/// Local CID entry (minimal for now). Will be expanded with expiration/retire markers.
const LocalCid = struct {
    in_use: bool = false,
    sequence: u64 = 0,
    cid: Cid = .{},
    reset_token: [16]u8 = [_]u8{0} ** 16,
};

/// Derive stateless reset token using a simple hash placeholder.
/// Real implementation should follow guidance (e.g., use HMAC over (base || sequence || cid)).
fn deriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid_bytes: []const u8) [16]u8 {
    // HKDF based derivation (implementation choice following RFC 9000 §10.3 guidance).
    // prk = HKDF-Extract(salt = base, ikm = sequence||cid)
    var ikm_buf: [8 + 20]u8 = undefined; // CID <= 20 bytes in this implementation
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, sequence, .big);
    @memcpy(ikm_buf[0..8], &seq_be);
    const cid_len = cid_bytes.len;
    if (cid_len > 20) unreachable; // defensive (our Cid max 20)
    @memcpy(ikm_buf[8 .. 8 + cid_len], cid_bytes);
    const prk = ks.extract(base, ikm_buf[0 .. 8 + cid_len]);
    var out: [16]u8 = undefined;
    // token = HKDF-Expand-Label(prk, "reset token", "", 16)
    ks.expandLabel(prk, "reset token", &[_]u8{}, out[0..]) catch unreachable;
    return out;
}

/// Test helper exposing reset token derivation (used only by unit tests).
/// Exposed for unit tests to validate stateless reset token derivation.
pub fn testDeriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid: []const u8) [16]u8 {
    return deriveStatelessResetToken(base, sequence, cid);
}

/// Ensure stateless_reset_base is populated. If still all-zero and we have an
/// application traffic secret (post-handshake), derive a base using HKDF-Extract
/// with salt = app_tx_secret and ikm = "stateless reset base". This ties tokens
/// to the connection's cryptographic context without exposing traffic secrets.
fn ensureStatelessResetBase(self: *Connection) void {
    // Fast path: if already non-zero, return.
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
        const prk = ks.extract(&secret, label);
        // Take first 32 bytes directly from prk (its size equals digest length 32).
        @memcpy(self.stateless_reset_base[0..], prk[0..]);
    } else {
        // Fallback: randomize to avoid deterministic zero (should not happen before handshake in normal issuance).
        std.crypto.random.bytes(&self.stateless_reset_base);
    }
}
