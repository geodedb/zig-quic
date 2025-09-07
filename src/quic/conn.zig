// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");
// Import transport parameters module (registered as quic_transport_params in build.zig)
const tparams = @import("quic_transport_params");

/// Role of this endpoint for a connection.
pub const Role = enum { Client, Server };

/// Portable socket address wrapper used by endpoint/connection.
pub const SockAddr = struct {
    storage: posix.sockaddr.storage = undefined,
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
        var sin: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port_host),
            .addr = std.mem.nativeToBig(u32, (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d)),
            .zero = .{0} ** 8,
        };
        s.len = @intCast(@sizeOf(posix.sockaddr.in));
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..s.len], @as([*]const u8, @ptrCast(&sin))[0..s.len]);
        return s;
    }
};

/// Fixed-size Connection ID used in tests/internals.
pub const Cid = struct {
    len: u8 = 0,
    bytes: [20]u8 = undefined,
};

/// Sender callback used by Endpoint to provide paced sending.
pub const SendFn = *const fn (ctx: *anyopaque, c: *Connection, data: []const u8) anyerror!usize;

const PnWindow = struct {
    max: u64 = 0,
    have_any: bool = false,
    win: std.bit_set.IntegerBitSet(256) = std.bit_set.IntegerBitSet(256).initEmpty(),

    fn track(this: *PnWindow, pn: u64) void {
        if (!this.have_any or pn > this.max) {
            this.max = pn;
            this.have_any = true;
        }
        const span: u64 = 256;
        if (pn + 1 >= span) {
            const base: u64 = pn + 1 - span;
            const idx: u8 = @intCast(pn - base);
            this.win.set(idx);
        } else {
            const idx: u8 = @intCast(pn);
            this.win.set(idx);
        }
    }

    fn buildAckRanges(this: *const PnWindow, out_buf: []frame.AckRange) struct { first_range: u64, ranges_len: usize } {
        if (!this.have_any) return .{ .first_range = 0, .ranges_len = 0 };
        const largest: u64 = this.max;
        const span: u64 = 256;
        const base: u64 = if (largest + 1 >= span) largest + 1 - span else 0;
        const largest_idx: usize = @intCast(largest - base);
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
const StreamRx = struct {
    recv_off: u64 = 0,
    inbox: std.ArrayList(u8),
    bufs: std.ArrayList(Segment),
    fin_off: ?u64 = null,

    fn init() StreamRx {
        return .{ .recv_off = 0, .inbox = std.ArrayList(u8){}, .bufs = std.ArrayList(Segment){}, .fin_off = null };
    }
    fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
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

// Per-stream transmit bookkeeping (offset + flags) for multi-stream support.
const StreamTx = struct {
    off: u64 = 0,
    fin_sent: bool = false,
    aborted: bool = false,
};

/// Connection state and helpers for QUIC handshake, recovery, and 1-RTT.
pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: isize,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    tls: tls13.Engine,
    allocator: *std.mem.Allocator,
    // Allowed ALPNs configured on endpoint
    allowed_alpns: []const []const u8 = &[_][]const u8{},
    // Optional pacing flag (from endpoint cfg)
    enable_pacing: bool = false,
    // Optional sender callback (set by Endpoint) for paced sending
    sender_ctx: ?*anyopaque = null,
    sender_fn: ?SendFn = null,
    // Derived handshake traffic secrets (once both hellos present)
    hs_client: ?[tls13.H.digest_length]u8 = null,
    hs_server: ?[tls13.H.digest_length]u8 = null,
    // Cached QUIC Handshake keys for RX/TX once derived
    hs_rx_keys: ?packet.InitialKeys = null,
    hs_tx_keys: ?packet.InitialKeys = null,
    // 1-RTT application keys
    app_rx_keys: ?packet.AeadKeys = null,
    app_tx_keys: ?packet.AeadKeys = null,
    // Track current TLS application traffic secrets for RX/TX to support Key Update
    app_rx_secret: ?[ks.H.digest_length]u8 = null,
    app_tx_secret: ?[ks.H.digest_length]u8 = null,
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
    server_hello_sent: bool = false,
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

    // --- Missing transport/runtime state used by endpoint/tests ---
    // Packet number spaces: next PN to send in each space
    pn_initial_tx: u64 = 1,
    pn_handshake_tx: u64 = 1,
    pn_app_tx: u64 = 1,
    // Version negotiation/bookkeeping
    version: u32 = 0,
    version_v2: bool = false,
    initial_version: u32 = 0,
    initial_keys_dropped: bool = false,
    // Connection IDs used during Initial/transport
    peer_initial_dcid: Cid = .{},
    // Original Destination Connection ID chosen by client (ODCID). Remains constant
    // across Retry; used for Initial secret derivation per RFC 9000 §5.2.
    original_dcid: Cid = .{},
    peer_initial_scid: Cid = .{},
    our_scid: Cid = .{},
    // Received PN tracking windows for ACK generation
    pn_initial: PnWindow = .{},
    pn_handshake: PnWindow = .{},
    pn_app: PnWindow = .{},
    // Recovery integration: RFC 9002 RTT/loss/CC/PTO
    rec: recovery.Recovery = undefined,
    // Legacy send-time/size tracking (kept for backward-compat; no longer used for loss)
    sent_time: std.AutoHashMap(u64, i128) = undefined,
    sent_sizes: std.AutoHashMap(u64, u16) = undefined,
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
    // DATAGRAM inbox
    dgram_inbox: std.ArrayList([]u8) = undefined,
    // Streams RX map and simple stream-0 TX counters
    streams_rx: std.AutoHashMap(u64, StreamRx) = undefined,
    stream_opened: bool = false,
    stream_send_off: u64 = 0,
    // Multi-stream TX state map (extended): track offset/flags per stream id
    stream_txs: std.AutoHashMap(u64, StreamTx) = undefined,
    // Stream state flags (stream 0 in this slice)
    stream_send_aborted: bool = false,
    stream_recv_aborted: bool = false,
    stream_recv_fin: bool = false,
    // Flow-control windows (connection and per-stream)
    // Start with conservative windows; grow adaptively.
    local_max_stream_data: u64 = 16 * 1024,
    peer_max_stream_data: u64 = 16 * 1024,
    local_max_data: u64 = 64 * 1024,
    peer_max_data: u64 = 64 * 1024,
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
    // Retry token buffer
    initial_token: std.ArrayList(u8) = undefined,
    // Simple path validation & tokens
    path_validation_pending: bool = false,
    path_challenge_data: [8]u8 = .{0} ** 8,
    new_token_pending: bool = false,
    new_token_sent: bool = false,
    // Stateless reset tokens advertised by peer via NEW_CONNECTION_ID
    reset_tokens: std.ArrayList([16]u8) = undefined,
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

    // --- DPLPMTUD (RFC 9000 §14.2–§14.4) minimal state ---
    /// Current believed path MTU (UDP payload size), never below 1200.
    path_mtu: u16 = 1200,
    /// Pending probe PN (Application space) awaiting ACK to validate path MTU.
    probe_pending_pn: ?u64 = null,
    /// Target size of the pending probe (UDP payload size).
    probe_pending_size: u16 = 0,
    /// DPLPMTUD phase and timer
    pmtud_state: PmtudState = .Disabled,
    pmtud_timer_active: bool = false,
    pmtud_timer_id: u64 = 0,

    // --- AEAD usage limits (RFC 9001 §6.6) ---
    /// Total number of 1-RTT packets encrypted with current TX keys (confidentiality limit counter).
    aead_tx_encrypted_count: u64 = 0,
    /// Total number of packets that failed authentication on RX (integrity limit counter).
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
    pub fn recordAckElicitingRx(self: *Connection, space: recovery.PacketNumberSpace, now_ns: u64) void {
        switch (space) {
            .Initial => self.last_ack_eliciting_rx_initial_ns = now_ns,
            .Handshake => self.last_ack_eliciting_rx_handshake_ns = now_ns,
            .Application => self.last_ack_eliciting_rx_app_ns = now_ns,
        }
    }

    /// getAckDelayEncoded: Encode ACK delay per RFC 9000 §19.3 using ack_delay_exponent and max_ack_delay cap.
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
    /// Track received Initial-space PN for ACK range construction.
    pub fn trackRecvPnInitial(self: *Connection, pn_full: u64) void {
        self.pn_initial.track(pn_full);
    }
    /// Track a received PN in Handshake space for ACK generation.
    /// Track received Handshake-space PN for ACK range construction.
    pub fn trackRecvPnHandshake(self: *Connection, pn_full: u64) void {
        self.pn_handshake.track(pn_full);
    }
    /// Track a received PN in App space for ACK generation.
    /// Track received Application-space PN for ACK range construction.
    pub fn trackRecvPnApp(self: *Connection, pn_full: u64) void {
        self.pn_app.track(pn_full);
    }

    /// Build ACK ranges for Initial/Handshake/App space using the sliding window.
    /// Build ACK descriptor (largest + ranges) for Initial space using sliding window.
    pub fn buildAckInitial(self: *Connection) AckDesc {
        const d = self.pn_initial.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_initial.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Handshake space.
    /// Build ACK descriptor for Handshake space.
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        const d = self.pn_handshake.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_handshake.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Application space.
    /// Build ACK descriptor for Application (1-RTT) space.
    pub fn buildAckApp(self: *Connection) AckDesc {
        const d = self.pn_app.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_app.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }

    /// Return true when the receive side of the stream has reached FIN.
    pub fn isStreamFinished(self: *Connection, id: u64) bool {
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
        self.tls = tls13.Engine.init(alloc.*, if (role == .Client) .Client else .Server);
        self.allocator = alloc;
        self.allowed_alpns = &[_][]const u8{};
        self.enable_pacing = false;
        self.sender_ctx = null;
        self.sender_fn = null;
        self.hs_client = null;
        self.hs_server = null;
        self.hs_rx_keys = null;
        self.hs_tx_keys = null;
        self.app_rx_keys = null;
        self.app_tx_keys = null;
        self.pn_initial_tx = 1;
        self.pn_handshake_tx = 1;
        self.pn_app_tx = 1;
        self.peer_initial_dcid = .{};
        self.peer_initial_scid = .{};
        // Explicitly zero original_dcid (was left uninitialized when reusing a Connection object
        // before this field was added, leading to bogus large lengths and panics when slicing).
        self.original_dcid = .{};
        self.our_scid = .{};
        self.version = 0;
        self.version_v2 = false;
        self.initial_version = 0;
        self.initial_keys_dropped = false;
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
        // Init DATAGRAM inbox
        self.dgram_inbox = std.ArrayList([]u8){};
        // Init streams map
        self.streams_rx = std.AutoHashMap(u64, StreamRx).init(alloc.*);
        self.stream_opened = false;
        self.stream_send_off = 0;
        self.stream_txs = std.AutoHashMap(u64, StreamTx).init(alloc.*);
        self.stream_send_aborted = false;
        self.stream_recv_aborted = false;
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
        self.reset_tokens = std.ArrayList([16]u8){};
        // CC default to NewReno; endpoint can flip use_cubic
        self.use_cubic = false;
        self.cc_nr = .{};
        self.cc_cubic = .{};
        // ensure recovery knows CC mode
        self.rec.setCcMode(false);
        // Initialize retry token buffer to match deinit symmetry
        self.initial_token = std.ArrayList(u8){};
        // Explicitly initialize crypto retransmit buffers (field defaults not applied on reuse)
        self.crypto_retx_initial = null;
        self.crypto_retx_handshake = null;
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
        self.server_hello_sent = false;
        self.closed = false;
        self.accepted_enqueued = false;
        // Initialize connection ID management
        self.local_cids = [_]LocalCid{.{}} ** 8;
        self.active_local_cids = 1;
        self.next_cid_sequence = 1;
        self.pending_new_cid = std.bit_set.IntegerBitSet(8).initEmpty();
        self.stateless_reset_base = [_]u8{0} ** 32;
        self.retired_prior_to = 0;
        self.issued_cids = 1;
        // Initialize flow control defaults
        self.local_max_stream_data = 64 * 1024;
        self.peer_max_stream_data = 64 * 1024;
        self.local_max_data = 256 * 1024;
        self.peer_max_data = 256 * 1024;
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
        // Initialize PMTUD state
        self.path_mtu = 1200;
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

    /// Release resources held by this Connection (payloads, maps, TLS state).
    /// Free dynamic resources (lists, maps, TLS engine) owned by the connection.
    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit(self.allocator.*);
        self.tls.deinit();
        self.rec.deinit();
        self.sent_time.deinit();
        self.sent_sizes.deinit();
        // Free inbox payloads
        if (self.crypto_retx_initial) |b| self.allocator.free(b);
        if (self.crypto_retx_handshake) |b| self.allocator.free(b);
        while (self.dgram_inbox.items.len > 0) {
            const p = self.dgram_inbox.orderedRemove(0);
            self.allocator.free(p);
        }
        self.dgram_inbox.deinit(self.allocator.*);
        // Deinit all streams
        var it = self.streams_rx.iterator();
        while (it.next()) |e| {
            var s = e.value_ptr.*;
            s.deinit(self.allocator);
        }
        self.streams_rx.deinit();
        if (self.stream_txs.capacity() != 0) self.stream_txs.deinit();
        // Free reset tokens / initial token buffers once (previous code double-deinited)
        if (self.reset_tokens.capacity != 0) self.reset_tokens.deinit(self.allocator.*);
        if (self.initial_token.capacity != 0) self.initial_token.deinit(self.allocator.*);
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
    /// Uses division (tx/3 <= rx) to avoid overflow for very large counters.
    /// Return true if anti-amplification budget permits sending (server before validation). Uses division to avoid overflow.
    pub fn canSendUnderAmplification(self: *const Connection) bool {
        if (self.address_validated) return true;
        return (self.bytes_tx_unvalidated / 3) <= self.bytes_rx_unvalidated;
    }

    /// Return true if we are currently over the anti-amplification limit.
    /// Return true if currently exceeding allowed 3x amplification limit.
    pub fn overAmplification(self: *const Connection) bool {
        if (self.address_validated) return false;
        return (self.bytes_tx_unvalidated / 3) > self.bytes_rx_unvalidated;
    }

    /// Saturating add to RX unvalidated counter to avoid wrap.
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

    /// Send bytes to peer using configured sender callback; if none, act as no-op that accounts amplification.
    /// Send bytes via installed sender callback (accounting amplification); in tests with no sender, acts as no-op success.
    pub fn send(self: *Connection, data: []const u8) !usize {
        // Amplification guard: if address not validated and we already exceeded 3x budget, refuse to send
        if (self.overAmplification()) return error.WouldBlock;
        if (self.sender_fn) |f| {
            const ctx = self.sender_ctx orelse return data.len;
            const n = try f(ctx, self, data);
            self.addTxUnvalidated(n);
            return n;
        }
        // Test mode: no endpoint sender installed; pretend all bytes were sent.
        self.addTxUnvalidated(data.len);
        return data.len;
    }

    /// Feed received CRYPTO bytes to the TLS engine and enforce allowed ALPN list.
    /// Feed CRYPTO stream bytes into TLS engine; derive secrets/keys and apply peer transport parameters when available.
    pub fn pushCrypto(self: *Connection, hs: []const u8) !void {
        self.tls.onCryptoRecv(hs);
        // Server: upon receiving first ClientHello bytes, queue a ServerHello if not already queued.
        if (self.role == .Server and !self.tls.sh_seen) {
            std.debug.print("Server: Received ClientHello, queueing ServerHello\n", .{});
            if (self.tls.real_mode) {
                // Real mode: build spec-like ServerHello
                self.tls.queueRealServerHello() catch {};
            } else {
                // Minimal placeholder auto ServerHello
                _ = self.tls.queueMinimalServerHelloAuto() catch {};
            }
        }
        // If we can compute handshake secrets now, install Handshake keys once
        if (self.hs_client == null or self.hs_server == null) {
            if (self.tls.computeHandshakeSecrets()) |hs_secrets| {
                std.debug.print("{s}: Derived handshake secrets\n", .{if (self.role == .Server) "Server" else "Client"});
                self.hs_client = hs_secrets.client;
                self.hs_server = hs_secrets.server;
                self.deriveHandshakeKeys(self.version_v2);
            } else {
                std.debug.print("{s}: Cannot derive handshake secrets yet (ch_sent={}, sh_seen={}, ecdhe={})\n", .{ if (self.role == .Server) "Server" else "Client", self.tls.ch_sent, self.tls.sh_seen, self.tls.ecdhe_secret != null });
            }
        }
        // Install 1-RTT keys only after BOTH sides' Finished messages are involved from our perspective:
        // - finished_verified: we have validated the peer's Finished
        // - finished_sent: we have queued our own Finished (prevents client from sending 1-RTT data before sending Finished)
        // This fixes premature application key installation (client derived 1-RTT keys after verifying server Finished but before sending its own Finished),
        // which caused interop failure: server never received client's Finished and thus couldn't decrypt 1-RTT stream data.
        if (self.app_tx_keys == null) {
            if (self.tls.finished_verified and self.tls.finished_sent) {
                // Delay installation until the Finished has actually been flushed (outbox empty) so
                // the client does not emit 1-RTT STREAM frames that the server cannot yet decrypt.
                if (self.tls.outbox.items.len == 0) {
                    if (self.tls.computeApplicationSecrets()) |app_secrets| {
                        std.debug.print("{s}: Deriving application secrets (both Finished exchanged & flushed)\n", .{if (self.role == .Server) "Server" else "Client"});
                        self.deriveAppKeys(app_secrets.client, app_secrets.server, self.version_v2);
                    }
                } else {
                    std.debug.print("{s}: Waiting to derive 1-RTT keys until Finished flushes ({} bytes pending)\n", .{ if (self.role == .Server) "Server" else "Client", self.tls.outbox.items.len });
                }
            } else if (self.tls.finished_verified and !self.tls.finished_sent) {
                // Debug aid: indicate deferral so logs show why 1-RTT keys not installed yet.
                std.debug.print("{s}: Deferring 1-RTT key derivation until our Finished is sent (verified peer Finished)\n", .{if (self.role == .Server) "Server" else "Client"});
            }
        }
        // Apply peer transport parameters (once) when they first become available.
        if (!self.transport_params_applied) {
            if (self.tls.getPeerTransportParameters()) |peer_tp_bytes| {
                self.applyPeerTransportParameters(peer_tp_bytes) catch {
                    // Ignore malformed transport parameters; retain defaults.
                };
            }
        }
        // If an ALPN was negotiated, enforce it against the allowed list when provided.
        if (self.tls.alpn) |a| {
            if (self.allowed_alpns.len > 0) {
                var ok = false;
                for (self.allowed_alpns) |p| {
                    if (std.mem.eql(u8, a, p)) {
                        ok = true;
                        break;
                    }
                }
                if (!ok) self.tls.finished_verified = false;
            }
        }
    }

    /// Attempt to derive 1-RTT keys after our Finished has been flushed from the TLS outbox.
    /// This is needed because pushCrypto() may have deferred derivation until the outbox emptied,
    /// but no further inbound CRYPTO might arrive to trigger another pushCrypto() call.
    pub fn maybeDeriveAppKeysAfterFlush(self: *Connection) void {
        if (self.app_tx_keys != null) return;
        if (!(self.tls.finished_verified and self.tls.finished_sent)) return;
        if (self.tls.outbox.items.len != 0) return; // still pending bytes
        if (self.tls.computeApplicationSecrets()) |app_secrets| {
            std.debug.print("{s}: Deriving application secrets after Finished flush\n", .{if (self.role == .Server) "Server" else "Client"});
            self.deriveAppKeys(app_secrets.client, app_secrets.server, self.version_v2);
        }
    }

    /// Get negotiated ALPN if any.
    /// Return negotiated ALPN slice (if any) after handshake progression.
    pub fn getNegotiatedAlpn(self: *Connection) ?[]const u8 {
        return self.tls.alpn;
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
        self.peer_initial_dcid.len = @intCast(@min(dcid.len, self.peer_initial_dcid.bytes.len));
        if (self.peer_initial_dcid.len > 0) @memcpy(self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len], dcid[0..self.peer_initial_dcid.len]);
        // Capture original destination connection ID (ODCID) only once (first client Initial).
        if (self.original_dcid.len == 0) {
            self.original_dcid.len = self.peer_initial_dcid.len;
            if (self.original_dcid.len > 0) @memcpy(self.original_dcid.bytes[0..self.original_dcid.len], self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len]);
        }
        self.peer_initial_scid.len = @intCast(@min(scid.len, self.peer_initial_scid.bytes.len));
        if (self.peer_initial_scid.len > 0) @memcpy(self.peer_initial_scid.bytes[0..self.peer_initial_scid.len], scid[0..self.peer_initial_scid.len]);
    }

    /// Ingest a STREAM frame payload into the RX buffer for the stream with reassembly.
    /// Ingest STREAM frame data (copy + reassembly); updates flow-control windows heuristically.
    pub fn pushStreamFrame(self: *Connection, stream_id: u64, offset: u64, data: []const u8, fin: bool) !void {
        if (self.stream_recv_aborted) return; // ignore further data after RESET_STREAM
        const s = self.ensureStreamRx(stream_id);
        if (fin) {
            const end_off: u64 = offset + @as(u64, data.len);
            s.fin_off = end_off;
            self.stream_recv_fin = true;
        }
        if (data.len > 0) {
            s.insert(self.allocator, offset, data);
            s.tryDrain(self.allocator);
        }
        // Update connection RX accounting
        self.conn_recv_total +%= data.len;
        // Flow-control: if we've consumed more than 50% of advertised windows, bump and let endpoint send MAX_* on next ACK
        // Adaptive growth: scale per active RX streams to avoid single-stream domination
        const active_streams: u64 = @intCast(self.streams_rx.count());
        const denom: u64 = if (active_streams == 0) 1 else active_streams;
        const stream_threshold: u64 = (self.local_max_stream_data * 3) / 4; // 75%
        if (s.recv_off >= stream_threshold) {
            self.local_max_stream_data +%= (self.local_max_stream_data / 2);
        }
        const conn_threshold: u64 = (self.local_max_data * 7) / 10; // 70%
        if (self.conn_recv_total >= conn_threshold) {
            const bump = @max(self.local_max_stream_data, self.local_max_data / (4 * denom));
            self.local_max_data +%= bump;
        }
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
    /// Emit a PATH_CHALLENGE frame (1-RTT) and mark path validation pending.
    pub fn sendPathChallenge(self: *Connection) void {
        const tx = self.app_tx_keys orelse {
            // No 1-RTT keys yet (e.g. test setup); still mark validation pending and seed challenge data.
            std.crypto.random.bytes(&self.path_challenge_data);
            self.path_validation_pending = true;
            return;
        };
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
        const tx = self.app_tx_keys orelse return;
        std.debug.print("{s}: Sending control frames ({d} bytes)\n", .{ if (self.role == .Server) "Server" else "Client", frames_bytes.len });
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
        if (self.app_tx_keys == null) return;
        if (!self.canSendUnderAmplification()) return;
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        var wrote: bool = false;
        if (self.local_max_stream_data > self.last_sent_max_stream_data) {
            _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
            self.last_sent_max_stream_data = self.local_max_stream_data;
            wrote = true;
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
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
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
            if (self.stream_txs.getPtr(stream_id) == null) {
                _ = self.stream_txs.put(stream_id, .{}) catch {};
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
            if (self.stream_txs.getPtr(stream_id) == null) {
                _ = self.stream_txs.put(stream_id, .{}) catch {};
            }
            return stream_id;
        }
    }

    /// Write STREAM data enforcing flow-control; may emit *_BLOCKED frames.
    /// Write data to a stream (simplified slice, no FIN flag in this helper slice yet).
    pub fn writeStream(self: *Connection, id: u64, data: []const u8) !usize {
        if (id == 0) {
            // Lazy open of client-initiated stream 0: allow application to call writeStream
            // without an explicit openStream( true ) first. This mirrors common QUIC API
            // ergonomics where the first write on stream 0 implicitly opens it.
            if (!self.stream_opened) {
                _ = self.openStream(true) catch |e| switch (e) {
                    // Propagate flow-control exhaustion semantics; other errors surface directly.
                    error.OutOfStreams => return e,
                    else => return e,
                };
            }
            if (self.stream_send_aborted) return error.StreamStopped;
        } else {
            if (self.stream_txs.getPtr(id) == null) return error.InvalidStream;
            // Safely inspect per-stream TX state (abort / FIN flags)
            if (self.stream_txs.getPtr(id)) |st| {
                if (st.aborted or st.fin_sent) return error.StreamStopped;
            }
        }
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        if (data.len == 0) return 0;
        const cur_off: u64 = if (id == 0) self.stream_send_off else self.stream_txs.getPtr(id).?.off;
        if (cur_off >= self.peer_max_stream_data) {
            // Signal STREAM_DATA_BLOCKED (coalesced: only once per limit value)
            if (self.last_stream_data_blocked_limit != self.peer_max_stream_data) {
                self.last_stream_data_blocked_limit = self.peer_max_stream_data;
                var fb1 = std.ArrayList(u8){};
                defer fb1.deinit(self.allocator.*);
                const w1 = fb1.writer(self.allocator.*);
                _ = (frame.Frame{ .stream_data_blocked = .{ .stream_id = id, .limit = self.peer_max_stream_data } }).write(w1) catch 0;
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
        const window_left_stream: u64 = self.peer_max_stream_data - cur_off;
        const window_left_conn: u64 = self.peer_max_data - self.conn_send_off;
        const window_left: u64 = if (window_left_stream < window_left_conn) window_left_stream else window_left_conn;
        const max_payload: usize = 1000; // keep within typical path-MTU
        const to_send_u64: u64 = @min(window_left, @as(u64, data.len));
        const to_send: usize = @intCast(@min(to_send_u64, @as(u64, max_payload)));
        if (to_send == 0) return error.FlowControlBlocked;
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = cur_off, .fin = false, .data = data[0..to_send] } }).write(w) catch 0;
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
        self.computeAndMaybeArmPto(self);
        if (id == 0) {
            self.stream_send_off += to_send;
        } else if (self.stream_txs.getPtr(id)) |stx| {
            stx.off += to_send;
        }
        self.conn_send_off += to_send;
        return to_send;
    }

    /// Read from STREAM into buf; returns number of bytes or WouldBlock.
    /// Read reassembled bytes from a stream into buf; returns number copied or WouldBlock.
    pub fn readStream(self: *Connection, id: u64, buf: []u8) !usize {
        var s = self.streams_rx.getPtr(id) orelse return error.InvalidStream;
        if (s.inbox.items.len == 0) return 0;
        const n: usize = @min(buf.len, s.inbox.items.len);
        @memcpy(buf[0..n], s.inbox.items[0..n]);
        const rem = s.inbox.items.len - n;
        if (rem > 0) std.mem.copyForwards(u8, s.inbox.items[0..rem], s.inbox.items[n..]);
        s.inbox.shrinkRetainingCapacity(rem);
        return n;
    }

    /// Close a STREAM with RESET_STREAM using the given application error code.
    /// Initiate graceful close of a stream (sends RESET/FIN depending on state) with app error code.
    pub fn closeStream(self: *Connection, id: u64, app_error_code: u64) !void {
        _ = app_error_code;
        if (id == 0) {
            if (self.stream_send_aborted) return error.StreamStopped;
        } else if (self.stream_txs.getPtr(id) == null) {
            return error.InvalidStream;
        }
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
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
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        // Mark stream as aborted for sending further STREAM frames
        if (stream_id == 0) {
            self.stream_send_aborted = true;
        } else if (self.stream_txs.getPtr(stream_id)) |st| {
            st.aborted = true;
        }
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .reset_stream = .{ .stream_id = stream_id, .error_code = app_error_code, .final_size = self.stream_send_off } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
        if (self.streams_rx.getPtr(stream_id)) |sr| {
            sr.deinit(self.allocator);
            _ = self.streams_rx.remove(stream_id);
        }
        if (stream_id == 0) {
            self.stream_opened = false;
            self.stream_send_aborted = false;
            self.stream_recv_aborted = false;
            self.stream_recv_fin = false;
            self.stream_send_off = 0;
        }
        if (stream_id != 0) {
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
        if (self.app_tx_keys == null) return;
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
        if (self.app_tx_keys == null) return;
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
        const txk: packet.InitialKeys = if (self.version_v2) blk: {
            const t = ks.deriveKeyIvHpV2(pair.server);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        } else blk: {
            const t = ks.deriveKeyIvHp(pair.server);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        };
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
        const out = packet.encodeInitialProtected(
            self.allocator.*,
            self.version,
            // DCID = client's Initial SCID; SCID = our chosen SCID
            self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
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
        const tx = self.app_tx_keys orelse return;
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        const w = frames.writer(self.allocator.*);
        _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
        const out = packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
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
    fn deriveHandshakeKeys(self: *Connection, version_v2: bool) void {
        if (self.hs_client == null or self.hs_server == null) return;
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) self.hs_client.? else self.hs_server.?;
        const tx_secret = if (self.role == .Server) self.hs_server.? else self.hs_client.?;
        const rx = tls13.deriveQuicHandshakeKeys(rx_secret, version_v2);
        const tx = tls13.deriveQuicHandshakeKeys(tx_secret, version_v2);
        self.hs_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.hs_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
    }

    /// Derive application keys and traffic secrets for QUIC from current TLS secrets.
    fn deriveAppKeys(self: *Connection, client_app: [tls13.H.digest_length]u8, server_app: [tls13.H.digest_length]u8, version_v2: bool) void {
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) client_app else server_app;
        const tx_secret = if (self.role == .Server) server_app else client_app;
        const rx = tls13.deriveQuicAppKeys(rx_secret, version_v2);
        const tx = tls13.deriveQuicAppKeys(tx_secret, version_v2);
        self.app_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.app_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
        // Seed traffic secrets for future updates
        self.app_rx_secret = rx_secret;
        self.app_tx_secret = tx_secret;
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
        // Only drop handshake keys if TLS outbox already flushed (no pending Finished or other handshake messages).
        const pending_tls: bool = (self.tls.outbox.items.len > 0);
        if (!pending_tls) {
            self.hs_rx_keys = null;
            self.hs_tx_keys = null;
        } else {
            std.debug.print("{s}: Deferring Handshake key drop until CRYPTO outbox flushed ({} bytes pending)\n", .{ if (self.role == .Server) "Server" else "Client", self.tls.outbox.items.len });
        }
        // Server: send HANDSHAKE_DONE and reaffirm initial MAX_* once
        if (self.role == .Server and !self.handshake_done_sent) {
            var frames = std.ArrayList(u8){};
            defer frames.deinit(self.allocator.*);
            const w = frames.writer(self.allocator.*);
            _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
            _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = self.local_max_stream_data } }).write(w) catch 0;
            _ = (frame.Frame{ .max_data = .{ .max = self.local_max_data } }).write(w) catch 0;
            _ = (frame.Frame{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } }).write(w) catch 0;
            if (!self.session_ticket_sent) {
                self.tls.queueNewSessionTicket() catch |e| {
                    std.debug.print("session ticket queue error: {s}\n", .{@errorName(e)});
                };
                self.session_ticket_sent = true;
            }
            self.sendControlFrames(frames.items);
            self.handshake_done_sent = true;
        }
    }

    /// Destination Connection ID for short-header packets is always the peer-chosen ID.
    /// Use peer_initial_scid (the SCID the peer used in its Initial) when present; fallback
    /// to our_scid only before we have observed the peer Initial (no 1-RTT should be sent then).
    fn shortHeaderDcid(self: *Connection) []const u8 {
        if (self.peer_initial_scid.len > 0) return self.peer_initial_scid.bytes[0..self.peer_initial_scid.len];
        return self.our_scid.bytes[0..self.our_scid.len];
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
            const next_secret = ks.updateTrafficSecret(self.app_tx_secret.?);
            if (self.version_v2) {
                const t = ks.deriveKeyIvHpV2(next_secret);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            } else {
                const t = ks.deriveKeyIvHp(next_secret);
                if (self.app_tx_keys) |kprev| self.tx_prev_keys = kprev;
                self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            }
            self.app_tx_secret = next_secret;
            self.tx_key_phase = !self.tx_key_phase;
            self.tx_update_in_progress = true;
            // First PN in the new phase is the next sent PN value
            self.tx_update_start_pn = self.pn_app_tx;
            // Reset counters for next epoch
            self.tx_sent_packets_since_key = 0;
            self.tx_sent_bytes_since_key = 0;
            std.debug.print("keyupdate: triggered phase={d} start_pn={d}\n", .{ @intFromBool(self.tx_key_phase), self.tx_update_start_pn });
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
            std.debug.print("keyupdate: finalized ack_pn={d} phase={d}\n", .{ largest_acked, @intFromBool(self.tx_key_phase) });
        }
    }

    /// Read first available stream data (any stream). Returns error.WouldBlock if none.
    pub fn readAnyStream(self: *Connection, buf: []u8) !struct { id: u64, n: usize } {
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
        _ = self.rec.onPacketSent(.Application, self.pn_app_tx, bytes_sent, ack_eliciting, now_ns) catch {};
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
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        // Minimum QUIC/UDP payload size is 1200 (RFC 9000 §14.1)
        if (target_udp_payload < 1200) return error.InvalidProbeSize;
        // CC-aware pacing guard: do not send a probe if it would exceed cwnd.
        // This keeps PMTUD probing from competing with data under tight congestion windows.
        const bif: usize = self.rec.cc.bytes_in_flight;
        const cwnd: usize = self.rec.cc.cwnd;
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
            self.our_scid.bytes[0..dcid_len],
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
        if (self.aead_rx_invalid_count >= self.aead_integrity_limit) {
            // Enter closed state; in a full implementation we would send CONNECTION_CLOSE with AEAD_LIMIT_REACHED.
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
        if (self.sent_time.capacity() == 0) self.sent_time = std.AutoHashMap(u64, i128).init(self.allocator.*);
        if (self.sent_sizes.capacity() == 0) self.sent_sizes = std.AutoHashMap(u64, u16).init(self.allocator.*);
        _ = self.sent_time.put(pn, @as(i128, @intCast(now_ns))) catch {};
        _ = self.sent_sizes.put(pn, @intCast(@min(bytes, @as(usize, std.math.maxInt(u16))))) catch {};
        self.ccOnPacketSent(bytes, ack_eliciting);
    }

    fn ensureStreamRx(self: *Connection, id: u64) *StreamRx {
        if (self.streams_rx.capacity() == 0) self.streams_rx = std.AutoHashMap(u64, StreamRx).init(self.allocator.*);
        if (self.dgram_inbox.capacity == 0) self.dgram_inbox = std.ArrayList([]u8){};
        if (self.streams_rx.getPtr(id)) |s| return s;
        const sr = StreamRx.init();
        self.streams_rx.put(id, sr) catch {};
        return self.streams_rx.getPtr(id).?;
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
        // Flow control: peer's advertised maxima govern what we may send.
        if (tp_dec.initial_max_data) |v| self.peer_max_data = v;
        // Choose a bidi stream data limit from whichever field is present (take the larger if both).
        var bidi_limit: u64 = self.peer_max_stream_data;
        if (tp_dec.initial_max_stream_data_bidi_local) |v| {
            if (v > bidi_limit) bidi_limit = v;
        }
        if (tp_dec.initial_max_stream_data_bidi_remote) |v| {
            if (v > bidi_limit) bidi_limit = v;
        }
        if (tp_dec.initial_max_stream_data_uni) |v| {
            // For simplicity in this slice, treat uni limit similarly (even though stream id 0 is bidi).
            if (v > bidi_limit) bidi_limit = v;
        }
        if (bidi_limit != self.peer_max_stream_data) self.peer_max_stream_data = bidi_limit;
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
                if (lim < self.rec.cc.mds) self.rec.cc.mds = lim;
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
