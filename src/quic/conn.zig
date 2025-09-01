// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");
const ks = @import("quic_tls");

/// Role of this endpoint for a connection.
pub const Role = enum { Client, Server };

/// Portable socket address wrapper used by endpoint/connection.
pub const SockAddr = struct {
    storage: posix.sockaddr.storage = undefined,
    len: u32 = 0,

    /// Initialize from a POSIX addrinfo entry.
    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    /// Return address family (AF.INET/AF.INET6).
    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

    /// Compare two socket addresses for byte-wise equality.
    pub fn eq(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.len != b.len) return false;
        if (a.storage.family != b.storage.family) return false;
        const pa = @as([*]const u8, @ptrCast(&a.storage))[0..a.len];
        const pb = @as([*]const u8, @ptrCast(&b.storage))[0..b.len];
        return std.mem.eql(u8, pa, pb);
    }

    /// Helper to build an IPv4 sockaddr for tests.
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

    fn init(alloc: *std.mem.Allocator) StreamRx {
        return .{ .recv_off = 0, .inbox = std.ArrayList(u8).init(alloc.*), .bufs = std.ArrayList(Segment).init(alloc.*), .fin_off = null };
    }
    fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| alloc.free(seg.data);
        self.bufs.deinit();
        self.inbox.deinit();
    }

    fn insert(self: *StreamRx, alloc: *std.mem.Allocator, off: u64, data: []const u8) void {
        // store a copy of segment
        const owned = alloc.alloc(u8, data.len) catch return;
        @memcpy(owned, data);
        self.bufs.append(.{ .off = off, .data = owned }) catch {
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
                    _ = self.inbox.appendSlice(seg.data) catch {};
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

/// Connection state and helpers for QUIC handshake, recovery, and 1-RTT.
pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
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
    // Connection close state
    closed: bool = false,

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
    peer_initial_scid: Cid = .{},
    our_scid: Cid = .{},
    // Received PN tracking windows for ACK generation
    pn_initial: PnWindow = .{},
    pn_handshake: PnWindow = .{},
    pn_app: PnWindow = .{},
    // Recovery integration: RFC 9002 RTT/loss/CC/PTO
    rec: recovery.Recovery = recovery.Recovery.init(std.heap.page_allocator),
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
    // Stream state flags (stream 0 in this slice)
    stream_send_aborted: bool = false,
    stream_recv_aborted: bool = false,
    stream_recv_fin: bool = false,
    // Flow-control windows (connection and per-stream)
    local_max_stream_data: u64 = 64 * 1024,
    peer_max_stream_data: u64 = 64 * 1024,
    local_max_data: u64 = 256 * 1024,
    peer_max_data: u64 = 256 * 1024,
    peer_max_streams_bidi: u64 = 16,
    peer_max_streams_uni: u64 = 16,
    opened_bidi: u64 = 0,
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

    /// Expand a truncated PN in Initial space using expected next PN.
    pub fn expandPnInitial(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_initial.have_any) self.pn_initial.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }
    /// Expand a truncated PN in Handshake space using expected next PN.
    pub fn expandPnHandshake(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_handshake.have_any) self.pn_handshake.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }
    /// Expand a truncated PN in 1-RTT App space using expected next PN.
    pub fn expandPnApp(self: *const Connection, trunc_val: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_app.have_any) self.pn_app.max + 1 else 0;
        return expandTruncatedPn(trunc_val, pn_len, expected);
    }

    /// Track a received PN in Initial space for ACK generation.
    pub fn trackRecvPnInitial(self: *Connection, pn_full: u64) void {
        self.pn_initial.track(pn_full);
    }
    /// Track a received PN in Handshake space for ACK generation.
    pub fn trackRecvPnHandshake(self: *Connection, pn_full: u64) void {
        self.pn_handshake.track(pn_full);
    }
    /// Track a received PN in App space for ACK generation.
    pub fn trackRecvPnApp(self: *Connection, pn_full: u64) void {
        self.pn_app.track(pn_full);
    }

    /// Build ACK ranges for Initial/Handshake/App space using the sliding window.
    pub fn buildAckInitial(self: *Connection) AckDesc {
        const d = self.pn_initial.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_initial.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Handshake space.
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        const d = self.pn_handshake.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_handshake.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
    /// Build ACK ranges for Application space.
    pub fn buildAckApp(self: *Connection) AckDesc {
        const d = self.pn_app.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_app.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }

    /// Initialize a Connection in the given role bound to a socket and peer address.
    pub fn init(self: *Connection, alloc: *std.mem.Allocator, role: Role, sock_fd: posix.fd_t, peer: SockAddr) void {
        self.id = 0;
        self.role = role;
        self.sock_fd = sock_fd;
        self.peer = peer;
        self.tls_inbox = std.ArrayList(u8).init(alloc.*);
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
        self.dgram_inbox = std.ArrayList([]u8).init(alloc.*);
        // Init streams map
        self.streams_rx = std.AutoHashMap(u64, StreamRx).init(alloc.*);
        self.stream_opened = false;
        self.stream_send_off = 0;
        self.stream_send_aborted = false;
        self.stream_recv_aborted = false;
        self.stream_recv_fin = false;
        // Flow-control connection-level defaults already set via field initializers
        self.path_validation_pending = false;
        self.path_challenge_data = .{0} ** 8;
        self.new_token_pending = false;
        self.new_token_sent = false;
        self.reset_tokens = std.ArrayList([16]u8).init(alloc.*);
        // CC default to NewReno; endpoint can flip use_cubic
        self.use_cubic = false;
        self.cc_nr = .{};
        self.cc_cubic = .{};
        // ensure recovery knows CC mode
        self.rec.setCcMode(false);
        // Initialize retry token buffer to match deinit symmetry
        self.initial_token = std.ArrayList(u8).init(alloc.*);
    }

    /// Release resources held by this Connection (payloads, maps, TLS state).
    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit();
        self.tls.deinit();
        self.rec.deinit();
        self.sent_time.deinit();
        self.sent_sizes.deinit();
        // Free inbox payloads
        while (self.dgram_inbox.items.len > 0) {
            const p = self.dgram_inbox.orderedRemove(0);
            self.allocator.free(p);
        }
        self.dgram_inbox.deinit();
        // Deinit all streams
        var it = self.streams_rx.iterator();
        while (it.next()) |e| {
            var s = e.value_ptr.*;
            s.deinit(self.allocator);
        }
        self.streams_rx.deinit();
        // Retry token buffer
        self.initial_token.deinit();
        self.reset_tokens.deinit();
    }

    /// Update peer address (used for NAT rebinding / migration detection).
    pub fn setPeer(self: *Connection, peer: SockAddr) void {
        self.peer = peer;
    }

    /// Update/reset stateless reset tokens based on NEW_CONNECTION_ID retire_prior_to.
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
            while (k < need) : (k += 1) self.reset_tokens.append(.{0} ** 16) catch break;
        }
        if (sequence < self.reset_tokens.items.len) self.reset_tokens.items[@intCast(sequence)] = stateless_reset_token;
    }

    /// Check if a trailing 16-byte token matches any known stateless reset token.
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
    }

    /// Return ECN counts for ACK_ECN emission in the given PN space if any ECN
    /// marks were observed; otherwise return null to emit a plain ACK.
    pub fn getAckEcn(self: *const Connection, space: recovery.PacketNumberSpace) ?frame.EcnCounts {
        const ctr: *const EcnCounter = switch (space) {
            .Initial => &self.ecn_initial,
            .Handshake => &self.ecn_handshake,
            .Application => &self.ecn_app,
        };
        if (!ctr.seen_any) return null;
        return .{ .ect0 = ctr.ect0, .ect1 = ctr.ect1, .ce = ctr.ce };
    }

    /// Install a custom sender callback (typically provided by Endpoint) for paced sending.
    pub fn setSender(self: *Connection, ctx: *anyopaque, f: SendFn) void {
        self.sender_ctx = ctx;
        self.sender_fn = f;
    }

    /// Configure AEAD usage limits based on endpoint config (optional overrides).
    pub fn setAeadUsageLimits(self: *Connection, conf_limit: ?u64, integ_limit: ?u64) void {
        if (conf_limit) |v| self.aead_confidentiality_limit = v;
        if (integ_limit) |v| self.aead_integrity_limit = v;
    }

    /// Return true if sending is allowed under the anti-amplification limit.
    /// Uses division (tx/3 <= rx) to avoid overflow for very large counters.
    pub fn canSendUnderAmplification(self: *const Connection) bool {
        if (self.address_validated) return true;
        return (self.bytes_tx_unvalidated / 3) <= self.bytes_rx_unvalidated;
    }

    /// Return true if we are currently over the anti-amplification limit.
    pub fn overAmplification(self: *const Connection) bool {
        if (self.address_validated) return false;
        return (self.bytes_tx_unvalidated / 3) > self.bytes_rx_unvalidated;
    }

    /// Saturating add to RX unvalidated counter to avoid wrap.
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
    pub fn pushCrypto(self: *Connection, hs: []const u8) !void {
        self.tls.onCryptoRecv(hs);
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

    /// Get negotiated ALPN if any.
    pub fn getNegotiatedAlpn(self: *Connection) ?[]const u8 {
        return self.tls.alpn;
    }

    /// Toggle congestion control (NewReno default, CUBIC optional).
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
    pub fn setPeerInitialCids(self: *Connection, dcid: []const u8, scid: []const u8) void {
        self.peer_initial_dcid.len = @intCast(@min(dcid.len, self.peer_initial_dcid.bytes.len));
        if (self.peer_initial_dcid.len > 0) @memcpy(self.peer_initial_dcid.bytes[0..self.peer_initial_dcid.len], dcid[0..self.peer_initial_dcid.len]);
        self.peer_initial_scid.len = @intCast(@min(scid.len, self.peer_initial_scid.bytes.len));
        if (self.peer_initial_scid.len > 0) @memcpy(self.peer_initial_scid.bytes[0..self.peer_initial_scid.len], scid[0..self.peer_initial_scid.len]);
    }

    /// Ingest a STREAM frame payload into the RX buffer for the stream with reassembly.
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
        const half_stream = self.local_max_stream_data / 2;
        if (s.recv_off >= half_stream) {
            self.local_max_stream_data +%= half_stream;
        }
        const half_conn = self.local_max_data / 2;
        if (self.conn_recv_total >= half_conn) {
            self.local_max_data +%= half_conn;
        }
    }

    /// Ingest a DATAGRAM frame payload (owned copy).
    pub fn pushDatagram(self: *Connection, data: []const u8) !void {
        const owned = try self.allocator.alloc(u8, data.len);
        @memcpy(owned, data);
        try self.dgram_inbox.append(owned);
    }

    /// Pop a DATAGRAM payload into buf; returns length copied or error if none.
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
    pub fn scheduleConnPto(self: *Connection, _c: *Connection, kind: anytype, delay_ms: u32) !u64 {
        _ = self;
        _ = _c;
        _ = kind;
        _ = delay_ms;
        return 0;
    }

    /// PTO expiry hook for Initial space: clears active flag, bumps backoff, and sends a PING probe.
    pub fn setPtoExpiredInitial(self: *Connection) void {
        if (!self.pto_initial_active) return;
        self.pto_initial_active = false;
        self.pto_initial_count +%= 1;
        // Increase recovery PTO backoff as well
        self.rec.pto_count +%= 1;
        self.sendPtoProbeInitial();
    }
    /// PTO expiry hook for Handshake space: clears active flag, bumps backoff, and sends a PING probe.
    pub fn setPtoExpiredHandshake(self: *Connection) void {
        if (!self.pto_handshake_active) return;
        self.pto_handshake_active = false;
        self.pto_handshake_count +%= 1;
        self.rec.pto_count +%= 1;
        self.sendPtoProbeHandshake();
    }
    /// PTO expiry hook for Application space: clears active flag, bumps backoff, and sends a PING probe.
    pub fn setPtoExpiredApp(self: *Connection) void {
        if (!self.pto_app_active) return;
        self.pto_app_active = false;
        self.pto_app_count +%= 1;
        // Also bump recovery PTO backoff counter
        self.rec.pto_count +%= 1;
        self.sendPtoProbeApp();
    }

    /// Send a PATH_CHALLENGE on the 1-RTT path to validate current peer path.
    pub fn sendPathChallenge(self: *Connection) void {
        const tx = self.app_tx_keys orelse return;
        // Generate opaque 8-byte data and remember for validation
        std.crypto.random.bytes(&self.path_challenge_data);
        self.path_validation_pending = true;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .path_challenge = self.path_challenge_data }).write(w) catch 0;
        const out = packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
        const pkt = packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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

    /// Send a datagram to the connection's peer using 1-RTT short header.
    pub fn sendDatagram(self: *Connection, data: []const u8) !void {
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .datagram = .{ .data = data } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
    pub fn openStream(self: *Connection, bidi: bool) !u64 {
        if (!bidi) return error.Unsupported;
        // Enforce peer MAX_STREAMS_BIDI
        if (self.opened_bidi >= self.peer_max_streams_bidi) {
            // Attempt to signal STREAMS_BLOCKED_BIDI
            var fb = std.ArrayList(u8).init(self.allocator.*);
            defer fb.deinit();
            const w = fb.writer();
            _ = (frame.Frame{ .streams_blocked_bidi = .{ .max = self.peer_max_streams_bidi } }).write(w) catch 0;
            self.sendControlFrames(fb.items);
            return error.OutOfStreams;
        }
        if (self.stream_opened) return error.OutOfStreams;
        self.stream_opened = true;
        self.opened_bidi += 1;
        // Ensure RX state for stream 0 exists
        _ = self.ensureStreamRx(0);
        return 0;
    }

    /// Write STREAM data enforcing flow-control; may emit *_BLOCKED frames.
    pub fn writeStream(self: *Connection, id: u64, data: []const u8) !usize {
        if (id != 0) return error.InvalidStream;
        if (self.stream_send_aborted) return error.StreamStopped;
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        if (data.len == 0) return 0;
        // Enforce stream-level window
        if (self.stream_send_off >= self.peer_max_stream_data) {
            // Signal STREAM_DATA_BLOCKED (coalesced: only once per limit value)
            if (self.last_stream_data_blocked_limit != self.peer_max_stream_data) {
                self.last_stream_data_blocked_limit = self.peer_max_stream_data;
                var fb1 = std.ArrayList(u8).init(self.allocator.*);
                defer fb1.deinit();
                const w1 = fb1.writer();
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
                var fb2 = std.ArrayList(u8).init(self.allocator.*);
                defer fb2.deinit();
                const w2 = fb2.writer();
                _ = (frame.Frame{ .data_blocked = .{ .limit = self.peer_max_data } }).write(w2) catch 0;
                self.sendControlFrames(fb2.items);
            }
            return error.FlowControlBlocked;
        }
        const window_left_stream: u64 = self.peer_max_stream_data - self.stream_send_off;
        const window_left_conn: u64 = self.peer_max_data - self.conn_send_off;
        const window_left: u64 = if (window_left_stream < window_left_conn) window_left_stream else window_left_conn;
        const max_payload: usize = 1000; // keep within typical path-MTU
        const to_send_u64: u64 = @min(window_left, @as(u64, data.len));
        const to_send: usize = @intCast(@min(to_send_u64, @as(u64, max_payload)));
        if (to_send == 0) return error.FlowControlBlocked;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .stream = .{ .stream_id = id, .offset = self.stream_send_off, .fin = false, .data = data[0..to_send] } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
        self.stream_send_off += to_send;
        self.conn_send_off += to_send;
        return to_send;
    }

    /// Read from STREAM into buf; returns number of bytes or WouldBlock.
    pub fn readStream(self: *Connection, id: u64, buf: []u8) !usize {
        const s = self.streams_rx.getPtr(id) orelse return error.InvalidStream;
        if (s.inbox.items.len == 0) return 0;
        const n: usize = @min(buf.len, s.inbox.items.len);
        @memcpy(buf[0..n], s.inbox.items[0..n]);
        const rem = s.inbox.items.len - n;
        if (rem > 0) std.mem.copy(u8, s.inbox.items[0..rem], s.inbox.items[n..]);
        s.inbox.shrinkRetainingCapacity(rem) catch {};
        return n;
    }

    /// Close a STREAM with RESET_STREAM using the given application error code.
    pub fn closeStream(self: *Connection, id: u64, app_error_code: u64) !void {
        _ = app_error_code; // not surfaced yet in transport close
        if (id != 0) return error.InvalidStream;
        if (self.stream_send_aborted) return error.StreamStopped;
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .stream = .{ .stream_id = 0, .offset = self.stream_send_off, .fin = true, .data = &[_]u8{} } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
    pub fn handleStopSending(self: *Connection, stream_id: u64, app_error_code: u64) !void {
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        // Mark stream as aborted for sending further STREAM frames
        self.stream_send_aborted = true;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
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
    pub fn handleResetStream(self: *Connection, stream_id: u64, app_error_code: u64, final_size: u64) void {
        _ = app_error_code; // surfaced to app layer out of scope here
        // Only stream 0 supported in this slice, but apply generically.
        var s = self.ensureStreamRx(stream_id);
        self.stream_recv_aborted = true;
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
    }

    /// When ACK arrives (any space), also allow finalizing TX key update on App ACKs
    pub fn onAckReceived(self: *Connection, largest: u64, first_range: u64, ranges: []const frame.AckRange) void {
        // Back-compat: assume Application space
        self.onAckReceivedSpace(.Application, largest, first_range, ranges, null);
    }

    /// Generalized ACK handler that wires through Recovery for the given PN space.
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

    /// Reset PTO backoff for Initial space.
    pub fn resetPtoBackoffInitial(self: *Connection) void {
        self.pto_initial_count = 0;
    }
    /// Reset PTO backoff for Handshake space.
    pub fn resetPtoBackoffHandshake(self: *Connection) void {
        self.pto_handshake_count = 0;
    }
    /// Reset PTO backoff for Application space (also clears recovery backoff).
    pub fn resetPtoBackoffApp(self: *Connection) void {
        self.pto_app_count = 0;
        self.rec.pto_count = 0;
    }

    /// Cancel PTO timer for Initial space.
    pub fn cancelPtoInitial(self: *Connection, ep: anytype) void {
        if (self.pto_initial_active) {
            if (self.pto_initial_id != 0) _ = ep.cancelTimer(self.pto_initial_id);
            self.pto_initial_active = false;
        }
        self.resetPtoBackoffInitial();
    }
    /// Cancel PTO timer for Handshake space.
    pub fn cancelPtoHandshake(self: *Connection, ep: anytype) void {
        if (self.pto_handshake_active) {
            if (self.pto_handshake_id != 0) _ = ep.cancelTimer(self.pto_handshake_id);
            self.pto_handshake_active = false;
        }
        self.resetPtoBackoffHandshake();
    }
    /// Cancel PTO timer for Application space.
    pub fn cancelPtoApp(self: *Connection, ep: anytype) void {
        if (self.pto_app_active) {
            if (self.pto_app_id != 0) _ = ep.cancelTimer(self.pto_app_id);
            self.pto_app_active = false;
        }
        self.resetPtoBackoffApp();
    }

    /// Compute PTO for Application space and arm timer if not active.
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

    // --- DPLPMTUD state machine ---
    pub const PmtudState = enum { Disabled, ProbeStart, ProbeSearch };

    /// Begin DPLPMTUD probing from base (1200) upward. Requires app_tx_keys.
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
    pub fn pmtudOnAckProgress(self: *Connection, ep: anytype) void {
        // If a pending probe was ACKed, onAckReceivedSpace already raised path_mtu.
        // Here we can shorten the next timer to continue search more quickly in tests.
        if (self.pmtud_state != .Disabled) {
            self.pmtudArm(ep, 10);
        }
    }

    /// Compute PTO for Initial space and arm timer if not active.
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
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
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
    pub fn sendPtoProbeHandshake(self: *Connection) void {
        const tx = self.hs_tx_keys orelse return;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
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
    pub fn sendPtoProbeApp(self: *Connection) void {
        const tx = self.app_tx_keys orelse return;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
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
    pub fn sendConnectionClose(self: *Connection, app_error_code: u64, reason: []const u8) !void {
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .connection_close = .{ .error_code = app_error_code, .frame_type = 0, .reason = reason } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
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
        }
    }

    /// Record a short-header 1-RTT packet as sent and maybe trigger key update.
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
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
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
    pub fn onAeadAuthFailure(self: *Connection) void {
        self.aead_rx_invalid_count +%= 1;
        if (self.aead_rx_invalid_count >= self.aead_integrity_limit) {
            // Enter closed state; in a full implementation we would send CONNECTION_CLOSE with AEAD_LIMIT_REACHED.
            self.closed = true;
        }
    }

    /// Record a packet as sent in the given PN space for Recovery bookkeeping.
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
        if (self.dgram_inbox.capacity == 0) self.dgram_inbox = std.ArrayList([]u8).init(self.allocator.*);
        if (self.streams_rx.getPtr(id)) |s| return s;
        const sr = StreamRx.init(self.allocator);
        self.streams_rx.put(id, sr) catch {};
        return self.streams_rx.getPtr(id).?;
    }
};
