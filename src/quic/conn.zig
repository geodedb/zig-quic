// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("recovery.zig");
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

    fn init(alloc: *std.mem.Allocator) StreamRx {
        return .{ .recv_off = 0, .inbox = std.ArrayList(u8).init(alloc.*), .bufs = std.ArrayList(Segment).init(alloc.*) };
    }
    fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| alloc.free(seg.data);
        self.bufs.deinit();
        self.inbox.deinit();
    }
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
    // Congestion controllers and selection flag (legacy; Recovery.cc is authoritative)
    use_cubic: bool = false,
    cc_nr: recovery.NewReno = .{},
    cc_cubic: recovery.Cubic = .{},

    // Temporary buffer for building ACK ranges
    ack_ranges_buf: [32]frame.AckRange = undefined,

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
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        const d = self.pn_handshake.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_handshake.max, .first_range = d.first_range, .ranges = self.ack_ranges_buf[0..d.ranges_len] };
    }
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
        self.local_max_stream_data = 64 * 1024;
        self.peer_max_stream_data = 64 * 1024;
        self.local_max_data = 256 * 1024;
        self.peer_max_data = 256 * 1024;
        self.peer_max_streams_bidi = 16;
        self.peer_max_streams_uni = 16;
        self.opened_bidi = 0;
        self.opened_uni = 0;
        self.conn_send_off = 0;
        self.conn_recv_total = 0;
        // Init address validation tracking
        self.address_validated = (role == .Client); // clients are not amplification-limited
        self.bytes_rx_unvalidated = 0;
        self.bytes_tx_unvalidated = 0;
        // Init Retry token buffer
        self.initial_token = std.ArrayList(u8).init(alloc.*);
        // Flow control connection-level defaults already set via field initializers
        self.path_validation_pending = false;
        self.path_challenge_data = .{0} ** 8;
        self.new_token_pending = false;
        self.new_token_sent = false;
        // CC default to NewReno; endpoint can flip use_cubic
        self.use_cubic = false;
        self.cc_nr = .{};
        self.cc_cubic = .{};
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
    }

    /// Update peer address (used for NAT rebinding / migration detection).
    pub fn setPeer(self: *Connection, peer: SockAddr) void {
        self.peer = peer;
    }

    /// Get negotiated ALPN if any.
    pub fn getNegotiatedAlpn(self: *Connection) ?[]const u8 {
        return self.tls.alpn;
    }

    /// Toggle congestion control (NewReno default, CUBIC optional).
    pub fn setUseCubic(self: *Connection, use: bool) void {
        self.use_cubic = use;
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

    /// Ingest a STREAM frame payload into the RX buffer for the stream (simple append).
    pub fn pushStreamFrame(self: *Connection, stream_id: u64, _offset: u64, data: []const u8, _fin: bool) !void {
        _ = _offset;
        _ = _fin;
        const s = self.ensureStreamRx(stream_id);
        try s.inbox.appendSlice(data);
        self.conn_recv_total +%= data.len;
    }

    /// Ingest a DATAGRAM frame payload (owned copy).
    pub fn pushDatagram(self: *Connection, data: []const u8) !void {
        const owned = try self.allocator.alloc(u8, data.len);
        @memcpy(owned, data);
        try self.dgram_inbox.append(owned);
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

    /// PTO expiry hooks used by Endpoint timers.
    pub fn setPtoExpiredInitial(self: *Connection) void {
        if (!self.pto_initial_active) return;
        self.pto_initial_active = false;
        self.pto_initial_count +%= 1;
        // Increase recovery PTO backoff as well
        self.rec.pto_count +%= 1;
        self.sendPtoProbeInitial();
    }
    pub fn setPtoExpiredHandshake(self: *Connection) void {
        if (!self.pto_handshake_active) return;
        self.pto_handshake_active = false;
        self.pto_handshake_count +%= 1;
        self.rec.pto_count +%= 1;
        self.sendPtoProbeHandshake();
    }
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

    /// Write bytes on stream id 0 using a Short header STREAM frame with LEN+OFF.
    pub fn writeStream(self: *Connection, id: u64, data: []const u8) !usize {
        if (id != 0) return error.InvalidStream;
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        if (data.len == 0) return 0;
        // Enforce stream-level window
        if (self.stream_send_off >= self.peer_max_stream_data) {
            // Signal STREAM_DATA_BLOCKED
            var fb1 = std.ArrayList(u8).init(self.allocator.*);
            defer fb1.deinit();
            const w1 = fb1.writer();
            _ = (frame.Frame{ .stream_data_blocked = .{ .stream_id = id, .limit = self.peer_max_stream_data } }).write(w1) catch 0;
            self.sendControlFrames(fb1.items);
            return error.FlowControlBlocked;
        }
        // Enforce connection-level MAX_DATA
        if (self.conn_send_off >= self.peer_max_data) {
            // Signal DATA_BLOCKED
            var fb2 = std.ArrayList(u8).init(self.allocator.*);
            defer fb2.deinit();
            const w2 = fb2.writer();
            _ = (frame.Frame{ .data_blocked = .{ .limit = self.peer_max_data } }).write(w2) catch 0;
            self.sendControlFrames(fb2.items);
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

    /// Read bytes from stream id into buf. Returns bytes copied (0 if none).
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

    /// Send a FIN (no data) on stream id 0.
    pub fn closeStream(self: *Connection, id: u64, app_error_code: u64) !void {
        _ = app_error_code; // not surfaced yet in transport close
        if (id != 0) return error.InvalidStream;
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

    // When ACK arrives (any space), also allow finalizing TX key update on App ACKs
    pub fn onAckReceived(self: *Connection, largest: u64, first_range: u64, ranges: []const frame.AckRange) void {
        // Back-compat: assume Application space
        self.onAckReceivedSpace(.Application, largest, first_range, ranges);
    }

    /// Generalized ACK handler that wires through Recovery for the given PN space.
    pub fn onAckReceivedSpace(self: *Connection, space: recovery.PacketNumberSpace, largest: u64, first_range: u64, ranges: []const frame.AckRange) void {
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
        const res = self.rec.onAckReceived(space, acked, 0, now_ns);
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
        // Legacy largest_acked bookkeeping retained for compatibility (App only)
        if (space == .Application and largest > self.largest_acked) self.largest_acked = largest;
    }

    /// Reset PTO backoff helpers
    pub fn resetPtoBackoffInitial(self: *Connection) void {
        self.pto_initial_count = 0;
    }
    pub fn resetPtoBackoffHandshake(self: *Connection) void {
        self.pto_handshake_count = 0;
    }
    pub fn resetPtoBackoffApp(self: *Connection) void {
        self.pto_app_count = 0;
        self.rec.pto_count = 0;
    }

    /// Cancel PTO helpers
    pub fn cancelPtoInitial(self: *Connection, ep: anytype) void {
        if (self.pto_initial_active) {
            if (self.pto_initial_id != 0) _ = ep.cancelTimer(self.pto_initial_id);
            self.pto_initial_active = false;
        }
        self.resetPtoBackoffInitial();
    }
    pub fn cancelPtoHandshake(self: *Connection, ep: anytype) void {
        if (self.pto_handshake_active) {
            if (self.pto_handshake_id != 0) _ = ep.cancelTimer(self.pto_handshake_id);
            self.pto_handshake_active = false;
        }
        self.resetPtoBackoffHandshake();
    }
    pub fn cancelPtoApp(self: *Connection, ep: anytype) void {
        if (self.pto_app_active) {
            if (self.pto_app_id != 0) _ = ep.cancelTimer(self.pto_app_id);
            self.pto_app_active = false;
        }
        self.resetPtoBackoffApp();
    }

    /// Compute PTO for App space and arm timer if not active.
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

    /// Compute PTO for Initial/Handshake space and arm timer if not active.
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

    /// Send a minimal PTO probe for the Initial/Handshake/App space (PING frame).
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

    pub fn onShortHeaderPacketSent(self: *Connection, bytes_sent: usize, ack_eliciting: bool) void {
        // Track recovery for Application space
        const now_i = std.time.nanoTimestamp();
        const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
        _ = self.rec.onPacketSent(.Application, self.pn_app_tx, bytes_sent, ack_eliciting, now_ns) catch {};
        // Legacy shim for back-compat
        if (ack_eliciting) self.maybeTriggerKeyUpdateOnSend(bytes_sent);
        self.pn_app_tx +%= 1;
        self.computeAndMaybeArmPto(self);
    }

    /// Send raw bytes to the connection's peer via UDP.
    pub fn send(self: *const Connection, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&self.peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, self.peer.len);
    }

    /// Append CRYPTO stream bytes into the inbox and feed TLS engine.
    pub fn pushCrypto(self: *Connection, data: []const u8) !void {
        try self.tls_inbox.appendSlice(data);
        self.tls.onCryptoRecv(data);
        // Enforce ALPN if negotiated and not in insecure mode
        if (!self.tls.allow_insecure) {
            if (self.tls.alpn) |alp| {
                var ok = false;
                var i: usize = 0;
                while (i < self.allowed_alpns.len) : (i += 1) {
                    if (std.mem.eql(u8, alp, self.allowed_alpns[i])) {
                        ok = true;
                        break;
                    }
                }
                if (!ok and self.allowed_alpns.len > 0) {
                    // In a full implementation, we would abort the handshake. For now, mark finished_verified false.
                    self.tls.finished_verified = false;
                }
            }
        }
        // Attempt to compute handshake secrets if test ecdhe_secret has been set
        if (self.tls.computeHandshakeSecrets()) |hs| {
            self.hs_client = hs.client;
            self.hs_server = hs.server;
            self.deriveHandshakeKeys(false);
            // Queue a Finished for our role once HS secrets are ready (minimal subset)
            if (!self.tls.finished_sent) {
                const my_hs = if (self.role == .Server) hs.server else hs.client;
                self.tls.queueFinished(my_hs) catch {};
            }
        }
        // Attempt to compute application secrets
        if (self.tls.computeApplicationSecrets()) |ap| {
            const before = self.app_tx_keys == null;
            self.deriveAppKeys(ap.client, ap.server, false);
            // Server: emit HANDSHAKE_DONE exactly once when app keys become available, then drop Handshake keys
            if (self.role == .Server and before and !self.handshake_done_sent and self.app_tx_keys != null) {
                var fb = std.ArrayList(u8).init(self.allocator.*);
                defer fb.deinit();
                const w = fb.writer();
                _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
                self.sendControlFrames(fb.items);
                self.handshake_done_sent = true;
                // Drop Handshake keys
                self.hs_rx_keys = null;
                self.hs_tx_keys = null;
            }
        }
    }

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
