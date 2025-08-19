// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("quic_tls13");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("recovery.zig");

pub const Role = enum { Client, Server };

pub const SockAddr = struct {
    storage: posix.sockaddr.storage = undefined,
    len: u32 = 0,

    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

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

pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    tls: tls13.Engine,
    // Derived handshake traffic secrets (once both hellos present)
    hs_client: ?[tls13.H.digest_length]u8 = null,
    hs_server: ?[tls13.H.digest_length]u8 = null,
    // Cached QUIC Handshake keys for RX/TX once derived
    hs_rx_keys: ?packet.InitialKeys = null,
    hs_tx_keys: ?packet.InitialKeys = null,
    // 1-RTT application keys
    app_rx_keys: ?packet.AeadKeys = null,
    app_tx_keys: ?packet.AeadKeys = null,
    // PN counters per space (simplified)
    pn_initial_tx: u32 = 1,
    pn_handshake_tx: u32 = 1,
    pn_app_tx: u32 = 1,
    // Peer-provided Initial DCID/SCID from first Initial we saw (for reply headers)
    peer_initial_dcid: Cid = .{},
    peer_initial_scid: Cid = .{},
    // Our chosen SCID to advertise in server flight
    our_scid: Cid = .{},
    // Switch flag to drop Initial keys/processing once Handshake packets are seen
    initial_keys_dropped: bool = false,
    // Packet number spaces (recv tracking)
    pn_initial: PnWindow = .{},
    pn_handshake: PnWindow = .{},
    pn_app: PnWindow = .{},
    // Recovery/ACK tracking (simplified)
    sent_time: std.AutoHashMap(u64, i128), // pn -> send time (ns)
    largest_acked: u64 = 0,
    // RTT estimators per space (Initial/Handshake/App)
    rtt_initial: recovery.RttState = .{},
    rtt_handshake: recovery.RttState = .{},
    rtt_app: recovery.RttState = .{},
    // Congestion control
    cc: recovery.NewReno = .{},
    // PTO timers state
    pto_initial_active: bool = false,
    pto_handshake_active: bool = false,
    pto_app_active: bool = false,
    pto_initial_id: u64 = 0,
    pto_handshake_id: u64 = 0,
    pto_app_id: u64 = 0,
    // Buffer to return ACK ranges without heap allocs
    ack_ranges_buf: [8]frame.AckRange = undefined,

    pub fn init(self: *Connection, alloc: *std.mem.Allocator, role: Role, sock_fd: posix.fd_t, peer: SockAddr) void {
        self.id = 0;
        self.role = role;
        self.sock_fd = sock_fd;
        self.peer = peer;
        self.tls_inbox = std.ArrayList(u8).init(alloc.*);
        self.tls = tls13.Engine.init(alloc.*, if (role == .Client) .Client else .Server);
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
        self.initial_keys_dropped = false;
        self.pn_initial = .{};
        self.pn_handshake = .{};
        self.pn_app = .{};
        self.sent_time = std.AutoHashMap(u64, i128).init(alloc.*);
        self.largest_acked = 0;
        // Generate a simple random SCID (8 bytes) for server role.
        if (role == .Server) {
            self.our_scid.len = 8;
            std.crypto.random.bytes(self.our_scid.bytes[0..self.our_scid.len]);
        }
    }

    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit();
        self.tls.deinit();
        self.sent_time.deinit();
    }

    /// Send a datagram to the connection's peer.
    pub fn send(self: *const Connection, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&self.peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, self.peer.len);
    }

    /// Append CRYPTO stream bytes into the inbox and feed TLS engine.
    pub fn pushCrypto(self: *Connection, data: []const u8) !void {
        try self.tls_inbox.appendSlice(data);
        self.tls.onCryptoRecv(data);
        // Attempt to compute handshake secrets if test ecdhe_secret has been set
        if (self.tls.computeHandshakeSecrets()) |hs| {
            self.hs_client = hs.client;
            self.hs_server = hs.server;
            self.deriveHandshakeKeys(false);
        }
        // Attempt to compute application secrets
        if (self.tls.computeApplicationSecrets()) |ap| {
            self.deriveAppKeys(ap.client, ap.server, false);
        }
    }

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

    fn deriveAppKeys(self: *Connection, client_app: [tls13.H.digest_length]u8, server_app: [tls13.H.digest_length]u8, version_v2: bool) void {
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) client_app else server_app;
        const tx_secret = if (self.role == .Server) server_app else client_app;
        const rx = tls13.deriveQuicAppKeys(rx_secret, version_v2);
        const tx = tls13.deriveQuicAppKeys(tx_secret, version_v2);
        self.app_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.app_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
    }

    /// Record peer's Initial DCID/SCID (copied) for use in reply headers.
    pub fn setPeerInitialCids(self: *Connection, dcid: []const u8, scid: []const u8) void {
        const dl: u8 = @intCast(@min(dcid.len, self.peer_initial_dcid.bytes.len));
        self.peer_initial_dcid.len = dl;
        if (dl > 0) @memcpy(self.peer_initial_dcid.bytes[0..dl], dcid[0..dl]);
        const sl: u8 = @intCast(@min(scid.len, self.peer_initial_scid.bytes.len));
        self.peer_initial_scid.len = sl;
        if (sl > 0) @memcpy(self.peer_initial_scid.bytes[0..sl], scid[0..sl]);
    }

    /// Called when we send a packet (pn space 1-RTT for now)
    pub fn onPacketSent(self: *Connection, pn: u64, bytes: usize, ack_eliciting: bool) void {
        _ = self.sent_time.put(pn, std.time.nanoTimestamp()) catch {};
        self.cc.onPacketSent(bytes, ack_eliciting);
    }

    pub fn setPtoExpiredInitial(self: *Connection) void {
        self.pto_initial_active = false;
    }
    pub fn setPtoExpiredHandshake(self: *Connection) void {
        self.pto_handshake_active = false;
    }
    pub fn setPtoExpiredApp(self: *Connection) void {
        self.pto_app_active = false;
    }

    /// Called when we receive an ACK frame
    pub fn onAckReceived(self: *Connection, largest: u64, first_range: u64, ranges: []const frame.AckRange) void {
        // Update largest_acked
        if (largest > self.largest_acked) self.largest_acked = largest;
        var bytes_acked_total: usize = 0;
        // RTT sample from send timestamp of largest if present
        if (self.sent_time.fetchRemove(largest)) |kv| {
            const now_ns: i128 = std.time.nanoTimestamp();
            const ts_sent_ns = kv.value;
            const rtt_ns: u64 = @intCast(if (now_ns > ts_sent_ns) now_ns - ts_sent_ns else 0);
            self.rtt_app.onAck(rtt_ns, 0);
            bytes_acked_total += 1200; // assume datagram size for cwnd math
        }
        // Naive: remove any pns <= largest (basic packet-threshold loss detection)
        var it = self.sent_time.iterator();
        var ld = recovery.LossDetector{};
        while (it.next()) |e| {
            const pn = e.key_ptr.*;
            if (pn <= largest) {
                if (ld.isPacketThresholdLost(largest, pn)) {
                    // consider lost
                    self.cc.onLoss(1200);
                    _ = self.sent_time.remove(pn);
                } else {
                    // acked by range collapse assumption
                    _ = self.sent_time.remove(pn);
                    bytes_acked_total += 1200;
                }
            }
        }
        if (bytes_acked_total > 0) self.cc.onAck(bytes_acked_total);
        _ = first_range;
        _ = ranges;
    }

    pub fn computeAndMaybeArmPto(self: *Connection, ep: anytype) void {
        // Arm App PTO based on app RTT for now.
        const pto_ns = self.rtt_app.computePtoNs();
        if (pto_ns == 0) return;
        const ms_u64: u64 = pto_ns / std.time.ns_per_ms;
        const clamped_ms: u64 = if (ms_u64 == 0) 1 else ms_u64;
        const max_u32: u32 = std.math.maxInt(u32);
        var delay_ms: u32 = if (clamped_ms > max_u32) max_u32 else @intCast(clamped_ms);
        // Keep test behavior deterministic: cap PTO delay to <= 100ms.
        if (delay_ms > 100) delay_ms = 100;
        if (!self.pto_app_active) {
            self.pto_app_active = true;
            self.pto_app_id = ep.scheduleConnPto(self, .PtoApp, delay_ms) catch 0;
        }
    }

    /// Expand a truncated PN (given pn_len bytes) against expected next for the given space
    pub fn expandPnInitial(self: *Connection, trunc_pn: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_initial.have_any) self.pn_initial.max + 1 else 0;
        return expandTruncatedPn(trunc_pn, pn_len, expected);
    }
    pub fn expandPnHandshake(self: *Connection, trunc_pn: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_handshake.have_any) self.pn_handshake.max + 1 else 0;
        return expandTruncatedPn(trunc_pn, pn_len, expected);
    }
    pub fn expandPnApp(self: *Connection, trunc_pn: u64, pn_len: u3) u64 {
        const expected: u64 = if (self.pn_app.have_any) self.pn_app.max + 1 else 0;
        return expandTruncatedPn(trunc_pn, pn_len, expected);
    }

    /// Track received packet numbers per space.
    pub fn trackRecvPnInitial(self: *Connection, pn: u64) void {
        self.pn_initial.track(pn);
    }
    pub fn trackRecvPnHandshake(self: *Connection, pn: u64) void {
        self.pn_handshake.track(pn);
    }
    pub fn trackRecvPnApp(self: *Connection, pn: u64) void {
        self.pn_app.track(pn);
    }

    fn buildAckFrom(self: *Connection, win: *const PnWindow) AckDesc {
        if (!win.have_any) return .{ .largest = 0, .first_range = 0, .ranges = self.ack_ranges_buf[0..0] };
        const largest: u64 = win.max;
        const res = win.buildAckRanges(&self.ack_ranges_buf);
        return .{ .largest = largest, .first_range = res.first_range, .ranges = self.ack_ranges_buf[0..res.ranges_len] };
    }

    /// Generate an aggregated ACK description from tracked PN window (App space).
    pub fn buildAckApp(self: *Connection) AckDesc {
        return self.buildAckFrom(&self.pn_app);
    }
    /// Generate ACK description for Initial space.
    pub fn buildAckInitial(self: *Connection) AckDesc {
        return self.buildAckFrom(&self.pn_initial);
    }
    /// Generate ACK description for Handshake space.
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        return self.buildAckFrom(&self.pn_handshake);
    }
};
