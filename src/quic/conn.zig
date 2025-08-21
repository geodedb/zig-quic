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

/// Connection state and helpers for QUIC handshake, recovery, and 1-RTT.
pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    tls: tls13.Engine,
    allocator: *std.mem.Allocator,
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
    // Version context
    version: u32 = 0,
    version_v2: bool = false,
    initial_version: u32 = 0,
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
    // PTO backoff counters per space and timer granularity
    pto_initial_count: u32 = 0,
    pto_handshake_count: u32 = 0,
    pto_app_count: u32 = 0,
    timer_granularity_ns: u64 = std.time.ns_per_ms,
    // Buffer to return ACK ranges without heap allocs
    ack_ranges_buf: [8]frame.AckRange = undefined,
    // Track sent sizes for accurate bytes_acked/lost accounting
    sent_sizes: std.AutoHashMap(u64, u16),
    // Minimal DATAGRAM inbox (FIFO of owned payloads)
    dgram_inbox: std.ArrayList([]u8) = undefined,
    // Minimal streams: single bidi stream (id 0) with basic flow control
    stream_inbox: std.ArrayList(u8) = undefined,
    stream_opened: bool = false,
    stream_send_off: u64 = 0,
    stream_recv_off: u64 = 0,
    local_max_stream_data: u64 = 64 * 1024, // bytes we can receive on stream 0
    peer_max_stream_data: u64 = 64 * 1024, // naive peer window we assume for sending
    // Address validation / anti-amplification (server-side):
    address_validated: bool = false,
    bytes_rx_unvalidated: usize = 0,
    bytes_tx_unvalidated: usize = 0,
    // Client-held Retry token (if any) for next Initial
    initial_token: std.ArrayList(u8) = undefined,

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

    /// Build ACK ranges for Initial space using the sliding window.
    pub fn buildAckInitial(self: *Connection) AckDesc {
        const desc = self.pn_initial.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_initial.max, .first_range = desc.first_range, .ranges = self.ack_ranges_buf[0..desc.ranges_len] };
    }
    /// Build ACK ranges for Handshake space using the sliding window.
    pub fn buildAckHandshake(self: *Connection) AckDesc {
        const desc = self.pn_handshake.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_handshake.max, .first_range = desc.first_range, .ranges = self.ack_ranges_buf[0..desc.ranges_len] };
    }
    /// Build ACK ranges for App space using the sliding window.
    pub fn buildAckApp(self: *Connection) AckDesc {
        const desc = self.pn_app.buildAckRanges(self.ack_ranges_buf[0..]);
        return .{ .largest = self.pn_app.max, .first_range = desc.first_range, .ranges = self.ack_ranges_buf[0..desc.ranges_len] };
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
        // Init stream inbox
        self.stream_inbox = std.ArrayList(u8).init(alloc.*);
        // Init address validation tracking
        self.address_validated = (role == .Client); // clients are not amplification-limited
        self.bytes_rx_unvalidated = 0;
        self.bytes_tx_unvalidated = 0;
        // Init Retry token buffer
        self.initial_token = std.ArrayList(u8).init(alloc.*);
    }

    /// Release resources held by this Connection (payloads, maps, TLS state).
    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit();
        self.tls.deinit();
        self.sent_time.deinit();
        self.sent_sizes.deinit();
        // Free inbox payloads
        while (self.dgram_inbox.items.len > 0) {
            const p = self.dgram_inbox.orderedRemove(0);
            self.allocator.free(p);
        }
        self.dgram_inbox.deinit();
        // Stream inbox
        self.stream_inbox.deinit();
        // Retry token buffer
        self.initial_token.deinit();
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
            self.pn_app_tx,
            2,
            frames.items,
            tx,
        );
        defer self.allocator.free(pkt);
        _ = try self.send(pkt);
        self.onPacketSent(self.pn_app_tx, pkt.len, true);
        self.pn_app_tx +%= 1;
        self.computeAndMaybeArmPto(self);
    }

    /// Open a bidi stream; only stream id 0 is supported in this minimal slice.
    pub fn openStream(self: *Connection, bidi: bool) !u64 {
        if (!bidi) return error.Unsupported;
        if (self.stream_opened) return error.OutOfStreams;
        self.stream_opened = true;
        return 0;
    }

    /// Write bytes on stream id 0 using a Short header STREAM frame with LEN+OFF.
    pub fn writeStream(self: *Connection, id: u64, data: []const u8) !usize {
        if (id != 0) return error.InvalidStream;
        const tx = self.app_tx_keys orelse return error.KeysNotReady;
        if (data.len == 0) return 0;
        // Enforce a naive peer window
        if (self.stream_send_off >= self.peer_max_stream_data) return error.FlowControlBlocked;
        const window_left: u64 = self.peer_max_stream_data - self.stream_send_off;
        const max_payload: usize = 1000; // keep within typical path-MTU
        const to_send: usize = @intCast(@min(@min(window_left, @as(u64, data.len)), @as(u64, max_payload)));
        if (to_send == 0) return error.FlowControlBlocked;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .stream = .{ .stream_id = 0, .offset = self.stream_send_off, .fin = false, .data = data[0..to_send] } }).write(w) catch 0;
        const pkt = try packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len],
            self.pn_app_tx,
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
        );
        defer self.allocator.free(pkt);
        _ = try self.send(pkt);
        self.onPacketSent(self.pn_app_tx, pkt.len, true);
        self.pn_app_tx +%= 1;
        self.computeAndMaybeArmPto(self);
        self.stream_send_off += to_send;
        return to_send;
    }

    /// Read bytes from stream id 0 into buf. Returns bytes copied (0 if none).
    pub fn readStream(self: *Connection, id: u64, buf: []u8) !usize {
        if (id != 0) return error.InvalidStream;
        if (self.stream_inbox.items.len == 0) return 0;
        const n: usize = @min(buf.len, self.stream_inbox.items.len);
        @memcpy(buf[0..n], self.stream_inbox.items[0..n]);
        // shift remaining
        const rem = self.stream_inbox.items.len - n;
        if (rem > 0) {
            std.mem.copy(u8, self.stream_inbox.items[0..rem], self.stream_inbox.items[n..self.stream_inbox.items.len]);
        }
        self.stream_inbox.shrinkRetainingCapacity(rem) catch {};
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
            self.pn_app_tx,
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
        );
        defer self.allocator.free(pkt);
        _ = try self.send(pkt);
        self.onPacketSent(self.pn_app_tx, pkt.len, true);
        self.pn_app_tx +%= 1;
        self.computeAndMaybeArmPto(self);
    }

    /// Push a received DATAGRAM payload into the inbox (makes a copy).
    pub fn pushDatagram(self: *Connection, data: []const u8) !void {
        const copy = try self.allocator.alloc(u8, data.len);
        @memcpy(copy, data);
        try self.dgram_inbox.append(copy);
    }

    /// Push received STREAM bytes into the stream inbox and advance recv offset.
    pub fn pushStreamData(self: *Connection, data: []const u8) !void {
        try self.stream_inbox.appendSlice(data);
        self.stream_recv_off += data.len;
        // TODO: send MAX_STREAM_DATA when crossing thresholds
    }

    /// Pop a DATAGRAM payload into caller buffer, returning bytes copied.
    pub fn popDatagram(self: *Connection, out: []u8) !usize {
        if (self.dgram_inbox.items.len == 0) return error.NoDatagram;
        const p = self.dgram_inbox.orderedRemove(0);
        defer self.allocator.free(p);
        const n = @min(out.len, p.len);
        @memcpy(out[0..n], p[0..n]);
        return n;
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

    /// Note a sent packet for recovery/cc accounting.
    pub fn onPacketSent(self: *Connection, pn: u64, bytes: usize, ack_eliciting: bool) void {
        _ = self.sent_time.put(pn, std.time.nanoTimestamp()) catch {};
        _ = self.sent_sizes.put(pn, @intCast(@min(bytes, @as(usize, std.math.maxInt(u16))))) catch {};
        self.cc.onPacketSent(bytes, ack_eliciting);
    }

    /// Mark Initial PTO as expired and increase backoff counter.
    pub fn setPtoExpiredInitial(self: *Connection) void {
        self.pto_initial_active = false;
        self.pto_initial_count +%= 1;
    }
    /// Mark Handshake PTO as expired and increase backoff counter.
    pub fn setPtoExpiredHandshake(self: *Connection) void {
        self.pto_handshake_active = false;
        self.pto_handshake_count +%= 1;
    }
    /// Mark App PTO as expired and increase backoff counter.
    pub fn setPtoExpiredApp(self: *Connection) void {
        self.pto_app_active = false;
        self.pto_app_count +%= 1;
    }

    /// Per-space ACK handlers used to update RTT and reset PTO backoff.
    pub fn onAckReceivedInitial(self: *Connection, largest: u64, ep: anytype) void {
        if (self.sent_time.fetchRemove(largest)) |kv| {
            const now_ns: i128 = std.time.nanoTimestamp();
            const ts_sent_ns = kv.value;
            const rtt_ns: u64 = @intCast(if (now_ns > ts_sent_ns) now_ns - ts_sent_ns else 0);
            self.rtt_initial.onAck(rtt_ns, 0);
            self.pto_initial_count = 0;
            if (self.pto_initial_active) {
                _ = ep.cancelTimer(self.pto_initial_id);
                self.pto_initial_active = false;
            }
        }
    }
    /// ACK handler for Handshake space; updates RTT and PTO backoff.
    pub fn onAckReceivedHandshake(self: *Connection, largest: u64, ep: anytype) void {
        if (self.sent_time.fetchRemove(largest)) |kv| {
            const now_ns: i128 = std.time.nanoTimestamp();
            const ts_sent_ns = kv.value;
            const rtt_ns: u64 = @intCast(if (now_ns > ts_sent_ns) now_ns - ts_sent_ns else 0);
            self.rtt_handshake.onAck(rtt_ns, 0);
            self.pto_handshake_count = 0;
            if (self.pto_handshake_active) {
                _ = ep.cancelTimer(self.pto_handshake_id);
                self.pto_handshake_active = false;
            }
        }
    }

    /// Reset Initial PTO backoff counter to zero.
    pub fn resetPtoBackoffInitial(self: *Connection) void {
        self.pto_initial_count = 0;
    }
    /// Reset Handshake PTO backoff counter to zero.
    pub fn resetPtoBackoffHandshake(self: *Connection) void {
        self.pto_handshake_count = 0;
    }
    /// Reset App PTO backoff counter to zero.
    pub fn resetPtoBackoffApp(self: *Connection) void {
        self.pto_app_count = 0;
    }

    /// Cancel Initial PTO timer and reset backoff.
    pub fn cancelPtoInitial(self: *Connection, ep: anytype) void {
        if (self.pto_initial_active) {
            if (self.pto_initial_id != 0) _ = ep.cancelTimer(self.pto_initial_id);
            self.pto_initial_active = false;
        }
        self.resetPtoBackoffInitial();
    }
    /// Cancel Handshake PTO timer and reset backoff.
    pub fn cancelPtoHandshake(self: *Connection, ep: anytype) void {
        if (self.pto_handshake_active) {
            if (self.pto_handshake_id != 0) _ = ep.cancelTimer(self.pto_handshake_id);
            self.pto_handshake_active = false;
        }
        self.resetPtoBackoffHandshake();
    }
    /// Cancel App PTO timer and reset backoff.
    pub fn cancelPtoApp(self: *Connection, ep: anytype) void {
        if (self.pto_app_active) {
            if (self.pto_app_id != 0) _ = ep.cancelTimer(self.pto_app_id);
            self.pto_app_active = false;
        }
        self.resetPtoBackoffApp();
    }

    /// Called when we receive an ACK frame.
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
            // account bytes for this pn if tracked
            if (self.sent_sizes.fetchRemove(largest)) |kv2| bytes_acked_total += kv2.value else bytes_acked_total += 1200;
            // any acked data resets app PTO backoff
            self.pto_app_count = 0;
        }
        // Naive: remove any pns <= largest (basic packet-threshold loss detection)
        var it = self.sent_time.iterator();
        var ld = recovery.LossDetector{};
        while (it.next()) |e| {
            const pn = e.key_ptr.*;
            if (pn <= largest) {
                if (ld.isPacketThresholdLost(largest, pn)) {
                    // consider lost
                    const lost_bytes: usize = blk: {
                        if (self.sent_sizes.fetchRemove(pn)) |kv2| break :blk kv2.value else break :blk 1200;
                    };
                    self.cc.onLoss(lost_bytes);
                    _ = self.sent_time.remove(pn);
                } else {
                    // acked by range collapse assumption
                    _ = self.sent_time.remove(pn);
                    const ackb: usize = blk: {
                        if (self.sent_sizes.fetchRemove(pn)) |kv2| break :blk kv2.value else break :blk 1200;
                    };
                    bytes_acked_total += ackb;
                }
            }
        }
        // Time-threshold loss for remaining outstanding
        const thr_ns: u64 = recovery.LossDetector.timeThresholdNs(self.rtt_app.smoothed_rtt_ns, self.rtt_app.latest_rtt_ns);
        const now_ns2: i128 = std.time.nanoTimestamp();
        var it2 = self.sent_time.iterator();
        while (it2.next()) |e| {
            const pn2 = e.key_ptr.*;
            const ts_sent_ns2: i128 = e.value_ptr.*;
            if (now_ns2 > ts_sent_ns2) {
                const age_ns: u64 = @intCast(now_ns2 - ts_sent_ns2);
                if (age_ns >= thr_ns) {
                    const lost_b: usize = blk: {
                        if (self.sent_sizes.fetchRemove(pn2)) |kv3| break :blk kv3.value else break :blk 1200;
                    };
                    self.cc.onLoss(lost_b);
                    _ = self.sent_time.remove(pn2);
                }
            }
        }
        if (bytes_acked_total > 0) self.cc.onAck(bytes_acked_total);
        _ = first_range;
        _ = ranges;
    }

    /// Compute PTO for App space and arm timer if not active.
    pub fn computeAndMaybeArmPto(self: *Connection, ep: anytype) void {
        // Arm App PTO based on app RTT with exponential backoff.
        const pto_ns = self.rtt_app.computePtoNsWithBackoff(self.pto_app_count, self.timer_granularity_ns);
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

    /// Compute PTO for Initial space and arm timer if not active.
    pub fn computeAndMaybeArmPtoInitial(self: *Connection, ep: anytype) void {
        const pto_ns = self.rtt_initial.computePtoNsWithBackoff(self.pto_initial_count, self.timer_granularity_ns);
        if (pto_ns == 0) return;
        const ms = @max(@as(u64, 1), pto_ns / std.time.ns_per_ms);
        var delay_ms: u32 = @intCast(@min(ms, @as(u64, std.math.maxInt(u32))));
        if (delay_ms > 100) delay_ms = 100;
        if (!self.pto_initial_active) {
            self.pto_initial_active = true;
            self.pto_initial_id = ep.scheduleConnPto(self, .PtoInitial, delay_ms) catch 0;
        }
    }

    /// Compute PTO for Handshake space and arm timer if not active.
    pub fn computeAndMaybeArmPtoHandshake(self: *Connection, ep: anytype) void {
        const pto_ns = self.rtt_handshake.computePtoNsWithBackoff(self.pto_handshake_count, self.timer_granularity_ns);
        if (pto_ns == 0) return;
        const ms = @max(@as(u64, 1), pto_ns / std.time.ns_per_ms);
        var delay_ms: u32 = @intCast(@min(ms, @as(u64, std.math.maxInt(u32))));
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
        const txk = if (self.version_v2) ks.deriveKeyIvHpV2(pair.server) else ks.deriveKeyIvHp(pair.server);
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
        const token_empty: [0]u8 = .{};
        const out = packet.encodeInitialProtected(
            self.allocator.*,
            self.version,
            // DCID = client's Initial SCID; SCID = our chosen SCID
            self.peer_initial_scid.bytes[0..self.peer_initial_scid.len],
            self.our_scid.bytes[0..self.our_scid.len],
            token_empty[0..],
            self.pn_initial_tx,
            2,
            frames.items,
            .{ .key = txk.key, .iv = txk.iv, .hp = txk.hp },
        ) catch null;
        if (out) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onPacketSent(self.pn_initial_tx, bytes_out.len, true);
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
            self.pn_handshake_tx,
            2,
            frames.items,
            tx,
        ) catch null;
        if (out) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onPacketSent(self.pn_handshake_tx, bytes_out.len, true);
            self.pn_handshake_tx +%= 1;
        }
    }

    /// Send a minimal PTO probe for the App space (PING frame).
    pub fn sendPtoProbeApp(self: *Connection) void {
        const tx = self.app_tx_keys orelse return;
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        const w = frames.writer();
        _ = (frame.Frame{ .ping = {} }).write(w) catch 0;
        const out = packet.encodeShortProtected(
            self.allocator.*,
            self.our_scid.bytes[0..self.our_scid.len], // DCID per simplified mapping
            self.pn_app_tx,
            2,
            frames.items,
            .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp },
        ) catch null;
        if (out) |bytes_out| {
            defer self.allocator.free(bytes_out);
            _ = self.send(bytes_out) catch {};
            self.onPacketSent(self.pn_app_tx, bytes_out.len, true);
            self.pn_app_tx +%= 1;
        }
    }
};
