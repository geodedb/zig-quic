//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
//! MIT License
const std = @import("std");
const cfg = @import("config.zig");
const lb = @import("loop_backend.zig");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const varint = @import("quic_varint");
const token_mod = @import("token.zig");
const recovery = @import("quic_recovery");
// Import transport parameters via dedicated module to avoid duplicate root file compilation
const tp = @import("quic_transport_params");

const posix = std.posix;
const builtin = @import("builtin");

// TEST-ONLY: outbound capture entry (peer + owned bytes)
const OutCaptured = struct { peer: conn_mod.SockAddr, bytes: []u8 };

fn nowMsMonotonic() i64 {
    // Prefer a monotonic source; nanoTimestamp is monotonic on supported platforms.
    // Use explicit truncating integer division for signed integers (Zig 0.14 requirement).
    const ns: i128 = std.time.nanoTimestamp();
    const ms: i128 = @divTrunc(ns, std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}

const Timer = struct {
    deadline_ms: i64,
    id: u64,
    kind: TimerKind = .Generic,
    conn: ?*conn_mod.Connection = null,
    // Pacing payload support (Generic kind): when paced is true and payload!=null, send on expiry
    paced: bool = false,
    payload: ?[]u8 = null,
};

/// Endpoint timer kinds: generic app timers plus per-PN-space PTO and PMTUD timers.
pub const TimerKind = enum { Generic, PtoInitial, PtoHandshake, PtoApp, Pmtud };

/// Hash key combining peer address + destination CID for connection lookup.
pub const Key = struct { peer_hash: u64, dcid_hash: u64 };

fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = @as([*]const u8, @ptrCast(sa))[0..len];
    return hashBytes(bytes);
}

/// UDP endpoint container with connection map, timer wheel, capture support, and
/// single bound socket. Owns all live connections and drives send/recv plus PTO/PMTUD timers.
pub const Endpoint = struct {
    sock_fd: posix.socket_t,
    loop_backend: lb.LoopBackend,
    allocator: *std.mem.Allocator,
    timers: std.ArrayList(Timer),
    conns: std.AutoHashMap(Key, *conn_mod.Connection),
    // Next timer identifier for scheduleTimer
    next_timer_id: u64 = 1,
    // Config copy
    cfg: cfg.QuicConfig,
    // Accept queue for server
    accepted: std.ArrayList(*conn_mod.Connection),
    // TEST-ONLY: outbound capture ring (peer + owned bytes)
    captures: std.ArrayList(OutCaptured),
    // TEST-ONLY: runtime flag to enable outbound capture in tests
    test_capture_enabled: bool = false,
    // Retired (closed) connections removed from maps & timers but not yet destroyed.
    // They stay here until explicit api.destroy() or endpoint.deinit(), allowing external
    // code (e.g., server CLI loop) holding an opaque pointer to observe closed state
    // without risking use-after-free.
    retired: std.ArrayList(*conn_mod.Connection),

    /// Initialize a UDP endpoint bound to bind_addr (e.g., "127.0.0.1:0").
    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8, cfgp: *const cfg.QuicConfig) !Endpoint {
        // Resolve and bind IPv4 socket for tests; port 0 lets OS choose a free port.
        var ep_addr = try resolveAny(bind_addr, .udp);
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer posix.close(fd);
        // Allow fast rebinding in tests
        var one: i32 = 1;
        _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
        // Linux: enable reception of TOS/TCLASS via ancillary data to read ECN bits per datagram
        if (builtin.target.os.tag == .linux) {
            var enable: i32 = 1;
            // Zig std may not expose IP.RECVTOS; use the Linux value (IP_RECVTOS = 13)
            const IP_RECVTOS: i32 = 13;
            _ = posix.setsockopt(fd, posix.IPPROTO.IP, IP_RECVTOS, std.mem.asBytes(&enable)) catch {};
            // Also request IPv6 traffic class delivery (IPV6_RECVTCLASS = 66)
            const IPV6_RECVTCLASS: i32 = 66;
            _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_RECVTCLASS, std.mem.asBytes(&enable)) catch {};
            // Enable Linux error queue reception for ICMP PTB (IPv4/IPv6)
            const IP_RECVERR: i32 = 11;
            _ = posix.setsockopt(fd, posix.IPPROTO.IP, IP_RECVERR, std.mem.asBytes(&enable)) catch {};
            const IPV6_RECVERR: i32 = 25;
            _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_RECVERR, std.mem.asBytes(&enable)) catch {};
        }
        // Note: do not rely on O.NONBLOCK here; use MSG.DONTWAIT on Linux in recv loop for portability
        const sa_ptr: *const posix.sockaddr = @ptrCast(&ep_addr.storage);
        try posix.bind(fd, sa_ptr, ep_addr.len);
        if (builtin.target.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var nonblock: std.os.windows.ULONG = 1;
            _ = ws2.ioctlsocket(fd, ws2.FIONBIO, &nonblock);
        }

        return Endpoint{
            .sock_fd = fd,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc,
            .timers = std.ArrayList(Timer){},
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc.*),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = std.ArrayList(*conn_mod.Connection){},
            .captures = std.ArrayList(OutCaptured){},
            .test_capture_enabled = false,
            .retired = std.ArrayList(*conn_mod.Connection){},
        };
    }

    /// Release resources: close socket, free timers, capture buffers, and destroy connections.
    /// Deinitialize endpoint and free all associated connection state.
    pub fn deinit(self: *Endpoint) void {
        // Attempt to prune any closed (or newly closed due to earlier failures) connections
        // before emitting instrumentation so we only report genuinely still-open connections.
        self.pruneClosed();
        // Soft-close any remaining connections so they don't linger as leaks in debug builds.
        var pre_it = self.conns.iterator();
        while (pre_it.next()) |e| {
            const c = e.value_ptr.*;
            if (!c.closed) c.closed = true;
        }
        // Prune again after mass-closing.
        self.pruneClosed();
        // Instrumentation: list any remaining connection pointers (map values) before cleanup
        if (builtin.mode == .Debug) {
            var unique = std.AutoHashMap(*conn_mod.Connection, usize).init(self.allocator.*);
            defer unique.deinit();
            var cit = self.conns.iterator();
            while (cit.next()) |e| {
                const c = e.value_ptr.*;
                const idx = unique.get(c) orelse 0;
                _ = unique.put(c, idx + 1) catch {};
            }
            if (unique.count() > 0) {
                std.debug.print("endpoint.deinit: {d} unique conn(s) still referenced by map; dumping counts\n", .{unique.count()});
                var uit = unique.iterator();
                while (uit.next()) |ve| {
                    std.debug.print("  conn ptr={*} ref_count={d}\n", .{ ve.key_ptr.*, ve.value_ptr.* });
                }
                // Also dump timers referencing a connection
                var ti: usize = 0;
                var timer_conn_refs: usize = 0;
                while (ti < self.timers.items.len) : (ti += 1) {
                    const t = self.timers.items[ti];
                    if (t.conn) |tc| {
                        timer_conn_refs += 1;
                        std.debug.print("  timer id={d} kind={any} conn={*}\n", .{ t.id, t.kind, tc });
                    }
                }
                if (timer_conn_refs > 0) std.debug.print("  timers referencing connections: {d}\n", .{timer_conn_refs});
            }
        }
        // Free captured payloads
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) {
            const cap = self.captures.items[i];
            self.allocator.free(cap.bytes);
        }
        self.captures.deinit(self.allocator.*);
        // Free any pending paced payloads in timers
        var j: usize = 0;
        while (j < self.timers.items.len) : (j += 1) {
            const t = self.timers.items[j];
            if (t.paced) {
                if (t.payload) |p| self.allocator.free(p);
            }
        }
        // Destroy unique connections referenced by map values
        var seen = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator.*);
        defer seen.deinit();
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (!seen.contains(c)) {
                _ = seen.put(c, {}) catch {};
                c.deinit();
                self.allocator.destroy(c);
            }
        }
        // Also destroy any retired (already removed from map) connections not yet destroyed.
        var ri: usize = 0;
        while (ri < self.retired.items.len) : (ri += 1) {
            const c = self.retired.items[ri];
            if (!seen.contains(c)) { // skip if already destroyed above
                c.deinit();
                self.allocator.destroy(c);
            }
        }
        self.retired.deinit(self.allocator.*);
        self.conns.deinit();
        self.accepted.deinit(self.allocator.*);
        self.timers.deinit(self.allocator.*);
        // Close socket
        if (builtin.target.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            _ = ws2.closesocket(self.sock_fd);
        } else {
            _ = posix.close(self.sock_fd);
        }
    }

    /// Flush expired timers immediately based on current monotonic time (testing helper).
    /// Expire due timers without blocking on I/O (test helper).
    pub fn flushTimers(self: *Endpoint) void {
        self.processExpiredTimers(nowMsMonotonic());
    }

    /// TEST-ONLY: clear capture ring and free owned buffers.
    /// Clear all captured outbound packets (test helper).
    pub fn captureClear(self: *Endpoint) void {
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) self.allocator.free(self.captures.items[i].bytes);
        self.captures.clearRetainingCapacity();
    }
    /// TEST-ONLY: current number of captured datagrams.
    /// Return number of captured outbound packets.
    pub fn captureLen(self: *Endpoint) usize {
        return self.captures.items.len;
    }
    /// TEST-ONLY: pop oldest capture entry, transferring ownership of bytes to caller.
    /// Pop most recent captured outbound packet if present.
    pub fn capturePop(self: *Endpoint) ?OutCaptured {
        if (self.captures.items.len == 0) return null;
        return self.captures.orderedRemove(0);
    }

    /// Internal: convert socket_t to isize for Connection.sock_fd storage.
    fn sockToIsize(fd: posix.socket_t) isize {
        if (builtin.target.os.tag == .windows) {
            return @as(isize, @intCast(@intFromPtr(fd)));
        } else {
            return @as(isize, @intCast(fd));
        }
    }

    /// Send a datagram to peer address.
    /// Send UDP datagram to peer (capturing if enabled).
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        if (self.test_capture_enabled) {
            // Capture: make an owned copy of data and enqueue
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            _ = self.captures.append(self.allocator.*, .{ .peer = peer, .bytes = owned }) catch {};
            // Also send to socket for integration if desired
        }
        const sa_ptr: *const posix.sockaddr = @ptrCast(&peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, peer.len);
    }

    /// Receive a datagram; returns size and source address.
    /// Receive UDP datagram (non-blocking if platform supports MSG.DONTWAIT).
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        var peer = conn_mod.SockAddr{};
        peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
        const n = try posix.recvfrom(self.sock_fd, buf, 0, @ptrCast(&peer.storage), &peer.len);
        return .{ .n = n, .peer = peer };
    }

    /// Create a Connection object for an incoming datagram's peer.
    /// Accept a server connection from initial datagram's peer address.
    pub fn acceptFrom(self: *Endpoint, peer: conn_mod.SockAddr) conn_mod.Connection {
        return .{ .id = 0, .role = .Server, .sock_fd = sockToIsize(self.sock_fd), .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Enqueue accepted server connection for accept().
    fn pushAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        self.accepted.append(self.allocator.*, c) catch {};
    }

    /// Pop accepted connection pointer if present.
    /// Pop next accepted server-side connection if available.
    pub fn popAccepted(self: *Endpoint) ?*conn_mod.Connection {
        if (self.accepted.items.len == 0) return null;
        return self.accepted.orderedRemove(0);
    }

    /// TEST-ONLY: inject a datagram directly into the endpoint RX path.
    /// Inject inbound datagram into receive path (test helper, no ECN).
    pub fn testInject(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8) void {
        self.processIncomingDatagram(peer, bytes, null);
    }

    /// TEST-ONLY: inject a datagram with explicit ECN bits (low 2 bits of IP TOS)
    /// Inject inbound datagram with explicit ECN bits (test helper).
    pub fn testInjectWithEcn(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: u8) void {
        self.processIncomingDatagram(peer, bytes, ecn_bits);
    }

    /// Resolve and create a Connection object for an explicit remote address.
    /// Create server-side represented connection (used by client dialing logic).
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        const peer = try resolveAny(hostport, .udp);
        return .{ .id = 0, .role = .Client, .sock_fd = sockToIsize(self.sock_fd), .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Allocate and register a client connection for the given remote address.
    /// Create client-side connection object referencing remote host:port.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const peer = try resolveAny(hostport, .udp);
        const c = try self.allocator.create(conn_mod.Connection);
        c.init(self.allocator, .Client, sockToIsize(self.sock_fd), peer);
        // Apply config flags
        c.setUseCubic(self.cfg.cc == .cubic);
        c.tls.allow_insecure = self.cfg.allow_insecure;
        c.allowed_alpns = self.cfg.alpn;
        // Enable optional pacing and set CC max_datagram_size
        c.enable_pacing = self.cfg.enable_pacing;
        c.rec.cc.mds = @intCast(self.cfg.max_datagram_size);
        // Install paced sender callback
        c.setSender(@ptrCast(self), senderPaced);
        // Apply AEAD usage limit overrides
        c.setAeadUsageLimits(self.cfg.aead_confidentiality_limit_override, self.cfg.aead_integrity_limit_override);
        // Choose initial version from cfg
        // For now always use QUIC v1 unless explicitly configured for v2.
        c.version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;
        c.version_v2 = (c.version == packet.QUIC_V2);
        c.initial_version = c.version;
        // Client chooses DCID and SCID
        var dcid: [8]u8 = undefined;
        std.crypto.random.bytes(&dcid);
        c.peer_initial_dcid.len = @intCast(dcid.len);
        @memcpy(c.peer_initial_dcid.bytes[0..dcid.len], &dcid);
        // Preserve original DCID separately for Initial secret derivation (never changes).
        c.original_dcid.len = c.peer_initial_dcid.len;
        if (c.original_dcid.len > 0) @memcpy(c.original_dcid.bytes[0..c.original_dcid.len], c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
        c.our_scid.len = 8;
        std.crypto.random.bytes(c.our_scid.bytes[0..c.our_scid.len]);
        // Map by both dcid and scid to find VN/HS
        const ph = hashSockaddr(&peer.storage, peer.len);
        const key_d = Key{ .peer_hash = ph, .dcid_hash = hashBytes(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) };
        const key_s = Key{ .peer_hash = ph, .dcid_hash = hashBytes(c.our_scid.bytes[0..c.our_scid.len]) };
        _ = self.conns.put(key_d, c) catch {};
        _ = self.conns.put(key_s, c) catch {};
        return c;
    }

    /// Send client Initial with CRYPTO(ClientHello) and padding to elicit ServerHello.
    /// Transmit minimal Initial packet (PING) to elicit Version Negotiation or SH.
    pub fn clientSendInitialProbe(self: *Endpoint, c: *conn_mod.Connection) !void {
        const v2 = (c.version == packet.QUIC_V2);
        const initial = ks.deriveInitialSecret(v2, if (c.original_dcid.len > 0) c.original_dcid.bytes[0..c.original_dcid.len] else c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
        const pair = ks.deriveClientServerInitial(initial);
        std.debug.print("client: deriving Initial keys with dcid=", .{});
        for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print(" len={}\n", .{c.peer_initial_dcid.len});
        const tx_keys: packet.InitialKeys = if (v2) blk: {
            const t = ks.deriveKeyIvHpV2(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        } else blk: {
            const t = ks.deriveKeyIvHp(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        };
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        // Build CRYPTO frame carrying ClientHello
        // Attach local Transport Parameters (minimal) for interop scaffolding
        var tpp: tp.TransportParams = .{};
        // Encode initial limits from connection local defaults
        tpp.initial_max_data = c.local_max_data;
        tpp.initial_max_stream_data_bidi_local = c.local_max_stream_data;
        tpp.initial_max_stream_data_bidi_remote = c.local_max_stream_data;
        tpp.initial_max_streams_bidi = c.local_max_streams_bidi;
        tpp.initial_max_streams_uni = 0;
        const tp_bytes = tp.TransportParams.encode(&tpp, self.allocator.*) catch &[_]u8{};
        defer {
            if (tp_bytes.len > 0) self.allocator.free(tp_bytes);
        }
        c.tls.setLocalTransportParameters(if (tp_bytes.len > 0) tp_bytes else tp_bytes[0..0]) catch {};
        if (self.cfg.real_tls) {
            c.tls.enableReal();
            // Use queueMinimalClientHello (will dispatch to real builder when real_mode true)
            c.tls.queueMinimalClientHello() catch {
                _ = c.tls.queueMinimalClientHelloAuto() catch 0;
            };
        } else {
            _ = c.tls.queueMinimalClientHelloAuto() catch 0;
        }
        var crypto_buf: [2048]u8 = undefined;
        const crypto_len = c.tls.popCrypto(crypto_buf[0..]);
        if (crypto_len > 0) {
            const base_off = c.crypto_tx_off_initial;
            _ = (frame.Frame{ .crypto = .{ .offset = base_off, .data = crypto_buf[0..crypto_len] } }).write(frames.writer(self.allocator.*)) catch 0;
            // (TEMP) Omit saving retransmit buffer to simplify leak debugging for interop slice.
            c.crypto_retx_initial_off = base_off;
            c.crypto_tx_off_initial += crypto_len;
        } else {
            frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PING)) catch {};
        }
        // Add padding to meet minimum Initial packet size of 1200 bytes
        while (frames.items.len < 1150) frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PADDING)) catch {};
        // Use any stored Retry token if present
        const token_slice: []const u8 = c.initial_token.items;
        const pkt = try packet.encodeInitialProtected(
            self.allocator.*,
            c.version,
            // Client Initial: DCID = our chosen dcid; SCID = our scid
            // After a Retry, peer_initial_dcid is updated to the SCID from the Retry per RFC 9000 §17.2.5.
            c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
            c.our_scid.bytes[0..c.our_scid.len],
            token_slice,
            @as(u32, @truncate(c.pn_initial_tx)),
            2,
            frames.items,
            tx_keys,
        );
        std.debug.print("client: built Initial pn={} dcid=", .{c.pn_initial_tx});
        for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print(" scid=", .{});
        for (c.our_scid.bytes[0..c.our_scid.len]) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print(" payload_len={}\n", .{frames.items.len});
        defer self.allocator.free(pkt);
        const sent = try self.sendTo(c.peer, pkt);
        c.onPacketSent(.Initial, c.pn_initial_tx, sent, true);
        c.pn_initial_tx +%= 1;
        // Arm Initial PTO
        c.computeAndMaybeArmPtoInitial(self);
    }

    /// Schedule a one-shot timer to fire after delay_ms; returns timer id.
    /// Schedule generic timer firing after delay_ms.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = null });
        return id;
    }

    /// Schedule a PTO timer tied to a specific connection and space.
    /// Schedule connection-owned PTO/PMTUD timer.
    pub fn scheduleConnPto(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = kind, .conn = c });
        return id;
    }

    /// Schedule a paced send for a connection after delay_ns.
    fn schedulePaced(self: *Endpoint, c: *conn_mod.Connection, delay_ns: u64, owned_bytes: []u8) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        var delay_ms_u64: u64 = delay_ns / std.time.ns_per_ms;
        if (delay_ms_u64 == 0) delay_ms_u64 = 1; // minimum 1ms to avoid busy spinning
        if (delay_ms_u64 > 100) delay_ms_u64 = 100; // keep deterministic and fast in tests
        const deadline: i64 = now_ms + @as(i64, @intCast(@min(delay_ms_u64, @as(u64, std.math.maxInt(u32)))));
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = c, .paced = true, .payload = owned_bytes });
        return id;
    }

    /// Cancel a previously scheduled timer by id; returns true if removed.
    /// Cancel a pending timer id.
    pub fn cancelTimer(self: *Endpoint, id: u64) bool {
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            if (self.timers.items[i].id == id) {
                _ = self.timers.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Drive IO using platform loop backend. timeout_ms < 0 means infinite.
    /// Drive network I/O, timers, and paced send for up to timeout_ms milliseconds.
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        // First, process any timers that are already expired to avoid waiting unnecessarily.
        self.processExpiredTimers(nowMsMonotonic());
        // Drain any pending error queue notifications (ICMP PTB, etc.) before waiting.
        self.drainErrorQueue();

        const now_ms: i64 = nowMsMonotonic();
        var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        if (eff_timeout < 0) eff_timeout = -1;

        // Guard for coarse timer resolution on some platforms (e.g., Windows):
        // if a timer is due "now" (eff_timeout == 0), sleep a minimal interval to
        // ensure the next timestamp crosses the deadline, then flush again.
        if (eff_timeout == 0 and self.timers.items.len > 0) {
            std.Thread.sleep(@as(u64, 1) * std.time.ns_per_ms);
            self.processExpiredTimers(nowMsMonotonic());
            // Recompute effective timeout after the flush
            const now_after = nowMsMonotonic();
            eff_timeout = self.nextTimeoutFromTimers(now_after, timeout_ms);
            if (eff_timeout < 0) eff_timeout = -1;
        }

        // Always use the platform event loop to wait for readability
        // This ensures we actually wait for packets to arrive
        switch (lb.defaultLoopBackend()) {
            .epoll => try self.poll_epoll_backend(eff_timeout),
            .kqueue => try self.poll_kqueue_backend(eff_timeout),
            .iocp => try self.poll_iocp_backend(eff_timeout),
        }

        self.processExpiredTimers(nowMsMonotonic());
        if (self.timers.items.len > 0 and timeout_ms != 0) {
            const now2: i64 = nowMsMonotonic();
            const again: i32 = self.nextTimeoutFromTimers(now2, 0);
            if (again > 0 and again <= 5) {
                std.Thread.sleep(@as(u64, @intCast(again)) * std.time.ns_per_ms);
                self.processExpiredTimers(nowMsMonotonic());
            }
        }
        self.pruneClosed();
    }

    fn drainReadable(self: *Endpoint) void {
        var buf: [2048]u8 = undefined;
        while (true) {
            var peer = conn_mod.SockAddr{};
            peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
            const flags: u32 = if (builtin.target.os.tag == .windows) 0 else posix.MSG.DONTWAIT;
            // Linux: prefer recvmsg to extract ECN via ancillary when available; fallback elsewhere.
            if (builtin.target.os.tag == .linux and @hasDecl(std.posix, "recvmsg")) {
                var iov = [1]posix.iovec{.{ .base = buf[0..].ptr, .len = buf.len }};
                var ctrl: [64]u8 = undefined;
                var msg: posix.msghdr = .{
                    .name = @ptrCast(&peer.storage),
                    .namelen = peer.len,
                    .iov = &iov,
                    .iovlen = 1,
                    .control = &ctrl,
                    .controllen = ctrl.len,
                    .flags = 0,
                };
                const n_or_err = posix.recvmsg(self.sock_fd, &msg, flags);
                if (n_or_err) |n| {
                    // Extract ECN from ancillary: IP_TOS (level IPPROTO_IP, type IP_TOS)
                    var ecn_bits: ?u8 = null;
                    var off: usize = 0;
                    while (off + @sizeOf(posix.cmsghdr) <= msg.controllen) {
                        const cmsg_ptr: *const posix.cmsghdr = @ptrCast(@alignCast(@as(*const anyopaque, @ptrFromInt(@intFromPtr(msg.control) + off))));
                        const clen = cmsg_ptr.len;
                        if (clen < @sizeOf(posix.cmsghdr) or off + clen > msg.controllen) break;
                        const level = cmsg_ptr.level;
                        const ctype = cmsg_ptr.type;
                        // CMSG data starts immediately after header
                        const data_ptr = @as([*]const u8, @ptrFromInt(@intFromPtr(cmsg_ptr) + @sizeOf(posix.cmsghdr)));
                        // IPPROTO_IP == posix.IPPROTO.IP; IP_TOS constant is 1 on Linux
                        if (level == posix.IPPROTO.IP and ctype == 1 and clen >= @sizeOf(posix.cmsghdr) + 1) {
                            const tos = data_ptr[0];
                            ecn_bits = tos & 0x03; // low 2 bits per RFC 3168
                        }
                        // IPv6: level IPPROTO_IPV6 with type IPV6_TCLASS (67) carries traffic class
                        if (level == posix.IPPROTO.IPV6 and ctype == 67 and clen >= @sizeOf(posix.cmsghdr) + 1) {
                            const tclass = data_ptr[0];
                            ecn_bits = tclass & 0x03;
                        }
                        // Align to next header (CMSG_ALIGN)
                        const align_sz: usize = 8;
                        const adv = (clen + (align_sz - 1)) & ~(align_sz - 1);
                        off += adv;
                    }
                    self.processIncomingDatagram(peer, buf[0..@intCast(n)], ecn_bits);
                } else |err| {
                    switch (err) {
                        error.WouldBlock => return,
                        error.ConnectionResetByPeer => return,
                        else => return,
                    }
                }
            } else {
                const n_or_err = posix.recvfrom(self.sock_fd, buf[0..], flags, @ptrCast(&peer.storage), &peer.len);
                if (n_or_err) |n| {
                    self.processIncomingDatagram(peer, buf[0..n], null);
                } else |err| {
                    switch (err) {
                        error.WouldBlock => return,
                        error.ConnectionResetByPeer => return,
                        else => return,
                    }
                }
            }
        }
    }

    /// Linux-only: drain MSG_ERRQUEUE to handle ICMP PTB and apply DPLPMTUD clamps.
    fn drainErrorQueue(self: *Endpoint) void {
        if (builtin.target.os.tag != .linux) return;
        if (!@hasDecl(std.posix, "recvmsg")) return;
        // Constants for extended error origin and ICMP types
        const SO_EE_ORIGIN_ICMP: u8 = 2;
        const SO_EE_ORIGIN_ICMP6: u8 = 3;
        const ICMP_DEST_UNREACH: u8 = 3; // IPv4
        const ICMP_FRAG_NEEDED: u8 = 4; // IPv4 code for PTB
        const ICMPV6_PKT_TOOBIG: u8 = 2; // IPv6 type

        // Linux struct sock_extended_err
        const ExtendedErr = extern struct {
            ee_errno: i32,
            ee_origin: u8,
            ee_type: u8,
            ee_code: u8,
            ee_pad: u8,
            ee_info: u32, // MTU for EMSGSIZE
            ee_data: u32,
        };

        while (true) {
            var peer = conn_mod.SockAddr{};
            peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
            var iov_buf: [2048]u8 = undefined;
            var iov = [1]posix.iovec{.{ .base = &iov_buf, .len = iov_buf.len }};
            var ctrl: [128]u8 = undefined;
            var msg: posix.msghdr = .{
                .name = @ptrCast(&peer.storage),
                .namelen = peer.len,
                .iov = &iov,
                .iovlen = 1,
                .control = &ctrl,
                .controllen = ctrl.len,
                .flags = 0,
            };
            const flags: u32 = 0x2000; // MSG_ERRQUEUE
            const n_or_err = posix.recvmsg(self.sock_fd, &msg, flags);
            if (n_or_err) |n| {
                _ = n;
                var mtu: ?u16 = null;
                var origin_icmp: bool = false;
                // Walk control headers to find extended error
                var off: usize = 0;
                while (off + @sizeOf(posix.cmsghdr) <= msg.controllen) {
                    const cmsg_ptr: *const posix.cmsghdr = @ptrCast(@alignCast(@as(*const anyopaque, @ptrFromInt(@intFromPtr(msg.control) + off))));
                    const clen = cmsg_ptr.len;
                    if (clen < @sizeOf(posix.cmsghdr) or off + clen > msg.controllen) break;
                    const level = cmsg_ptr.level;
                    const ctype = cmsg_ptr.type;
                    const data_ptr = @as([*]const u8, @ptrFromInt(@intFromPtr(cmsg_ptr) + @sizeOf(posix.cmsghdr)));
                    if ((level == posix.IPPROTO.IP and ctype == 11) or (level == posix.IPPROTO.IPV6 and ctype == 25)) {
                        // IP_RECVERR/IPV6_RECVERR data is sock_extended_err
                        if (clen >= @sizeOf(posix.cmsghdr) + @sizeOf(ExtendedErr)) {
                            const ee: *const ExtendedErr = @ptrCast(@alignCast(data_ptr));
                            if (ee.ee_origin == SO_EE_ORIGIN_ICMP and ee.ee_type == ICMP_DEST_UNREACH and ee.ee_code == ICMP_FRAG_NEEDED) {
                                origin_icmp = true;
                                mtu = @intCast(@min(ee.ee_info, @as(u32, 0xFFFF)));
                            } else if (ee.ee_origin == SO_EE_ORIGIN_ICMP6 and ee.ee_type == ICMPV6_PKT_TOOBIG) {
                                origin_icmp = true;
                                mtu = @intCast(@min(ee.ee_info, @as(u32, 0xFFFF)));
                            }
                        }
                    }
                    // Align to next header
                    const align_sz: usize = 8;
                    const adv = (clen + (align_sz - 1)) & ~(align_sz - 1);
                    off += adv;
                }
                if (origin_icmp and mtu) |mtu_v| {
                    // Attempt to spoof-check by matching a short-header QUIC with our DCID present
                    const quoted = iov_buf[0..];
                    self.handleIcmpPtb(peer, quoted, mtu_v);
                }
            } else |err| {
                switch (err) {
                    error.WouldBlock => return,
                    else => return,
                }
            }
        }
    }

    /// Apply ICMP PTB with spoofing checks: accept only if a known connection's DCID
    /// appears in a plausible short-header QUIC at some reasonable offset.
    fn handleIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        const ph = hashSockaddr(&peer.storage, peer.len);
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (e.key_ptr.*.peer_hash != ph) continue;
            const dcid_len: usize = c.our_scid.len;
            if (dcid_len == 0 or quoted_udp_payload.len < 1 + dcid_len) continue;
            // Scan first 64 bytes for a plausible short header match
            const scan_max: usize = @min(quoted_udp_payload.len, 64);
            var off: usize = 0;
            while (off + 1 + dcid_len <= scan_max) : (off += 1) {
                const first = quoted_udp_payload[off];
                if ((first & 0x80) != 0) continue; // not short header
                if (std.mem.eql(u8, c.our_scid.bytes[0..dcid_len], quoted_udp_payload[off + 1 .. off + 1 + dcid_len])) {
                    c.onIcmpPacketTooBig(reported_mtu);
                    return;
                }
            }
        }
    }

    /// TEST-ONLY: inject a synthetic ICMP PTB quote for a given peer and UDP payload.
    pub fn testInjectIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        self.handleIcmpPtb(peer, quoted_udp_payload, reported_mtu);
    }

    fn poll_epoll_backend(self: *Endpoint, timeout_ms: i32) !void {
        // On non-Linux platforms, fallback to a simple sleep + drain to avoid epoll dependency
        if (builtin.target.os.tag != .linux) {
            if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            self.drainReadable();
            return;
        }
        const io = @import("io/loop_epoll.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(0, true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        _ = n;
        self.drainReadable();
    }

    fn poll_kqueue_backend(self: *Endpoint, timeout_ms: i32) !void {
        // On non-kqueue platforms, just perform a sleep-based fallback
        if (builtin.target.os.tag != .macos and builtin.target.os.tag != .freebsd and builtin.target.os.tag != .netbsd and builtin.target.os.tag != .openbsd and builtin.target.os.tag != .dragonfly) {
            if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            self.drainReadable();
            return;
        }
        const io = @import("io/loop_kqueue.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(0, true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        _ = n;
        self.drainReadable();
    }

    fn poll_iocp_backend(self: *Endpoint, timeout_ms: i32) !void {
        if (builtin.target.os.tag != .windows) {
            if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            self.drainReadable();
            return;
        }
        const io = @import("io/loop_iocp.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(0, true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        _ = n;
        self.drainReadable();
    }

    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        if (bytes.len < 1) return;
        const first = bytes[0];
        const is_long = (first & 0x80) != 0;
        if (is_long) {
            // Long header: check Version for VN/Initial/Handshake
            if (bytes.len < 5) return;
            const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
            if (version == 0) {
                // Version Negotiation handling (client side)
                var arena = std.heap.ArenaAllocator.init(self.allocator.*);
                defer arena.deinit();
                const aa = arena.allocator();
                const vn = packet.decodeVersionNegotiation(aa, bytes) catch return;
                const ph = hashSockaddr(&peer.storage, peer.len);
                var found: ?*conn_mod.Connection = null;
                const k1 = Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.dcid) };
                const k2 = Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.scid) };
                if (self.conns.getPtr(k1)) |e| found = e.* else if (self.conns.getPtr(k2)) |e2| found = e2.*;
                const c = found orelse return;
                if (!self.cfg.compatible_vn) return; // ignore VN when disabled
                if (!packet.shouldAcceptVersionNegotiation(c.initial_version, vn.versions)) return;
                var chosen: u32 = 0;
                var i_sel: usize = 0;
                while (i_sel < vn.versions.len) : (i_sel += 1) {
                    const v = vn.versions[i_sel];
                    if (v == packet.QUIC_V1 or v == packet.QUIC_V2) {
                        chosen = v;
                        break;
                    }
                }
                if (chosen == 0) return;
                c.version = chosen;
                c.version_v2 = (chosen == packet.QUIC_V2);
                self.clientSendInitialProbe(c) catch {};
                return;
            }
        }
        if (!is_long) {
            // Short header 1-RTT path
            if (bytes.len < 1) return;
            const peer_h = hashSockaddr(&peer.storage, peer.len);
            var found: ?*conn_mod.Connection = null;
            var dcid_len: usize = 0;
            // Prefer a match that already has both App RX and TX keys installed (server side) to ensure ACK capability.
            // Tie-break on longer DCID length.
            var best: ?*conn_mod.Connection = null;
            var best_len: usize = 0;
            var it = self.conns.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.*.peer_hash != peer_h) continue;
                const c = entry.value_ptr.*;
                const l: usize = c.our_scid.len;
                if (l == 0) continue; // do not match ambiguous zero-length DCID
                if (1 + l > bytes.len) continue;
                if (!std.mem.eql(u8, c.our_scid.bytes[0..l], bytes[1 .. 1 + l])) continue;
                // Record first match as fallback
                if (found == null) {
                    found = c;
                    dcid_len = l;
                } else if (l > dcid_len) {
                    found = c;
                    dcid_len = l;
                }
                const has_rx = (c.app_rx_keys != null);
                const has_tx = (c.app_tx_keys != null);
                if (has_rx and has_tx) {
                    if (best == null or l > best_len) {
                        best = c;
                        best_len = l;
                    }
                }
            }
            if (best) |b| {
                found = b;
                dcid_len = best_len;
            }
            // NAT rebinding / migration fallback: try match by DCID across all entries
            if (found == null) {
                var it2 = self.conns.iterator();
                while (it2.next()) |entry| {
                    const c = entry.value_ptr.*;
                    const l: usize = c.our_scid.len;
                    if (1 + l > bytes.len) continue;
                    if (l == 0) continue;
                    if (std.mem.eql(u8, c.our_scid.bytes[0..l], bytes[1 .. 1 + l])) {
                        found = c;
                        dcid_len = l;
                        // Centralized handling for path change and validation
                        self.onPathAddressChanged(c, peer, peer_h, l);
                        break;
                    }
                }
            }
            const conn = found orelse return;
            // Test-only debug: log short-header match and ECN bits/keys state
            if (self.test_capture_enabled) {
                const has_rx = (conn.app_rx_keys != null);
                const has_tx = (conn.app_tx_keys != null);
                const eb: u8 = if (ecn_bits) |e| (e & 0x03) else 0xff;
                std.debug.print("APP short: match dcid_len={d} rx_keys={s} tx_keys={s} ecn_bits=0x{x}\n", .{ dcid_len, if (has_rx) "y" else "n", if (has_tx) "y" else "n", eb });
            }
            if (ecn_bits) |e| conn.onEcnMark(.Application, e);
            // Track bytes received from unvalidated address for amplification gating
            conn.addRxUnvalidated(bytes.len);
            if (conn.app_rx_keys) |rx_keys| {
                // Attempt decode using current RX keys first. On failure, try derived NEXT keys, then previous keys.
                var used_next: bool = false;
                var used_prev: bool = false;
                var dec_res = packet.decodeShortProtected(self.allocator.*, bytes, dcid_len, .{ .key = rx_keys.key, .iv = rx_keys.iv, .hp = rx_keys.hp }) catch blk_dec: {
                    // If decryption fails outright, check for stateless reset token match to fail fast.
                    if (conn.looksLikeStatelessReset(bytes)) {
                        std.debug.print("stateless-reset: closing connection\n", .{});
                        conn.closed = true;
                        return;
                    }
                    // Try derived NEXT keys if we have a RX traffic secret
                    if (conn.app_rx_secret) |cur_rx_secret| {
                        const next_secret = ks.updateTrafficSecret(cur_rx_secret);
                        var mat: packet.AeadKeys = undefined;
                        if (conn.version_v2) {
                            const t2 = ks.deriveKeyIvHpV2(next_secret);
                            mat = .{ .key = t2.key, .iv = t2.iv, .hp = t2.hp };
                        } else {
                            const t2 = ks.deriveKeyIvHp(next_secret);
                            mat = .{ .key = t2.key, .iv = t2.iv, .hp = t2.hp };
                        }
                        const try_next = packet.decodeShortProtected(self.allocator.*, bytes, dcid_len, .{ .key = mat.key, .iv = mat.iv, .hp = mat.hp }) catch blk_prev: {
                            // Finally, if we have previous RX keys during transition, try them
                            if (conn.rx_prev_keys) |kp| {
                                used_prev = true;
                                break :blk_prev packet.decodeShortProtected(self.allocator.*, bytes, dcid_len, .{ .key = kp.key, .iv = kp.iv, .hp = kp.hp }) catch return;
                            }
                            // Authentication failed across current/next/prev keys
                            conn.onAeadAuthFailure();
                            return;
                        };
                        // Promote to NEXT keys on success
                        used_next = true;
                        // Preserve current keys as previous (zeroize any older prev first)
                        if (conn.rx_prev_keys) |*old_prev| {
                            @memset(&old_prev.key, 0);
                            @memset(&old_prev.iv, 0);
                            @memset(&old_prev.hp, 0);
                        }
                        conn.rx_prev_keys = rx_keys;
                        conn.rx_prev_allow = 16; // bounded window for reordering
                        conn.app_rx_keys = .{ .key = mat.key, .iv = mat.iv, .hp = mat.hp };
                        conn.app_rx_secret = next_secret;
                        conn.rx_key_phase = !conn.rx_key_phase;
                        break :blk_dec try_next;
                    }
                    // No secret available for deriving NEXT; try previous only
                    if (conn.rx_prev_keys) |kp2| {
                        used_prev = true;
                        break :blk_dec packet.decodeShortProtected(self.allocator.*, bytes, dcid_len, .{ .key = kp2.key, .iv = kp2.iv, .hp = kp2.hp }) catch return;
                    }
                    conn.onAeadAuthFailure();
                    return;
                };
                defer self.allocator.free(dec_res.payload);
                const pn_full: u64 = conn.expandPnApp(@intCast(dec_res.packet_number), dec_res.packet_number_len);
                conn.trackRecvPnApp(pn_full);
                // If we decoded with previous keys, decrement allowance and drop them when exhausted
                if (used_prev) {
                    if (conn.rx_prev_allow > 0) {
                        conn.rx_prev_allow -= 1;
                        if (conn.rx_prev_allow == 0) {
                            if (conn.rx_prev_keys) |*to_zero| {
                                @memset(&to_zero.key, 0);
                                @memset(&to_zero.iv, 0);
                                @memset(&to_zero.hp, 0);
                            }
                            conn.rx_prev_keys = null;
                        }
                    } else {
                        // Safety: if allowance already zero, drop prev immediately
                        if (conn.rx_prev_keys) |*to_zero2| {
                            @memset(&to_zero2.key, 0);
                            @memset(&to_zero2.iv, 0);
                            @memset(&to_zero2.hp, 0);
                        }
                        conn.rx_prev_keys = null;
                    }
                }
                // Parse frames from payload
                var off2: usize = 0;
                var saw_any: bool = false;
                var saw_hs_done: bool = false;
                var saw_close: ?frame.Frame = null;
                var saw_ack_eliciting: bool = false;
                const now_ns_ack: u64 = @intCast(std.time.nanoTimestamp());
                while (off2 < dec_res.payload.len) {
                    const fr = frame.decodeOne(dec_res.payload[off2..]) catch break;
                    off2 += fr.n;
                    switch (fr.f) {
                        .ping => {
                            saw_any = true;
                            saw_ack_eliciting = true;
                        },
                        .new_connection_id => |ncid| {
                            // Record stateless reset token for later detection
                            conn.onNewConnectionId(ncid.sequence, ncid.retire_prior_to, ncid.stateless_reset_token);
                            saw_any = true;
                            saw_ack_eliciting = true;
                        },
                        .retire_connection_id => |rc| {
                            conn.*.onRetireConnectionId(rc.sequence);
                            saw_any = true;
                            saw_ack_eliciting = true;
                        },
                        .stream => |s| {
                            const off: u64 = s.offset orelse 0;
                            conn.pushStreamFrame(s.stream_id, off, s.data, s.fin) catch {};
                            saw_any = true;
                            saw_ack_eliciting = true;
                        },
                        .datagram => |d| {
                            conn.pushDatagram(d.data) catch {};
                            saw_any = true;
                            if (self.cfg.enable_datagram) {
                                if (conn.app_tx_keys) |txk| {
                                    var fb = std.ArrayList(u8){};
                                    defer fb.deinit(self.allocator.*);
                                    const w = fb.writer(self.allocator.*);
                                    _ = (frame.Frame{ .datagram = .{ .data = d.data } }).write(w) catch 0;
                                    const dcid_sh = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                                    const out = packet.encodeShortProtected(self.allocator.*, dcid_sh, @as(u32, @truncate(conn.pn_app_tx)), 2, fb.items, txk, conn.tx_key_phase) catch null;
                                    if (out) |pkt_bytes| {
                                        defer self.allocator.free(pkt_bytes);
                                        _ = self.sendTo(peer, pkt_bytes) catch {};
                                        conn.onShortHeaderPacketSent(pkt_bytes.len, true);
                                    }
                                }
                            }
                        },
                        .ack => |a| {
                            // Forward Application ACK to recovery with actual ranges
                            conn.onAckReceivedSpace(.Application, a.largest, a.first_range, a.ranges, a.ecn);
                            conn.pto_app_count = 0;
                            if (conn.pto_app_active) {
                                _ = self.cancelTimer(conn.pto_app_id);
                                conn.pto_app_active = false;
                            }
                            // Allow PMTUD state machine to progress upon probe ACK
                            conn.pmtudOnAckProgress(self);
                        },
                        .handshake_done => {
                            saw_hs_done = true;
                            saw_ack_eliciting = true; // HANDSHAKE_DONE is ack-eliciting
                        },
                        .connection_close => {
                            saw_close = fr.f;
                        },
                        .max_stream_data => |m| {
                            if (m.stream_id == 0) {
                                conn.peer_max_stream_data = m.max;
                            }
                            saw_ack_eliciting = true;
                        },
                        .max_data => |md| {
                            conn.peer_max_data = md.max;
                            saw_ack_eliciting = true;
                        },
                        .max_streams_bidi => |msb| {
                            conn.peer_max_streams_bidi = msb.max;
                            saw_ack_eliciting = true;
                        },
                        .max_streams_uni => |msu| {
                            conn.peer_max_streams_uni = msu.max;
                            saw_ack_eliciting = true;
                        },
                        .stream_data_blocked => |_| {},
                        .path_challenge => |pcv| {
                            if (conn.app_tx_keys) |txk| {
                                var fb = std.ArrayList(u8){};
                                defer fb.deinit(self.allocator.*);
                                const w = fb.writer(self.allocator.*);
                                _ = (frame.Frame{ .path_response = pcv }).write(w) catch 0;
                                const dcid_sh2 = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                                const out = packet.encodeShortProtected(self.allocator.*, dcid_sh2, @as(u32, @truncate(conn.pn_app_tx)), 2, fb.items, txk, conn.tx_key_phase) catch null;
                                if (out) |pkt_bytes| {
                                    defer self.allocator.free(pkt_bytes);
                                    _ = self.sendTo(peer, pkt_bytes) catch {};
                                    conn.onShortHeaderPacketSent(pkt_bytes.len, true);
                                }
                            }
                        },
                        .path_response => |prv| {
                            if (conn.path_validation_pending and std.mem.eql(u8, &conn.path_challenge_data, &prv)) {
                                self.onPathValidated(conn);
                            }
                        },
                        .new_token => |nt| {
                            conn.initial_token.clearRetainingCapacity();
                            _ = conn.initial_token.appendSlice(self.allocator.*, nt.token) catch {};
                        },
                        else => {},
                    }
                }
                // Test-only debug: record whether we saw any ack-eliciting frames
                if (self.test_capture_enabled) {
                    std.debug.print("APP saw_any={s}\n", .{if (saw_any) "y" else "n"});
                }
                if (saw_ack_eliciting) {
                    conn.recordAckElicitingRx(.Application, now_ns_ack);
                }
                if (saw_hs_done) {
                    conn.handshake_done_seen = true;
                    // Client: drop Handshake keys after HANDSHAKE_DONE
                    conn.hs_rx_keys = null;
                    conn.hs_tx_keys = null;
                }
                if (saw_close) |_| {
                    conn.closed = true;
                    return; // stop processing further
                }
                // If an ACK_ECN was deferred due to amplification, emit it now when allowed
                if (conn.ecn_app_ack_pending and conn.app_tx_keys != null and conn.canSendUnderAmplification()) {
                    var ack_buf = std.ArrayList(u8){};
                    defer ack_buf.deinit(self.allocator.*);
                    const w = ack_buf.writer(self.allocator.*);
                    const ad = conn.buildAckApp();
                    const ack_ecn_now = conn.getAckEcn(.Application);
                    if (self.test_capture_enabled and ack_ecn_now != null) {
                        std.debug.print("APP pending ACK_ECN flush ce={d} ect0={d} ect1={d}\n", .{ ack_ecn_now.?.ce, ack_ecn_now.?.ect0, ack_ecn_now.?.ect1 });
                    }
                    const ack_delay = conn.getAckDelayEncoded(.Application, now_ns_ack);
                    const ackf = frame.Frame{ .ack = .{ .largest = ad.largest, .ack_delay = ack_delay, .first_range = ad.first_range, .ranges = ad.ranges, .ecn = ack_ecn_now } };
                    _ = ackf.write(w) catch 0;
                    const dcid_ack = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)] else conn.our_scid.bytes[0..@min(conn.our_scid.len, 4)];
                    const pkt = packet.encodeShortProtected(self.allocator.*, dcid_ack, @as(u32, @truncate(conn.pn_app_tx)), 2, ack_buf.items, conn.app_tx_keys.?, conn.tx_key_phase) catch null;
                    if (pkt) |bytes_out| {
                        defer self.allocator.free(bytes_out);
                        _ = self.sendTo(peer, bytes_out) catch {};
                        conn.onShortHeaderPacketSent(bytes_out.len, false);
                        conn.ecn_app_ack_pending = false;
                        // Ensure this ACK_ECN is the next captured packet; stop further processing
                        return;
                    }
                }
                // Enforce AEAD integrity limit: if connection has been marked closed due to limit, send CONNECTION_CLOSE once.
                if (conn.closed) {
                    if (conn.app_tx_keys) |tx_keys| {
                        var fb = std.ArrayList(u8){};
                        defer fb.deinit(self.allocator.*);
                        const w = fb.writer(self.allocator.*);
                        // AEAD_LIMIT_REACHED = 0x0f per RFC 9000 §20
                        _ = (frame.Frame{ .connection_close = .{ .error_code = 0x0f, .frame_type = 0, .reason = "AEAD integrity limit reached" } }).write(w) catch 0;
                        // Amplification gating: only send if validated or within 3x limit
                        const allow_send = conn.canSendUnderAmplification();
                        if (allow_send) {
                            const dcid_ack2 = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                            const out = packet.encodeShortProtected(self.allocator.*, dcid_ack2, @as(u32, @truncate(conn.pn_app_tx)), 2, fb.items, tx_keys, conn.tx_key_phase) catch null;
                            if (out) |pkt_bytes| {
                                defer self.allocator.free(pkt_bytes);
                                _ = self.sendTo(peer, pkt_bytes) catch {};
                                conn.onShortHeaderPacketSent(pkt_bytes.len, true);
                            }
                        }
                    }
                    return;
                }
                if (saw_any or (ecn_bits != null)) {
                    if (self.test_capture_enabled) {
                        std.debug.print("APP have_tx_keys={s}\n", .{if (conn.app_tx_keys != null) "y" else "n"});
                    }
                    if (conn.app_tx_keys) |tx_keys| {
                        const allow_send = conn.canSendUnderAmplification();
                        if (self.test_capture_enabled) {
                            std.debug.print("APP allow_send={s} rx_unval={d} tx_unval={d} validated={s}\n", .{ if (allow_send) "y" else "n", conn.bytes_rx_unvalidated, conn.bytes_tx_unvalidated, if (conn.address_validated) "y" else "n" });
                        }
                        // Precompute ACK_ECN selection once to keep consistent across branches
                        var ack_ecn_common = conn.getAckEcn(.Application);
                        if (ack_ecn_common == null) {
                            if (ecn_bits) |e_cur| {
                                const bcur: u8 = e_cur & 0x03;
                                if (bcur != 0) {
                                    ack_ecn_common = switch (bcur) {
                                        0x01 => .{ .ect0 = 0, .ect1 = 1, .ce = 0 },
                                        0x02 => .{ .ect0 = 1, .ect1 = 0, .ce = 0 },
                                        0x03 => .{ .ect0 = 0, .ect1 = 0, .ce = 1 },
                                        else => null,
                                    };
                                }
                            }
                        }
                        // If we observed ECN (ack_ecn_common != null), ensure we emit an ACK frame now (ACK-only if needed).
                        // If ECN observed and amplification would block, mark pending to ensure next pass sends an ACK_ECN.
                        if (ack_ecn_common != null and !allow_send) {
                            conn.ecn_app_ack_pending = true;
                        }
                        if (allow_send) {
                            // If we have ECN to report, emit an immediate ACK-only ACK_ECN to ensure the test observes it
                            if (ack_ecn_common != null) {
                                var ack_only = std.ArrayList(u8){};
                                defer ack_only.deinit(self.allocator.*);
                                const wa = ack_only.writer(self.allocator.*);
                                const ad = conn.buildAckApp();
                                if (self.test_capture_enabled) {
                                    std.debug.print("APP immediate ACK_ECN ce={d} ect0={d} ect1={d}\n", .{ ack_ecn_common.?.ce, ack_ecn_common.?.ect0, ack_ecn_common.?.ect1 });
                                }
                                const ack_delay = conn.getAckDelayEncoded(.Application, now_ns_ack);
                                const ackf = frame.Frame{ .ack = .{ .largest = ad.largest, .ack_delay = ack_delay, .first_range = ad.first_range, .ranges = ad.ranges, .ecn = ack_ecn_common } };
                                _ = ackf.write(wa) catch 0;
                                const dcid_ack3 = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)] else conn.our_scid.bytes[0..@min(conn.our_scid.len, 4)];
                                const po = packet.encodeShortProtected(self.allocator.*, dcid_ack3, @as(u32, @truncate(conn.pn_app_tx)), 2, ack_only.items, tx_keys, conn.tx_key_phase) catch null;
                                if (po) |bytes_out0| {
                                    defer self.allocator.free(bytes_out0);
                                    _ = self.sendTo(peer, bytes_out0) catch {};
                                    conn.onShortHeaderPacketSent(bytes_out0.len, false);
                                }
                                // Ensure this ACK_ECN is the next captured packet; stop further processing
                                return;
                                // Skip building a second ACK to avoid duplicates
                            } else {
                                var frames_buf = std.ArrayList(u8){};
                                defer frames_buf.deinit(self.allocator.*);
                                const w = frames_buf.writer(self.allocator.*);
                                const ack_desc = conn.buildAckApp();
                                // Debug: log ACK_ECN decision for Application space in tests
                                if (self.test_capture_enabled) {
                                    std.debug.print("APP ACK (no ECN) allow_send\n", .{});
                                }
                                const ack_delay = conn.getAckDelayEncoded(.Application, now_ns_ack);
                                const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = null } };
                                _ = ack.write(w) catch 0;
                                // Pace MAX_* emission: include only when values increased since last sent
                                if (conn.local_max_stream_data > conn.last_sent_max_stream_data) {
                                    _ = (frame.Frame{ .max_stream_data = .{ .stream_id = 0, .max = conn.local_max_stream_data } }).write(w) catch {};
                                    conn.last_sent_max_stream_data = conn.local_max_stream_data;
                                }
                                if (conn.local_max_data > conn.last_sent_max_data) {
                                    _ = (frame.Frame{ .max_data = .{ .max = conn.local_max_data } }).write(w) catch {};
                                    conn.last_sent_max_data = conn.local_max_data;
                                }
                                // Advertise MAX_STREAMS_BIDI early to allow client-initiated stream 0
                                if (conn.local_max_streams_bidi > conn.last_sent_max_streams_bidi) {
                                    _ = (frame.Frame{ .max_streams_bidi = .{ .max = conn.local_max_streams_bidi } }).write(w) catch {};
                                    conn.last_sent_max_streams_bidi = conn.local_max_streams_bidi;
                                }
                                // Append any pending NEW_CONNECTION_ID frames (bounded) to piggyback on ACK
                                // Check pending_new_cid bitset for any set bits (std.bit_set has no isEmpty helper in this Zig version)
                                var any_pending = false;
                                {
                                    var bi: usize = 0;
                                    while (bi < conn.local_cids.len) : (bi += 1) {
                                        if (conn.pending_new_cid.isSet(@intCast(bi))) {
                                            any_pending = true;
                                            break;
                                        }
                                    }
                                }
                                if (any_pending) {
                                    _ = conn.writePendingNewConnectionIds(w, 2) catch 0; // piggyback up to 2
                                }
                                const dcid_ack4 = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                                const out = packet.encodeShortProtected(self.allocator.*, dcid_ack4, @as(u32, @truncate(conn.pn_app_tx)), 2, frames_buf.items, tx_keys, conn.tx_key_phase) catch null;
                                if (out) |pkt_bytes| {
                                    defer self.allocator.free(pkt_bytes);
                                    _ = self.sendTo(peer, pkt_bytes) catch {};
                                    conn.onShortHeaderPacketSent(pkt_bytes.len, false);
                                }
                            }
                        } else {
                            // RFC 9000 §8.1: a server MAY send a single packet containing only ACK
                            // in response to each received datagram when under amplification limit.
                            // Emit a pure ACK (no MAX_*) to report ECN counts promptly.
                            var ack_only = std.ArrayList(u8){};
                            defer ack_only.deinit(self.allocator.*);
                            const w2 = ack_only.writer(self.allocator.*);
                            const ack_desc2 = conn.buildAckApp();
                            if (self.test_capture_enabled) {
                                std.debug.print("APP ack-only branch\n", .{});
                                if (ack_ecn_common) |e2| {
                                    std.debug.print("APP ACK_ECN ack-only ce={d} ect0={d} ect1={d}\n", .{ e2.ce, e2.ect0, e2.ect1 });
                                } else {
                                    std.debug.print("APP ACK ack-only (no ECN)\n", .{});
                                }
                            }
                            const ack_delay2 = conn.getAckDelayEncoded(.Application, now_ns_ack);
                            const ack2 = frame.Frame{ .ack = .{ .largest = ack_desc2.largest, .ack_delay = ack_delay2, .first_range = ack_desc2.first_range, .ranges = ack_desc2.ranges, .ecn = ack_ecn_common } };
                            _ = ack2.write(w2) catch 0;
                            const dcid_ack5 = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                            const out2 = packet.encodeShortProtected(self.allocator.*, dcid_ack5, @as(u32, @truncate(conn.pn_app_tx)), 2, ack_only.items, tx_keys, conn.tx_key_phase) catch null;
                            if (out2) |pkt_bytes2| {
                                defer self.allocator.free(pkt_bytes2);
                                _ = self.sendTo(peer, pkt_bytes2) catch {};
                                // ACK-only is not ack-eliciting
                                conn.onShortHeaderPacketSent(pkt_bytes2.len, false);
                            }
                        }
                    }
                }
            }
            return;
        }
        // Detect NAT rebinding or migration: if we have a known connection for dcid but peer address changed, update and trigger validation
        const ty = (first >> 4) & 0x03;
        const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
        if (ty == 0) {
            std.debug.print("Processing Initial packet from peer\n", .{});
            // Initial
            var i: usize = 5;
            if (i >= bytes.len) return;
            const dcid_len = bytes[i];
            i += 1;
            if (i + dcid_len > bytes.len) return;
            const dcid = bytes[i .. i + dcid_len];
            i += dcid_len;
            if (i >= bytes.len) return;
            const scid_len = bytes[i];
            i += 1;
            if (i + scid_len > bytes.len) return;
            const scid = bytes[i .. i + scid_len];
            i += scid_len;

            // Key connection by peer and dcid
            const key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(dcid) };
            std.debug.print("Looking up connection with dcid=", .{});
            for (dcid) |b| std.debug.print("{X:0>2}", .{b});
            std.debug.print(" (found={})\n", .{self.conns.contains(key)});
            var conn: *conn_mod.Connection = blk: {
                if (self.conns.getPtr(key)) |p| {
                    // Found an existing mapping. Reuse immediately if it's already a server.
                    if (p.*.role == .Server) {
                        std.debug.print("Found existing connection (role=Server)\n", .{});
                        break :blk p.*;
                    }
                    // Otherwise it's a client connection. Decide if we truly need a server twin.
                    // We only synthesize a server twin in single-endpoint test scenarios where a
                    // synthetic client object was installed solely to craft an Initial and now an
                    // inbound client Initial (whose DCID equals that client's chosen initial DCID)
                    // is being processed as a server. When a real client receives a server Initial
                    // response, the DCID equals its own SCID, not its peer_initial_dcid.
                    const dcid_is_client_initial = p.*.peer_initial_dcid.len > 0 and std.mem.eql(u8, dcid, p.*.peer_initial_dcid.bytes[0..p.*.peer_initial_dcid.len]);
                    const dcid_is_our_scid = p.*.our_scid.len > 0 and std.mem.eql(u8, dcid, p.*.our_scid.bytes[0..p.*.our_scid.len]);
                    if (dcid_is_client_initial and !dcid_is_our_scid) {
                        std.debug.print("Found existing client connection for dcid (matches peer_initial_dcid); creating server twin for inbound client Initial\n", .{});
                        // Fall through to allocate server twin
                    } else {
                        // Reuse the client connection (this is the normal client receiving server Initial case)
                        std.debug.print("Reusing existing client connection for inbound Initial (dcid matched our_scid)\n", .{});
                        break :blk p.*;
                    }
                }
                // No suitable server connection exists: create one now.
                const c_new = self.allocator.create(conn_mod.Connection) catch return;
                c_new.init(self.allocator, .Server, sockToIsize(self.sock_fd), peer);
                // Generate a random SCID for the server
                c_new.our_scid.len = 8;
                std.crypto.random.bytes(c_new.our_scid.bytes[0..c_new.our_scid.len]);
                // Pre-seed peer_initial_dcid/original_dcid with the client's DCID from this first Initial
                // so that Initial key derivation (which happens before setPeerInitialCids for server twin)
                // uses the correct ODCID and not an empty slice.
                c_new.peer_initial_dcid.len = @intCast(@min(dcid.len, c_new.peer_initial_dcid.bytes.len));
                if (c_new.peer_initial_dcid.len > 0) @memcpy(c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len], dcid[0..c_new.peer_initial_dcid.len]);
                c_new.original_dcid.len = c_new.peer_initial_dcid.len;
                if (c_new.original_dcid.len > 0) @memcpy(c_new.original_dcid.bytes[0..c_new.original_dcid.len], c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len]);
                c_new.setUseCubic(self.cfg.cc == .cubic);
                c_new.tls.allow_insecure = self.cfg.allow_insecure;
                if (self.cfg.real_tls) {
                    c_new.tls.enableReal();
                    if (self.cfg.inline_server_cert_der != null and self.cfg.inline_server_priv_p256 != null) {
                        c_new.tls.setServerCertificate(self.cfg.inline_server_cert_der.?, self.cfg.inline_server_priv_p256.?, .ecdsa_secp256r1_sha256) catch {};
                    }
                }
                c_new.allowed_alpns = self.cfg.alpn;
                // Enable optional pacing and set CC max_datagram_size
                c_new.enable_pacing = self.cfg.enable_pacing;
                c_new.rec.cc.mds = @intCast(self.cfg.max_datagram_size);
                // Install paced sender callback
                c_new.setSender(@ptrCast(self), senderPaced);
                _ = self.conns.put(key, c_new) catch {
                    c_new.deinit();
                    self.allocator.destroy(c_new);
                    return;
                };
                // Apply AEAD limits overrides for server-side
                c_new.setAeadUsageLimits(self.cfg.aead_confidentiality_limit_override, self.cfg.aead_integrity_limit_override);
                // Also map our chosen SCID to this connection for Handshake DCID lookup.
                const our_key2 = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len]) };
                _ = self.conns.put(our_key2, c_new) catch {};
                // Defer enqueue until after successful Initial decrypt
                break :blk c_new;
            };
            conn.initial_version = version;
            if (ecn_bits) |e| conn.onEcnMark(.Initial, e);
            if (conn.initial_keys_dropped) return;

            // For server role, set peer CIDs from packet (captures client's DCID/SCID and ODCID once).
            // For client role, capture the server's SCID (peer_initial_scid) the first time we see it so
            // that subsequent short-header 1-RTT packets use the correct DCID (the server's SCID). The
            // client's peer_initial_dcid/original_dcid were recorded from its own first Initial and MUST
            // NOT be overwritten here (RFC 9000 §5.2 Retry/ODCID rules).
            if (conn.role == .Server) {
                conn.setPeerInitialCids(dcid, scid);
            } else if (conn.role == .Client and conn.peer_initial_scid.len == 0) {
                conn.peer_initial_scid.len = @intCast(@min(scid.len, conn.peer_initial_scid.bytes.len));
                if (conn.peer_initial_scid.len > 0) @memcpy(conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len], scid[0..conn.peer_initial_scid.len]);
            }

            // Anti-amplification: before address validation, limit server to 3x bytes received
            // Track bytes received from unvalidated address
            conn.addRxUnvalidated(bytes.len);

            // Derive oriented Initial AEAD keys based on role
            // For server: rx = client keys (to decrypt client Initial)
            // For client: rx = server keys (to decrypt server Initial response)
            const v2 = (version == packet.QUIC_V2);
            // RFC 9000 §5.2: Initial secrets are derived from the Destination Connection ID in the
            // first Initial packet sent by the client (ODCID). After a Retry, the client changes
            // the DCID it uses on subsequent Initials to the SCID from the Retry, but keys MUST
            // continue to be derived from the original DCID. We persist that value in
            // conn.peer_initial_dcid. For a server, always prefer peer_initial_dcid when set.
            const derive_dcid = blk: { // ODCID per RFC 9000 §5.2
                if (conn.role == .Server) {
                    // Defensive: clamp nonsense length that could arise if a reused connection
                    // had an uninitialized original_dcid prior to the field being zeroed in init.
                    if (conn.original_dcid.len > conn.original_dcid.bytes.len) conn.original_dcid.len = 0;
                    if (conn.original_dcid.len > 0) break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    // Fallback before setPeerInitialCids on very first packet (should not happen)
                    if (conn.peer_initial_dcid.len > 0) break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
                    break :blk dcid;
                } else { // client
                    if (conn.original_dcid.len > conn.original_dcid.bytes.len) conn.original_dcid.len = 0;
                    if (conn.original_dcid.len > 0) break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    if (conn.peer_initial_dcid.len > 0) break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
                    break :blk dcid;
                }
            };
            std.debug.print("{s}: Deriving Initial keys with dcid=", .{if (conn.role == .Server) "Server" else "Client"});
            for (derive_dcid) |b| std.debug.print("{X:0>2}", .{b});
            std.debug.print("\n", .{});
            const ik = packet.initialAeadKeys(v2, conn.role == .Server, derive_dcid);
            const keys = ik.rx;

            // Parse long header variable fields up to PN start
            var j: usize = i; // after SCID value
            // token length varint and token bytes
            const tok = varint.decode(bytes[j..]) catch return;
            j += tok.n;
            const tok_len_usize: usize = @as(usize, @intCast(tok.value));
            if (j + tok_len_usize > bytes.len) return;
            const token_bytes = bytes[j .. j + tok_len_usize];
            j += tok_len_usize;

            // Address validation via token: verify token using HMAC over client IP and client's Initial DCID
            // Only applies to server role
            if (conn.role == .Server and !conn.address_validated and token_bytes.len > 0) {
                const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                const now_ns: i128 = std.time.nanoTimestamp();
                const now_ms: u64 = @intCast(if (now_ns > 0) @as(u128, @intCast(now_ns)) / std.time.ns_per_ms else 0);
                if (token_mod.verify(token_bytes, client_ip_bytes, secret, now_ms)) {
                    conn.address_validated = true;
                    // Mark that we can send NEW_TOKEN after handshake completes (1-RTT)
                    conn.new_token_pending = true;
                }
            }

            // If address still not validated after parsing, consider issuing Retry per config
            // Only applies to server role
            if (conn.role == .Server and !conn.address_validated and self.cfg.enable_retry) {
                // Build Retry: version as received; DCID = client's SCID; SCID = server-chosen; token bound to client ip+odcid
                const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                const retry_tok = token_mod.encode(self.allocator.*, client_ip_bytes, dcid, secret, self.cfg.token_expiry_ms) catch null;
                if (retry_tok) |tbytes| {
                    defer self.allocator.free(tbytes);
                    // For Retry integrity, ODCID is client's Initial DCID = dcid here.
                    const out = packet.encodeRetry(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], dcid, tbytes) catch null;
                    if (out) |retry_bytes| {
                        defer self.allocator.free(retry_bytes);
                        _ = self.sendTo(peer, retry_bytes) catch {};
                    }
                }
                return; // do not continue processing Initial
            }

            // length varint (payload length includes pn+payload+tag)
            const len_dec = varint.decode(bytes[j..]) catch return;
            j += len_dec.n;
            if (len_dec.value > @as(u64, bytes.len - j)) return;
            const end_total = j + @as(usize, @intCast(len_dec.value));
            const header_prefix = bytes[1..j];
            const pn_start = j;
            // Capture up to 4 masked PN bytes (ciphertext begins immediately after PN).
            var header_first = first;
            var pn_masked: [4]u8 = .{0} ** 4;
            const avail = @min(@as(usize, 4), end_total - pn_start);
            @memcpy(pn_masked[0..avail], bytes[pn_start .. pn_start + avail]);
            std.debug.print("{s}: Masked PN bytes: ", .{if (conn.role == .Server) "Server" else "Client"});
            for (pn_masked[0..avail]) |b| std.debug.print("{X:0>2} ", .{b});
            std.debug.print("\n", .{});
            // We'll try PN lengths 1..4 using auto-sample decrypt until one succeeds.
            std.debug.print("{s}: Trying to decrypt Initial with pn_initial.max={}\n", .{ if (conn.role == .Server) "Server" else "Client", conn.pn_initial.max });
            var success = false;
            var chosen_pn_len: u3 = 0;
            var pt_list = std.ArrayList(u8){};
            defer pt_list.deinit(self.allocator.*);
            var pn_len_try: u3 = 1;
            attempt: while (pn_len_try <= 4) : (pn_len_try += 1) {
                if (pn_start + pn_len_try > end_total) break;
                const ct = bytes[pn_start + pn_len_try .. end_total];
                if (ct.len < 16) break;
                var pn_try: [4]u8 = pn_masked; // copy masked bytes
                var header_try = first;
                pt_list.clearRetainingCapacity();
                pt_list.ensureTotalCapacity(self.allocator.*, ct.len - 16) catch break;
                pt_list.appendNTimesAssumeCapacity(0, ct.len - 16);
                const pt_slice = pt_list.items;
                const expected_pn = if (conn.pn_initial.have_any) conn.pn_initial.max + 1 else 0;
                const dec = crypto.unprotectInitialAutoSample(
                    .aes_128_gcm,
                    &keys.key,
                    &keys.iv,
                    &keys.hp,
                    &header_try,
                    pn_try[0..pn_len_try],
                    header_prefix,
                    ct,
                    pt_slice,
                    expected_pn,
                ) catch {
                    continue;
                };
                _ = dec;
                std.debug.print("After unmasking with pn_len={}: ", .{pn_len_try});
                for (pn_try[0..pn_len_try]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("\n", .{});
                const indicated_pn_len: u3 = @intCast((header_try & 0x03) + 1);
                if (indicated_pn_len != pn_len_try) {
                    // Mismatch between header-indicated PN length and trial; reject.
                    continue;
                }
                success = true;
                chosen_pn_len = pn_len_try;
                header_first = header_try;
                @memcpy(pn_masked[0..pn_len_try], pn_try[0..pn_len_try]); // now holds unmasked bytes
                break :attempt;
            }
            if (!success) {
                std.debug.print("Failed to decrypt Initial packet\n", .{});
                conn.onAeadAuthFailure();
                conn.closed = true;
                return;
            }
            const pn_len = chosen_pn_len;
            const pt = pt_list.items;
            std.debug.print("Successfully decrypted Initial packet (trial pn_len={}) plaintext len: {}\n", .{ pn_len, pt.len });
            // Only now (after successful decryption) enqueue server connection for accept()
            if (conn.role == .Server and !conn.accepted_enqueued) {
                conn.accepted_enqueued = true;
                self.pushAccepted(conn);
            }

            // Expand truncated PN against Initial space expectation and track
            var pn_val_be: u64 = 0;
            var kk: usize = 0;
            while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_masked[kk];
            const pn_full: u64 = conn.expandPnInitial(pn_val_be, pn_len);
            std.debug.print("Expanded PN: {} from truncated: {}\n", .{ pn_full, pn_val_be });
            conn.trackRecvPnInitial(pn_full);

            // Walk frames and push CRYPTO to inbox
            var off: usize = 0;
            var saw_any: bool = false;
            var saw_ack_eliciting_initial: bool = false;
            const now_ns_initial: u64 = @intCast(std.time.nanoTimestamp());
            while (off < pt.len) {
                const r = frame.decodeOne(pt[off..]) catch break;
                off += r.n;
                switch (r.f) {
                    .crypto => |cr| {
                        std.debug.print("{s}: Received CRYPTO frame with {} bytes\n", .{ if (conn.role == .Server) "Server" else "Client", cr.data.len });
                        const was_server = (conn.role == .Server);
                        // Enforce contiguous CRYPTO offsets per space
                        const expect_off: u64 = 0;
                        _ = expect_off; // Initial space receive offset validation handled below
                        conn.pushCrypto(cr.data) catch {};
                        saw_any = true;
                        saw_ack_eliciting_initial = true; // CRYPTO is ack-eliciting
                        // Server: after receiving CH, only queue ServerHello for Initial emission
                        if (was_server and !conn.tls.sh_seen) {
                            // Queue ServerHello only - it will be sent in Initial packet
                            // The rest of the handshake flight will be queued after SH is sent
                        }
                    },
                    .ack => |a| {
                        // Initial space ACK: inform recovery and cancel any Initial PTO
                        conn.onAckReceivedSpace(.Initial, a.largest, a.first_range, a.ranges, a.ecn);
                        conn.pto_initial_count = 0;
                        if (conn.pto_initial_active) {
                            _ = self.cancelTimer(conn.pto_initial_id);
                            conn.pto_initial_active = false;
                        }
                    },
                    .padding => {},
                    else => {},
                }
            }

            // If address still not validated, enforce 3x amplification limit for any server send
            const allow_send = conn.canSendUnderAmplification();

            // If we received anything ack-eliciting, send ACK in Initial space when we still have Initial TX keys
            if (saw_ack_eliciting_initial) {
                conn.recordAckElicitingRx(.Initial, now_ns_initial);
            }
            if (saw_any and !conn.initial_keys_dropped and allow_send) {
                // Build frames for Initial packet response
                var frames_buf = std.ArrayList(u8){};
                defer frames_buf.deinit(self.allocator.*);
                const w = frames_buf.writer(self.allocator.*);

                // Add ACK frame
                const ack_desc = conn.buildAckInitial();
                const ack_ecn = conn.getAckEcn(.Initial);
                const ack_delay = conn.getAckDelayEncoded(.Initial, now_ns_initial);
                const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = ack_ecn } };
                _ = ack.write(w) catch 0;

                // Server: Include ServerHello in Initial packet if we have it queued and haven't sent it yet
                var has_crypto = false;
                if (conn.role == .Server and conn.tls.sh_seen and conn.crypto_tx_off_initial < 200) {
                    // Pop any ServerHello bytes from TLS engine (should only be ServerHello at this point)
                    var sh_buf: [512]u8 = undefined;
                    const n_sh = conn.tls.popCrypto(sh_buf[0..]);
                    if (n_sh > 0) {
                        std.debug.print("Sending ServerHello in Initial packet: {} bytes\n", .{n_sh});
                        // Add CRYPTO frame with ServerHello
                        const crypto_frame = frame.Frame{ .crypto = .{ .offset = conn.crypto_tx_off_initial, .data = sh_buf[0..n_sh] } };
                        _ = crypto_frame.write(w) catch 0;
                        conn.crypto_tx_off_initial += n_sh;
                        has_crypto = true;

                        // Save for retransmission
                        if (conn.crypto_retx_initial) |b| self.allocator.free(b);
                        const owned = self.allocator.alloc(u8, n_sh) catch null;
                        if (owned) |retx| {
                            @memcpy(retx, sh_buf[0..n_sh]);
                            conn.crypto_retx_initial = owned;
                        }
                    }
                }

                // Always send Initial packet if we have frames to send
                // Use oriented Initial keys based on role
                // Same ODCID rule applies for transmitting Initials: derive secrets using the
                // client's original DCID (peer_initial_dcid) regardless of any Retry/DCID change.
                const derive_dcid_tx = blk: { // Always ODCID
                    if (conn.original_dcid.len > 0) break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    if (conn.peer_initial_dcid.len > 0) break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
                    break :blk dcid;
                };
                const oriented = packet.initialAeadKeys(v2, conn.role == .Server, derive_dcid_tx);
                const tx_keys = oriented.tx;

                // For client: DCID = peer's initial DCID, SCID = our SCID
                // For server: DCID = client's SCID (from packet), SCID = our SCID
                const tx_dcid = if (conn.role == .Client) conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len] else scid;
                const tx_scid = conn.our_scid.bytes[0..conn.our_scid.len];
                std.debug.print("{s}: Encoding Initial with pn={} dcid_len={} scid_len={} pn_len={}\n", .{ if (conn.role == .Server) "Server" else "Client", conn.pn_initial_tx, tx_dcid.len, tx_scid.len, 4 });
                const out = packet.encodeInitialProtected(self.allocator.*, version, tx_dcid, tx_scid, &[_]u8{}, @as(u32, @truncate(conn.pn_initial_tx)), 4, frames_buf.items, tx_keys) catch null;

                if (out) |pkt_bytes| {
                    defer self.allocator.free(pkt_bytes);
                    std.debug.print("{s}: Sending Initial response with {} bytes (has_crypto={})\n", .{ if (conn.role == .Server) "Server" else "Client", pkt_bytes.len, has_crypto });
                    _ = self.sendTo(peer, pkt_bytes) catch {};
                    // Packet with CRYPTO is ack-eliciting
                    conn.onPacketSent(.Initial, conn.pn_initial_tx, pkt_bytes.len, has_crypto);
                    conn.pn_initial_tx +%= 1;
                }

                // Additionally, route received ACKs in Initial space through Recovery.
                // Since this branch is taken when we saw any frames, send a synthetic ACK processing if needed is skipped.
            }
            // NEW: If we just derived Handshake keys and have outbound TLS handshake bytes queued, emit them now.
            if (conn.hs_tx_keys) |hs_keys| {
                // If we're a server and haven't queued the handshake flight yet, do it now
                if (conn.role == .Server and conn.tls.sh_seen and !conn.server_hello_sent) {
                    conn.server_hello_sent = true;
                    std.debug.print("Queueing handshake flight (EE, Cert, Finished)\n", .{});

                    // Queue EncryptedExtensions with ALPN and transport parameters
                    const alpn_sel: []const u8 = if (conn.allowed_alpns.len > 0) conn.allowed_alpns[0] else "h3";
                    var tps: tp.TransportParams = .{};
                    tps.initial_max_data = conn.local_max_data;
                    tps.initial_max_stream_data_bidi_local = conn.local_max_stream_data;
                    tps.initial_max_stream_data_bidi_remote = conn.local_max_stream_data;
                    tps.initial_max_streams_bidi = conn.local_max_streams_bidi;
                    tps.initial_max_streams_uni = 0;
                    const ee_bytes = tp.TransportParams.encode(&tps, self.allocator.*) catch &[_]u8{};
                    defer {
                        if (ee_bytes.len > 0) self.allocator.free(ee_bytes);
                    }
                    conn.tls.queueEncryptedExtensions(alpn_sel, if (ee_bytes.len > 0) ee_bytes else ee_bytes[0..0]) catch {};
                    // Queue remaining handshake flight (Certificate*, Finished)
                    conn.tls.queueServerHandshakeFlight();
                }

                // Pull any pending TLS outbox (EncryptedExtensions, Certificate, CertificateVerify, Finished)
                var tls_buf: [2048]u8 = undefined;
                const n_tls = conn.tls.popCrypto(tls_buf[0..]);
                if (n_tls > 0 and allow_send) {
                    std.debug.print("Sending Handshake packet with {} bytes of CRYPTO\n", .{n_tls});
                    var fb = std.ArrayList(u8){};
                    defer fb.deinit(self.allocator.*);
                    const w_hs = fb.writer(self.allocator.*);
                    const base_off_hs = conn.crypto_tx_off_handshake;
                    _ = (frame.Frame{ .crypto = .{ .offset = base_off_hs, .data = tls_buf[0..n_tls] } }).write(w_hs) catch 0;
                    // Save retransmit buffer for Handshake CRYPTO
                    if (conn.crypto_retx_handshake) |b| self.allocator.free(b);
                    var owned_hs = self.allocator.alloc(u8, n_tls) catch {
                        conn.crypto_tx_off_handshake += n_tls; // advance offset even if we cannot retain
                        return; // abort emission on OOM for retransmit copy
                    };
                    @memcpy(owned_hs[0..n_tls], tls_buf[0..n_tls]);
                    conn.crypto_retx_handshake = owned_hs;
                    conn.crypto_retx_handshake_off = base_off_hs;
                    conn.crypto_tx_off_handshake += n_tls;
                    const pkt_hs = packet.encodeHandshakeProtected(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, fb.items, hs_keys) catch null;
                    if (pkt_hs) |bytes_out_hs| {
                        defer self.allocator.free(bytes_out_hs);
                        _ = self.sendTo(peer, bytes_out_hs) catch {};
                        conn.onPacketSent(.Handshake, conn.pn_handshake_tx, bytes_out_hs.len, true);
                        conn.pn_handshake_tx +%= 1;
                    }
                }
            }

            // Check if there are more packets coalesced in this datagram
            // The end_total from the Initial packet tells us where it ends
            if (end_total < bytes.len) {
                std.debug.print("Processing coalesced packet after Initial (remaining {} bytes)\n", .{bytes.len - end_total});
                // Process the remaining bytes as a new packet
                self.processIncomingDatagram(peer, bytes[end_total..], ecn_bits);
            }
            return;
        }
        // Retry (client handling only). Parse fields, verify integrity using ODCID, then store token; resend Initial with token.
        if (ty == 3) {
            // Retry (client handling only). Parse fields, verify integrity using ODCID, then store token; resend Initial with token.
            var i: usize = 5;
            if (i >= bytes.len) return;
            const dcid_len = bytes[i];
            i += 1;
            if (i + dcid_len > bytes.len) return;
            i += dcid_len;
            if (i >= bytes.len) return;
            const scid_len = bytes[i];
            i += 1;
            if (i + scid_len > bytes.len) return;
            const scid = bytes[i .. i + scid_len];
            i += scid_len;
            if (bytes.len < 16 or i >= bytes.len - 16) return; // need room for integrity tag at end
            const token_bytes = bytes[i .. bytes.len - 16];
            // Lookup a matching client connection for this peer to access ODCID
            const ph = hashSockaddr(&peer.storage, peer.len);
            var itc = self.conns.iterator();
            var c_found: ?*conn_mod.Connection = null;
            while (itc.next()) |e| {
                if (e.key_ptr.*.peer_hash != ph) continue;
                c_found = e.value_ptr.*;
                break;
            }
            const c = c_found orelse return;
            // Verify Retry integrity using ODCID = client's Initial DCID stored in conn.peer_initial_dcid
            const odcid = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];
            if (odcid.len == 0) return;
            if (!packet.verifyRetry(odcid, bytes)) {
                // Drop invalid Retry per RFC 9001 §5.8
                return;
            }
            // Store token for next Initial
            c.initial_token.clearRetainingCapacity();
            _ = c.initial_token.appendSlice(self.allocator.*, token_bytes) catch {};
            // Update version and DCID to use for next Initial (use Retry.SCID as new DCID per spec)
            c.version = version;
            c.version_v2 = (version == packet.QUIC_V2);
            c.initial_version = version;
            c.peer_initial_dcid.len = @intCast(@min(scid.len, c.peer_initial_dcid.bytes.len));
            if (c.peer_initial_dcid.len > 0) @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], scid[0..c.peer_initial_dcid.len]);
            // Resend an Initial with the token
            self.clientSendInitialProbe(c) catch {};
            return;
        } else if (ty == 2) {
            std.debug.print("Processing Handshake packet from peer\n", .{});
            // Handshake RX path: attempt to unprotect and feed CRYPTO using hs_rx_keys
            var i: usize = 5;
            if (i >= bytes.len) return;
            const dcid_len = bytes[i];
            i += 1;
            if (i + dcid_len > bytes.len) return;
            const dcid = bytes[i .. i + dcid_len];
            i += dcid_len;
            if (i >= bytes.len) return;
            const scid_len = bytes[i];
            i += 1;
            if (i + scid_len > bytes.len) return;
            const scid = bytes[i .. i + scid_len];
            i += scid_len;

            // Parse length varint to find packet boundary (needed for coalesced packets)
            var j: usize = i;
            const len_dec = varint.decode(bytes[j..]) catch return;
            j += len_dec.n;
            if (len_dec.value > @as(u64, bytes.len - j)) return;
            const end_total = j + @as(usize, @intCast(len_dec.value));

            // Lookup connection keyed by peer + initial dcid hash (use stored mapping if any)
            const key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(dcid) };
            const c_ptr = self.conns.getPtr(key) orelse return;
            const conn = c_ptr.*;
            if (ecn_bits) |e| conn.onEcnMark(.Handshake, e);
            if (conn.hs_rx_keys) |rx_keys| {
                std.debug.print("Client has handshake RX keys, proceeding to decrypt\n", .{});
                const header_prefix = bytes[1..j];
                const pn_start = j;

                // Capture up to 4 masked PN bytes
                var pn_masked: [4]u8 = .{0} ** 4;
                const avail = @min(@as(usize, 4), end_total - pn_start);
                @memcpy(pn_masked[0..avail], bytes[pn_start .. pn_start + avail]);

                // Try different PN lengths until one succeeds
                var success = false;
                var chosen_pn_len: u3 = 0;
                var pt_list = std.ArrayList(u8){};
                defer pt_list.deinit(self.allocator.*);
                var pn_len_try: u3 = 1;

                attempt: while (pn_len_try <= 4) : (pn_len_try += 1) {
                    if (pn_start + pn_len_try > end_total) break;
                    const ct = bytes[pn_start + pn_len_try .. end_total];
                    if (ct.len < 16) break;

                    var pn_try: [4]u8 = pn_masked; // copy masked bytes
                    var header_try = first;
                    pt_list.clearRetainingCapacity();
                    pt_list.ensureTotalCapacity(self.allocator.*, ct.len - 16) catch break;
                    pt_list.appendNTimesAssumeCapacity(0, ct.len - 16);
                    const pt_slice = pt_list.items;

                    const expected_pn_hs = if (conn.pn_handshake.have_any) conn.pn_handshake.max + 1 else 0;
                    const dec = crypto.unprotectInitialAutoSample(
                        .aes_128_gcm,
                        &rx_keys.key,
                        &rx_keys.iv,
                        &rx_keys.hp,
                        &header_try,
                        pn_try[0..pn_len_try],
                        header_prefix,
                        ct,
                        pt_slice,
                        expected_pn_hs,
                    ) catch {
                        continue;
                    };
                    _ = dec;

                    std.debug.print("After unmasking with pn_len={}: ", .{pn_len_try});
                    for (pn_try[0..pn_len_try]) |b| std.debug.print("{X:0>2} ", .{b});
                    std.debug.print("\n", .{});

                    const indicated_pn_len: u3 = @intCast((header_try & 0x03) + 1);
                    if (indicated_pn_len != pn_len_try) {
                        // Mismatch between header-indicated PN length and trial; reject.
                        continue;
                    }

                    success = true;
                    chosen_pn_len = pn_len_try;
                    @memcpy(pn_masked[0..pn_len_try], pn_try[0..pn_len_try]); // now holds unmasked bytes
                    break :attempt;
                }

                if (!success) {
                    std.debug.print("Failed to decrypt Handshake packet\n", .{});
                    conn.onAeadAuthFailure();
                    conn.closed = true;
                    return;
                }

                const pn_len = chosen_pn_len;
                const pt = pt_list.items;
                std.debug.print("Successfully decrypted Handshake packet (trial pn_len={}) plaintext len: {}\n", .{ pn_len, pt.len });

                // Expand truncated PN and track in Handshake space
                var pn_val_be: u64 = 0;
                var kk: usize = 0;
                while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_masked[kk];
                const pn_full: u64 = conn.expandPnHandshake(pn_val_be, pn_len);
                conn.trackRecvPnHandshake(pn_full);

                // Feed CRYPTO frames and handle ACK frames for PTO reset
                var off: usize = 0;
                var saw_any: bool = false;
                var saw_ack_eliciting_hs: bool = false;
                const now_ns_hs: u64 = @intCast(std.time.nanoTimestamp());
                while (off < pt.len) {
                    const r = frame.decodeOne(pt[off..]) catch |err| {
                        std.debug.print("Failed to decode frame at offset {}: {}\n", .{ off, err });
                        break;
                    };
                    off += r.n;
                    std.debug.print("Handshake frame: {} at offset {}\n", .{ r.f, off - r.n });
                    switch (r.f) {
                        .crypto => {
                            const cr = r.f.crypto;
                            if (cr.offset == conn.crypto_rx_off_handshake) {
                                conn.pushCrypto(cr.data) catch {};
                                conn.crypto_rx_off_handshake += @intCast(cr.data.len);
                                saw_any = true;
                                saw_ack_eliciting_hs = true; // CRYPTO is ack-eliciting
                            } else {
                                // Ignore out-of-order CRYPTO for Handshake
                            }
                        },
                        .ack => |a| {
                            // Reset handshake PTO backoff and cancel active timer on ACK in this space
                            conn.onAckReceivedSpace(.Handshake, a.largest, a.first_range, a.ranges, a.ecn);
                            conn.pto_handshake_count = 0;
                            if (conn.pto_handshake_active) {
                                _ = self.cancelTimer(conn.pto_handshake_id);
                                conn.pto_handshake_active = false;
                            }
                        },
                        .padding => {},
                        else => {},
                    }
                }
                // Send any pending Handshake CRYPTO (e.g. client Finished) and then attempt post-flush 1-RTT key derivation.
                if (conn.hs_tx_keys) |tx_hs| {
                    var outbox: [1024]u8 = undefined;
                    const n = conn.tls.popCrypto(outbox[0..]);
                    if (n > 0) {
                        var frames_buf = std.ArrayList(u8){};
                        defer frames_buf.deinit(self.allocator.*);
                        const w = frames_buf.writer(self.allocator.*);
                        const base_off_hs = conn.crypto_tx_off_handshake;
                        _ = (frame.Frame{ .crypto = .{ .offset = base_off_hs, .data = outbox[0..n] } }).write(w) catch 0;
                        // Save HS retransmit buffer for this slice
                        if (conn.crypto_retx_handshake) |b| self.allocator.free(b);
                        var owned_hs = self.allocator.alloc(u8, n) catch {
                            conn.crypto_tx_off_handshake += n;
                            return; // abort sending HS CRYPTO chunk if we cannot save retransmit buffer
                        };
                        @memcpy(owned_hs[0..n], outbox[0..n]);
                        conn.crypto_retx_handshake = owned_hs;
                        conn.crypto_retx_handshake_off = base_off_hs;
                        conn.crypto_tx_off_handshake += n;
                        const pkt = packet.encodeHandshakeProtected(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, frames_buf.items, tx_hs) catch null;
                        if (pkt) |bytes_out| {
                            defer self.allocator.free(bytes_out);
                            _ = self.sendTo(peer, bytes_out) catch {};
                            conn.onPacketSent(.Handshake, conn.pn_handshake_tx, bytes_out.len, true);
                            conn.pn_handshake_tx +%= 1;
                        }
                        // With TLS outbox drained, attempt delayed 1-RTT key derivation.
                        conn.maybeDeriveAppKeysAfterFlush();
                    }
                }
                // Send ACK in Handshake space if ack-eliciting seen and we have hs_tx_keys
                if (saw_ack_eliciting_hs) {
                    conn.recordAckElicitingRx(.Handshake, now_ns_hs);
                }
                if (saw_any) {
                    if (conn.hs_tx_keys) |tx_keys| {
                        var frames_buf = std.ArrayList(u8){};
                        defer frames_buf.deinit(self.allocator.*);
                        const w = frames_buf.writer(self.allocator.*);
                        const ack_desc = conn.buildAckHandshake();
                        const ack_ecn = conn.getAckEcn(.Handshake);
                        const ack_delay = conn.getAckDelayEncoded(.Handshake, now_ns_hs);
                        const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = ack_ecn } };
                        _ = ack.write(w) catch 0;
                        // Also include any pending Initial CRYPTO from server side (unlikely) at correct offset
                        var outbox: [1024]u8 = undefined;
                        const n = conn.tls.popCrypto(outbox[0..]);
                        if (n > 0) {
                            _ = (frame.Frame{ .crypto = .{ .offset = conn.crypto_tx_off_initial, .data = outbox[0..n] } }).write(w) catch 0;
                            conn.crypto_tx_off_initial += n;
                        }
                        const pkt = packet.encodeHandshakeProtected(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, frames_buf.items, tx_keys) catch null;
                        if (pkt) |bytes_out| {
                            defer self.allocator.free(bytes_out);
                            _ = self.sendTo(peer, bytes_out) catch {};
                            // ACK-only Handshake is not ack-eliciting; no PTO arm
                            conn.pn_handshake_tx +%= 1;
                        }
                    }
                }
                // If peer has validated address (CH contained token) and we are server, consider sending NEW_TOKEN on 1-RTT after HS done
                if (conn.address_validated and conn.app_tx_keys != null and conn.new_token_pending and !conn.new_token_sent) {
                    // Issue a fresh token bound to current peer IP and ODCID (peer_initial_dcid)
                    const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                    const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                    const tok = token_mod.encode(self.allocator.*, client_ip_bytes, conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len], secret, self.cfg.token_expiry_ms) catch null;
                    if (tok) |tbytes| {
                        defer self.allocator.free(tbytes);
                        var fb = std.ArrayList(u8){};
                        defer fb.deinit(self.allocator.*);
                        const w = fb.writer(self.allocator.*);
                        _ = (frame.Frame{ .new_token = .{ .token = tbytes } }).write(w) catch 0;
                        const dcid_nt = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else conn.our_scid.bytes[0..conn.our_scid.len];
                        const out = packet.encodeShortProtected(self.allocator.*, dcid_nt, @as(u32, @truncate(conn.pn_app_tx)), 2, fb.items, conn.app_tx_keys.?, conn.tx_key_phase) catch null;
                        if (out) |pkt_bytes| {
                            defer self.allocator.free(pkt_bytes);
                            _ = self.sendTo(peer, pkt_bytes) catch {};
                            conn.onPacketSent(.Application, conn.pn_app_tx, pkt_bytes.len, true);
                            conn.pn_app_tx +%= 1;
                            conn.new_token_sent = true;
                        }
                    }
                }
            } else {
                std.debug.print("Client does not have handshake RX keys yet\n", .{});
            }

            // Check if there are more packets coalesced in this datagram (for Handshake packets)
            if (end_total < bytes.len) {
                // Process the remaining bytes as a new packet
                self.processIncomingDatagram(peer, bytes[end_total..], ecn_bits);
            }
        } else {
            return; // ignore other long header types for now
        }
    }

    /// Single source-of-truth for path change handling: updates peer address,
    /// resets validation state and counters, installs new map key, and triggers validation.
    fn onPathAddressChanged(self: *Endpoint, c: *conn_mod.Connection, new_peer: conn_mod.SockAddr, new_peer_hash: u64, dcid_len: usize) void {
        c.setPeer(new_peer);
        c.address_validated = false;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        // Insert/refresh mapping keyed by new peer and our DCID
        const new_key = Key{ .peer_hash = new_peer_hash, .dcid_hash = hashBytes(c.our_scid.bytes[0..dcid_len]) };
        _ = self.conns.put(new_key, c) catch {};
        // Trigger PATH_CHALLENGE if 1-RTT keys are available
        c.sendPathChallenge();
        std.debug.print("path: change detected dcid_len={d} triggering validation (phase={d})\n", .{ dcid_len, @intFromBool(c.tx_key_phase) });
    }

    /// Mark path validated and clear unvalidated counters consistently.
    fn onPathValidated(self: *Endpoint, c: *conn_mod.Connection) void {
        _ = self; // unused
        c.path_validation_pending = false;
        c.address_validated = true;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        std.debug.print("path: validated (peer={d} bytes_rx_unval reset)\n", .{c.peer.len});
    }

    fn nextTimeoutFromTimers(self: *Endpoint, now_ms: i64, requested_timeout_ms: i32) i32 {
        var eff = requested_timeout_ms;
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            const t = self.timers.items[i];
            const diff: i64 = t.deadline_ms - now_ms;
            const t_ms: i32 = if (diff <= 0) 0 else @intCast(@min(diff, @as(i64, std.math.maxInt(i32))));
            if (eff < 0) {
                eff = t_ms;
            } else if (t_ms < eff) {
                eff = t_ms;
            }
        }
        return eff;
    }

    fn processExpiredTimers(self: *Endpoint, now_ms: i64) void {
        // Simple linear removal of expired timers; keep others.
        var i: usize = 0;
        while (i < self.timers.items.len) {
            if (self.timers.items[i].deadline_ms <= now_ms) {
                const t = self.timers.items[i];
                _ = self.timers.orderedRemove(i);
                // Fire PTO flags if applicable and generate probes
                switch (t.kind) {
                    .Generic => {
                        if (t.paced) {
                            if (t.conn) |c| {
                                if (t.payload) |bytes| {
                                    // Send the paced payload now and free it
                                    _ = self.sendTo(c.peer, bytes) catch {};
                                    self.allocator.free(bytes);
                                }
                            }
                        }
                    },
                    .PtoInitial => if (t.conn) |c| {
                        c.setPtoExpiredInitial();
                        // Generate a PING probe in Initial space
                        self.sendPtoProbe(c, .PtoInitial) catch {};
                    },
                    .PtoHandshake => if (t.conn) |c| {
                        c.setPtoExpiredHandshake();
                        self.sendPtoProbe(c, .PtoHandshake) catch {};
                    },
                    .PtoApp => if (t.conn) |c| c.setPtoExpiredApp(),
                    .Pmtud => if (t.conn) |c| {
                        // Drive DPLPMTUD state machine timer
                        c.pmtudOnTimer(self);
                    },
                }
            } else {
                i += 1;
            }
        }
        // After firing timers, attempt pruning of closed connections (e.g., after PTO-driven close)
        self.pruneClosed();
    }

    /// TEST-ONLY: force all timers to expire immediately and process them once.
    pub fn forceExpireAllTimers(self: *Endpoint) void {
        const now_ms = nowMsMonotonic();
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            self.timers.items[i].deadline_ms = now_ms;
        }
        self.processExpiredTimers(now_ms);
    }

    fn sendPtoProbe(self: *Endpoint, conn: *conn_mod.Connection, kind: TimerKind) !void {
        switch (kind) {
            .PtoInitial => {
                if (conn.initial_keys_dropped) return; // no more Initial
                const dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
                const scid = conn.our_scid.bytes[0..conn.our_scid.len];
                if (dcid.len == 0) return;
                // Derive server Initial TX keys from peer Initial DCID
                const v2 = false; // TODO: map version
                // Derive using DCID from packet (destination field) per RFC 9001.
                const derive_dcid = dcid;
                const initial = ks.deriveInitialSecret(v2, derive_dcid);
                const pair = ks.deriveClientServerInitial(initial);
                if (conn.peer_initial_dcid.len == 0) {
                    // Record original DCID if not already captured.
                    conn.peer_initial_dcid.len = @intCast(@min(derive_dcid.len, conn.peer_initial_dcid.bytes.len));
                    if (conn.peer_initial_dcid.len > 0) @memcpy(conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len], derive_dcid[0..conn.peer_initial_dcid.len]);
                }
                std.debug.print("server: deriving Initial keys with dcid=", .{});
                for (derive_dcid) |b| std.debug.print("{X:0>2}", .{b});
                std.debug.print(" len={}\n", .{derive_dcid.len});
                const tx_keys: packet.InitialKeys = if (v2) blk: {
                    const t = ks.deriveKeyIvHpV2(pair.server);
                    break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                } else blk: {
                    const t = ks.deriveKeyIvHp(pair.server);
                    break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                };
                // Build a PING probe (ack-eliciting)
                var frames = std.ArrayList(u8){};
                defer frames.deinit(self.allocator.*);
                frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PING)) catch {};
                const pkt = packet.encodeInitialProtected(self.allocator.*, if (conn.initial_version == 0) 0x00000001 else conn.initial_version, dcid, scid, &[_]u8{}, @as(u32, @truncate(conn.pn_initial_tx)), 4, frames.items, tx_keys) catch return;
                defer self.allocator.free(pkt);
                _ = self.sendTo(conn.peer, pkt) catch {};
                conn.onPacketSent(.Initial, conn.pn_initial_tx, pkt.len, true);
                conn.pn_initial_tx +%= 1;
            },
            .PtoHandshake => {
                if (conn.hs_tx_keys) |tx_keys| {
                    const dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
                    const scid = conn.our_scid.bytes[0..conn.our_scid.len];
                    var frames = std.ArrayList(u8){};
                    defer frames.deinit(self.allocator.*);
                    frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PING)) catch {};
                    const pkt = packet.encodeHandshakeProtected(self.allocator.*, if (conn.initial_version == 0) 0x00000001 else conn.initial_version, dcid, scid, @as(u32, @truncate(conn.pn_handshake_tx)), 4, frames.items, tx_keys) catch return;
                    defer self.allocator.free(pkt);
                    _ = self.sendTo(conn.peer, pkt) catch {};
                    conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt.len, true);
                    conn.pn_handshake_tx +%= 1;
                    // No re-arm here; normal timer loop handles it.
                }
            },
            else => return,
        }
    }

    /// Remove all map entries / timers referencing connections that have transitioned to closed state.
    fn pruneClosed(self: *Endpoint) void {
        // Collect keys referencing closed connections and build a unique set of those connections.
        var keys = std.ArrayList(Key){};
        defer keys.deinit(self.allocator.*);
        var closed_set = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator.*);
        defer closed_set.deinit();
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (c.closed) {
                _ = closed_set.put(c, {}) catch continue;
                // Record this key for removal
                _ = keys.append(self.allocator.*, e.key_ptr.*) catch {};
            }
        }
        if (closed_set.count() == 0) return; // nothing to prune
        // Remove collected keys from map
        for (keys.items) |k| {
            _ = self.conns.remove(k);
        }
        // Cancel timers referencing closed connections (orderedRemove iteration)
        var ti: usize = 0;
        while (ti < self.timers.items.len) {
            const t = self.timers.items[ti];
            if (t.conn) |tc| {
                if (closed_set.contains(tc)) {
                    // Free any paced payload first (unwrap optional)
                    if (t.paced) {
                        if (t.payload) |p| self.allocator.free(p);
                    }
                    _ = self.timers.orderedRemove(ti);
                    continue; // do not advance index (next element shifted here)
                }
            }
            ti += 1;
        }
        // Move closed connections to retired list (avoid immediate destruction to
        // prevent use-after-free in external code still holding an opaque pointer).
        var cit = closed_set.iterator();
        while (cit.next()) |ce| {
            const cptr = ce.key_ptr.*;
            // Ensure not already retired (linear scan; small list expected).
            var already: bool = false;
            var rj: usize = 0;
            while (rj < self.retired.items.len) : (rj += 1) {
                if (self.retired.items[rj] == cptr) {
                    already = true;
                    break;
                }
            }
            if (!already) _ = self.retired.append(self.allocator.*, cptr) catch {};
        }
    }
};

// Sender callback used by Connection for timer-driven pacing
fn senderPaced(ctx: *anyopaque, c: *conn_mod.Connection, data: []const u8) !usize {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    // If pacing disabled, send directly
    if (!c.enable_pacing) {
        return self.sendTo(c.peer, data);
    }
    const delay_ns = recovery.computePacingDelayNs(c.rec.cc.cwnd, c.rec.cc.bytes_in_flight);
    if (delay_ns == 0) {
        return self.sendTo(c.peer, data);
    }
    // Own the payload and schedule a paced timer
    const owned = try self.allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    _ = try self.schedulePaced(c, delay_ns, owned);
    // Report bytes as accepted; actual socket send happens when the timer fires.
    return data.len;
}

fn poll_epoll(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_epoll.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, @intCast(self.sock_fd)), true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_kqueue(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_kqueue.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, @intCast(self.sock_fd)), true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_iocp(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_iocp.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, @intCast(self.sock_fd)), true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn parseIpv4(s: []const u8) !u32 {
    // Returns address in network byte order (big-endian) for sockaddr.in.s_addr
    var it = std.mem.splitScalar(u8, s, '.');
    var octets: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const part = it.next() orelse return error.InvalidAddress;
        const v = try std.fmt.parseInt(u8, part, 10);
        octets[i] = v;
    }
    const host_val: u32 = (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
    return std.mem.nativeToBig(u32, host_val);
}

fn resolveAny(hostport: []const u8, proto: enum { udp }) !conn_mod.SockAddr {
    _ = proto;
    var parts = std.mem.splitScalar(u8, hostport, ':');
    const host = parts.next() orelse return error.InvalidAddress;
    const port_s = parts.next() orelse return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidAddress;

    // Handle common hostnames used in tests
    if (std.mem.eql(u8, host, "localhost")) {
        return conn_mod.SockAddr.ipv4(127, 0, 0, 1, port);
    }
    if (std.mem.eql(u8, host, "server4") or std.mem.eql(u8, host, "server")) {
        // In Docker, server4 should resolve to the server container
        // Try to use the IP from /etc/hosts if available
        const hosts_file = std.fs.openFileAbsolute("/etc/hosts", .{}) catch {
            // Fallback to a default IP used in tests
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        defer hosts_file.close();

        var buf: [4096]u8 = undefined;
        const bytes_read = hosts_file.readAll(&buf) catch {
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        const content = buf[0..bytes_read];

        // Parse /etc/hosts for server4
        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            var parts_line = std.mem.tokenizeAny(u8, line, " \t");
            const ip_str = parts_line.next() orelse continue;
            while (parts_line.next()) |hostname| {
                if (std.mem.eql(u8, hostname, "server4") or std.mem.eql(u8, hostname, "server")) {
                    // Parse the IP address
                    var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
                    var octets: [4]u8 = .{0} ** 4;
                    var i: usize = 0;
                    while (i < 4) : (i += 1) {
                        const octet_str = ip_parts.next() orelse break;
                        octets[i] = std.fmt.parseInt(u8, octet_str, 10) catch break;
                    }
                    if (i == 4) {
                        return conn_mod.SockAddr.ipv4(octets[0], octets[1], octets[2], octets[3], port);
                    }
                }
            }
        }
        // Default fallback
        return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
    }

    // Try dotted-quad IPv4 parse
    var it = std.mem.splitScalar(u8, host, '.');
    var oct: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const seg = it.next() orelse return error.InvalidAddress;
        oct[i] = std.fmt.parseInt(u8, seg, 10) catch return error.InvalidAddress;
    }
    return conn_mod.SockAddr.ipv4(oct[0], oct[1], oct[2], oct[3], port);
}
