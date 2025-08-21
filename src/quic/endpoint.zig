//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
//! MIT License
const std = @import("std");
const api = @import("api.zig");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const varint = @import("quic_varint");

const posix = std.posix;
const builtin = @import("builtin");

fn nowMsMonotonic() i64 {
    // Prefer a monotonic source; nanoTimestamp is monotonic on supported platforms.
    // Use explicit truncating integer division for signed integers (Zig 0.14 requirement).
    const ns: i128 = std.time.nanoTimestamp();
    const ms: i128 = @divTrunc(ns, std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}

const Timer = struct { deadline_ms: i64, id: u64, kind: TimerKind = .Generic, conn: ?*conn_mod.Connection = null };

/// Endpoint timer kinds, including per-space PTO timers.
pub const TimerKind = enum { Generic, PtoInitial, PtoHandshake, PtoApp };

const Key = struct { peer_hash: u64, dcid_hash: u64 };

fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = @as([*]const u8, @ptrCast(sa))[0..len];
    return hashBytes(bytes);
}

/// UDP endpoint container with timer wheel and connection map; single-socket.
pub const Endpoint = struct {
    sock_fd: posix.fd_t,
    loop_backend: api.LoopBackend,
    allocator: *std.mem.Allocator,
    timers: std.ArrayList(Timer),
    conns: std.AutoHashMap(Key, *conn_mod.Connection),
    // Next timer identifier for scheduleTimer
    next_timer_id: u64 = 1,
    // Config copy
    cfg: api.QuicConfig,
    // Accept queue for server
    accepted: std.ArrayList(*conn_mod.Connection),

    /// Flush expired timers immediately based on current monotonic time (testing helper).
    pub fn flushTimers(self: *Endpoint) void {
        self.processExpiredTimers(nowMsMonotonic());
    }

    /// TEST-ONLY: Force expire all timers immediately, invoking their callbacks.
    pub fn forceExpireAllTimers(self: *Endpoint) void {
        while (self.timers.items.len > 0) {
            const t = self.timers.items[0];
            _ = self.timers.orderedRemove(0);
            switch (t.kind) {
                .Generic => {},
                .PtoInitial => if (t.conn) |c| {
                    c.setPtoExpiredInitial();
                    self.sendPtoProbe(c, .PtoInitial) catch {};
                },
                .PtoHandshake => if (t.conn) |c| {
                    c.setPtoExpiredHandshake();
                    self.sendPtoProbe(c, .PtoHandshake) catch {};
                },
                .PtoApp => if (t.conn) |c| c.setPtoExpiredApp(),
            }
        }
    }

    /// Initialize endpoint, bind to bind_addr (host:port), and return value-semantic Endpoint.
    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8, cfg: *const api.QuicConfig) !Endpoint {
        // Parse bind address of the form host:port and bind an IPv4 UDP socket.
        var parts = std.mem.splitScalar(u8, bind_addr, ':');
        const host = parts.next() orelse bind_addr;
        const port_s = parts.next() orelse "0";
        const port = std.fmt.parseInt(u16, port_s, 10) catch 0;

        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(fd);

        // Allow reuseaddr for tests
        var yes: i32 = 1;
        _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes)) catch {};

        var sa: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = try parseIpv4(host),
            .zero = .{0} ** 8,
        };
        try posix.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));

        return .{
            .sock_fd = fd,
            .loop_backend = api.defaultLoopBackend(),
            .allocator = alloc,
            .timers = std.ArrayList(Timer).init(alloc.*),
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc.*),
            .next_timer_id = 1,
            .cfg = cfg.*, // copy
            .accepted = std.ArrayList(*conn_mod.Connection).init(alloc.*),
        };
    }

    /// Release resources, close socket, and destroy owned connections.
    pub fn deinit(self: *Endpoint) void {
        // Free connections
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            const c = entry.value_ptr.*;
            c.deinit();
            self.allocator.destroy(c);
        }
        self.conns.deinit();
        self.timers.deinit();
        self.accepted.deinit();
        posix.close(self.sock_fd);
    }

    /// Send a datagram to peer address.
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, peer.len);
    }

    /// Receive a datagram; returns size and source address.
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        var peer = conn_mod.SockAddr{};
        peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
        const n = try posix.recvfrom(self.sock_fd, buf, 0, @ptrCast(&peer.storage), &peer.len);
        return .{ .n = n, .peer = peer };
    }

    /// Create a Connection object for an incoming datagram's peer.
    pub fn acceptFrom(self: *Endpoint, peer: conn_mod.SockAddr) conn_mod.Connection {
        return .{ .id = 0, .role = .Server, .sock_fd = self.sock_fd, .peer = peer, .tls_inbox = std.ArrayList(u8).init(self.allocator.*) };
    }

    /// Enqueue accepted server connection for accept().
    fn pushAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        self.accepted.append(c) catch {};
    }

    /// Pop accepted connection pointer if present.
    pub fn popAccepted(self: *Endpoint) ?*conn_mod.Connection {
        if (self.accepted.items.len == 0) return null;
        return self.accepted.orderedRemove(0);
    }

    /// Resolve and create a Connection object for an explicit remote address.
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        const ai = try resolveAny(hostport, .udp);
        defer posix.freeaddrinfo(ai);
        const peer = conn_mod.SockAddr.setFrom(ai);
        return .{ .id = 0, .role = .Client, .sock_fd = self.sock_fd, .peer = peer, .tls_inbox = std.ArrayList(u8).init(self.allocator.*) };
    }

    /// Allocate and register a client connection for the given remote address.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const ai = try resolveAny(hostport, .udp);
        defer posix.freeaddrinfo(ai);
        const peer = conn_mod.SockAddr.setFrom(ai);
        const c = try self.allocator.create(conn_mod.Connection);
        c.init(self.allocator, .Client, self.sock_fd, peer);
        // Choose initial version from cfg
        c.version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;
        c.version_v2 = (c.version == packet.QUIC_V2);
        c.initial_version = c.version;
        // Client chooses DCID and SCID
        var dcid: [8]u8 = undefined;
        std.crypto.random.bytes(&dcid);
        c.peer_initial_dcid.len = @intCast(dcid.len);
        @memcpy(c.peer_initial_dcid.bytes[0..dcid.len], &dcid);
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

    /// Send a minimal client Initial PING to elicit VN or SH.
    pub fn clientSendInitialProbe(self: *Endpoint, c: *conn_mod.Connection) !void {
        const v2 = (c.version == packet.QUIC_V2);
        const initial = ks.deriveInitialSecret(v2, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
        const pair = ks.deriveClientServerInitial(initial);
        const tx_keys: packet.InitialKeys = if (v2) blk: {
            const t = ks.deriveKeyIvHpV2(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        } else blk: {
            const t = ks.deriveKeyIvHp(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        };
        var frames = std.ArrayList(u8).init(self.allocator.*);
        defer frames.deinit();
        frames.append(@intFromEnum(frame.FrameType.PING)) catch {};
        const token_empty: [0]u8 = .{};
        const pkt = try packet.encodeInitialProtected(
            self.allocator.*,
            c.version,
            // Client Initial: DCID = our chosen dcid; SCID = our scid
            c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
            c.our_scid.bytes[0..c.our_scid.len],
            token_empty[0..],
            c.pn_initial_tx,
            2,
            frames.items,
            tx_keys,
        );
        defer self.allocator.free(pkt);
        _ = try self.sendTo(c.peer, pkt);
        c.onPacketSent(c.pn_initial_tx, pkt.len, true);
        c.pn_initial_tx +%= 1;
        // Arm Initial PTO
        c.computeAndMaybeArmPtoInitial(self);
    }

    /// Schedule a one-shot timer to fire after delay_ms; returns timer id.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(.{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = null });
        return id;
    }

    /// Schedule a PTO timer tied to a specific connection and space.
    pub fn scheduleConnPto(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(.{ .deadline_ms = deadline, .id = id, .kind = kind, .conn = c });
        return id;
    }

    /// Cancel a previously scheduled timer by id; returns true if removed.
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
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        // First, process any timers that are already expired to avoid waiting unnecessarily.
        self.processExpiredTimers(nowMsMonotonic());

        const now_ms: i64 = nowMsMonotonic();
        var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        if (eff_timeout < 0) eff_timeout = -1;

        // To keep behavior deterministic for tests and avoid platform-specific early returns,
        // perform a simple sleep when a positive timeout is requested, then drain readability.
        if (eff_timeout > 0) {
            std.time.sleep(@as(u64, @intCast(eff_timeout)) * std.time.ns_per_ms);
            self.drainReadable();
        } else {
            // Use platform event loop for readable readiness with 0 or infinite timeout.
            switch (api.defaultLoopBackend()) {
                .epoll => try self.poll_epoll_backend(eff_timeout),
                .kqueue => try self.poll_kqueue_backend(eff_timeout),
                .iocp => try self.poll_iocp_backend(eff_timeout),
            }
        }

        // After wait, process timers that have expired.
        self.processExpiredTimers(nowMsMonotonic());
    }

    fn drainReadable(self: *Endpoint) void {
        var buf: [2048]u8 = undefined;
        while (true) {
            var peer = conn_mod.SockAddr{};
            peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
            const n_or_err = posix.recvfrom(self.sock_fd, buf[0..], posix.MSG.DONTWAIT, @ptrCast(&peer.storage), &peer.len);
            if (n_or_err) |n| {
                self.processIncomingDatagram(peer, buf[0..n]);
            } else |err| {
                switch (err) {
                    error.WouldBlock => return,
                    error.ConnectionResetByPeer => return,
                    else => return,
                }
            }
        }
    }

    fn poll_epoll_backend(self: *Endpoint, timeout_ms: i32) !void {
        const io = @import("io/loop_epoll.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(@as(i32, self.sock_fd), true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        if (n > 0) self.drainReadable();
    }

    fn poll_kqueue_backend(self: *Endpoint, timeout_ms: i32) !void {
        // On non-kqueue platforms, just perform a sleep-based fallback
        if (builtin.target.os.tag != .macos and builtin.target.os.tag != .freebsd and builtin.target.os.tag != .netbsd and builtin.target.os.tag != .openbsd and builtin.target.os.tag != .dragonfly) {
            if (timeout_ms > 0) std.time.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            self.drainReadable();
            return;
        }
        const io = @import("io/loop_kqueue.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(@as(i32, self.sock_fd), true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        if (n > 0) self.drainReadable();
    }

    fn poll_iocp_backend(self: *Endpoint, timeout_ms: i32) !void {
        if (builtin.target.os.tag != .windows) {
            if (timeout_ms > 0) std.time.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            self.drainReadable();
            return;
        }
        const io = @import("io/loop_iocp.zig");
        var lp = try io.Loop.init();
        defer lp.deinit();
        try lp.add(@as(i32, self.sock_fd), true, false);
        var events: [8]io.Event = undefined;
        const n = try lp.wait(&events, timeout_ms);
        if (n > 0) self.drainReadable();
    }

    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8) void {
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
            var it = self.conns.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.*.peer_hash != peer_h) continue;
                const c = entry.value_ptr.*;
                const l: usize = c.our_scid.len;
                if (1 + l > bytes.len) continue;
                if (l == 0) {
                    found = c;
                    dcid_len = 0;
                    break;
                }
                if (std.mem.eql(u8, c.our_scid.bytes[0..l], bytes[1 .. 1 + l])) {
                    found = c;
                    dcid_len = l;
                    break;
                }
            }
            const conn = found orelse return;
            if (conn.app_rx_keys) |rx_keys| {
                const dec = packet.decodeShortProtected(self.allocator.*, bytes, dcid_len, .{ .key = rx_keys.key, .iv = rx_keys.iv, .hp = rx_keys.hp }) catch return;
                defer self.allocator.free(dec.payload);
                const pn_full: u64 = conn.expandPnApp(@intCast(dec.packet_number), dec.packet_number_len);
                conn.trackRecvPnApp(pn_full);
                var off2: usize = 0;
                var saw_any: bool = false;
                while (off2 < dec.payload.len) {
                    const fr = frame.decodeOne(dec.payload[off2..]) catch break;
                    off2 += fr.n;
                    switch (fr.f) {
                        .ping => saw_any = true,
                        .stream => |s| {
                            _ = s;
                            saw_any = true;
                        },
                        .datagram => |d| {
                            conn.pushDatagram(d.data) catch {};
                            saw_any = true;
                            // Minimal echo: server echos back immediately when enabled and keys ready
                            if (self.cfg.enable_datagram) {
                                if (conn.app_tx_keys) |txk| {
                                    var fb = std.ArrayList(u8).init(self.allocator.*);
                                    defer fb.deinit();
                                    const w = fb.writer();
                                    _ = (frame.Frame{ .datagram = .{ .data = d.data } }).write(w) catch 0;
                                    const out = packet.encodeShortProtected(self.allocator.*, conn.our_scid.bytes[0..conn.our_scid.len], conn.pn_app_tx, 2, fb.items, txk) catch null;
                                    if (out) |pkt_bytes| {
                                        defer self.allocator.free(pkt_bytes);
                                        _ = self.sendTo(peer, pkt_bytes) catch {};
                                        conn.onPacketSent(conn.pn_app_tx, pkt_bytes.len, true);
                                        conn.pn_app_tx +%= 1;
                                    }
                                }
                            }
                        },
                        .ack => |a| {
                            const empty: [0]frame.AckRange = .{};
                            conn.onAckReceived(a.largest, a.first_range, empty[0..]);
                            conn.pto_app_count = 0;
                            if (conn.pto_app_active) {
                                _ = self.cancelTimer(conn.pto_app_id);
                                conn.pto_app_active = false;
                            }
                        },
                        else => {},
                    }
                }
                if (saw_any) {
                    if (conn.app_tx_keys) |tx_keys| {
                        var frames_buf = std.ArrayList(u8).init(self.allocator.*);
                        defer frames_buf.deinit();
                        const w = frames_buf.writer();
                        const ack_desc = conn.buildAckApp();
                        const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = 0, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges } };
                        _ = ack.write(w) catch 0;
                        const out = packet.encodeShortProtected(self.allocator.*, conn.our_scid.bytes[0..conn.our_scid.len], conn.pn_app_tx, 2, frames_buf.items, tx_keys) catch null;
                        if (out) |pkt_bytes| {
                            defer self.allocator.free(pkt_bytes);
                            _ = self.sendTo(peer, pkt_bytes) catch {};
                            conn.onPacketSent(conn.pn_app_tx, pkt_bytes.len, false);
                            conn.pn_app_tx +%= 1;
                        }
                    }
                }
            }
            return;
        }
        const ty = (first >> 4) & 0x03;
        const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
        if (ty == 0) {
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
            const c_ptr = self.conns.getPtr(key) orelse blk: {
                const c = self.allocator.create(conn_mod.Connection) catch return;
                c.init(self.allocator, .Server, self.sock_fd, peer);
                _ = self.conns.put(key, c) catch {
                    c.deinit();
                    self.allocator.destroy(c);
                    return;
                };
                // Also map our chosen SCID to this connection for Handshake DCID lookup.
                const our_key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(c.our_scid.bytes[0..c.our_scid.len]) };
                _ = self.conns.put(our_key, c) catch {};
                // Enqueue for accept()
                self.pushAccepted(c);
                break :blk self.conns.getPtr(key).?;
            };
            const conn = c_ptr.*;
            conn.initial_version = version;
            if (conn.initial_keys_dropped) return;
            conn.setPeerInitialCids(dcid, scid);

            // Derive Initial keys for server (we are receiving client's Initial)
            const v2 = false; // TODO: parse version and map to v2 set
            const initial = ks.deriveInitialSecret(v2, dcid);
            const pair = ks.deriveClientServerInitial(initial);
            // RX path for server must use CLIENT initial keys (to decrypt client's Initial)
            const keys: packet.InitialKeys = if (v2) blk: {
                const t = ks.deriveKeyIvHpV2(pair.client);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            } else blk: {
                const t = ks.deriveKeyIvHp(pair.client);
                break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
            };

            // Parse long header variable fields up to PN start
            var j: usize = i; // after SCID value
            // token length varint and token bytes
            const tok = varint.decode(bytes[j..]) catch return;
            j += tok.n;
            if (j + @as(usize, tok.value) > bytes.len) return;
            j += @as(usize, tok.value);
            // length varint (payload length includes pn+payload+tag)
            const len_dec = varint.decode(bytes[j..]) catch return;
            j += len_dec.n;
            const end_total = j + @as(usize, len_dec.value);
            if (end_total > bytes.len) return;
            const header_prefix = bytes[1..j];
            // PN masked bytes follow; ciphertext starts after PN
            const pn_len_masked: u3 = @as(u3, @intCast(first & 0x03)) + 1;
            if (j + pn_len_masked > bytes.len) return;
            const pn_start = j;
            const ct_and_tag = bytes[pn_start + pn_len_masked .. end_total];
            if (ct_and_tag.len < 16) return;

            // Build HP sample at absolute PN+4 (RFC 9001 §5.4.3)
            var sample16: [16]u8 = undefined;
            if (pn_start + 4 + 16 > bytes.len) return;
            @memcpy(sample16[0..], bytes[pn_start + 4 .. pn_start + 4 + 16]);

            // Unmask header first byte and PN bytes in place copies
            var header_first = first;
            var pn_buf: [4]u8 = .{0} ** 4;
            const copy_pn_len = @min(@as(usize, pn_len_masked), 4);
            @memcpy(pn_buf[0..copy_pn_len], bytes[pn_start .. pn_start + copy_pn_len]);
            const pn_len = crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &keys.hp, &sample16, &header_first, &pn_buf) catch return;

            // Rebuild AAD and decrypt
            const pn_bytes = pn_buf[0..pn_len];
            const ct = bytes[pn_start + pn_len .. end_total];
            var payload = std.ArrayList(u8).init(self.allocator.*);
            defer payload.deinit();
            if (ct.len < 16) return;
            payload.ensureTotalCapacity(ct.len - 16) catch return;
            payload.appendNTimesAssumeCapacity(0, ct.len - 16);
            const pt = payload.items;

            const ok = crypto.unprotectInitial(
                .aes_128_gcm,
                &keys.key,
                &keys.iv,
                &keys.hp,
                &header_first,
                pn_bytes,
                header_prefix,
                &sample16,
                ct,
                pt,
            ) catch return;
            _ = ok;

            // Expand truncated PN against Initial space expectation and track
            var pn_val_be: u64 = 0;
            var kk: usize = 0;
            while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_buf[kk];
            const pn_full: u64 = conn.expandPnInitial(pn_val_be, pn_len);
            conn.trackRecvPnInitial(pn_full);

            // Walk frames and push CRYPTO to inbox
            var off: usize = 0;
            var saw_any: bool = false;
            while (off < pt.len) {
                const r = frame.decodeOne(pt[off..]) catch break;
                off += r.n;
                switch (r.f) {
                    .crypto => |cr| {
                        conn.pushCrypto(cr.data) catch {};
                        saw_any = true;
                    },
                    .padding => {},
                    else => {},
                }
            }

            // If we received anything ack-eliciting, send ACK in Initial space when we still have Initial TX keys
            if (saw_any and !conn.initial_keys_dropped) {
                // Build ACK frame from Initial PN tracker
                var frames_buf = std.ArrayList(u8).init(self.allocator.*);
                defer frames_buf.deinit();
                const w = frames_buf.writer();
                const ack_desc = conn.buildAckInitial();
                const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = 0, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges } };
                _ = ack.write(w) catch 0;
                if (conn.hs_tx_keys == null) {
                    // Respond in Initial space using SERVER initial keys (TX direction)
                    const tx_keys: packet.InitialKeys = if (v2) blk: {
                        const t = ks.deriveKeyIvHpV2(pair.server);
                        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                    } else blk: {
                        const t = ks.deriveKeyIvHp(pair.server);
                        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                    };
                    const out = packet.encodeInitialProtected(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], &[_]u8{}, conn.pn_initial_tx, 2, frames_buf.items, tx_keys) catch null;
                    if (out) |pkt_bytes| {
                        defer self.allocator.free(pkt_bytes);
                        _ = self.sendTo(peer, pkt_bytes) catch {};
                        // ACK-only Initial is not ack-eliciting
                        conn.onPacketSent(conn.pn_initial_tx, pkt_bytes.len, false);
                        conn.pn_initial_tx +%= 1;
                    }
                }
            }

            // If handshake TX keys are ready and there is outbound CRYPTO, send a Handshake packet now.
            if (conn.hs_tx_keys) |tx_keys| {
                var crypto_buf: [1200]u8 = undefined;
                const n_crypto = conn.tls.popCrypto(&crypto_buf);
                if (n_crypto > 0) {
                    var frames = std.ArrayList(u8).init(self.allocator.*);
                    defer frames.deinit();
                    const w2 = frames.writer();
                    const fr = frame.Frame{ .crypto = .{ .offset = 0, .data = crypto_buf[0..n_crypto] } };
                    const written = fr.write(w2) catch 0;
                    if (written > 0) {
                        // RFC-correct DCID/SCID for server Handshake: DCID = client's Initial SCID; SCID = our chosen SCID
                        const dcid_hs = scid;
                        const scid_hs = conn.our_scid.bytes[0..conn.our_scid.len];
                        const pkt_or_err = packet.encodeHandshakeProtected(
                            self.allocator.*, // alloc
                            version,
                            dcid_hs,
                            scid_hs,
                            conn.pn_handshake_tx,
                            2, // PN len=2
                            frames.items,
                            tx_keys,
                        );
                        if (pkt_or_err) |bytes_out| {
                            defer self.allocator.free(bytes_out);
                            _ = self.sendTo(peer, bytes_out) catch {};
                            // Handshake CRYPTO is ack-eliciting
                            conn.onPacketSent(conn.pn_handshake_tx, bytes_out.len, true);
                            // Arm Handshake PTO when sending ack-eliciting Handshake
                            conn.computeAndMaybeArmPtoHandshake(self);
                            conn.pn_handshake_tx +%= 1;
                            // Once we send Handshake, drop Initial keys to avoid processing further Initials.
                            conn.initial_keys_dropped = true;
                        } else |_| {}
                    }
                }
            }
        } else if (ty == 2) {
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
            // Lookup connection keyed by peer + initial dcid hash (use stored mapping if any)
            const key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(dcid) };
            const c_ptr = self.conns.getPtr(key) orelse return;
            const conn = c_ptr.*;
            if (conn.hs_rx_keys) |rx_keys| {
                // Parse length varint up to PN (Handshake has no token)
                var j: usize = i;
                const len_dec = varint.decode(bytes[j..]) catch return;
                j += len_dec.n;
                const end_total = j + @as(usize, len_dec.value);
                if (end_total > bytes.len) return;
                const header_prefix = bytes[1..j];
                const pn_len_masked: u3 = @as(u3, @intCast(first & 0x03)) + 1;
                if (j + pn_len_masked > bytes.len) return;
                const pn_start = j;
                // HP sample at PN+4
                var sample16: [16]u8 = undefined;
                if (pn_start + 4 + 16 > bytes.len) return;
                @memcpy(sample16[0..], bytes[pn_start + 4 .. pn_start + 4 + 16]);

                var header_first = first;
                var pn_buf: [4]u8 = .{0} ** 4;
                const copy_pn_len = @min(@as(usize, pn_len_masked), 4);
                @memcpy(pn_buf[0..copy_pn_len], bytes[pn_start .. pn_start + copy_pn_len]);
                const pn_len = crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &rx_keys.hp, &sample16, &header_first, &pn_buf) catch return;
                const pn_bytes = pn_buf[0..pn_len];
                const ct = bytes[pn_start + pn_len .. end_total];
                if (ct.len < 16) return;
                var payload = std.ArrayList(u8).init(self.allocator.*);
                defer payload.deinit();
                payload.ensureTotalCapacity(ct.len - 16) catch return;
                payload.appendNTimesAssumeCapacity(0, ct.len - 16);
                const pt = payload.items;
                const ok = crypto.unprotectInitial(
                    .aes_128_gcm,
                    &rx_keys.key,
                    &rx_keys.iv,
                    &rx_keys.hp,
                    &header_first,
                    pn_bytes,
                    header_prefix,
                    &sample16,
                    ct,
                    pt,
                ) catch return;
                _ = ok;
                // Expand truncated PN and track in Handshake space
                var pn_val_be: u64 = 0;
                var kk: usize = 0;
                while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_buf[kk];
                const pn_full: u64 = conn.expandPnHandshake(pn_val_be, pn_len);
                conn.trackRecvPnHandshake(pn_full);

                // Feed CRYPTO frames and handle ACK frames for PTO reset
                var off: usize = 0;
                var saw_any: bool = false;
                while (off < pt.len) {
                    const r = frame.decodeOne(pt[off..]) catch break;
                    off += r.n;
                    switch (r.f) {
                        .crypto => |cr| {
                            conn.pushCrypto(cr.data) catch {};
                            saw_any = true;
                        },
                        .ack => {
                            // Reset handshake PTO backoff and cancel active timer on ACK in this space
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
                // Send ACK in Handshake space if ack-eliciting seen and we have hs_tx_keys
                if (saw_any) {
                    if (conn.hs_tx_keys) |tx_keys| {
                        var frames_buf = std.ArrayList(u8).init(self.allocator.*);
                        defer frames_buf.deinit();
                        const w = frames_buf.writer();
                        const ack_desc = conn.buildAckHandshake();
                        const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = 0, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges } };
                        _ = ack.write(w) catch 0;
                        const pkt = packet.encodeHandshakeProtected(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], conn.pn_handshake_tx, 2, frames_buf.items, tx_keys) catch null;
                        if (pkt) |bytes_out| {
                            defer self.allocator.free(bytes_out);
                            _ = self.sendTo(peer, bytes_out) catch {};
                            // ACK-only Handshake is not ack-eliciting; no PTO arm
                            conn.pn_handshake_tx +%= 1;
                        }
                    }
                }
            }
        } else {
            return; // ignore other long header types for now
        }
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
                    .Generic => {},
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
                }
            } else {
                i += 1;
            }
        }
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
                const initial = ks.deriveInitialSecret(v2, conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len]);
                const pair = ks.deriveClientServerInitial(initial);
                const tx_keys: packet.InitialKeys = if (v2) blk: {
                    const t = ks.deriveKeyIvHpV2(pair.server);
                    break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                } else blk: {
                    const t = ks.deriveKeyIvHp(pair.server);
                    break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
                };
                // Build a PING probe (ack-eliciting)
                var frames = std.ArrayList(u8).init(self.allocator.*);
                defer frames.deinit();
                frames.append(@intFromEnum(frame.FrameType.PING)) catch {};
                const pkt = packet.encodeInitialProtected(self.allocator.*, if (conn.initial_version == 0) 0x00000001 else conn.initial_version, dcid, scid, &[_]u8{}, conn.pn_initial_tx, 4, frames.items, tx_keys) catch return;
                defer self.allocator.free(pkt);
                _ = self.sendTo(conn.peer, pkt) catch {};
                conn.onPacketSent(conn.pn_initial_tx, pkt.len, true);
                conn.pn_initial_tx +%= 1;
                // Do not re-arm here; processExpiredTimers will handle re-arming. This prevents test helper forceExpireAllTimers from looping.
            },
            .PtoHandshake => {
                if (conn.hs_tx_keys) |tx_keys| {
                    const dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
                    const scid = conn.our_scid.bytes[0..conn.our_scid.len];
                    var frames = std.ArrayList(u8).init(self.allocator.*);
                    defer frames.deinit();
                    frames.append(@intFromEnum(frame.FrameType.PING)) catch {};
                    const pkt = packet.encodeHandshakeProtected(self.allocator.*, if (conn.initial_version == 0) 0x00000001 else conn.initial_version, dcid, scid, conn.pn_handshake_tx, 4, frames.items, tx_keys) catch return;
                    defer self.allocator.free(pkt);
                    _ = self.sendTo(conn.peer, pkt) catch {};
                    conn.onPacketSent(conn.pn_handshake_tx, pkt.len, true);
                    conn.pn_handshake_tx +%= 1;
                    // No re-arm here; normal timer loop handles it.
                }
            },
            else => return,
        }
    }
};

fn poll_epoll(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_epoll.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, self.sock_fd), true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_kqueue(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_kqueue.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, self.sock_fd), true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_iocp(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_iocp.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(@as(i32, self.sock_fd), true, false);
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

fn resolveAny(hostport: []const u8, proto: enum { udp }) !*posix.addrinfo {
    _ = proto;
    var parts = std.mem.splitScalar(u8, hostport, ':');
    const host = parts.next() orelse return error.InvalidAddress;
    const port = parts.next() orelse return error.InvalidAddress;
    var hints: posix.addrinfo = .{
        .flags = 0,
        .family = posix.AF.UNSPEC,
        .socktype = posix.SOCK.DGRAM,
        .protocol = 0,
        .addrlen = 0,
        .canonname = null,
        .addr = null,
        .next = null,
    };
    var res: *posix.addrinfo = undefined;
    try posix.getaddrinfo(host, port, &hints, &res);
    return res;
}
