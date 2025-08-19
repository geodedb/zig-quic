//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
//! MIT License
const std = @import("std");
const api = @import("api.zig");
const conn_mod = @import("conn.zig");
const packet = @import("packet.zig");
const frame = @import("quic_frame");
const ks = @import("tls/key_schedule.zig");
const crypto = @import("quic_crypto");
const varint = @import("quic_varint");

const posix = std.posix;

fn nowMsMonotonic() i64 {
    // Prefer a monotonic source; nanoTimestamp is monotonic on supported platforms.
    // Use explicit truncating integer division for signed integers (Zig 0.14 requirement).
    const ns: i128 = std.time.nanoTimestamp();
    const ms: i128 = @divTrunc(ns, std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}

const Timer = struct { deadline_ms: i64, id: u64 };

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

pub const Endpoint = struct {
    sock_fd: posix.fd_t,
    loop_backend: api.LoopBackend,
    allocator: *std.mem.Allocator,
    timers: std.ArrayList(Timer),
    conns: std.AutoHashMap(Key, *conn_mod.Connection),
    // Next timer identifier for scheduleTimer
    next_timer_id: u64 = 1,

    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8) !Endpoint {
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
        };
    }

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
        posix.close(self.sock_fd);
    }

    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, peer.len);
    }

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

    /// Resolve and create a Connection object for an explicit remote address.
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        const ai = try resolveAny(hostport, .udp);
        defer posix.freeaddrinfo(ai);
        const peer = conn_mod.SockAddr.setFrom(ai);
        return .{ .id = 0, .role = .Client, .sock_fd = self.sock_fd, .peer = peer, .tls_inbox = std.ArrayList(u8).init(self.allocator.*) };
    }

    /// Schedule a one-shot timer to fire after delay_ms; returns timer id.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(.{ .deadline_ms = deadline, .id = id });
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
        const now_ms: i64 = nowMsMonotonic();
        var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        if (eff_timeout < 0) eff_timeout = -1;
        // Deterministic wait without relying on OS event loops for tests
        if (eff_timeout > 0) {
            std.time.sleep(@as(u64, @intCast(eff_timeout)) * std.time.ns_per_ms);
        } else if (eff_timeout == 0) {
            // yield once
            std.time.sleep(0);
        }
        // Drain readable datagrams (nonblocking)
        var buf: [2048]u8 = undefined;
        while (true) {
            var peer = conn_mod.SockAddr{};
            peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
            const n_or_err = posix.recvfrom(self.sock_fd, buf[0..], posix.MSG.DONTWAIT, @ptrCast(&peer.storage), &peer.len);
            if (n_or_err) |n| {
                self.processIncomingDatagram(peer, buf[0..n]);
            } else |err| {
                switch (err) {
                    error.WouldBlock => break,
                    error.ConnectionResetByPeer => break,
                    else => break,
                }
            }
        }
        // After wait, process timers that have expired.
        self.processExpiredTimers(nowMsMonotonic());
    }

    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8) void {
        if (bytes.len < 7) return;
        const first = bytes[0];
        const is_long = (first & 0x80) != 0;
        if (!is_long) return; // handle short later
        const ty = (first >> 4) & 0x03;
        if (ty != 0) return; // only Initial for now
        // Version
        const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
        // keep `version` for later Handshake reply construction
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
            break :blk self.conns.getPtr(key).?;
        };
        const conn = c_ptr.*;
        // Remember peer's Initial CIDs (for Handshake header construction)
        conn.setPeerInitialCids(dcid, scid);

        // Derive Initial keys for server (we are receiving client's Initial)
        const v2 = false; // TODO: parse version and map to v2 set
        const initial = ks.deriveInitialSecret(v2, dcid);
        const pair = ks.deriveClientServerInitial(initial);
        const sk = if (v2) ks.deriveKeyIvHpV2(pair.server) else ks.deriveKeyIvHp(pair.server);
        const keys: packet.InitialKeys = .{ .key = sk.key, .iv = sk.iv, .hp = sk.hp };

        // Parse long header variable fields up to PN start
        var j: usize = 5 + 1 + dcid_len + 1 + scid_len; // after SCID len+value
        // token length varint and token bytes
        const tok = varint.decode(bytes[j..]) catch return;
        j += tok.n + @as(usize, tok.value);
        // length varint (payload length includes pn+payload+tag)
        const len_dec = varint.decode(bytes[j..]) catch return;
        j += len_dec.n;
        const header_prefix = bytes[1..j];
        // PN masked bytes follow; ciphertext starts after PN
        const pn_len_masked: u3 = @as(u3, @intCast(first & 0x03)) + 1;
        if (j + pn_len_masked > bytes.len) return;
        const pn_start = j;
        const ct_and_tag = bytes[pn_start + pn_len_masked .. j + @as(usize, len_dec.value)];
        if (ct_and_tag.len < 16) return;

        // Build HP sample at absolute PN+4 (RFC 9001 §5.4.3)
        var sample16: [16]u8 = undefined;
        if (pn_start + 4 + 16 > bytes.len) return;
        @memcpy(sample16[0..], bytes[pn_start + 4 .. pn_start + 4 + 16]);

        // Unmask header first byte and PN bytes in place copies
        var header_first = first;
        var pn_buf: [4]u8 = .{0} ** 4;
        // Copy up to 4 masked PN bytes so helper can xor in place
        const copy_pn_len = @min(@as(usize, pn_len_masked), 4);
        @memcpy(pn_buf[0..copy_pn_len], bytes[pn_start .. pn_start + copy_pn_len]);
        const pn_len = crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &keys.hp, &sample16, &header_first, &pn_buf) catch return;

        // Rebuild AAD and decrypt
        const pn_bytes = pn_buf[0..pn_len];
        // ciphertext_and_tag starts immediately after PN (actual pn_len after unmask)
        const ct = bytes[pn_start + pn_len .. j + @as(usize, len_dec.value)];
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

        // Walk frames and push CRYPTO to inbox
        var off: usize = 0;
        while (off < pt.len) {
            const r = frame.decodeOne(pt[off..]) catch break;
            off += r.n;
            switch (r.f) {
                .crypto => |cr| conn.pushCrypto(cr.data) catch {},
                .padding => {},
                else => {},
            }
        }

        // If handshake TX keys are ready and there is outbound CRYPTO, send a Handshake packet now.
        if (conn.hs_tx_keys) |tx_keys| {
            // Drain TLS outbox
            var crypto_buf: [1200]u8 = undefined;
            const n_crypto = conn.tls.popCrypto(&crypto_buf);
            if (n_crypto > 0) {
                // Wrap in a CRYPTO frame offset=0 (simplified; no fragmentation)
                var frames = std.ArrayList(u8).init(self.allocator.*);
                defer frames.deinit();
                const w = frames.writer();
                const fr = frame.Frame{ .crypto = .{ .offset = 0, .data = crypto_buf[0..n_crypto] } };
                const written = fr.write(w) catch 0;
                if (written > 0) {
                    // Build Handshake packet DCID = peer SCID, SCID = some chosen (reuse dcid for now)
                    const dcid_hs = scid;
                    const scid_hs = dcid;
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
                        conn.pn_handshake_tx +%= 1;
                    } else |_| {
                        // ignore encode errors for now
                    }
                }
            }
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
                _ = self.timers.orderedRemove(i);
            } else {
                i += 1;
            }
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
