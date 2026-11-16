// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// A loopback UDP relay for tests with real QUIC endpoints (SONNY-6522,
// SONNY-6649). The client talks to the relay, which forwards each datagram
// to the server and back, as a network would. Nothing in the QUIC stack is
// replaced: the relay only decides which datagrams it forwards, and can
// capture one or send extra datagrams to the server from the client's path.

const std = @import("std");
const linux = std.os.linux;
const api = @import("quic_api");

pub fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// CLOCK_MONOTONIC in nanoseconds, the clock the QUIC stack's deadlines use.
pub fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn sleepUs(us: u64) void {
    const ts = linux.timespec{ .sec = @intCast(us / 1_000_000), .nsec = @intCast((us % 1_000_000) * 1000) };
    _ = linux.nanosleep(&ts, null);
}

pub fn loopback(port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
}

pub fn udpSocket(port: u16) !i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    // Large buffers: the relay must not be what drops.
    const big: i32 = 8 * 1024 * 1024;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&big), @sizeOf(i32));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDBUF, std.mem.asBytes(&big), @sizeOf(i32));
    var addr = loopback(port);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.BindFailed;
    }
    return fd;
}

/// What the relay learned about a 1-RTT packet: its key phase and packet
/// number, read by removing header protection with the sender's HP key
/// (RFC 9001 §5.4; the HP key does not change with a key update, §6).
pub const ShortInfo = struct { phase: bool, pn: u64 };

/// Counters and parameters a drop rule keeps for its test.
pub const RuleState = struct {
    dropped: u32 = 0,
    delivered_gen1: u32 = 0,
    /// A packet of key generation 2 was sent before any packet of
    /// generation 1 reached the peer.
    gen2_before_gen1_delivered: bool = false,
    max_gen: u32 = 0,
    /// Packet numbers in [drop_from, drop_until) are dropped by
    /// `dropPacketNumberRange`.
    drop_from: u64 = 0,
    drop_until: u64 = 0,
    /// Largest packet number the rule saw.
    max_pn: u64 = 0,
};

pub const Rule = *const fn (*RuleState, ShortInfo, u32) bool;

/// A test's own forwarding decision for 1-RTT packets, with its context.
pub const Filter = *const fn (ctx: *anyopaque, pkt: []const u8, info: ShortInfo) bool;

/// Drops the 1-RTT packets numbered [drop_from, drop_until): a blackout of
/// the path, after which packets get through again.
pub fn dropPacketNumberRange(st: *RuleState, info: ShortInfo, g: u32) bool {
    _ = g;
    if (info.pn > st.max_pn) st.max_pn = info.pn;
    if (info.pn >= st.drop_from and info.pn < st.drop_until) {
        st.dropped += 1;
        return false;
    }
    return true;
}

/// Forwards every packet, recording the largest key generation seen.
pub fn observeGenerations(st: *RuleState, info: ShortInfo, g: u32) bool {
    if (info.pn > st.max_pn) st.max_pn = info.pn;
    if (g > st.max_gen) st.max_gen = g;
    return true;
}

/// Reads the key phase and packet number of a 1-RTT packet by removing
/// header protection with the sender's HP key (RFC 9001 §5.4) and decoding
/// the packet number against `largest`, the largest decoded so far (RFC 9000
/// Appendix A.3), which it updates. Null when `pkt` is not a short header
/// long enough to carry a header protection sample.
pub fn decodeShortHeader(hp_key: [16]u8, dcid_len: usize, pkt: []const u8, largest: *?u64) ?ShortInfo {
    if (pkt.len == 0 or (pkt[0] & 0x80) != 0) return null;
    const pn_off = 1 + dcid_len;
    if (pkt.len < pn_off + 4 + 16) return null;
    const aes = std.crypto.core.aes.Aes128.initEnc(hp_key);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, pkt[pn_off + 4 ..][0..16]);
    const first = pkt[0] ^ (mask[0] & 0x1f);
    const pn_len: usize = (first & 0x03) + 1;
    var trunc: u64 = 0;
    for (0..pn_len) |i| trunc = (trunc << 8) | (pkt[pn_off + i] ^ mask[1 + i]);
    // The relay sees every packet the sender sends, so its largest is
    // always current.
    const expected: u64 = if (largest.*) |l| l + 1 else 0;
    const win: u64 = @as(u64, 1) << @intCast(pn_len * 8);
    const hwin = win / 2;
    var pn = (expected & ~(win - 1)) | trunc;
    if (pn + hwin <= expected and pn < (@as(u64, 1) << 62) - win) {
        pn += win;
    } else if (pn > expected + hwin and pn >= win) {
        pn -= win;
    }
    if (largest.* == null or pn > largest.*.?) largest.* = pn;
    return .{ .phase = (first & 0x04) != 0, .pn = pn };
}

/// The first bytes of every 1-RTT datagram a link forwarded, in order,
/// recorded whether or not the sender's header protection key is known yet:
/// packets sent while the handshake completes can be read once it is
/// (SONNY-6654). `head_len` bytes cover the header and the header
/// protection sample for any connection ID length.
pub const ShortLog = struct {
    pub const capacity: usize = 4096;
    pub const head_len: usize = 64;
    heads: [capacity][head_len]u8 = undefined,
    lens: [capacity]usize = undefined,
    count: std.atomic.Value(usize) = .init(0),

    fn record(self: *ShortLog, pkt: []const u8) void {
        if (pkt.len == 0 or (pkt[0] & 0x80) != 0) return;
        const n = self.count.load(.monotonic);
        if (n >= capacity) return;
        const len = @min(pkt.len, head_len);
        @memcpy(self.heads[n][0..len], pkt[0..len]);
        self.lens[n] = pkt.len;
        self.count.store(n + 1, .release);
    }

    /// The recorded head of datagram `i` (at most `head_len` bytes).
    pub fn head(self: *const ShortLog, i: usize) []const u8 {
        return self.heads[i][0..@min(self.lens[i], head_len)];
    }
};

pub const capture_capacity: usize = 2048;
pub const max_held: usize = 64;

/// One direction of the relay. Tracks the sender's key generation as seen on
/// the wire: it advances when a packet with a newer packet number carries
/// the other key phase bit.
pub const Link = struct {
    rule: ?Rule = null,
    /// Applied before `rule`; false drops the packet.
    filter: ?Filter = null,
    filter_ctx: *anyopaque = undefined,
    state: RuleState = .{},
    hp_ready: std.atomic.Value(bool) = .init(false),
    hp_key: [16]u8 = undefined,
    dcid_len: usize = 0,
    largest_pn: ?u64 = null,
    gen: u32 = 0,
    gen_phase: bool = false,
    gen_start_pn: u64 = 0,
    /// While set, every datagram starting with a short header (1-RTT) is
    /// dropped, whether or not its sender's keys are published yet.
    block_short: std.atomic.Value(bool) = .init(false),
    /// When set, the next 1-RTT datagram forwarded is copied to `captured`.
    capture: std.atomic.Value(bool) = .init(false),
    captured: [capture_capacity]u8 = undefined,
    captured_len: std.atomic.Value(usize) = .init(0),
    /// When set, packets of key generation 0 numbered from `hold_from_pn`
    /// are held back (at most `max_held`) instead of forwarded, until the
    /// test sets `release_requested`: a reordering across a key update.
    hold_from_pn: ?u64 = null,
    held: [max_held][capture_capacity]u8 = undefined,
    held_len: [max_held]usize = undefined,
    held_count: usize = 0,
    release_requested: std.atomic.Value(bool) = .init(false),
    /// Held datagrams sent, once released.
    released: std.atomic.Value(usize) = .init(0),
    /// 1-RTT packets of a key generation after the first, forwarded.
    later_gen_forwarded: std.atomic.Value(u32) = .init(0),
    /// When set, the head of every 1-RTT datagram forwarded is recorded,
    /// before the sender's keys are published (SONNY-6654).
    log: ?*ShortLog = null,

    /// Publishes the sender's header-protection key and the DCID length of
    /// its short headers, once its 1-RTT keys exist.
    pub fn publish(self: *Link, sender: *api.Connection) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        sender.mu.lockUncancelable(io);
        defer sender.mu.unlock(io);
        self.hp_key = sender.app_tx_keys.?.hp;
        self.dcid_len = sender.shortHeaderDcid().len;
        self.hp_ready.store(true, .release);
    }

    pub fn decodeShort(self: *Link, pkt: []const u8) ?ShortInfo {
        if (!self.hp_ready.load(.acquire)) return null;
        return decodeShortHeader(self.hp_key, self.dcid_len, pkt, &self.largest_pn);
    }

    fn generationOf(self: *Link, info: ShortInfo) u32 {
        if (info.phase == self.gen_phase) return self.gen;
        if (info.pn > self.gen_start_pn) {
            self.gen += 1;
            self.gen_phase = info.phase;
            self.gen_start_pn = info.pn;
            return self.gen;
        }
        // Reordered across the update: the previous generation.
        return self.gen -| 1;
    }

    /// Whether a datagram is forwarded now (false: dropped or held).
    fn forward(self: *Link, pkt: []const u8) bool {
        if (self.block_short.load(.acquire) and pkt.len > 0 and (pkt[0] & 0x80) == 0) {
            self.state.dropped += 1;
            return false;
        }
        if (self.log) |l| l.record(pkt);
        const info = self.decodeShort(pkt) orelse return true;
        if (self.capture.load(.acquire) and pkt.len <= capture_capacity) {
            @memcpy(self.captured[0..pkt.len], pkt);
            self.capture.store(false, .release);
            self.captured_len.store(pkt.len, .release);
        }
        if (self.filter) |f| {
            if (!f(self.filter_ctx, pkt, info)) {
                self.state.dropped += 1;
                return false;
            }
        }
        const g = self.generationOf(info);
        if (self.hold_from_pn) |from| {
            if (g == 0 and info.pn >= from and !self.release_requested.load(.acquire) and self.held_count < max_held and pkt.len <= capture_capacity) {
                @memcpy(self.held[self.held_count][0..pkt.len], pkt);
                self.held_len[self.held_count] = pkt.len;
                self.held_count += 1;
                return false;
            }
        }
        const rule = self.rule orelse {
            if (g > 0) _ = self.later_gen_forwarded.fetchAdd(1, .monotonic);
            return true;
        };
        const fwd = rule(&self.state, info, g);
        if (fwd and g > 0) _ = self.later_gen_forwarded.fetchAdd(1, .monotonic);
        return fwd;
    }

    /// The number of held datagrams to send now: all of them, once, after
    /// `release_requested`.
    fn takeDue(self: *Link) usize {
        if (!self.release_requested.load(.acquire) or self.released.load(.acquire) != 0) return 0;
        self.released.store(@max(self.held_count, 1), .release);
        return self.held_count;
    }

    /// The datagram captured after `capture` was set, if any yet.
    pub fn capturedDatagram(self: *Link) ?[]const u8 {
        const n = self.captured_len.load(.acquire);
        if (n == 0) return null;
        return self.captured[0..n];
    }
};

/// A UDP relay between the client and the server on loopback. The client
/// sends to `front_port`; the relay forwards to the server from its own
/// socket and relays the server's datagrams back. `up` (client to server)
/// and `down` (server to client) decide which 1-RTT datagrams get through.
pub const Relay = struct {
    front: i32,
    back: i32,
    front_port: u16,
    server: linux.sockaddr.in,
    client: linux.sockaddr.in = undefined,
    have_client: bool = false,
    done: std.atomic.Value(bool) = .init(false),
    up: Link = .{},
    down: Link = .{},

    pub fn init(server_port: u16) !Relay {
        const front = try udpSocket(0);
        errdefer _ = linux.close(front);
        var bound: linux.sockaddr.in = undefined;
        var bound_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.errno(linux.getsockname(front, @ptrCast(&bound), &bound_len)) != .SUCCESS) return error.GetSockNameFailed;
        const back = try udpSocket(0);
        return .{ .front = front, .back = back, .front_port = std.mem.bigToNative(u16, bound.port), .server = loopback(server_port) };
    }

    pub fn deinit(self: *Relay) void {
        _ = linux.close(self.front);
        _ = linux.close(self.back);
    }

    /// Sends `bytes` to the server from the relay's server-side socket: to
    /// the server it arrives on the client's path, like the client's own
    /// datagrams.
    pub fn sendToServer(self: *Relay, bytes: []const u8) void {
        _ = linux.sendto(self.back, bytes.ptr, bytes.len, 0, @ptrCast(&self.server), @sizeOf(linux.sockaddr.in));
    }

    pub fn run(self: *Relay) void {
        var buf: [65536]u8 = undefined;
        var fds = [_]linux.pollfd{
            .{ .fd = self.front, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = self.back, .events = linux.POLL.IN, .revents = 0 },
        };
        while (!self.done.load(.acquire)) {
            _ = linux.poll(&fds, fds.len, 1);
            while (true) {
                var from: linux.sockaddr.in = undefined;
                var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
                const rc = linux.recvfrom(self.front, &buf, buf.len, 0, @ptrCast(&from), &from_len);
                if (linux.errno(rc) != .SUCCESS) break;
                self.client = from;
                self.have_client = true;
                if (!self.up.forward(buf[0..rc])) continue;
                _ = linux.sendto(self.back, &buf, rc, 0, @ptrCast(&self.server), @sizeOf(linux.sockaddr.in));
            }
            const due = self.up.takeDue();
            for (0..due) |i| _ = linux.sendto(self.back, &self.up.held[i], self.up.held_len[i], 0, @ptrCast(&self.server), @sizeOf(linux.sockaddr.in));
            while (true) {
                const rc = linux.recvfrom(self.back, &buf, buf.len, 0, null, null);
                if (linux.errno(rc) != .SUCCESS) break;
                if (!self.have_client) continue;
                if (!self.down.forward(buf[0..rc])) continue;
                _ = linux.sendto(self.front, &buf, rc, 0, @ptrCast(&self.client), @sizeOf(linux.sockaddr.in));
            }
        }
    }
};
