// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6522): long single-stream transfers must not stall
// for good under heavy loss.
//
// Under CPU starvation (2 CPUs shared with 16 busy loops) the 16/64 MiB
// loopback transfers of test_large_stream_flow_control stalled in up to half
// the runs. These tests reproduce the stalls deterministically: a real client
// and server endpoint talk over loopback UDP through a relay (`Relay`) that
// drops chosen datagrams, as a lossy network would. Nothing in the QUIC stack
// is replaced; the relay only decides which datagrams it forwards.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const linux = std.os.linux;
const testlog = @import("testlog");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

// The loopback handshake with the embedded test certificate does not complete
// under -Dfips; key update and loss recovery are crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
const MiB: usize = 1024 * 1024;
const write_chunk: usize = 16 * 1024;
var next_port = std.atomic.Value(u16).init(23700);

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn sleepUs(us: u64) void {
    const ts = linux.timespec{ .sec = 0, .nsec = @intCast(us * 1000) };
    _ = linux.nanosleep(&ts, null);
}

fn loopback(port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
}

fn udpSocket(port: u16) !i32 {
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
const ShortInfo = struct { phase: bool, pn: u64 };

/// Counters a drop rule keeps for its test.
const RuleState = struct {
    dropped: u32 = 0,
    delivered_gen1: u32 = 0,
    /// A packet of key generation 2 was sent before any packet of
    /// generation 1 reached the peer.
    gen2_before_gen1_delivered: bool = false,
    max_gen: u32 = 0,
};

const Rule = *const fn (*RuleState, ShortInfo, u32) bool;

/// One direction of the relay. Tracks the sender's key generation as seen on
/// the wire: it advances when a packet with a newer packet number carries
/// the other key phase bit.
const Link = struct {
    rule: ?Rule = null,
    state: RuleState = .{},
    hp_ready: std.atomic.Value(bool) = .init(false),
    hp_key: [16]u8 = undefined,
    dcid_len: usize = 0,
    largest_pn: ?u64 = null,
    gen: u32 = 0,
    gen_phase: bool = false,
    gen_start_pn: u64 = 0,

    /// Publishes the sender's header-protection key and the DCID length of
    /// its short headers, once its 1-RTT keys exist.
    fn publish(self: *Link, sender: *api.Connection) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        sender.mu.lockUncancelable(io);
        defer sender.mu.unlock(io);
        self.hp_key = sender.app_tx_keys.?.hp;
        self.dcid_len = sender.shortHeaderDcid().len;
        self.hp_ready.store(true, .release);
    }

    fn decodeShort(self: *Link, pkt: []const u8) ?ShortInfo {
        if (!self.hp_ready.load(.acquire)) return null;
        if (pkt.len == 0 or (pkt[0] & 0x80) != 0) return null;
        const pn_off = 1 + self.dcid_len;
        if (pkt.len < pn_off + 4 + 16) return null;
        const aes = std.crypto.core.aes.Aes128.initEnc(self.hp_key);
        var mask: [16]u8 = undefined;
        aes.encrypt(&mask, pkt[pn_off + 4 ..][0..16]);
        const first = pkt[0] ^ (mask[0] & 0x1f);
        const pn_len: usize = (first & 0x03) + 1;
        var trunc: u64 = 0;
        for (0..pn_len) |i| trunc = (trunc << 8) | (pkt[pn_off + i] ^ mask[1 + i]);
        // RFC 9000 Appendix A.3 packet number decoding.
        const expected: u64 = if (self.largest_pn) |l| l + 1 else 0;
        const win: u64 = @as(u64, 1) << @intCast(pn_len * 8);
        const hwin = win / 2;
        var pn = (expected & ~(win - 1)) | trunc;
        if (pn + hwin <= expected and pn < (@as(u64, 1) << 62) - win) {
            pn += win;
        } else if (pn > expected + hwin and pn >= win) {
            pn -= win;
        }
        if (self.largest_pn == null or pn > self.largest_pn.?) self.largest_pn = pn;
        return .{ .phase = (first & 0x04) != 0, .pn = pn };
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

    /// Whether a datagram is forwarded.
    fn forward(self: *Link, pkt: []const u8) bool {
        const rule = self.rule orelse return true;
        const info = self.decodeShort(pkt) orelse return true;
        return rule(&self.state, info, self.generationOf(info));
    }
};

/// A UDP relay between the client and the server on loopback. The client
/// sends to `front_port`; the relay forwards to the server from its own
/// socket and relays the server's datagrams back. `up` (client to server)
/// and `down` (server to client) decide which 1-RTT datagrams get through.
const Relay = struct {
    front: i32,
    back: i32,
    front_port: u16,
    server: linux.sockaddr.in,
    client: linux.sockaddr.in = undefined,
    have_client: bool = false,
    done: std.atomic.Value(bool) = .init(false),
    up: Link = .{},
    down: Link = .{},

    fn init(server_port: u16) !Relay {
        const front = try udpSocket(0);
        errdefer _ = linux.close(front);
        var bound: linux.sockaddr.in = undefined;
        var bound_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.errno(linux.getsockname(front, @ptrCast(&bound), &bound_len)) != .SUCCESS) return error.GetSockNameFailed;
        const back = try udpSocket(0);
        return .{ .front = front, .back = back, .front_port = std.mem.bigToNative(u16, bound.port), .server = loopback(server_port) };
    }

    fn deinit(self: *Relay) void {
        _ = linux.close(self.front);
        _ = linux.close(self.back);
    }

    fn run(self: *Relay) void {
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

fn patternByte(i: usize) u8 {
    return @truncate((i *% 131) ^ (i >> 13));
}

const Direction = enum { upload, download };

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    direction: Direction,
    size: usize,
    payload: []const u8,
    /// Upload: bytes the server read. Download: bytes the server wrote.
    progress: *std.atomic.Value(u64),
    corrupt: *std.atomic.Value(bool),
    conn_out: *std.atomic.Value(?*api.Connection),
};

/// Upload: reads `size` bytes and answers "OK" + FIN. Download: reads the
/// request and answers with `size` bytes + FIN.
fn serverThread(ctx: ServerCtx) void {
    var conn: ?*api.Connection = null;
    var sid: ?api.QuicStreamId = null;
    var got: usize = 0;
    var sent: usize = 0;
    var request_done = false;
    var responded = false;
    var scratch: [64 * 1024]u8 = undefined;
    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(1) catch {};
        if (conn == null) {
            conn = api.tryAccept(ctx.ep);
            if (conn) |c| ctx.conn_out.store(c, .release);
        }
        const c = conn orelse continue;
        if (sid == null and api.hasIncomingStreams(c)) sid = api.acceptStream(c) catch null;
        const s = sid orelse continue;
        while (!request_done) {
            const n = api.readStream(c, s, &scratch) catch break;
            if (n == 0) {
                if (api.isStreamFinished(c, s)) request_done = true;
                break;
            }
            if (ctx.direction == .upload) {
                for (scratch[0..n], got..) |b, i| {
                    if (b != patternByte(i)) ctx.corrupt.store(true, .release);
                }
            }
            got += n;
            if (ctx.direction == .upload) ctx.progress.store(got, .release);
        }
        if (!request_done or responded) continue;
        switch (ctx.direction) {
            .upload => {
                if (got != ctx.size) continue;
                _ = api.writeStream(c, s, "OK", true) catch continue;
                responded = true;
            },
            .download => while (sent < ctx.size) {
                const end = @min(ctx.size, sent + write_chunk);
                const n = api.writeStream(c, s, ctx.payload[sent..end], end == ctx.size) catch break;
                if (n == 0) break;
                sent += n;
                ctx.progress.store(sent, .release);
                if (sent == ctx.size) responded = true;
                // One chunk per poll: the server's own loop processes ACKs.
                break;
            },
        }
    }
}

fn clientPollThread(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
}

const Outcome = struct { delivered: u64, completed: bool, corrupt: bool };

fn serverHasAppKeys(sc: ?*api.Connection) bool {
    const c = sc orelse return false;
    const io = std.Io.Threaded.global_single_threaded.io();
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    return c.app_tx_keys != null;
}

/// Moves `size` bytes on one stream through `relay`, client to server
/// (upload, answered by "OK" + FIN) or server to client (download, after a
/// short request), within `budget_ms`.
fn transferThroughRelay(relay: *Relay, server_port: u16, direction: Direction, size: usize, budget_ms: i64) !Outcome {
    const allocator = testing.allocator;
    const payload = try allocator.alloc(u8, size);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = patternByte(i);

    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{server_port});
    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var server_ep = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    defer server_ep.deinit();

    var server_done = std.atomic.Value(bool).init(false);
    var progress = std.atomic.Value(u64).init(0);
    var corrupt = std.atomic.Value(bool).init(false);
    var server_conn = std.atomic.Value(?*api.Connection).init(null);
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{ServerCtx{
        .ep = &server_ep,
        .done = &server_done,
        .direction = direction,
        .size = size,
        .payload = payload,
        .progress = &progress,
        .corrupt = &corrupt,
        .conn_out = &server_conn,
    }});
    defer {
        server_done.store(true, .release);
        srv_thread.join();
    }
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{relay.front_port});
    const conn = try api.connect(&client_ep, target, "localhost");
    const hs_deadline = nowMs() + 5_000;
    while (nowMs() < hs_deadline and !(api.isHandshakeConfirmed(conn) and serverHasAppKeys(server_conn.load(.acquire)))) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));
    const sc = server_conn.load(.acquire) orelse return error.NotAccepted;
    try testing.expect(serverHasAppKeys(sc));
    relay.up.publish(conn);
    relay.down.publish(sc);

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const sid = try api.openStream(conn, true);
    var sent: usize = 0;
    var received: usize = 0;
    var corrupt_rx = false;
    var completed = false;
    var buf: [64 * 1024]u8 = undefined;
    if (direction == .download) _ = try api.writeStream(conn, sid, "GET", true);
    const deadline = nowMs() + budget_ms;
    while (nowMs() < deadline and !completed) {
        if (direction == .upload and sent < size) {
            const end = @min(size, sent + write_chunk);
            const n = api.writeStream(conn, sid, payload[sent..end], end == size) catch |err| switch (err) {
                error.FlowControlBlocked => 0,
                else => return err,
            };
            sent += n;
            // Yield between chunks, as an application writing a large body
            // does, so the poll thread processes ACKs during the transfer.
            if (n != 0) {
                sleepUs(50);
                continue;
            }
        }
        sleepUs(100);
        while (true) {
            const r = api.readStream(conn, sid, &buf) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (r == 0) {
                if (api.isStreamFinished(conn, sid)) completed = true;
                break;
            }
            if (direction == .download) {
                for (buf[0..r], received..) |b, i| {
                    if (b != patternByte(i)) corrupt_rx = true;
                }
            }
            received += r;
        }
    }

    const delivered: u64 = if (direction == .upload) progress.load(.acquire) else received;
    const out = Outcome{ .delivered = delivered, .completed = completed, .corrupt = corrupt.load(.acquire) or corrupt_rx };
    if (!completed) {
        const io = std.Io.Threaded.global_single_threaded.io();
        std.debug.print("\n  SONNY-6522 {s}: delivered={d} of {d}\n", .{ @tagName(direction), delivered, size });
        sc.mu.lockUncancelable(io);
        std.debug.print("  server: rx_phase={} rx_gen={d} tx_phase={} tx_gen={d} largest_rx_pn={d} pn_tx={d}\n", .{ sc.rx_key_phase, sc.rx_key_gen, sc.tx_key_phase, sc.tx_key_gen, sc.pn_app.max, sc.pn_app_tx });
        sc.mu.unlock(io);
        conn.mu.lockUncancelable(io);
        std.debug.print("  client: rx_phase={} rx_gen={d} tx_phase={} tx_gen={d} largest_rx_pn={d} pn_tx={d}\n", .{ conn.rx_key_phase, conn.rx_key_gen, conn.tx_key_phase, conn.tx_key_gen, conn.pn_app.max, conn.pn_app_tx });
        conn.mu.unlock(io);
    } else {
        _ = api.close(conn, 0, "done") catch {};
    }
    return out;
}

// ---------------------------------------------------------------------------
// Key-phase desync (RFC 9001 §6.1).
// ---------------------------------------------------------------------------

const gen1_drops: u32 = 2000;

/// Drops the first `gen1_drops` packets protected with the first updated
/// keys (generation 1), as a burst loss right after a key update would.
fn dropFirstUpdatedGeneration(st: *RuleState, info: ShortInfo, g: u32) bool {
    _ = info;
    if (g > st.max_gen) st.max_gen = g;
    if (g >= 2 and st.delivered_gen1 == 0) st.gen2_before_gen1_delivered = true;
    if (g == 1) {
        if (st.dropped < gen1_drops) {
            st.dropped += 1;
            return false;
        }
        st.delivered_gen1 += 1;
    }
    return true;
}

// The sender initiates a key update after 512 packets
// (maybeTriggerKeyUpdateOnSend). Every packet it then sends with the new
// keys is lost until 2000 have been dropped. RFC 9001 §6.1: "An endpoint MUST
// NOT initiate a subsequent key update unless it has received an
// acknowledgment for a packet that was sent protected with keys from the
// current key phase." The update counted as acknowledged when the packet that
// triggered it, still protected with the old keys, was acknowledged; the
// sender then updated again 512 packets later, two generations ahead of the
// receiver, which could decrypt nothing more: the connection was dead,
// although the receiver kept polling and the sender kept probing.
fn keyUpdateBurstLoss(direction: Direction) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const server_port = next_port.fetchAdd(1, .seq_cst);
    var relay = try Relay.init(server_port);
    defer relay.deinit();
    const link = if (direction == .upload) &relay.up else &relay.down;
    link.rule = dropFirstUpdatedGeneration;

    const size = 4 * MiB;
    const out = try transferThroughRelay(&relay, server_port, direction, size, 60_000);
    const st = link.state;
    testlog.print("\n  SONNY-6522 key update ({s}): dropped={d} gen1 delivered={d} max gen={d} gen2 before gen1 delivered={}\n", .{ @tagName(direction), st.dropped, st.delivered_gen1, st.max_gen, st.gen2_before_gen1_delivered });

    try testing.expect(!st.gen2_before_gen1_delivered);
    try testing.expectEqual(gen1_drops, st.dropped);
    try testing.expect(!out.corrupt);
    try testing.expectEqual(@as(u64, size), out.delivered);
    try testing.expect(out.completed);
}

test "SONNY-6522 upload: no second key update before the first is acknowledged (RFC 9001 §6.1)" {
    try keyUpdateBurstLoss(.upload);
}

test "SONNY-6522 download: no second key update before the first is acknowledged (RFC 9001 §6.1)" {
    try keyUpdateBurstLoss(.download);
}

// ---------------------------------------------------------------------------
// NEWGAP-11: an RTT sample from the handshake (RFC 9002 §5.1, §6.2.2).
// ---------------------------------------------------------------------------

test "SONNY-6522 the client has an RTT sample once the handshake is confirmed" {
    // The client's Initial and Handshake packets are ack-eliciting; the
    // server's acknowledgement of them is the client's first RTT sample
    // (RFC 9002 §5.1). Without one the client's first application PTO is
    // computed from the 333 ms initial RTT, about 1 s (RFC 9002 §6.2.2), so a
    // request lost right after the handshake waited about a second on
    // loopback. The server sent its Initial ACK after its own flight, by when
    // the client had dropped its Initial keys and discarded it unread.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const allocator = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var server_ep = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    defer server_ep.deinit();
    var server_done = std.atomic.Value(bool).init(false);
    const st = try std.Thread.spawn(.{}, struct {
        fn run(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
            while (!done.load(.acquire)) {
                _ = ep.pollWithStats(1) catch {};
                _ = api.tryAccept(ep);
            }
        }
    }.run, .{ &server_ep, &server_done });
    defer {
        server_done.store(true, .release);
        st.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});
    const conn = try api.connect(&client_ep, target, "localhost");
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline and !(api.isHandshakeConfirmed(conn) and conn.handshake_done_seen)) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(conn.handshake_done_seen);

    const io = std.Io.Threaded.global_single_threaded.io();
    conn.mu.lockUncancelable(io);
    const have_sample = conn.rec.rtt.have_sample;
    const srtt_us = conn.rec.rtt.smoothed_rtt_ns / 1000;
    conn.mu.unlock(io);
    testlog.print("\n  SONNY-6522 handshake RTT: have_sample={} srtt_us={d}\n", .{ have_sample, srtt_us });
    try testing.expect(have_sample);
    _ = api.close(conn, 0, "done") catch {};
}

// ---------------------------------------------------------------------------
// A connection the server application never sees.
// ---------------------------------------------------------------------------

fn acceptWithin(server_ep: *endpoint_mod.Endpoint, client_ep: *endpoint_mod.Endpoint, ms: i64) ?*api.Connection {
    const deadline = nowMs() + ms;
    while (nowMs() < deadline) {
        _ = server_ep.pollWithStats(1) catch {};
        _ = client_ep.pollWithStats(1) catch {};
        if (api.tryAccept(server_ep)) |c| return c;
    }
    return null;
}

test "SONNY-6522 a server port in use cannot be bound by a second endpoint" {
    // The UDP socket of a server endpoint was bound with SO_REUSEADDR. On
    // Linux that lets any later socket that also sets it bind the same
    // address and port while the first is still open, and the kernel then
    // delivers unicast datagrams to the newer socket only. A second endpoint
    // on the port of a live server (a concurrent test run, a restarted
    // process that overlapped the old one, or another local user) took over
    // its traffic: clients completed the handshake and every packet was
    // acknowledged, but by the other endpoint, so the first server's
    // application never got the connection from tryAccept. UDP has no
    // TIME_WAIT, so rebinding a port after close needs no SO_REUSEADDR.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const allocator = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var first = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    defer first.deinit();

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    if (endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg)) |second_ep| {
        var second = second_ep;
        defer second.deinit();
        // Show what the second binding does to the first server.
        _ = try api.connect(&client_ep, target, "localhost");
        const got_first = acceptWithin(&first, &client_ep, 2_000) != null;
        const got_second = api.tryAccept(&second) != null or acceptWithin(&second, &client_ep, 500) != null;
        std.debug.print("\n  SONNY-6522: second endpoint bound the live port; first server accepted={} second accepted={}\n", .{ got_first, got_second });
        return error.SecondBindSucceeded;
    } else |_| {}

    // The live server still gets its connections.
    _ = try api.connect(&client_ep, target, "localhost");
    try testing.expect(acceptWithin(&first, &client_ep, 5_000) != null);
}
