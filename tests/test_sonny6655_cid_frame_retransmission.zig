// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6655, NEWGAP-21, NEWGAP-02): NEW_CONNECTION_ID and
// RETIRE_CONNECTION_ID frames are sent again when the packet carrying them is
// lost (RFC 9000 §13.3), and connection IDs the peer asks us to retire are
// retired with RETIRE_CONNECTION_ID (RFC 9000 §5.1.2). A real client and
// server endpoint talk over loopback UDP through a relay (udp_relay.zig) that
// drops chosen server datagrams. Nothing in the QUIC stack is replaced.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const testlog = @import("testlog");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");
const packet_mod = @import("quic_packet");
const frame_mod = @import("quic_frame");
const relay_mod = @import("udp_relay.zig");
const Relay = relay_mod.Relay;
const nowMs = relay_mod.nowMs;
const sleepUs = relay_mod.sleepUs;

// The loopback handshake with the embedded test certificate does not complete
// under -Dfips; connection ID management is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
var next_port = std.atomic.Value(u16).init(24300);

const io = std.Io.Threaded.global_single_threaded.io();

/// A server endpoint polled on its own thread. It accepts one connection,
/// reads its first stream to the end and answers "OK" + FIN.
const Server = struct {
    ep: endpoint_mod.Endpoint,
    done: std.atomic.Value(bool) = .init(false),
    conn: std.atomic.Value(?*api.Connection) = .init(null),
    finished: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
    config: cfg.QuicConfig,

    fn start(self: *Server, port: u16) !void {
        var bind_buf: [32]u8 = undefined;
        const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
        self.config = .{
            .alpn = &test_alpn,
            .inline_server_cert_der = test_certs.server_cert_der,
            .inline_server_priv_p256 = test_certs.server_key_der,
            .allow_insecure = true,
        };
        self.ep = try endpoint_mod.Endpoint.init(testing.allocator, bind_addr, &self.config);
        errdefer self.ep.deinit();
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn stop(self: *Server) void {
        self.done.store(true, .release);
        self.thread.join();
        self.ep.deinit();
    }

    fn run(self: *Server) void {
        var conn: ?*api.Connection = null;
        var sid: ?api.QuicStreamId = null;
        var answered = false;
        var scratch: [64 * 1024]u8 = undefined;
        while (!self.done.load(.acquire)) {
            _ = self.ep.pollWithStats(1) catch {};
            if (conn == null) {
                conn = api.tryAccept(&self.ep);
                if (conn) |c| self.conn.store(c, .release);
            }
            const c = conn orelse continue;
            if (sid == null and api.hasIncomingStreams(c)) sid = api.acceptStream(c) catch null;
            const s = sid orelse continue;
            while (!self.finished.load(.acquire)) {
                const n = api.readStream(c, s, &scratch) catch break;
                if (n == 0) {
                    if (api.isStreamFinished(c, s)) self.finished.store(true, .release);
                    break;
                }
            }
            if (self.finished.load(.acquire) and !answered) {
                _ = api.writeStream(c, s, "OK", true) catch continue;
                answered = true;
            }
        }
    }
};

fn clientPollThread(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
}

const max_cids = 8;

/// The connection IDs (sequence >= 1) a connection issued.
const Issued = struct {
    seq: [max_cids]u64 = undefined,
    cid: [max_cids][20]u8 = undefined,
    len: [max_cids]usize = undefined,
    n: usize = 0,

    fn of(c: *api.Connection) Issued {
        var out: Issued = .{};
        c.mu.lockUncancelable(io);
        defer c.mu.unlock(io);
        for (c.local_cids) |lc| {
            if (!lc.in_use or lc.sequence == 0) continue;
            out.seq[out.n] = lc.sequence;
            out.len[out.n] = lc.cid.len;
            @memcpy(out.cid[out.n][0..lc.cid.len], lc.cid.bytes[0..lc.cid.len]);
            out.n += 1;
        }
        return out;
    }
};

/// Whether `c` holds the peer connection ID `seq` with the bytes `cid`.
fn hasPeerCid(c: *api.Connection, seq: u64, cid: []const u8) bool {
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    for (c.peer_cids) |pc| {
        if (pc.in_use and pc.sequence == seq and std.mem.eql(u8, pc.cid.bytes[0..pc.cid.len], cid)) return true;
    }
    return false;
}

fn serverReady(sc: ?*api.Connection) bool {
    const c = sc orelse return false;
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    return c.app_tx_keys != null and c.handshake_done_sent and c.issued_cids > 1;
}

/// Sends `request` on a new stream, FIN included.
fn sendRequest(conn: *api.Connection, request: []const u8) !api.QuicStreamId {
    const sid = try api.openStream(conn, true);
    var off: usize = 0;
    const deadline = nowMs() + 10_000;
    while (nowMs() < deadline) {
        const n = api.writeStream(conn, sid, request[off..], true) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        off += n;
        if (off == request.len) break;
        if (n == 0) sleepUs(100);
    }
    try testing.expectEqual(request.len, off);
    return sid;
}

/// Waits for the server's "OK" + FIN on `sid`.
fn awaitAnswer(conn: *api.Connection, sid: api.QuicStreamId) !void {
    var buf: [16]u8 = undefined;
    var got: usize = 0;
    const deadline = nowMs() + 10_000;
    while (nowMs() < deadline) {
        const n = api.readStream(conn, sid, buf[got..]) catch 0;
        got += n;
        if (got >= 2 and api.isStreamFinished(conn, sid)) break;
        if (n == 0) sleepUs(1_000);
    }
    try testing.expectEqualStrings("OK", buf[0..got]);
}

test "SONNY-6655 a lost NEW_CONNECTION_ID is sent again until the peer has the connection ID (RFC 9000 §13.3)" {
    // RFC 9000 §13.3: "New connection IDs are sent in NEW_CONNECTION_ID
    // frames and retransmitted if the packet containing them is lost." The
    // server advertises its connection IDs in the packet that carries
    // HANDSHAKE_DONE; that packet was not recorded for control-frame
    // retransmission and NEW_CONNECTION_ID was not resent from any lost
    // packet, so when it was lost the client never learned them and could
    // never migrate. Here the relay drops every server 1-RTT datagram until
    // the server has sent HANDSHAKE_DONE with the first of its connection
    // IDs (the others follow in later packets).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    relay.down.block_short.store(true, .release);
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{relay.front_port});
    const conn = try api.connect(&client_ep, target, "localhost");
    const hs_deadline = nowMs() + 5_000;
    // Until the HANDSHAKE_DONE packet has reached the relay and been dropped.
    while (nowMs() < hs_deadline and !(serverReady(server.conn.load(.acquire)) and @atomicLoad(u32, &relay.down.state.dropped, .acquire) >= 1)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    const sc = server.conn.load(.acquire) orelse return error.NotAccepted;
    try testing.expect(serverReady(sc));
    const issued = Issued.of(sc);
    try testing.expect(issued.n >= 1);
    const dropped = @atomicLoad(u32, &relay.down.state.dropped, .acquire);
    try testing.expect(dropped >= 1);
    for (0..issued.n) |i| try testing.expect(!hasPeerCid(conn, issued.seq[i], issued.cid[i][0..issued.len[i]]));

    // The path recovers; the client sends a request, and the server's
    // packets are acknowledged again.
    relay.down.block_short.store(false, .release);
    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }
    var request: [16 * 1024]u8 = undefined;
    @memset(&request, 'r');
    const sid = try sendRequest(conn, &request);
    try awaitAnswer(conn, sid);

    var learned: usize = 0;
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline) {
        learned = 0;
        for (0..issued.n) |i| {
            if (hasPeerCid(conn, issued.seq[i], issued.cid[i][0..issued.len[i]])) learned += 1;
        }
        if (learned == issued.n) break;
        sleepUs(1_000);
    }
    testlog.print("\n  SONNY-6655 NEW_CONNECTION_ID: server issued {d} connection IDs, server datagrams dropped {d}, client learned {d}\n", .{ issued.n, dropped, learned });
    try testing.expectEqual(issued.n, learned);
    _ = api.close(conn, 0, "done") catch {};
}

/// Opens the server's 1-RTT packets on the relay with its keys and drops the
/// first `drop_left` that carry RETIRE_CONNECTION_ID. Counts the
/// RETIRE_CONNECTION_ID frames seen and the server packets addressed to
/// `switched_cid` once one was seen.
const RetireWatch = struct {
    keys: packet_mod.AeadKeys,
    dcid_len: usize,
    drop_left: u32,
    switched_cid: [20]u8 = undefined,
    switched_len: usize = 0,
    frames_seen: std.atomic.Value(u32) = .init(0),
    packets_dropped: std.atomic.Value(u32) = .init(0),
    packets_to_switched: std.atomic.Value(u32) = .init(0),

    fn filter(ctx: *anyopaque, pkt: []const u8, info: relay_mod.ShortInfo) bool {
        const self: *RetireWatch = @ptrCast(@alignCast(ctx));
        if (self.frames_seen.load(.monotonic) > 0 and pkt.len > self.switched_len and
            std.mem.eql(u8, pkt[1 .. 1 + self.switched_len], self.switched_cid[0..self.switched_len]))
        {
            _ = self.packets_to_switched.fetchAdd(1, .monotonic);
        }
        var payload: [2048]u8 = undefined;
        const dec = packet_mod.decodeShortProtectedInto(pkt, self.dcid_len, self.keys, info.pn -| 1, &payload) catch return true;
        var retire: u32 = 0;
        var off: usize = 0;
        while (off < dec.payload.len) {
            const fr = frame_mod.decodeOne(dec.payload[off..]) catch break;
            if (fr.n == 0) break;
            off += fr.n;
            if (fr.f == .retire_connection_id) retire += 1;
        }
        if (retire == 0) return true;
        _ = self.frames_seen.fetchAdd(retire, .monotonic);
        if (self.drop_left > 0) {
            self.drop_left -= 1;
            _ = self.packets_dropped.fetchAdd(1, .monotonic);
            return false;
        }
        return true;
    }
};

/// Whether every connection ID `c` issued below `below` is retired.
fn localRetiredBelow(c: *api.Connection, below: u64) bool {
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    for (c.local_cids) |lc| {
        if (lc.in_use and lc.sequence < below) return false;
    }
    return true;
}

test "SONNY-6655 connection IDs the peer retires are retired with RETIRE_CONNECTION_ID, sent again when lost (RFC 9000 §5.1.2, §13.3)" {
    // RFC 9000 §5.1.2: "Upon receipt of an increased Retire Prior To field,
    // the peer MUST stop using the corresponding connection IDs and retire
    // them with RETIRE_CONNECTION_ID frames"; §13.3: those frames are
    // "retransmitted if the packet containing them is lost". The client asks
    // the server to retire its connection IDs below the newest one it issued
    // (a NEW_CONNECTION_ID with Retire Prior To = its sequence number, sent
    // with the client's own send path), and the relay drops the first server
    // packet carrying RETIRE_CONNECTION_ID. The server used to retire the
    // connection IDs locally, never tell the client, and keep sending to the
    // first one.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{relay.front_port});
    const conn = try api.connect(&client_ep, target, "localhost");

    const hs_deadline = nowMs() + 5_000;
    while (nowMs() < hs_deadline and !(api.isHandshakeConfirmed(conn) and server.conn.load(.acquire) != null)) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));

    // The client issues connection IDs up to the server's limit and sends
    // them (the client stack only does this on demand), and waits until the
    // server holds them; "newest" is the one with the largest sequence.
    conn.mu.lockUncancelable(io);
    _ = try conn.ensureLocalConnectionIdSupply();
    while ((try conn.flushPendingNewConnectionIds()) > 0) {}
    conn.mu.unlock(io);
    const issued = Issued.of(conn);
    try testing.expect(issued.n >= 1);
    var b: usize = 0;
    for (0..issued.n) |i| {
        if (issued.seq[i] > issued.seq[b]) b = i;
    }
    const newest_seq = issued.seq[b];
    const newest_len = issued.len[b];
    var newest: [20]u8 = undefined;
    @memcpy(newest[0..newest_len], issued.cid[b][0..newest_len]);
    var newest_token: [16]u8 = undefined;
    var held = false;
    const cid_deadline = nowMs() + 5_000;
    while (nowMs() < cid_deadline and !held) {
        _ = client_ep.pollWithStats(1) catch {};
        held = hasPeerCid(server.conn.load(.acquire).?, newest_seq, newest[0..newest_len]);
    }
    try testing.expect(held);
    const sc = server.conn.load(.acquire).?;

    conn.mu.lockUncancelable(io);
    conn.disable_auto_key_update = true;
    for (conn.local_cids) |lc| {
        if (lc.in_use and lc.sequence == newest_seq) newest_token = lc.reset_token;
    }
    conn.mu.unlock(io);
    sc.mu.lockUncancelable(io);
    sc.disable_auto_key_update = true;
    var watch = RetireWatch{ .keys = sc.app_tx_keys.?, .dcid_len = sc.shortHeaderDcid().len, .drop_left = 1 };
    sc.mu.unlock(io);
    @memcpy(watch.switched_cid[0..newest_len], newest[0..newest_len]);
    watch.switched_len = newest_len;
    relay.down.publish(sc);
    relay.down.filter_ctx = &watch;
    relay.down.filter = RetireWatch.filter;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    // The client asks the server to retire every connection ID below its
    // newest one, the initial one included.
    var frame_buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&frame_buf);
    _ = try (frame_mod.Frame{ .new_connection_id = .{
        .sequence = newest_seq,
        .retire_prior_to = newest_seq,
        .connection_id = newest[0..newest_len],
        .stateless_reset_token = newest_token,
    } }).write(&w);
    conn.mu.lockUncancelable(io);
    conn.sendControlFrames(frame_buf[0..w.end]);
    conn.mu.unlock(io);

    var request: [16 * 1024]u8 = undefined;
    @memset(&request, 'r');
    const sid = try sendRequest(conn, &request);
    try awaitAnswer(conn, sid);

    var retired = false;
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline and !retired) {
        retired = localRetiredBelow(conn, newest_seq);
        if (!retired) sleepUs(1_000);
    }
    // A second exchange after the retirement: the server now sends to the
    // newest connection ID, which the client still routes.
    const sid2 = try sendRequest(conn, "again");
    _ = sid2;
    sleepUs(100_000);
    testlog.print("\n  SONNY-6655 RETIRE_CONNECTION_ID: client CIDs below {d} retired={} frames seen={d} packets dropped={d} server packets to the newest CID={d}\n", .{ newest_seq, retired, watch.frames_seen.load(.acquire), watch.packets_dropped.load(.acquire), watch.packets_to_switched.load(.acquire) });
    try testing.expect(retired);
    try testing.expectEqual(@as(u32, 1), watch.packets_dropped.load(.acquire));
    try testing.expect(watch.frames_seen.load(.acquire) >= 2 * newest_seq);
    try testing.expect(watch.packets_to_switched.load(.acquire) > 0);
    _ = api.close(conn, 0, "done") catch {};
}
