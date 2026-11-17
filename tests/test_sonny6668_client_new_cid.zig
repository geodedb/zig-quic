// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6668): the client issues connection IDs to the
// server (RFC 9000 §5.1.1), and a lost NEW_CONNECTION_ID from the client is
// sent again (§13.3). A real client and server endpoint talk over loopback
// UDP through a relay (udp_relay.zig) that drops chosen client datagrams.
// Nothing in the QUIC stack is replaced.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const testlog = @import("testlog");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");
const relay_mod = @import("udp_relay.zig");
const Relay = relay_mod.Relay;
const nowMs = relay_mod.nowMs;
const sleepUs = relay_mod.sleepUs;

// The loopback handshake with the embedded test certificate does not complete
// under -Dfips; connection ID management is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
var next_port = std.atomic.Value(u16).init(24500);

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

fn clientReady(c: *api.Connection) bool {
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    return c.handshake_done_seen and c.issued_cids > 1;
}

test "SONNY-6668 the client issues connection IDs, and sends a lost NEW_CONNECTION_ID again (RFC 9000 §5.1.1, §13.3)" {
    // RFC 9000 §5.1.1: "An endpoint SHOULD ensure that its peer has a
    // sufficient number of available and unused connection IDs", up to the
    // peer's active_connection_id_limit. The server issued its connection
    // IDs when it sent HANDSHAKE_DONE; the client never issued any, so the
    // server could never change the connection ID it sends to (migration,
    // or retiring the client's initial one). Here the relay drops every
    // client 1-RTT datagram until the client has confirmed the handshake,
    // then lets them through.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    relay.up.block_short.store(true, .release);
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
    // The client confirms the handshake (HANDSHAKE_DONE, server to client,
    // is not blocked) and issues its connection IDs; the datagrams that
    // carry them to the server are dropped.
    const hs_deadline = nowMs() + 5_000;
    while (nowMs() < hs_deadline and !(clientReady(conn) and @atomicLoad(u32, &relay.up.state.dropped, .acquire) >= 1)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    const sc = server.conn.load(.acquire) orelse return error.NotAccepted;
    const issued = Issued.of(conn);
    testlog.print("\n  SONNY-6668: client confirmed={} issued {d} connection IDs, client datagrams dropped {d}\n", .{ api.isHandshakeConfirmed(conn), issued.n, @atomicLoad(u32, &relay.up.state.dropped, .acquire) });
    try testing.expect(clientReady(conn));
    try testing.expect(issued.n >= 1);
    for (0..issued.n) |i| try testing.expect(!hasPeerCid(sc, issued.seq[i], issued.cid[i][0..issued.len[i]]));

    // The path recovers; a request/response gets the client's packets
    // acknowledged again, and the lost NEW_CONNECTION_ID is sent again.
    relay.up.block_short.store(false, .release);
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
            if (hasPeerCid(sc, issued.seq[i], issued.cid[i][0..issued.len[i]])) learned += 1;
        }
        if (learned == issued.n) break;
        sleepUs(1_000);
    }
    testlog.print("  SONNY-6668: server learned {d} of the client's {d} connection IDs\n", .{ learned, issued.n });
    try testing.expectEqual(issued.n, learned);
    _ = api.close(conn, 0, "done") catch {};
}
