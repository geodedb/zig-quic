// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6673): an application thread writing a stream as
// fast as it can must not starve the endpoint's own receive path. Both take
// Connection.mu; the writer released it and took it again at once, before
// the woken receive thread ran, so the receive path almost never got the
// lock: a client that sent 75000 packets processed about 40 of the server's
// ACKs (SONNY-6649), believed nearly everything it sent was lost, and
// retransmitted it. Real endpoints over loopback UDP through the relay of
// udp_relay.zig; nothing in the QUIC stack is replaced.

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
// under -Dfips; the locking under test is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
var next_port = std.atomic.Value(u16).init(24100);

const io = std.Io.Threaded.global_single_threaded.io();

/// A server endpoint polled on its own thread. It accepts one connection and
/// reads its first stream to the end.
const Server = struct {
    ep: endpoint_mod.Endpoint,
    done: std.atomic.Value(bool) = .init(false),
    conn: std.atomic.Value(?*api.Connection) = .init(null),
    received: std.atomic.Value(u64) = .init(0),
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
        var got: u64 = 0;
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
                got += n;
                self.received.store(got, .release);
            }
        }
    }
};

fn serverHasAppKeys(sc: ?*api.Connection) bool {
    const c = sc orelse return false;
    c.mu.lockUncancelable(io);
    defer c.mu.unlock(io);
    return c.app_tx_keys != null;
}

fn clientPollThread(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
}

/// Packets the writer sends, one 16-byte STREAM frame each.
const write_packets: u64 = 20_000;
/// Samples before this many packets are sent are not counted: the
/// connection is still warming up.
const warmup_packets: u64 = 2_000;
const sample_every: u64 = 250;
/// Largest allowed gap between the largest packet number the server has
/// received (and so acknowledges within two packets, RFC 9000 §13.2.1) and
/// the largest the client has seen acknowledged. A receive path that gets
/// the connection lock keeps it to the ACKs in flight and in the client's
/// socket; a starved one lets it grow with every packet sent.
const max_ack_lag: u64 = 2_048;

test "SONNY-6673 a saturating stream writer does not starve the connection's ACK processing" {
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
    while (nowMs() < hs_deadline and !(api.isHandshakeConfirmed(conn) and serverHasAppKeys(server.conn.load(.acquire)))) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));
    const sc = server.conn.load(.acquire) orelse return error.NoServerConnection;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    // The application thread writes as fast as the stream takes data.
    const sid = try api.openStream(conn, true);
    const chunk = "0123456789abcdef";
    var sent: u64 = 0;
    var writes: u64 = 0;
    var worst_lag: u64 = 0;
    var worst_at: u64 = 0;
    var samples: u64 = 0;
    const write_deadline = nowMs() + 120_000;
    while (writes < write_packets and nowMs() < write_deadline) {
        const n = api.writeStream(conn, sid, chunk, false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        if (n == 0) {
            sleepUs(100);
            continue;
        }
        sent += n;
        writes += 1;
        if (writes < warmup_packets or writes % sample_every != 0) continue;
        sc.mu.lockUncancelable(io);
        const server_largest_rx = sc.pn_app.max;
        sc.mu.unlock(io);
        conn.mu.lockUncancelable(io);
        const largest_acked = conn.largest_acked;
        conn.mu.unlock(io);
        const lag = server_largest_rx -| largest_acked;
        samples += 1;
        if (lag > worst_lag) {
            worst_lag = lag;
            worst_at = writes;
        }
    }
    try testing.expectEqual(write_packets, writes);

    while (true) {
        _ = api.writeStream(conn, sid, "", true) catch |err| switch (err) {
            error.FlowControlBlocked => {
                sleepUs(100);
                continue;
            },
            else => return err,
        };
        break;
    }
    const deadline = nowMs() + 60_000;
    while (nowMs() < deadline and !server.finished.load(.acquire)) sleepUs(1_000);

    conn.mu.lockUncancelable(io);
    const retx_packets = conn.stream_retx_packets;
    const largest_acked_end = conn.largest_acked;
    conn.mu.unlock(io);
    testlog.print("\n  SONNY-6673 writer: packets={d} samples={d} worst ACK lag={d} (at packet {d}) largest acked at end={d} retransmission packets={d} delivered={d} of {d} finished={}\n", .{ writes, samples, worst_lag, worst_at, largest_acked_end, retx_packets, server.received.load(.acquire), sent, server.finished.load(.acquire) });

    try testing.expect(samples > 0);
    try testing.expect(worst_lag <= max_ack_lag);
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(sent, server.received.load(.acquire));
    _ = api.close(conn, 0, "done") catch {};
}
