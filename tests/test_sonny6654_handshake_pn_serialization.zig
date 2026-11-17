// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6654, NEWGAP-23): no two 1-RTT packets share a
// packet number, and so an AEAD nonce, while the handshake completes. A real
// client and server endpoint talk over loopback UDP through a relay
// (udp_relay.zig) that records the server's 1-RTT datagrams; their packet
// numbers are read afterwards with the server's header protection key.
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
// under -Dfips; packet number allocation is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
var next_port = std.atomic.Value(u16).init(24100);

const io = std.Io.Threaded.global_single_threaded.io();

/// Connections run one after the other.
const handshakes: u32 = 40;
/// Packets the server application sends on each connection, starting the
/// moment its 1-RTT keys can be used.
const writes_per_conn: u32 = 8;

/// A server endpoint polled on its own thread, handing each connection it
/// accepts to the test.
const Server = struct {
    ep: endpoint_mod.Endpoint,
    done: std.atomic.Value(bool) = .init(false),
    accepted: std.atomic.Value(?*api.Connection) = .init(null),
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
        while (!self.done.load(.acquire)) {
            _ = self.ep.pollWithStats(1) catch {};
            // A connection is accepted on its first Initial, before the
            // handshake completes (defer_accept_until_stream is off).
            if (api.tryAccept(&self.ep)) |c| self.accepted.store(c, .release);
        }
    }
};

/// The server application: opens a stream on the connection it is handed as
/// soon as it is accepted and writes to it in a loop. Writes send nothing
/// (return 0) until the server's 1-RTT keys are confirmed, so the first
/// packet goes out the moment the receive path, completing the handshake,
/// sends HANDSHAKE_DONE.
const Writer = struct {
    server: *Server,
    sent: std.atomic.Value(u32) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),

    fn run(self: *Writer) void {
        const deadline = nowMs() + 10_000;
        var conn: ?*api.Connection = null;
        while (conn == null and nowMs() < deadline) conn = self.server.accepted.swap(null, .acq_rel);
        const c = conn orelse return self.failed.store(true, .release);
        var sid: ?u64 = null;
        while (sid == null and nowMs() < deadline) sid = api.openStream(c, true) catch null;
        const s = sid orelse return self.failed.store(true, .release);
        var n: u32 = 0;
        while (n < writes_per_conn and nowMs() < deadline) {
            const w = api.writeStream(c, s, "early response 0123", false) catch return self.failed.store(true, .release);
            if (w > 0) n += 1;
        }
        self.sent.store(n, .release);
    }
};

/// Reads the packet numbers of the recorded server datagrams with the
/// server's header protection key, and counts those seen more than once.
fn countDuplicates(log: *const relay_mod.ShortLog, hp: [16]u8, dcid_len: usize, decoded: *u32) !u32 {
    var seen = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, 1 << 16);
    defer seen.deinit(testing.allocator);
    var largest: ?u64 = null;
    var dups: u32 = 0;
    const n = log.count.load(.acquire);
    for (0..n) |i| {
        const info = relay_mod.decodeShortHeader(hp, dcid_len, log.head(i), &largest) orelse continue;
        if (info.pn >= seen.bit_length) continue;
        decoded.* += 1;
        if (seen.isSet(@intCast(info.pn))) dups += 1 else seen.set(@intCast(info.pn));
    }
    return dups;
}

test "SONNY-6654 no server packet number is used twice while the handshake completes and the application writes" {
    // RFC 9000 §12.3: "A packet number MUST NOT be reused within the same
    // packet number space"; a reused one also reuses the AEAD nonce under the
    // same key (RFC 9001 §5.3). Packets are numbered from pn_app_tx under
    // Connection.mu (SONNY-4379), but the step that completes the handshake
    // sent without it: the HANDSHAKE_DONE packet from pushCrypto
    // (sendHandshakeDoneControl) and deriveAppKeys. A server application
    // writing the moment its 1-RTT keys are usable sends under the mutex,
    // concurrently with that packet, and both can take the same number.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();

    const log = try testing.allocator.create(relay_mod.ShortLog);
    defer testing.allocator.destroy(log);

    var total_dups: u32 = 0;
    var dup_conns: u32 = 0;
    var total_decoded: u32 = 0;
    var completed: u32 = 0;
    var i: u32 = 0;
    while (i < handshakes) : (i += 1) {
        log.* = .{};
        var relay = try Relay.init(port);
        defer relay.deinit();
        relay.down.log = log;
        const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
        defer {
            relay.done.store(true, .release);
            relay_thread.join();
        }

        var writer = Writer{ .server = &server };
        server.accepted.store(null, .release);
        const writer_thread = try std.Thread.spawn(.{}, Writer.run, .{&writer});

        var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
        var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
        defer client_ep.deinit();
        var target_buf: [32]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{relay.front_port});
        const conn = try api.connect(&client_ep, target, "localhost");
        const deadline = nowMs() + 10_000;
        while (nowMs() < deadline and !(api.isHandshakeConfirmed(conn) and writer.sent.load(.acquire) == writes_per_conn)) {
            _ = client_ep.pollWithStats(1) catch {};
        }
        writer_thread.join();
        // Let the last datagrams through the relay.
        const settle = nowMs() + 50;
        while (nowMs() < settle) _ = client_ep.pollWithStats(1) catch {};

        try testing.expect(!writer.failed.load(.acquire));
        try testing.expect(api.isHandshakeConfirmed(conn));
        try testing.expectEqual(writes_per_conn, writer.sent.load(.acquire));
        completed += 1;

        // The client's view of the server connection: the server encrypts
        // with the client's receive keys, and addresses the client's CID.
        conn.mu.lockUncancelable(io);
        const hp = conn.app_rx_keys.?.hp;
        const dcid_len: usize = conn.our_scid.len;
        conn.mu.unlock(io);
        var decoded: u32 = 0;
        const dups = try countDuplicates(log, hp, dcid_len, &decoded);
        total_decoded += decoded;
        total_dups += dups;
        if (dups > 0) dup_conns += 1;
        _ = api.close(conn, 0, "done") catch {};
    }
    testlog.print("\n  SONNY-6654: handshakes={d} server 1-RTT packets read={d} duplicate packet numbers={d} (in {d} connections)\n", .{ completed, total_decoded, total_dups, dup_conns });
    try testing.expectEqual(handshakes, completed);
    try testing.expect(total_decoded >= handshakes * writes_per_conn);
    try testing.expectEqual(@as(u32, 0), total_dups);
}
