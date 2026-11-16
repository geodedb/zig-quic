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

const relay_mod = @import("udp_relay.zig");
const nowMs = relay_mod.nowMs;
const sleepUs = relay_mod.sleepUs;
const ShortInfo = relay_mod.ShortInfo;
const RuleState = relay_mod.RuleState;
const Relay = relay_mod.Relay;

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
