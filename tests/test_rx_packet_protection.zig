// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6649): 1-RTT packet protection on the receive
// path and packet number encoding on the send path. A real client and
// server endpoint talk over loopback UDP through a relay (udp_relay.zig)
// that drops, captures or adds datagrams on the client's path, as a network
// or an off-path attacker would. Nothing in the QUIC stack is replaced.

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
// under -Dfips; packet protection and packet numbers are crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
var next_port = std.atomic.Value(u16).init(23800);

const io = std.Io.Threaded.global_single_threaded.io();

/// A server endpoint polled on its own thread. It accepts one connection,
/// reads its first stream to the end and answers "OK" + FIN.
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
                got += n;
                self.received.store(got, .release);
            }
            if (self.finished.load(.acquire) and !answered) {
                _ = api.writeStream(c, s, "OK", true) catch continue;
                answered = true;
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

/// Connects a client endpoint to `server` through `relay` and waits until
/// both ends have 1-RTT keys. Publishes the client's header protection key
/// to the client-to-server link.
fn connectThroughRelay(client_ep: *endpoint_mod.Endpoint, relay: *Relay, server: *Server) !*api.Connection {
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{relay.front_port});
    const conn = try api.connect(client_ep, target, "localhost");
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline and !(api.isHandshakeConfirmed(conn) and serverHasAppKeys(server.conn.load(.acquire)))) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));
    try testing.expect(serverHasAppKeys(server.conn.load(.acquire)));
    relay.up.publish(conn);
    return conn;
}

fn clientPollThread(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
}

// ---------------------------------------------------------------------------
// The cost of an undecryptable packet (RFC 9001 §5.4, §6.3, §9.5).
// ---------------------------------------------------------------------------

const forged_count: u64 = 256;

test "SONNY-6649 an undecryptable 1-RTT packet costs one protection removal (RFC 9001 §5.4, §6.3)" {
    // A short header does not carry the DCID length, but a receiver knows
    // it: the DCID is one of the connection IDs it issued, and the lookup
    // that found the connection matched it. Header protection keys are not
    // updated with a key update (RFC 9001 §6), so after removing header
    // protection the key phase bit says which keys protect the packet: the
    // current keys, or the next or previous ones (§6.3, §6.5). One AEAD open
    // per packet. The receive path instead tried every DCID length 0..20
    // with the current, next and previous keys (and a "hybrid" of them),
    // then 21 more forced next-key attempts: about 85 header protection
    // removals and AEAD opens for every packet that fails, which anyone who
    // knows a connection ID and its peer's address can send.
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
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;

    // Capture one of the client's 1-RTT datagrams as the forgeries' template.
    relay.up.capture.store(true, .release);
    const sid = try api.openStream(conn, true);
    _ = try api.writeStream(conn, sid, "ping", false);
    const cap_deadline = nowMs() + 2_000;
    while (nowMs() < cap_deadline and relay.up.capturedDatagram() == null) _ = client_ep.pollWithStats(1) catch {};
    const template = relay.up.capturedDatagram() orelse return error.NothingCaptured;
    // The client is not polled while the forgeries arrive, so every 1-RTT
    // packet the server receives meanwhile is one of them.
    sleepUs(100_000);

    sc.mu.lockUncancelable(io);
    const rx_gen_before = sc.rx_key_gen;
    sc.mu.unlock(io);
    const attempts_before = sc.rx_short_decrypt_attempts.load(.monotonic);
    const invalid_before = @atomicLoad(u64, &sc.aead_rx_invalid_count, .monotonic);

    var forged: [relay_mod.capture_capacity]u8 = undefined;
    for (0..forged_count) |i| {
        @memcpy(forged[0..template.len], template);
        // A wrong authentication tag; every other one also claims the other
        // key phase (flipping a protected header bit flips the plain bit).
        forged[template.len - 1] ^= 0x5a;
        if (i % 2 == 1) forged[0] ^= 0x04;
        relay.sendToServer(forged[0..template.len]);
    }
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline and @atomicLoad(u64, &sc.aead_rx_invalid_count, .monotonic) - invalid_before < forged_count) sleepUs(1_000);
    sleepUs(50_000);

    const attempts = sc.rx_short_decrypt_attempts.load(.monotonic) - attempts_before;
    const invalid = @atomicLoad(u64, &sc.aead_rx_invalid_count, .monotonic) - invalid_before;
    sc.mu.lockUncancelable(io);
    const rx_gen_after = sc.rx_key_gen;
    sc.mu.unlock(io);
    testlog.print("\n  SONNY-6649 forged packets={d}: rejected={d} protection removals={d} ({d} per packet) rx key gen {d} -> {d}\n", .{ forged_count, invalid, attempts, attempts / @max(invalid, 1), rx_gen_before, rx_gen_after });

    try testing.expectEqual(forged_count, invalid);
    try testing.expectEqual(forged_count, attempts);
    // A forged packet claiming the next key phase does not update the keys.
    try testing.expectEqual(rx_gen_before, rx_gen_after);

    // The connection still works.
    _ = try api.writeStream(conn, sid, "pong", true);
    const done_deadline = nowMs() + 5_000;
    while (nowMs() < done_deadline and !server.finished.load(.acquire)) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(@as(u64, 8), server.received.load(.acquire));
    _ = api.close(conn, 0, "done") catch {};
}

// ---------------------------------------------------------------------------
// Packet number length (RFC 9000 §17.1, Appendix A.2, A.3).
// ---------------------------------------------------------------------------

const blackout_from: u64 = 40_000;
const blackout_len: u64 = 33_000;

test "SONNY-6649 1-RTT packet numbers stay decodable after a long blackout (RFC 9000 §17.1, Appendix A)" {
    // RFC 9000 §17.1: "the sender MUST use a packet number size able to
    // represent more than twice as large a range as the difference between
    // the largest acknowledged packet number and the packet number being
    // sent." Every 1-RTT packet used a 2-byte packet number. The receiver
    // decodes it relative to the largest packet number it received
    // (Appendix A.3); once more than 2^15 packets in a row are lost, the
    // next one decodes 65536 too low, its AEAD nonce is wrong, and so is
    // every later packet's: the connection is dead. The client here sends
    // one small STREAM frame per packet; the relay drops its packets
    // [40000, 73000), after which they get through again. The lost frames
    // must then be retransmitted together, a full packet at a time: one
    // packet per lost frame did not finish within the deadline on a 2-vCPU
    // runner (SONNY-6649, main pipeline 3073168754).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    relay.up.state.drop_from = blackout_from;
    relay.up.state.drop_until = blackout_from + blackout_len;
    relay.up.rule = relay_mod.dropPacketNumberRange;
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const sid = try api.openStream(conn, true);
    const chunk = "0123456789abcdef";
    var sent: u64 = 0;
    const target_pn = blackout_from + blackout_len + 2_000;
    const write_deadline = nowMs() + 120_000;
    while (nowMs() < write_deadline) {
        conn.mu.lockUncancelable(io);
        const pn_tx = conn.pn_app_tx;
        conn.mu.unlock(io);
        if (pn_tx >= target_pn) break;
        const n = api.writeStream(conn, sid, chunk, false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        sent += n;
        if (n == 0) sleepUs(100);
    }
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

    sc.mu.lockUncancelable(io);
    const server_largest_rx = sc.pn_app.max;
    sc.mu.unlock(io);
    const invalid = @atomicLoad(u64, &sc.aead_rx_invalid_count, .monotonic);
    conn.mu.lockUncancelable(io);
    const pn_tx = conn.pn_app_tx;
    const retx_packets = conn.stream_retx_packets;
    conn.mu.unlock(io);
    testlog.print("\n  SONNY-6649 blackout: dropped={d} client pn_tx={d} relay largest={d} server largest rx={d} undecryptable={d} retransmission packets={d} delivered={d} of {d} finished={}\n", .{ relay.up.state.dropped, pn_tx, relay.up.state.max_pn, server_largest_rx, invalid, retx_packets, server.received.load(.acquire), sent, server.finished.load(.acquire) });

    try testing.expectEqual(@as(u32, blackout_len), relay.up.state.dropped);
    try testing.expect(server_largest_rx >= blackout_from + blackout_len);
    try testing.expectEqual(@as(u64, 0), invalid);
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(sent, server.received.load(.acquire));
    // Lost data goes out again in full packets, not one 16-byte frame per
    // packet: even if every byte sent had to be retransmitted, that takes
    // at most sent / 500 packets (SONNY-6649). One packet per lost frame
    // was more than 33000 packets, over a minute of recovery on a loaded
    // 2-vCPU runner.
    try testing.expect(retx_packets <= sent / 500);
    _ = api.close(conn, 0, "done") catch {};
}

// ---------------------------------------------------------------------------
// Key updates and handshake confirmation (RFC 9001 §4.1.2, §6.1).
// ---------------------------------------------------------------------------

const unconfirmed_packets: u64 = 700;

test "SONNY-6649 no key update before the handshake is confirmed (RFC 9001 §6.1)" {
    // RFC 9001 §6.1: "An endpoint MUST NOT initiate a key update prior to
    // having confirmed the handshake (Section 4.1.2)." A client confirms the
    // handshake when it receives HANDSHAKE_DONE (§4.1.2); before that it can
    // already send 1-RTT data. The client initiated a key update after 512
    // ack-eliciting packets whether or not the handshake was confirmed. Here
    // the relay drops every 1-RTT datagram from the server, HANDSHAKE_DONE
    // included, while the client sends 700 packets; then lets them through.
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
    relay.up.rule = relay_mod.observeGenerations;
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
    // Handshake complete (the server's Finished verified, 1-RTT keys), but
    // not confirmed: HANDSHAKE_DONE travels in a 1-RTT packet.
    const hs_deadline = nowMs() + 5_000;
    while (nowMs() < hs_deadline and !(api.isHandshakeConfirmed(conn) and serverHasAppKeys(server.conn.load(.acquire)))) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));
    relay.up.publish(conn);

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const sid = try api.openStream(conn, true);
    var sent: u64 = 0;
    const write_deadline = nowMs() + 30_000;
    while (nowMs() < write_deadline) {
        conn.mu.lockUncancelable(io);
        const pn_tx = conn.pn_app_tx;
        conn.mu.unlock(io);
        if (pn_tx >= unconfirmed_packets) break;
        const n = api.writeStream(conn, sid, "0123456789abcdef", false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        sent += n;
        if (n == 0) sleepUs(100);
    }
    sleepUs(100_000);
    conn.mu.lockUncancelable(io);
    const confirmed = conn.handshake_done_seen;
    const tx_gen = conn.tx_key_gen;
    conn.mu.unlock(io);
    const wire_gen = @atomicLoad(u32, &relay.up.state.max_gen, .acquire);
    const wire_pn = @atomicLoad(u64, &relay.up.state.max_pn, .acquire);
    testlog.print("\n  SONNY-6649 unconfirmed: client sent pn up to {d}, handshake_done_seen={} tx key gen={d} key gen on the wire={d}\n", .{ wire_pn, confirmed, tx_gen, wire_gen });
    try testing.expect(!confirmed);
    try testing.expect(wire_pn + 1 >= unconfirmed_packets);
    try testing.expectEqual(@as(u64, 0), tx_gen);
    try testing.expectEqual(@as(u32, 0), wire_gen);

    // Once HANDSHAKE_DONE gets through, the transfer completes.
    relay.down.block_short.store(false, .release);
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
    const deadline = nowMs() + 30_000;
    while (nowMs() < deadline and !server.finished.load(.acquire)) sleepUs(1_000);
    // HANDSHAKE_DONE is sent again once the server finds it lost (RFC 9000
    // §13.3), which takes an ACK for one of its later packets.
    var confirmed_after = false;
    const confirm_deadline = nowMs() + 5_000;
    while (nowMs() < confirm_deadline and !confirmed_after) {
        conn.mu.lockUncancelable(io);
        confirmed_after = conn.handshake_done_seen;
        conn.mu.unlock(io);
        if (!confirmed_after) sleepUs(1_000);
    }
    testlog.print("  SONNY-6649 unblocked: finished={} delivered={d} of {d} handshake_done_seen={}\n", .{ server.finished.load(.acquire), server.received.load(.acquire), sent, confirmed_after });
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(sent, server.received.load(.acquire));
    try testing.expect(confirmed_after);
    _ = api.close(conn, 0, "done") catch {};
}

// ---------------------------------------------------------------------------
// Retention of the previous receive keys (RFC 9001 §6.5).
// ---------------------------------------------------------------------------

/// Uploads 1200-byte STREAM frames, one per packet, until the relay has
/// forwarded `after_update` packets of a key generation after the first,
/// then FIN; returns the bytes written. Paced, so that the server's RTT
/// samples (and the PTO its key retention follows) are not those of its own
/// receive queue.
fn uploadPastKeyUpdate(conn: *api.Connection, sid: api.QuicStreamId, link: *relay_mod.Link, after_update: u32) !u64 {
    var payload: [1200]u8 = undefined;
    @memset(&payload, 'k');
    var sent: u64 = 0;
    const deadline = nowMs() + 30_000;
    while (nowMs() < deadline) {
        if (link.later_gen_forwarded.load(.acquire) >= after_update) break;
        const n = api.writeStream(conn, sid, &payload, false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        sent += n;
        sleepUs(100);
    }
    while (true) {
        _ = api.writeStream(conn, sid, "", true) catch |err| switch (err) {
            error.FlowControlBlocked => {
                sleepUs(100);
                continue;
            },
            else => return err,
        };
        return sent;
    }
}

const PrevKeysOutcome = struct {
    held: usize,
    rejected: u64,
    rx_key_gen: u64,
    prev_keys_kept: bool,
    delivered_all: bool,
    /// Released before the server's discard deadline for the previous keys.
    released_in_window: bool,
    /// The server's retention period: three PTOs (ms).
    retention_ms: u64,
};

const Release = enum { at_once, after_retention };

/// Holds back the client's packets of key generation 0 numbered from
/// `hold_from_pn` (at most relay_mod.max_held) across its first key update,
/// and releases them once the server opened 16 packets with the new keys:
/// at once, or after the server's retention period for the previous keys.
fn reorderAcrossKeyUpdate(hold_from_pn: u64, when: Release) !PrevKeysOutcome {
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    relay.up.hold_from_pn = hold_from_pn;
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;
    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const sid = try api.openStream(conn, true);
    // One key update (after 512 ack-eliciting packets once the handshake is
    // confirmed), not two: the next comes 512 packets after it.
    const sent = try uploadPastKeyUpdate(conn, sid, &relay.up, 100);
    var discard_ns: u64 = 0;
    var promoted_ns: u64 = 0;
    const promoted_deadline = nowMs() + 10_000;
    while (nowMs() < promoted_deadline) {
        sc.mu.lockUncancelable(io);
        const promoted = sc.rx_key_gen >= 1 and sc.pn_app.max >= sc.rx_key_gen_start_pn + 16;
        discard_ns = sc.rx_prev_discard_ns;
        sc.mu.unlock(io);
        if (promoted) {
            promoted_ns = relay_mod.nowNs();
            break;
        }
        sleepUs(200);
    }
    if (when == .after_retention) {
        // Past the server's deadline, bounded so that a broken deadline
        // cannot hang the test.
        const target = @min(discard_ns, promoted_ns + 60 * std.time.ns_per_s) + 50 * std.time.ns_per_ms;
        const now = relay_mod.nowNs();
        if (target > now) sleepUs((target - now) / 1000);
    }
    const released_ns = relay_mod.nowNs();
    relay.up.release_requested.store(true, .release);
    const deadline = nowMs() + 30_000;
    while (nowMs() < deadline and !(server.finished.load(.acquire) and relay.up.released.load(.acquire) > 0)) sleepUs(1_000);
    // Let the server process the released packets.
    sleepUs(200_000);

    sc.mu.lockUncancelable(io);
    const rx_key_gen = sc.rx_key_gen;
    const prev_keys_kept = sc.rx_prev_keys != null;
    sc.mu.unlock(io);
    const out = PrevKeysOutcome{
        .held = relay.up.held_count,
        .rejected = @atomicLoad(u64, &sc.aead_rx_invalid_count, .monotonic),
        .rx_key_gen = rx_key_gen,
        .prev_keys_kept = prev_keys_kept,
        .delivered_all = server.finished.load(.acquire) and server.received.load(.acquire) == sent,
        .released_in_window = released_ns < discard_ns,
        .retention_ms = (discard_ns -| promoted_ns) / std.time.ns_per_ms,
    };
    _ = api.close(conn, 0, "done") catch {};
    return out;
}

test "SONNY-6649 packets reordered across a key update are opened with the previous keys (RFC 9001 §6.5)" {
    // RFC 9001 §6.5: packets protected with older keys might arrive late,
    // and retaining the old keys lets them be processed; an endpoint
    // "SHOULD retain old read keys for no more than three times the PTO
    // after having received a packet protected using the new keys". The
    // receiver kept them for 16 packets opened with them instead: of the
    // last packets of the old generation, reordered behind the first ones of
    // the new generation, those after the 16th were dropped as undecryptable.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const out = try reorderAcrossKeyUpdate(472, .at_once);
    testlog.print("\n  SONNY-6649 reordered: held={d} undecryptable={d} rx key gen={d} released within retention={} (~{d} ms) delivered all={}\n", .{ out.held, out.rejected, out.rx_key_gen, out.released_in_window, out.retention_ms, out.delivered_all });
    try testing.expect(out.held > 16);
    try testing.expect(out.released_in_window);
    try testing.expectEqual(@as(u64, 1), out.rx_key_gen);
    try testing.expectEqual(@as(u64, 0), out.rejected);
    try testing.expect(out.delivered_all);
}

test "SONNY-6649 the previous receive keys are discarded three PTOs after the key update (RFC 9001 §6.5)" {
    // Old read keys SHOULD be discarded within three PTOs of the first packet
    // under the new keys (RFC 9001 §6.5). They were kept until 16 packets
    // had been opened with them, so without reordering for the life of the
    // generation. Packets of the old generation released after the server's
    // three PTOs must no longer open.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const out = try reorderAcrossKeyUpdate(505, .after_retention);
    testlog.print("\n  SONNY-6649 late: held={d} undecryptable={d} rx key gen={d} retention ~{d} ms prev keys kept={} delivered all={}\n", .{ out.held, out.rejected, out.rx_key_gen, out.retention_ms, out.prev_keys_kept, out.delivered_all });
    try testing.expect(out.held > 0);
    try testing.expect(!out.released_in_window);
    try testing.expectEqual(@as(u64, 1), out.rx_key_gen);
    try testing.expectEqual(@as(u64, out.held), out.rejected);
    try testing.expect(!out.prev_keys_kept);
    try testing.expect(out.delivered_all);
}

// ---------------------------------------------------------------------------
// Out-of-order STREAM data behind one hole (RFC 9000 §2.2, §4.1).
// ---------------------------------------------------------------------------

/// Drops every client packet that carries STREAM bytes [0, hole_end), the
/// first frame and each retransmission of it, until `open_after` STREAM
/// frames past it were forwarded. Reads the frames by decrypting the
/// client's packets with its 1-RTT keys (key updates are disabled).
const HoleFilter = struct {
    keys: packet_mod.AeadKeys,
    dcid_len: usize,
    hole_end: u64,
    open_after: u32,
    open: std.atomic.Value(bool) = .init(false),
    behind: std.atomic.Value(u32) = .init(0),
    dropped_hole: std.atomic.Value(u32) = .init(0),

    fn filter(ctx: *anyopaque, pkt: []const u8, info: relay_mod.ShortInfo) bool {
        const self: *HoleFilter = @ptrCast(@alignCast(ctx));
        if (self.open.load(.acquire)) return true;
        var scratch: [4096]u8 = undefined;
        const view = packet_mod.decodeShortProtectedInto(pkt, self.dcid_len, self.keys, info.pn -| 1, &scratch) catch return true;
        var off: usize = 0;
        var carries_hole = false;
        var behind: u32 = 0;
        while (off < view.payload.len) {
            const fr = frame_mod.decodeOne(view.payload[off..]) catch break;
            if (fr.n == 0) break;
            off += fr.n;
            switch (fr.f) {
                .stream => |st| {
                    if ((st.offset orelse 0) < self.hole_end) carries_hole = true else behind += 1;
                },
                else => {},
            }
        }
        if (carries_hole) {
            _ = self.dropped_hole.fetchAdd(1, .monotonic);
            return false;
        }
        if (behind > 0 and self.behind.fetchAdd(behind, .monotonic) + behind >= self.open_after) self.open.store(true, .release);
        return true;
    }
};

const small_frames: u32 = 22_000;
const frames_behind_hole: u32 = 20_000;

test "SONNY-6649 small STREAM frames behind one lost packet are not a flow control error (RFC 9000 §4.1)" {
    // Flow control limits bytes (RFC 9000 §4.1): a peer within its stream
    // and connection windows has not violated it, however small its STREAM
    // frames. The receiver capped the number of buffered out-of-order
    // segments at 16384 and closed the connection with FLOW_CONTROL_ERROR
    // beyond it, so a sender of small frames lost its connection after one
    // lost packet once 16384 frames had arrived behind the hole. Here the
    // client sends 16-byte frames, one per packet, and the relay drops the
    // first one (and its retransmissions) until 20000 frames behind it got
    // through.
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
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;
    // One key set for the relay to read the client's packets with.
    sc.mu.lockUncancelable(io);
    sc.disable_auto_key_update = true;
    sc.mu.unlock(io);
    conn.mu.lockUncancelable(io);
    conn.disable_auto_key_update = true;
    var hole = HoleFilter{
        .keys = conn.app_tx_keys.?,
        .dcid_len = conn.shortHeaderDcid().len,
        .hole_end = 16,
        .open_after = frames_behind_hole,
    };
    conn.mu.unlock(io);
    relay.up.filter_ctx = &hole;
    relay.up.filter = HoleFilter.filter;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const sid = try api.openStream(conn, true);
    const chunk = "0123456789abcdef";
    var sent: u64 = 0;
    var frames: u32 = 0;
    const write_deadline = nowMs() + 60_000;
    while (nowMs() < write_deadline and frames < small_frames) {
        const n = api.writeStream(conn, sid, chunk, false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => break,
        };
        sent += n;
        if (n == chunk.len) frames += 1;
        if (n == 0) sleepUs(100);
    }
    while (frames == small_frames) {
        _ = api.writeStream(conn, sid, "", true) catch |err| switch (err) {
            error.FlowControlBlocked => {
                sleepUs(100);
                continue;
            },
            else => break,
        };
        break;
    }
    const deadline = nowMs() + 30_000;
    while (nowMs() < deadline and !server.finished.load(.acquire) and !sc.closed) sleepUs(1_000);
    testlog.print("\n  SONNY-6649 hole: client frames={d} hole packets dropped={d} frames behind the hole before it opened={d} server closed={} delivered={d} of {d} finished={}\n", .{ frames, hole.dropped_hole.load(.acquire), hole.behind.load(.acquire), sc.closed, server.received.load(.acquire), sent, server.finished.load(.acquire) });

    try testing.expectEqual(small_frames, frames);
    try testing.expect(hole.dropped_hole.load(.acquire) >= 1);
    try testing.expect(hole.behind.load(.acquire) >= frames_behind_hole);
    try testing.expect(!sc.closed);
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(sent, server.received.load(.acquire));
    _ = api.close(conn, 0, "done") catch {};
}

// ---------------------------------------------------------------------------
// Packet number allocation is serialized (SONNY-4379; RFC 9000 §12.3).
// ---------------------------------------------------------------------------

/// Counts 1-RTT packet numbers the server used more than once, read on the
/// server-to-client link (header protection removed with the server's key).
const DuplicatePns = struct {
    seen: std.DynamicBitSetUnmanaged,
    duplicates: std.atomic.Value(u32) = .init(0),
    first_duplicate: std.atomic.Value(u64) = .init(0),

    fn filter(ctx: *anyopaque, pkt: []const u8, info: relay_mod.ShortInfo) bool {
        _ = pkt;
        const self: *DuplicatePns = @ptrCast(@alignCast(ctx));
        if (info.pn >= self.seen.bit_length) return true;
        if (self.seen.isSet(@intCast(info.pn))) {
            if (self.duplicates.fetchAdd(1, .monotonic) == 0) self.first_duplicate.store(info.pn, .monotonic);
        } else self.seen.set(@intCast(info.pn));
        return true;
    }
};

const fin_streams: u32 = 600;

/// Opens `fin_streams` streams on the accepted connection, writes a short
/// response on each and closes it (FIN), as fast as it can.
fn finWriter(server: *Server, done: *std.atomic.Value(u32)) void {
    const c = server.conn.load(.acquire) orelse return;
    var n: u32 = 0;
    while (n < fin_streams) : (n += 1) {
        const sid = api.openStream(c, true) catch break;
        _ = api.writeStream(c, sid, "response page 0123456", false) catch break;
        api.closeStream(c, sid, 0) catch break;
    }
    done.store(n, .release);
}

test "SONNY-4379 no two server packets share a packet number while FINs race the receive path" {
    // RFC 9000 §12.3: "A packet number MUST NOT be reused within the same
    // packet number space"; a reused one also reuses the AEAD nonce
    // (RFC 9001 §5.3). The application thread sends STREAM data and FINs
    // under Connection.mu (closeStream, writeStream), but some packets the
    // receive path sends did not take it: answering a PATH_CHALLENGE, a
    // DATA_BLOCKED, a late Handshake packet, a DATAGRAM echo. Each read
    // pn_app_tx while a FIN was being sent with the same one: two packets,
    // one packet number, and the peer drops the second as a duplicate (a
    // geode server lost response pages and its client stalled). Here the
    // server writes and closes 600 streams while the relay injects client
    // packets carrying PATH_CHALLENGE.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server: Server = undefined;
    server = .{ .ep = undefined, .config = undefined };
    try server.start(port);
    defer server.stop();
    var relay = try Relay.init(port);
    defer relay.deinit();
    var dups = DuplicatePns{ .seen = try std.DynamicBitSetUnmanaged.initEmpty(testing.allocator, 1 << 20) };
    defer dups.seen.deinit(testing.allocator);
    const relay_thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    defer {
        relay.done.store(true, .release);
        relay_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;
    sc.mu.lockUncancelable(io);
    sc.disable_auto_key_update = true;
    sc.mu.unlock(io);
    conn.mu.lockUncancelable(io);
    conn.disable_auto_key_update = true;
    const client_keys = conn.app_tx_keys.?;
    const client_phase = conn.tx_key_phase;
    var dcid_buf: [20]u8 = undefined;
    const dcid_len = conn.shortHeaderDcid().len;
    @memcpy(dcid_buf[0..dcid_len], conn.shortHeaderDcid());
    conn.mu.unlock(io);
    relay.down.publish(sc);
    relay.down.filter_ctx = &dups;
    relay.down.filter = DuplicatePns.filter;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    var streams_done = std.atomic.Value(u32).init(std.math.maxInt(u32));
    const writer = try std.Thread.spawn(.{}, finWriter, .{ &server, &streams_done });
    // Client packets the client never sent, numbered far above its own, each
    // with a PATH_CHALLENGE (RFC 9000 §8.2.2: answered with PATH_RESPONSE).
    var injected: u32 = 0;
    var pkt_buf: [256]u8 = undefined;
    while (streams_done.load(.acquire) == std.math.maxInt(u32) and injected < 3000) : (injected += 1) {
        var frame_buf: [16]u8 = undefined;
        var w: std.Io.Writer = .fixed(&frame_buf);
        var challenge: [8]u8 = undefined;
        std.mem.writeInt(u64, &challenge, injected, .big);
        _ = (frame_mod.Frame{ .path_challenge = challenge }).write(&w) catch unreachable;
        const len = try packet_mod.encodeShortProtectedInto(&pkt_buf, dcid_buf[0..dcid_len], 1_000_000 + @as(u64, injected), 4, frame_buf[0..w.end], client_keys, client_phase);
        relay.sendToServer(pkt_buf[0..len]);
        sleepUs(50);
    }
    writer.join();
    sleepUs(200_000);
    testlog.print("\n  SONNY-4379: streams closed={d} PATH_CHALLENGEs injected={d} duplicate server packet numbers={d} (first {d})\n", .{ streams_done.load(.acquire), injected, dups.duplicates.load(.acquire), dups.first_duplicate.load(.acquire) });

    try testing.expectEqual(fin_streams, streams_done.load(.acquire));
    try testing.expect(injected > 0);
    try testing.expectEqual(@as(u32, 0), dups.duplicates.load(.acquire));
    _ = api.close(conn, 0, "done") catch {};
}

test "SONNY-6649 spurious retransmissions into a full window behind a hole are not a flow control error" {
    // The receiver coalesces contiguous out-of-order data into one segment.
    // A retransmission of bytes inside such a run was buffered again and
    // counted a second time against the stream window: once the peer had
    // filled the window behind a hole (a 64 MiB transfer on a starved CI
    // runner: lmsd - recv_off = 16 MiB exactly), any spurious retransmission
    // pushed the count past the window and the receiver closed the
    // connection with FLOW_CONTROL_ERROR; the transfer stopped at the hole.
    // Here the relay holds the first packet back (and its retransmissions)
    // while the client fills the stream window behind it, then blocks the
    // server's packets so that the client, hearing no ACKs, retransmits data
    // the server already has; then everything gets through.
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
    const conn = try connectThroughRelay(&client_ep, &relay, &server);
    const sc = server.conn.load(.acquire).?;
    sc.mu.lockUncancelable(io);
    sc.disable_auto_key_update = true;
    sc.mu.unlock(io);
    conn.mu.lockUncancelable(io);
    conn.disable_auto_key_update = true;
    var hole = HoleFilter{
        .keys = conn.app_tx_keys.?,
        .dcid_len = conn.shortHeaderDcid().len,
        .hole_end = 1,
        .open_after = std.math.maxInt(u32),
    };
    conn.mu.unlock(io);
    relay.up.filter_ctx = &hole;
    relay.up.filter = HoleFilter.filter;

    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    // Fill the stream window behind the hole: write until flow control has
    // blocked the writer for a second.
    const sid = try api.openStream(conn, true);
    var payload: [1200]u8 = undefined;
    @memset(&payload, 'w');
    var sent: u64 = 0;
    var blocked_since: ?i64 = null;
    const fill_deadline = nowMs() + 60_000;
    while (nowMs() < fill_deadline) {
        const n = api.writeStream(conn, sid, &payload, false) catch |err| switch (err) {
            error.FlowControlBlocked => 0,
            else => return err,
        };
        sent += n;
        if (n == 0) {
            const since = blocked_since orelse nowMs();
            blocked_since = since;
            if (nowMs() - since > 1_000) break;
            sleepUs(1_000);
        } else blocked_since = null;
    }
    // No ACKs reach the client for a while: its PTO probes resend data the
    // server already buffered.
    relay.down.block_short.store(true, .release);
    sleepUs(3_000_000);
    relay.down.block_short.store(false, .release);
    hole.open.store(true, .release);

    while (true) {
        const n = api.writeStream(conn, sid, &payload, false) catch |err| switch (err) {
            error.FlowControlBlocked => {
                sleepUs(1_000);
                if (sc.closed) break;
                continue;
            },
            else => return err,
        };
        sent += n;
        break;
    }
    while (!sc.closed) {
        _ = api.writeStream(conn, sid, "", true) catch |err| switch (err) {
            error.FlowControlBlocked => {
                sleepUs(1_000);
                continue;
            },
            else => return err,
        };
        break;
    }
    const deadline = nowMs() + 30_000;
    while (nowMs() < deadline and !server.finished.load(.acquire) and !sc.closed) sleepUs(1_000);
    testlog.print("\n  SONNY-6649 full window behind a hole: sent={d} delivered={d} hole drops={d} server closed={} finished={}\n", .{ sent, server.received.load(.acquire), hole.dropped_hole.load(.acquire), sc.closed, server.finished.load(.acquire) });

    try testing.expect(sent >= 16 * 1024 * 1024);
    try testing.expect(!sc.closed);
    try testing.expect(server.finished.load(.acquire));
    try testing.expectEqual(sent, server.received.load(.acquire));
    _ = api.close(conn, 0, "done") catch {};
}
