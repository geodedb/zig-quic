// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-4791 follow-up): a client Finished whose UDP
// submission returns error.WouldBlock (EAGAIN on a full socket send buffer)
// must not be lost.
//
// TLS hands the client's Finished to QUIC exactly once (pollCrypto transfers
// ownership). Before the fix, `pushCrypto` freed those bytes when
// `sendHandshakeCrypto` failed, before any retransmit copy existed, and never
// marked the local Finished as sent. Nothing could resend it: the server's
// retransmitted flight is a duplicate the client does not re-feed to TLS, and
// the client's Handshake PTO had no CRYPTO to probe with. The client never
// derived 1-RTT keys and the connection stalled until the idle timeout.
//
// The fix keeps the polled bytes in `pending_hs_messages`, marks the
// connection for the endpoint's bounded pending-handshake retry queue, and
// marks the Finished sent only after a successful submission.
//
// This test runs a real loopback handshake with the client's sender wrapped
// so that the Handshake packet carrying the client Finished is refused once
// with error.WouldBlock. The handshake must still complete on both sides.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

// The loopback handshake with the embedded test certificate does not complete
// under -Dfips (FIPS key-share policy); the send-retry path under test is
// crypto-agnostic and is covered by the -Dfips=false gate, as in
// tests/test_small_rcvbuf_bulk_stream.zig.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";
const HANDSHAKE_TIMEOUT_MS: i64 = 5_000;

// 20300+ avoids the ranges used by the other loopback tests.
var next_port = std.atomic.Value(u16).init(20300);

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// Wraps the endpoint's sender and refuses the client's first Finished
/// submission with error.WouldBlock, the error the UDP transport reports
/// for EAGAIN.
const BlockFinishedOnce = struct {
    inner_ctx: *anyopaque,
    inner_fn: *const fn (ctx: *anyopaque, c: *api.Connection, data: []const u8) anyerror!usize,
    blocked: usize = 0,
    finished_submissions: usize = 0,

    fn isClientFinished(c: *api.Connection, data: []const u8) bool {
        // QUIC v1 long-header Handshake packet (type 0b10). Header
        // protection masks only the low four bits of the first byte.
        if (data.len == 0 or data[0] & 0xf0 != 0xe0) return false;
        // The client's Finished is its first Handshake CRYPTO and is sent
        // right after it verifies the server's Finished; the CRYPTO offset
        // advances only once a submission succeeds.
        return c.role == .Client and c.peer_finished_verified and c.crypto_tx_off_handshake == 0;
    }

    fn send(raw: *anyopaque, c: *api.Connection, data: []const u8) anyerror!usize {
        const self: *BlockFinishedOnce = @ptrCast(@alignCast(raw));
        if (isClientFinished(c, data)) {
            self.finished_submissions += 1;
            if (self.blocked == 0) {
                self.blocked += 1;
                return error.WouldBlock;
            }
        }
        return self.inner_fn(self.inner_ctx, c, data);
    }
};

test "client Finished refused with WouldBlock is retried and the handshake completes" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;

    const allocator = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var addr_buf: [32]u8 = undefined;
    const server_addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var server_ep = try endpoint_mod.Endpoint.init(allocator, server_addr, &server_cfg);
    defer server_ep.deinit();

    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var client_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();

    const conn = try api.connect(&client_ep, server_addr, SERVER_SNI);

    var gate = BlockFinishedOnce{
        .inner_ctx = conn.sender_ctx orelse return error.NoEndpointSender,
        .inner_fn = conn.sender_fn orelse return error.NoEndpointSender,
    };
    conn.setSender(@ptrCast(&gate), BlockFinishedOnce.send);
    defer conn.setSender(gate.inner_ctx, gate.inner_fn);

    var server_conn: ?*api.Connection = null;
    const deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < deadline) {
        _ = client_ep.pollWithStats(1) catch {};
        _ = server_ep.pollWithStats(1) catch {};
        if (server_conn == null) server_conn = api.tryAccept(&server_ep);
        if (api.isHandshakeConfirmed(conn)) {
            if (server_conn) |sc| {
                if (sc.peer_finished_verified) break;
            }
        }
    }

    if (!api.isHandshakeConfirmed(conn)) {
        std.debug.print(
            "\n  FAIL: client handshake stalled after a blocked Finished submission.\n" ++
                "  blocked={d} finished_submissions={d} local_finished_sent={} pending_hs_send={} pending_hs_messages={} last_handshake_error={s}\n",
            .{
                gate.blocked,
                gate.finished_submissions,
                if (conn.tls_context) |tls| tls.flags.local_finished_sent else false,
                conn.pending_hs_send,
                conn.pending_hs_messages != null,
                if (conn.last_handshake_error) |err| @errorName(err) else "none",
            },
        );
    }

    // The injection actually hit the client Finished, and it was submitted again.
    try testing.expectEqual(@as(usize, 1), gate.blocked);
    try testing.expect(gate.finished_submissions >= 2);
    try testing.expect(api.isHandshakeConfirmed(conn));
    try testing.expect(conn.tls_context.?.flags.local_finished_sent);
    try testing.expect(conn.crypto_tx_off_handshake > 0);
    try testing.expect(conn.pending_hs_messages == null);
    try testing.expect(!conn.pending_hs_send);
    // The server verified the client's Finished, which it only can if the
    // retried bytes reached it intact.
    const sc = server_conn orelse return error.ServerDidNotAccept;
    try testing.expect(sc.peer_finished_verified);

    _ = api.close(conn, 0, "done") catch {};
    _ = client_ep.pollWithStats(1) catch {};
}
