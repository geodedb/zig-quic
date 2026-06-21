// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test for the server-side `NoHandshakeKeys` connection-stranding
// race surfaced by the host-haleth bug-triager subagent.
//
// Bug summary:
//
//   `processInitial` in src/quic/endpoint/incoming.zig calls
//   `sendHandshakePackets` after deriving Handshake secrets. Even with
//   the 4b246b2 reorder (pollCrypto before hs_tx_keys check), the
//   `onSecretAvailable` callback that installs `conn.hs_tx_keys` may
//   not have fired yet on the very first tick. Pre-fix, `processInitial`
//   simply logged
//
//     ERROR: processInitial: sendHandshakePackets failed: NoHandshakeKeys
//
//   and dropped the connection's handshake-flight emission. No retry.
//   Under fan-in concurrency (msft-graph --workers 16) 12 of 16
//   connections never reached the accept queue and stalled past the
//   QUIC idle timeout because the server never re-attempted the
//   Handshake send after that single first-tick miss.
//
// Fix shape (Option A in the triage):
//
//   1. Add `pending_hs_send: bool = false` to `Connection`
//      (src/quic/conn.zig).
//   2. In `processInitial`, when `sendHandshakePackets` returns
//      `error.NoHandshakeKeys`, set `conn.pending_hs_send = true`
//      instead of logging an error and dropping.
//   3. In the endpoint poll loop (`Endpoint.pollWithStats` in
//      src/quic/endpoint.zig), add a Phase 4.5 drain that snapshots
//      the endpoint pending-hs-send set and retries `sendHandshakePackets`.
//      On success, clear the flag. On a second `NoHandshakeKeys`, leave the
//      flag set; the next tick tries again.
//
// What this test proves:
//
//   The poll loop's Phase 4.5 retry path consumes `pending_hs_send`
//   when keys are present, and leaves it set (without erroring) when
//   keys are still missing. We exercise both cases directly so the
//   regression is gated on pure unit-level invariants that don't
//   depend on packet-arrival timing on a quiet localhost (which the
//   sibling `test_concurrent_handshake_race.zig` already concedes
//   does not distinguish revert from HEAD on a quiet runner).

const std = @import("std");
const compat = @import("compat");
const testlog = @import("testlog");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

// Under -Dfips the server only accepts the FIPS-approved X25519MLKEM768
// hybrid key-share; the hardcoded x25519-only ClientHello below is correctly
// rejected with UnsupportedKeyShareGroup before any Handshake secret is
// derived. The pending_hs_send retry mechanics these tests cover are
// crypto-agnostic and fully exercised by the -Dfips=false gate, so skip in
// FIPS mode rather than weakening the server's group policy (a security
// regression) just to satisfy a transport-mechanics unit test.
const skip_under_fips = build_options.fips;

// ---------------------------------------------------------------------------
// Minimal ClientHello builder. Lifted from
// tests/test_server_initial_processing.zig so the two tests share the same
// well-formed CH structure (TLS 1.3, x25519, h3 ALPN, QUIC TPs).
// ---------------------------------------------------------------------------

fn buildStandardClientHello(alloc: std.mem.Allocator) ![]u8 {
    var sk: [32]u8 = undefined;
    compat.randomBytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    var body = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer body.deinit(alloc);

    // legacy_version = 0x0303
    try body.appendSlice(alloc, &.{ 0x03, 0x03 });

    var rnd: [32]u8 = undefined;
    compat.randomBytes(&rnd);
    try body.appendSlice(alloc, &rnd);

    // session_id (empty)
    try body.append(alloc, 0);

    // cipher_suites: TLS_AES_128_GCM_SHA256
    try body.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    // legacy_compression_methods
    try body.appendSlice(alloc, &.{ 0x01, 0x00 });

    var ext_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer ext_buf.deinit(alloc);

    // supported_versions: TLS 1.3
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
    // supported_groups: x25519
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
    // signature_algorithms
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x0d,
        0x00, 0x08,
        0x00, 0x06,
        0x08, 0x04,
        0x04, 0x03,
        0x08, 0x07,
    });
    // ALPN: h3
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x10,
        0x00, 0x05,
        0x00, 0x03,
        0x02, 'h',
        '3',
    });
    // quic_transport_params (minimal)
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x39,
        0x00, 0x0c,
        0x04, 0x04,
        0x80, 0x10,
        0x00, 0x00,
        0x05, 0x04,
        0x80, 0x04,
        0x00, 0x00,
    });
    // key_share: x25519 + pk
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 });
    const key_share_len: u16 = 2 + 2 + 32;
    const total_len: u16 = key_share_len + 2;
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x1d });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 32 });
    try ext_buf.appendSlice(alloc, &pk);

    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(alloc, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(alloc, ext_buf.items);

    const body_len: u32 = @intCast(body.items.len);
    const result = try alloc.alloc(u8, 4 + body.items.len);
    result[0] = 0x01;
    result[1] = @intCast((body_len >> 16) & 0xff);
    result[2] = @intCast((body_len >> 8) & 0xff);
    result[3] = @intCast(body_len & 0xff);
    @memcpy(result[4..], body.items);
    return result;
}

fn sockAddrIp4(ip: [4]u8, port: u16) conn_mod.SockAddr {
    var out: conn_mod.SockAddr = .{};
    out.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    var sin: std.posix.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.readInt(u32, &ip, .little),
        .zero = .{0} ** 8,
    };
    out.len = @intCast(@sizeOf(std.posix.sockaddr.in));
    @memcpy(@as([*]u8, @ptrCast(&out.storage))[0..out.len], @as([*]const u8, @ptrCast(&sin))[0..out.len]);
    return out;
}

// ---------------------------------------------------------------------------
// Drive a real ClientHello through processInitial so we get a server-role
// Connection with valid TLS context. Returns the connection pointer; the
// endpoint owns the connection and will deinit it.
// ---------------------------------------------------------------------------

fn injectClientHelloAndGetConn(
    ep: *endpoint.Endpoint,
    alloc: std.mem.Allocator,
) !*conn_mod.Connection {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const initial = ks.deriveInitialSecret(false, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const client_keys = ks.deriveKeyIvHp(pair.client);

    const ch_bytes = try buildStandardClientHello(alloc);
    defer alloc.free(ch_bytes);

    var crypto_payload = std.ArrayList(u8).empty;
    defer crypto_payload.deinit(alloc);
    const w = compat.arrayListWriter(&crypto_payload, alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_bytes } }).write(w);

    const initial_pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        &[_]u8{},
        1,
        2,
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp },
    );
    defer alloc.free(initial_pkt);

    const peer = sockAddrIp4([4]u8{ 127, 0, 0, 1 }, 12345);
    ep.testInject(peer, initial_pkt);

    if (ep.accepted.items.len == 0) return error.NoServerConnection;
    return ep.accepted.items[0];
}

// ---------------------------------------------------------------------------
// Test 1: poll() drains pending_hs_send when hs_tx_keys are installed.
// ---------------------------------------------------------------------------

test "pending_hs_send: poll drains the flag when hs_tx_keys are installed" {
    if (skip_under_fips) return error.SkipZigTest;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_retry = false,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4444", &cfg);
    defer ep.deinit();

    const conn = try injectClientHelloAndGetConn(&ep, alloc);

    // Sanity: server processed CH and installed Handshake TX keys.
    try std.testing.expect(conn.hs_tx_keys != null);

    // Synthetically arm the flag — this is what processInitial would have
    // done on a NoHandshakeKeys-on-first-tick race.
    ep.markPendingHandshakeSend(conn);

    // One poll tick. timeout=0 means: no transport wait, just drain pending
    // work and run the Phase 4.5 retry path.
    _ = try ep.pollWithStats(0);

    // The retry path called sendHandshakePackets, which succeeded because
    // hs_tx_keys is non-null, and cleared the flag.
    try std.testing.expect(!conn.pending_hs_send);

    testlog.print("Test passed: poll() drained pending_hs_send when keys are installed\n", .{});
}

// ---------------------------------------------------------------------------
// Test 2: poll() leaves pending_hs_send set when hs_tx_keys are missing.
//
// Pre-fix this branch would never have been reached because processInitial
// just logged-and-dropped. Post-fix the flag is the queue. We simulate the
// "TLS state machine still has not derived hs_tx_keys" case by clearing
// hs_tx_keys after CH processing, arming the flag, and asserting it stays
// armed across one poll tick (i.e., the retry attempted, got
// NoHandshakeKeys again, and left the flag for the next tick).
// ---------------------------------------------------------------------------

test "pending_hs_send: poll leaves flag set when keys are still missing" {
    if (skip_under_fips) return error.SkipZigTest;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_retry = false,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4445", &cfg);
    defer ep.deinit();

    const conn = try injectClientHelloAndGetConn(&ep, alloc);

    // Force the "keys not yet installed" race. Save+clear hs_tx_keys so
    // pollCrypto inside sendHandshakePackets cannot return CRYPTO bytes
    // either (Handshake-level secrets already drained on the prior CH
    // processing tick — the TLS engine has no fresh data to emit).
    const saved_hs_tx = conn.hs_tx_keys;
    conn.hs_tx_keys = null;
    defer conn.hs_tx_keys = saved_hs_tx;

    ep.markPendingHandshakeSend(conn);

    _ = try ep.pollWithStats(0);

    // Retry attempted, got NoHandshakeKeys again, did NOT clear the flag.
    // (Did NOT crash, did NOT escalate to last_handshake_error either.)
    try std.testing.expect(conn.pending_hs_send);
    try std.testing.expect(conn.last_handshake_error == null);

    testlog.print("Test passed: poll() preserved pending_hs_send when keys are missing\n", .{});
}

// ---------------------------------------------------------------------------
// Test 3: processInitial sets pending_hs_send instead of erroring when
// sendHandshakePackets returns NoHandshakeKeys.
//
// We exercise this end-to-end by injecting a CH on a fresh connection,
// then immediately clearing hs_tx_keys (simulating the "keys derivation
// callback hasn't fired yet" race) and re-injecting another Initial
// containing a duplicate-CH CRYPTO frame. The second processInitial
// invocation runs through sendHandshakePackets; with no hs_tx_keys the
// new branch sets `pending_hs_send` instead of logging-and-dropping.
//
// This is a structural assertion: pre-fix, processInitial logged
// `processInitial: sendHandshakePackets failed: NoHandshakeKeys` to
// stderr and left no observable per-connection state change. Post-fix,
// the flag is set so the poll loop's Phase 4.5 drain can recover the
// connection on a subsequent tick.
// ---------------------------------------------------------------------------

test "pending_hs_send: processInitial sets the flag on NoHandshakeKeys (no error log)" {
    if (skip_under_fips) return error.SkipZigTest;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_retry = false,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4446", &cfg);
    defer ep.deinit();

    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const initial = ks.deriveInitialSecret(false, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const client_keys = ks.deriveKeyIvHp(pair.client);

    const ch_bytes = try buildStandardClientHello(alloc);
    defer alloc.free(ch_bytes);

    var crypto_payload = std.ArrayList(u8).empty;
    defer crypto_payload.deinit(alloc);
    const w = compat.arrayListWriter(&crypto_payload, alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_bytes } }).write(w);

    // First Initial: creates server connection, derives hs_tx_keys.
    const initial_pkt_1 = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        &[_]u8{},
        1,
        2,
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp },
    );
    defer alloc.free(initial_pkt_1);

    const peer = sockAddrIp4([4]u8{ 127, 0, 0, 1 }, 12345);
    ep.testInject(peer, initial_pkt_1);

    if (ep.accepted.items.len == 0) return error.NoServerConnection;
    const conn = ep.accepted.items[0];
    try std.testing.expect(conn.hs_tx_keys != null);

    // Force the race: clear hs_tx_keys before the next inbound Initial
    // re-runs processInitial -> sendHandshakePackets. Because pollCrypto
    // already drained Handshake-level CRYPTO data on the first tick, it
    // returns null on the retry, and the keys check returns
    // error.NoHandshakeKeys.
    conn.hs_tx_keys = null;
    conn.pending_hs_send = false; // Make sure we observe the SET, not a leftover.

    // Build a second Initial with a different packet number (server expects
    // monotonically-increasing PNs). We reuse the same CRYPTO payload so the
    // server treats it as a duplicate CH and re-runs the handshake hooks.
    const initial_pkt_2 = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        &[_]u8{},
        2,
        2,
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp },
    );
    defer alloc.free(initial_pkt_2);

    ep.testInject(peer, initial_pkt_2);

    // Post-fix: pending_hs_send is set so the poll loop will retry.
    // Pre-fix: the flag did not exist; processInitial logged
    // `processInitial: sendHandshakePackets failed: NoHandshakeKeys`
    // and the connection silently stalled.
    try std.testing.expect(conn.pending_hs_send);
    // Importantly, the NoHandshakeKeys path does NOT escalate to
    // last_handshake_error — only fatal errors do.
    try std.testing.expect(conn.last_handshake_error == null);

    testlog.print("Test passed: processInitial set pending_hs_send on NoHandshakeKeys race\n", .{});
}
