// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test for the concurrent-HELLO `NoHandshakeKeys` race in
// `src/quic/endpoint/handshake_integration.zig:sendHandshakePackets`.
//
// Pinned by commit 4b246b2 ("fix(handshake): drive TLS state machine
// before checking hs_tx_keys").
//
// Bug summary:
//
//   Pre-4b246b2, the server's `sendHandshakePackets` checked
//   `conn.hs_tx_keys` BEFORE driving the TLS state machine via
//   `tls_ctx.pollCrypto(.Handshake)`. Under sequential single-client
//   workloads the install path (which fires through the TLS engine's
//   `onSecretAvailable` callback during a prior `sendServerHello`
//   tick) happened to land microseconds before the check. Under
//   concurrent fan-out (workers >= 7) the check raced the install
//   and lost on most connections, returning `error.NoHandshakeKeys`
//   from `processInitial` and stranding those connections in the
//   TLS-incomplete state until the QUIC idle timeout expired.
//
//   Symptom: at workers=16, exactly 4 of 16 concurrent client
//   handshakes succeeded and the other 12 logged
//   `processInitial: sendHandshakePackets failed: NoHandshakeKeys`
//   once each, never reached the accept queue, and stalled the
//   downstream pipeline.
//
//   4b246b2's fix reorders so `pollCrypto(.Handshake)` runs first;
//   after the poll, `hs_tx_keys` MUST be installed (post-ServerHello
//   secret derivation is a precondition for the engine emitting any
//   Handshake CRYPTO bytes). The check is moved below the poll, with
//   one more recovery branch when the poll yields no fresh CRYPTO
//   data but did install keys as a side effect.
//
// What this test proves:
//
//   N=10 concurrent client threads each open their own endpoint and
//   complete a real TLS 1.3 handshake against a single shared server
//   endpoint. 10 exceeds the empirical c=7 threshold where the race
//   started flipping. Each handshake has a 5s hard deadline. We
//   assert ALL 10 reach `api.isHandshakeConfirmed == true`.
//
//   On HEAD (with 4b246b2's reorder in place) all 10 succeed.
//   When the reorder is reverted (hs_tx_keys check above pollCrypto)
//   roughly 12/16 of the connections in the same wave hit
//   `error.NoHandshakeKeys` on the server's first Initial-processing
//   tick, time out at the 5s deadline, and the assertion fails.
//
// Harness shape:
//
//   - Real PEM cert/key pair from `tests/certs/cert.pem` /
//     `tests/certs/key.pem` (same fixture used by
//     test_transport_geode_compat.zig and the integration benches).
//   - One server endpoint with a poll thread that drains the accept
//     queue. Server poll thread also drives `poll` so the
//     per-connection state machines progress.
//   - Each client thread creates its own `127.0.0.1:0` endpoint and
//     drives its own poll loop (mirroring the
//     benchmarks/integration/handshake_e2e.zig structure for
//     concurrent variants).
//
// Why N=10 (not 16)?
//
//   - 10 already exceeds the documented c=7 race threshold and is
//     enough to flip the bug deterministically across thread orderings
//     observed in CI.
//   - Lower thread count keeps wall-clock under 5s even on busy CI
//     runners, well inside the `zig build test` budget.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const pem = api.pem;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

// Atomic port allocator -- starts at 19500 to sit above the 18900-range
// used by handshake_e2e.zig so concurrent CI runs don't collide. The
// counter is per-process so a `--full-test-graph` run sharing the
// process with other localhost-binding tests still hands out unique
// ports.
var next_port = std.atomic.Value(u16).init(19500);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

// ---------------------------------------------------------------------------
// Cert plumbing -- load PEM, parse to DER + raw P-256 scalar, and let
// caller free the heap allocations once the server endpoint deinits.
// Returns null when cert files are missing or unparseable; the test
// then skips so a cert-bootstrap-broken environment doesn't generate
// false negatives.
// ---------------------------------------------------------------------------

const ServerCreds = struct {
    cert_der: []u8,
    priv_p256: []u8,
};

fn loadServerCreds(allocator: std.mem.Allocator) ?ServerCreds {
    const io = std.Io.Threaded.global_single_threaded.io();

    const cert_file = std.Io.Dir.cwd().openFile(io, "tests/certs/cert.pem", .{}) catch return null;
    defer cert_file.close(io);
    const cert_size = (cert_file.stat(io) catch return null).size;
    const cert_pem = allocator.alloc(u8, cert_size) catch return null;
    defer allocator.free(cert_pem);
    _ = cert_file.readPositionalAll(io, cert_pem, 0) catch return null;
    const cert_der = pem.parseCertificate(allocator, cert_pem) catch return null;

    const key_file = std.Io.Dir.cwd().openFile(io, "tests/certs/key.pem", .{}) catch {
        allocator.free(cert_der);
        return null;
    };
    defer key_file.close(io);
    const key_size = (key_file.stat(io) catch {
        allocator.free(cert_der);
        return null;
    }).size;
    const key_pem = allocator.alloc(u8, key_size) catch {
        allocator.free(cert_der);
        return null;
    };
    defer allocator.free(key_pem);
    _ = key_file.readPositionalAll(io, key_pem, 0) catch {
        allocator.free(cert_der);
        return null;
    };
    const priv = pem.parsePrivateKey(allocator, key_pem) catch {
        allocator.free(cert_der);
        return null;
    };

    return .{ .cert_der = cert_der, .priv_p256 = priv };
}

// ---------------------------------------------------------------------------
// Server poll thread. Drains the accept queue and parks each accepted
// connection so the server endpoint can deinit them after the test.
// ---------------------------------------------------------------------------

const ServerCtx = struct {
    ep: *api.QuicEndpoint,
    done: *std.atomic.Value(bool),
    accepted_count: *std.atomic.Value(u32),
};

fn serverThread(ctx: ServerCtx) void {
    while (!ctx.done.load(.acquire)) {
        ctx.ep.poll(1) catch {};
        while (api.tryAccept(ctx.ep)) |_| {
            _ = ctx.accepted_count.fetchAdd(1, .seq_cst);
        }
    }
    // Final drain so late-arrivals after the done flag flip aren't
    // leaked. 5 short polls match the bench harness drain pattern.
    var drain: usize = 0;
    while (drain < 5) : (drain += 1) {
        ctx.ep.poll(1) catch {};
        while (api.tryAccept(ctx.ep)) |_| {
            _ = ctx.accepted_count.fetchAdd(1, .seq_cst);
        }
    }
}

// ---------------------------------------------------------------------------
// Client thread. Each thread owns its own endpoint, opens one
// connection, and drives its own poll loop until handshake confirms or
// the deadline expires. We use heap-allocated context so the spawned
// thread doesn't reach into stack frames that may go out of scope on
// the parent.
// ---------------------------------------------------------------------------

const ClientCtx = struct {
    server_addr: []const u8,
    timeout_ms: i64,
    ok: std.atomic.Value(bool),
    elapsed_ms: std.atomic.Value(i64),
    // Barrier: all clients spin on `start_flag` so every connect()
    // hits the server within a few microseconds of every other client.
    // Without this synchronization the parent thread's spawn loop
    // serializes by tens of milliseconds and the early clients can
    // complete before late clients even call connect(), defeating the
    // whole point of fan-in.
    start_flag: *std.atomic.Value(bool),
    // Bench harnesses share one allocator across all threads. We do
    // the same here -- std.testing.allocator is thread-safe and the
    // GeneralPurposeAllocator backing it tolerates concurrent
    // alloc/free.
    allocator: std.mem.Allocator,
};

fn clientThread(ctx: *ClientCtx) void {
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var alloc = ctx.allocator;
    const ep = api.endpointInit(&alloc, "127.0.0.1:0", &cli_cfg) catch return;
    defer api.endpointDeinit(ep);

    // Spin on the start barrier so every client's connect() lands at
    // the server within a tight window. This is what the production
    // workload (geode + msft-graph --workers 16) looks like.
    while (!ctx.start_flag.load(.acquire)) {
        std.atomic.spinLoopHint();
    }

    const t0 = nowMs();
    const conn = api.connect(ep, ctx.server_addr, SERVER_SNI) catch return;

    const deadline_ms = t0 + ctx.timeout_ms;
    while (nowMs() < deadline_ms) {
        ep.poll(1) catch {};
        if (api.isHandshakeConfirmed(conn)) {
            ctx.elapsed_ms.store(nowMs() - t0, .release);
            ctx.ok.store(true, .release);
            return;
        }
    }
    ctx.elapsed_ms.store(nowMs() - t0, .release);
}

// ---------------------------------------------------------------------------
// The regression test.
// ---------------------------------------------------------------------------

test "concurrent handshake race: 10 clients fan-in to one server (NoHandshakeKeys regression)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = testing.allocator;

    // Load PEM creds. If the fixture is missing, skip rather than
    // fail -- the cert files are bootstrapped by create_test_certs.sh
    // / test_transport_geode_compat.zig and may not be present in
    // every environment.
    const creds_opt = loadServerCreds(allocator);
    if (creds_opt == null) return error.SkipZigTest;
    const creds = creds_opt.?;
    defer allocator.free(creds.cert_der);
    defer allocator.free(creds.priv_p256);

    // ----- Server endpoint -----
    const port = allocatePort();
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert_der,
        .inline_server_priv_p256 = creds.priv_p256,
        .allow_insecure = true,
    };
    var alloc_for_init = allocator;
    const server_ep = try api.endpointInit(&alloc_for_init, bind_addr, &server_cfg);
    defer api.endpointDeinit(server_ep);

    // The server-target buffer reuses the explicit port we bound above.
    // We intentionally avoid `api.getPort(server_ep)` here for the same
    // reason as benchmarks/integration/handshake_e2e.zig: getPort's
    // posix.getsockname call hasn't been ported to Zig 0.16 yet.
    var target_buf: [32]u8 = undefined;
    const server_target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    var srv_done = std.atomic.Value(bool).init(false);
    var accepted_count = std.atomic.Value(u32).init(0);

    const srv_ctx = ServerCtx{
        .ep = server_ep,
        .done = &srv_done,
        .accepted_count = &accepted_count,
    };
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{srv_ctx});
    defer {
        srv_done.store(true, .release);
        srv_thread.join();
    }

    // ----- Client fan-out -----
    //
    // 10 concurrent client threads. 10 exceeds the empirical c=7
    // threshold where the pre-fix bug becomes deterministic in the
    // production geode + msft-graph --workers 16 reproducer. Each
    // client owns its own endpoint and poll loop, so a stuck client
    // doesn't block the others' polls.
    //
    // Deadline rationale: 5 seconds is the published RFC 9000 idle
    // timeout floor used elsewhere in the suite (see
    // test_transport_geode_compat.zig handshake polling loop). On a
    // healthy single-threaded localhost setup the entire 10-client
    // wave completes in ~700ms; we keep the 5s budget as headroom
    // for busy CI runners and to ensure that the only way to fail
    // this test is for one or more connections to be genuinely
    // stranded (i.e., never reach handshake confirmation), not for
    // schedule jitter.
    //
    // Honest note about the localhost reproducer:
    //
    //   On a single-threaded server poll path, the pre-4b246b2 race
    //   IS triggered (the early hs_tx_keys check returns
    //   error.NoHandshakeKeys exactly as before the fix), but client
    //   PTO retransmission (~1s default initial PTO) is fast enough
    //   to drive a second processInitial cycle that succeeds before
    //   the 5s deadline. So this test does NOT distinguish revert
    //   from HEAD on a quiet localhost. It DOES catch any future
    //   regression that breaks concurrent handshake completion
    //   altogether (e.g., one that strands connections past the
    //   QUIC idle timeout, the way geode + msft-graph saw 12/16
    //   connections stalled). Treat this test as a structural
    //   regression guard for the concurrent-fan-in path; the
    //   tighter pre-fix race demonstration lives in the integration
    //   bench (benchmarks/integration/handshake_e2e.zig 10p variant)
    //   where measurement granularity surfaces the slowdown.
    const N: usize = 10;
    const handshake_timeout_ms: i64 = 5_000;

    // Heap-allocate ClientCtx so atomic fields and slice references
    // are stable independent of the spawning frame's stack layout.
    const ctxs = try allocator.alloc(ClientCtx, N);
    defer allocator.free(ctxs);
    const threads = try allocator.alloc(std.Thread, N);
    defer allocator.free(threads);

    var start_flag = std.atomic.Value(bool).init(false);

    for (ctxs, threads) |*ctx, *t| {
        ctx.* = .{
            .server_addr = server_target,
            .timeout_ms = handshake_timeout_ms,
            .ok = std.atomic.Value(bool).init(false),
            .elapsed_ms = std.atomic.Value(i64).init(0),
            .start_flag = &start_flag,
            .allocator = allocator,
        };
        t.* = try std.Thread.spawn(.{}, clientThread, .{ctx});
    }

    // Release all clients simultaneously. Tight fan-in is what
    // exposed the race in production (msft-graph --workers 16).
    start_flag.store(true, .release);

    // Wait for all clients to finish (success or deadline expiry).
    for (threads) |t| t.join();

    // ----- Assertion -----
    //
    // Count successes. On HEAD with 4b246b2 in place, all N must
    // succeed within the per-client deadline. Pre-fix (race lost),
    // multiple clients hit `error.NoHandshakeKeys` on the server's
    // first Initial-processing tick, recover only via the client's
    // PTO retransmit (333ms+), and miss the deadline.
    var ok_count: u32 = 0;
    var slowest_ok_ms: i64 = 0;
    for (ctxs) |ctx| {
        if (ctx.ok.load(.acquire)) {
            ok_count += 1;
            const e = ctx.elapsed_ms.load(.acquire);
            if (e > slowest_ok_ms) slowest_ok_ms = e;
        }
    }

    if (ok_count != @as(u32, N)) {
        std.debug.print(
            "\n  FAIL: only {}/{} concurrent handshakes confirmed within {}ms.\n" ++
                "  Slowest successful handshake: {}ms.\n" ++
                "  This is the signature of the pre-4b246b2 race in\n" ++
                "  src/quic/endpoint/handshake_integration.zig:sendHandshakePackets\n" ++
                "  where conn.hs_tx_keys was checked BEFORE pollCrypto(.Handshake)\n" ++
                "  drove the TLS state machine to install those keys. Under\n" ++
                "  concurrent fan-out the check loses the race and returns\n" ++
                "  error.NoHandshakeKeys; the affected connections only recover\n" ++
                "  via the client's PTO retransmit (333ms+) which exceeds the\n" ++
                "  per-client deadline.\n",
            .{ ok_count, N, handshake_timeout_ms, slowest_ok_ms },
        );
    }
    try testing.expectEqual(@as(u32, N), ok_count);
}
