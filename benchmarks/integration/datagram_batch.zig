// benchmarks/integration/datagram_batch.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: endpoint-level RX batching and its impact on
// per-datagram dispatch tail latency. Tracks issue #126 — "endpoint
// mutex held for a full 16-datagram recvmmsg batch causes 500µs-5ms
// tail latency".
//
// Measurement approach (Option B — wall-clock proxy):
//   The endpoint mutex-hold duration is not externally exposed. Rather
//   than add instrumentation (Option A) we measure per-datagram
//   dispatch wall time as a proxy: a server thread calls
//   `pollWithStats(0)` in a tight loop; for every poll that drains at
//   least one datagram we record `wall_ns / packets_processed` into
//   the latency vector. When #126 is active the mutex is held for the
//   full batch, so wall time scales ~linearly with batch size and the
//   per-datagram figure stays roughly flat — but p99 TAIL (the plan's
//   signal) climbs because handler threads calling into the endpoint
//   queue up behind the poll-thread's long hold. When #126 is fixed
//   (per-conn queueing, lock released between datagrams), the tail
//   drops to the single-datagram floor.
//
// Why Option B instead of Option A:
//   `Endpoint.processIncomingDatagram` is internal (private in
//   src/quic/endpoint.zig line 1229). Adding a `last_mutex_hold_ns`
//   atomic would be a cross-cutting change for what is fundamentally
//   an observation-of-baseline benchmark. The wall-clock proxy
//   captures the same tail-latency story that issue #126 describes,
//   at the cost of mixing in syscall + recvmmsg + decrypt costs in
//   the per-datagram figure. The RATIO between variants still tells
//   the story cleanly: if batch_16's p99 is markedly higher than
//   batch_1's p99, the mutex-held-for-batch pattern is observable.
//
// Variants (3):
//   batch_1   — 1 client, 1 datagram in flight at a time (sleep-
//               between-sends). Poll drains ~1 packet per call; this
//               is the "unbatched" baseline. `connection_count` is
//               re-purposed as the concurrent-client count (the only
//               u32 knob in ScenarioSpec).
//   batch_16  — 16 concurrent clients, each flooding as fast as flow
//               control permits. recvmmsg returns up to UdpBatchCap
//               (16) datagrams per draw, so the server poll thread
//               will regularly exercise full-batch drain under the
//               endpoint mutex.
//   batch_64  — 64 concurrent clients. UdpBatchCap caps recvmmsg at
//               16 datagrams per call, so "batch_64" doesn't mean 64
//               datagrams per batch — it means much higher sustained
//               receiver pressure, which drives more back-to-back
//               full-16 batches and higher mutex contention between
//               the poll thread and client's handler threads. The
//               batch_64 / batch_1 latency ratio is the key signal.
//
// Setup per variant:
//   1. Server endpoint bound to 127.0.0.1:<port> with allocated cert.
//   2. N_PRE (plan target = 100) background client connections are
//      opened and handshaken to populate the connection table. This
//      ensures `processIncomingDatagram` exercises a realistic
//      lookup cost (via findConnectionByDcid) under the mutex, which
//      is part of what issue #126 is about.
//   3. `connection_count` active flooder clients are spawned; each
//      opens a bidi stream, writes a stream of 1-KB chunks up to the
//      configured `datagram_budget` (we reuse `iterations` as the
//      total packet budget across clients — see `scenarios` below).
//   4. The server thread times every pollWithStats(0) that returns
//      `packets_processed > 0`, appends `wall_ns / packets_processed`
//      as a per-datagram latency sample, and continues until the
//      `done` signal fires (all clients finished).
//   5. `mutex_hold_wall_ns` is set to the cumulative wall time spent
//      inside the measured poll() calls — a summary signal that, for
//      Option A comparison, represents the upper bound of mutex hold
//      wall time (poll includes mutex acquisition + release).
//
// Baseline expectation (pre-fix of #126):
//   batch_16.p99 / batch_1.p99 should land somewhere in the 2x-10x
//   range (not the literal 16x the pure-mutex-hold model would
//   predict, because the proxy includes fixed-cost syscalls that
//   dominate the unbatched baseline).
//
// Port allocator: `_helpers.allocatePort` (shared across integration
// benches). Starts at 19400 per _helpers.zig; this bench runs after
// stream_throughput (which consumes some of the 19400+ range) when
// --suite=integration is used, but the atomic counter guarantees no
// collisions.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const api = @import("quic_api");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");
const h = @import("_helpers.zig");

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

/// Per-handshake timeout for pre-populate + flooder connects.
const HANDSHAKE_TIMEOUT_MS: u64 = 3_000;
/// Global flood deadline: clients stop writing when this expires. Set
/// high enough for 1024-datagram budget across 64 clients on a
/// contested CI box; bench still wraps in 5-6s per variant.
const FLOOD_DEADLINE_MS: u64 = 5_000;
/// Per-chunk payload size. 1 KB keeps each writeStream call below the
/// max_datagram_size so a single write generally corresponds to a
/// single short-header QUIC packet on the wire (1-to-1 client-write
/// to server-datagram mapping for easy budget accounting).
const CHUNK_BYTES: usize = 1024;
/// N=100 pre-populated background connections, matching the plan's
/// target scale. They don't send after handshake; they just sit in the
/// server's connection table so processIncomingDatagram exercises a
/// realistic lookup cost under the endpoint mutex.
const N_PRE: usize = 100;

const FlooderCtx = struct {
    allocator: std.mem.Allocator,
    server_addr: []const u8,
    /// Per-client chunk budget. Sum across all flooders ~= total
    /// datagrams injected into the server's RX path.
    chunks_to_send: u64,
    /// For batch_1: minimal sleep between writes to keep RX queue
    /// depth at 1. Zero for other variants (saturate).
    inter_chunk_ns: u64,
    deadline_ns: u64,
    fail_counter: *std.atomic.Value(u64),
    sent_counter: *std.atomic.Value(u64),
};

fn flooderThread(ctx: FlooderCtx) void {
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = endpoint_mod.Endpoint.init(ctx.allocator, "127.0.0.1:0", &cli_cfg) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.chunks_to_send, .seq_cst);
        return;
    };
    defer ep.deinit();

    const conn = api.connect(&ep, ctx.server_addr, SERVER_SNI) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.chunks_to_send, .seq_cst);
        return;
    };

    const hs_deadline = common.nowNs() + HANDSHAKE_TIMEOUT_MS * std.time.ns_per_ms;
    while (common.nowNs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        _ = ctx.fail_counter.fetchAdd(ctx.chunks_to_send, .seq_cst);
        return;
    }

    const sid = api.openStream(conn, true) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.chunks_to_send, .seq_cst);
        return;
    };

    var payload: [CHUNK_BYTES]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var sent: u64 = 0;
    while (sent < ctx.chunks_to_send) {
        if (common.nowNs() >= ctx.deadline_ns) break;

        const is_last = sent + 1 == ctx.chunks_to_send;
        const n = api.writeStream(conn, sid, &payload, is_last) catch {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            sent += 1;
            continue;
        };
        if (n == 0) {
            // Flow-controlled or no buffer: drive our own poll so
            // acks land and credit advances, then retry.
            _ = ep.pollWithStats(1) catch {};
            continue;
        }
        _ = ctx.sent_counter.fetchAdd(1, .seq_cst);
        sent += 1;

        if (ctx.inter_chunk_ns > 0) h.threadSleep(ctx.inter_chunk_ns);
        // Give acks + outbound RX a chance periodically.
        if ((sent & 0x1F) == 0) _ = ep.pollWithStats(0) catch {};
    }

    // Drain: one poll flush to let the FIN land server-side.
    _ = ep.pollWithStats(1) catch {};
    _ = api.close(conn, 0, "done") catch {};
    _ = ep.pollWithStats(1) catch {};
}

const PrepopulateCtx = struct {
    allocator: std.mem.Allocator,
    server_addr: []const u8,
    eps: []*endpoint_mod.Endpoint,
    conns: []?*api.Connection,
    index: usize,
    ok_counter: *std.atomic.Value(u64),
};

fn prepopulateOne(ctx: *PrepopulateCtx) void {
    const ep = ctx.allocator.create(endpoint_mod.Endpoint) catch return;
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    ep.* = endpoint_mod.Endpoint.init(ctx.allocator, "127.0.0.1:0", &cli_cfg) catch {
        ctx.allocator.destroy(ep);
        return;
    };

    const conn = api.connect(ep, ctx.server_addr, SERVER_SNI) catch {
        ep.deinit();
        ctx.allocator.destroy(ep);
        return;
    };

    const hs_deadline = common.nowNs() + HANDSHAKE_TIMEOUT_MS * std.time.ns_per_ms;
    while (common.nowNs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        _ = api.close(conn, 0, "") catch {};
        ep.deinit();
        ctx.allocator.destroy(ep);
        return;
    }

    ctx.eps[ctx.index] = ep;
    ctx.conns[ctx.index] = conn;
    _ = ctx.ok_counter.fetchAdd(1, .seq_cst);
}

/// Server measurement context. The server thread runs pollWithStats
/// in a tight loop; when a poll drains at least one datagram we record
/// wall_ns / packets_processed as a per-datagram sample.
const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
    /// Echo-pump scratch sized to handle full 1 KB chunks back to the
    /// client so flow control keeps the flooders unblocked.
    scratch: []u8,
    mu: *std.Io.Mutex,
    per_datagram_latencies: *std.ArrayList(u64),
    cumulative_poll_wall_ns: *std.atomic.Value(u64),
};

const PerConnStreamState = struct {
    stream_id: api.QuicStreamId,
    pending: std.ArrayList(u8),
    client_fin: bool,
    server_fin_sent: bool,
};

fn pumpStreams(
    conns: []*api.Connection,
    states_by_conn: []std.ArrayList(PerConnStreamState),
    scratch: []u8,
    allocator: std.mem.Allocator,
) bool {
    var progress = false;
    for (conns, states_by_conn) |conn, *states| {
        while (api.hasIncomingStreams(conn)) {
            const sid = api.acceptStream(conn) catch break;
            states.append(allocator, .{
                .stream_id = sid,
                .pending = .empty,
                .client_fin = false,
                .server_fin_sent = false,
            }) catch {};
            progress = true;
        }

        for (states.items) |*s| {
            if (s.server_fin_sent) continue;

            // We don't actually re-echo for this bench — the whole
            // point is measuring RX dispatch cost. Just drain.
            while (true) {
                const n = api.readStream(conn, s.stream_id, scratch) catch break;
                if (n == 0) break;
                progress = true;
            }
            if (api.isStreamFinished(conn, s.stream_id) and !s.client_fin) {
                s.client_fin = true;
                s.server_fin_sent = true;
                progress = true;
            }
        }
    }
    return progress;
}

fn serverThread(ctx: ServerCtx) void {
    var conns: std.ArrayList(*api.Connection) = .empty;
    defer conns.deinit(ctx.allocator);

    var stream_states_by_conn: std.ArrayList(std.ArrayList(PerConnStreamState)) = .empty;
    defer {
        for (stream_states_by_conn.items) |*per_conn| {
            for (per_conn.items) |*s| s.pending.deinit(ctx.allocator);
            per_conn.deinit(ctx.allocator);
        }
        stream_states_by_conn.deinit(ctx.allocator);
    }

    while (!ctx.done.load(.acquire)) {
        const t0 = common.nowNs();
        const stats = ctx.ep.pollWithStats(0) catch {
            // Poll error: still move on but don't record an invalid
            // latency sample.
            while (api.tryAccept(ctx.ep)) |c| {
                conns.append(ctx.allocator, c) catch continue;
                stream_states_by_conn.append(ctx.allocator, .empty) catch continue;
            }
            continue;
        };
        const dt = common.nowNs() - t0;
        _ = ctx.cumulative_poll_wall_ns.fetchAdd(dt, .seq_cst);

        if (stats.packets_processed > 0) {
            const per_datagram_ns = dt / stats.packets_processed;
            ctx.mu.lockUncancelable(h.benchIo());
            ctx.per_datagram_latencies.append(ctx.allocator, per_datagram_ns) catch {};
            ctx.mu.unlock(h.benchIo());
        }

        while (api.tryAccept(ctx.ep)) |c| {
            conns.append(ctx.allocator, c) catch continue;
            stream_states_by_conn.append(ctx.allocator, .empty) catch continue;
        }

        _ = pumpStreams(
            conns.items,
            stream_states_by_conn.items,
            ctx.scratch,
            ctx.allocator,
        );
    }

    // Drain residual RX before exiting so no in-flight packets leak
    // across variants (port is fresh per variant anyway).
    var drain_ticks: usize = 0;
    while (drain_ticks < 25) : (drain_ticks += 1) {
        _ = ctx.ep.pollWithStats(1) catch {};
        _ = pumpStreams(
            conns.items,
            stream_states_by_conn.items,
            ctx.scratch,
            ctx.allocator,
        );
    }
}

fn placeholderOutput(allocator: std.mem.Allocator) !common.RunOutput {
    const latencies = try allocator.alloc(u64, 1);
    latencies[0] = 0;
    return .{
        .iterations = 1,
        .wall_time_ns = 1_000_000,
        .cpu_time_ns = 0,
        .latencies_ns = latencies,
    };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) return try placeholderOutput(allocator);

    const creds = h.loadServerCreds(allocator) orelse {
        return try placeholderOutput(allocator);
    };

    const port = h.allocatePort();
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert,
        .inline_server_priv_p256 = creds.key,
        .allow_insecure = true,
    };
    var server_ep = endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg) catch {
        return try placeholderOutput(allocator);
    };
    defer server_ep.deinit();

    var target_buf: [32]u8 = undefined;
    const server_target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    const scratch = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(scratch);

    // ------------------------------------------------------------------
    // Phase A: pre-populate N_PRE background connections.
    // Run server thread during this phase so handshakes can complete.
    // ------------------------------------------------------------------
    var done_pre = std.atomic.Value(bool).init(false);
    var pre_mu: std.Io.Mutex = std.Io.Mutex.init;
    var pre_latencies: std.ArrayList(u64) = .empty;
    defer pre_latencies.deinit(allocator);
    var pre_cum_wall = std.atomic.Value(u64).init(0);

    const pre_srv_ctx = ServerCtx{
        .ep = &server_ep,
        .done = &done_pre,
        .allocator = allocator,
        .scratch = scratch,
        .mu = &pre_mu,
        .per_datagram_latencies = &pre_latencies,
        .cumulative_poll_wall_ns = &pre_cum_wall,
    };
    const pre_srv = try std.Thread.spawn(.{}, serverThread, .{pre_srv_ctx});

    const pre_eps = try allocator.alloc(*endpoint_mod.Endpoint, N_PRE);
    const pre_conns = try allocator.alloc(?*api.Connection, N_PRE);
    @memset(pre_conns, null);

    var ok_counter = std.atomic.Value(u64).init(0);
    // Sequential pre-populate: 100 concurrent client endpoints is too
    // heavy for some CI boxes and introduces its own noise. Sequential
    // handshakes complete in ~1-2s total on loopback.
    var pre_actual: usize = 0;
    var pi: usize = 0;
    while (pi < N_PRE) : (pi += 1) {
        var pctx = PrepopulateCtx{
            .allocator = allocator,
            .server_addr = server_target,
            .eps = pre_eps,
            .conns = pre_conns,
            .index = pre_actual,
            .ok_counter = &ok_counter,
        };
        prepopulateOne(&pctx);
        if (pre_conns[pre_actual] != null) pre_actual += 1;
    }
    // Deferred cleanup — only destroy endpoints that were actually
    // populated (pre_actual). Indices >= pre_actual hold uninitialized
    // pointers.
    defer {
        var ci: usize = 0;
        while (ci < pre_actual) : (ci += 1) {
            pre_eps[ci].deinit();
            allocator.destroy(pre_eps[ci]);
        }
        allocator.free(pre_eps);
        allocator.free(pre_conns);
    }

    // Stop the pre-populate server thread. We'll restart a fresh one
    // with new measurement buffers for the flood phase.
    done_pre.store(true, .release);
    pre_srv.join();

    // ------------------------------------------------------------------
    // Phase B: the actual measurement — flood N_flood clients and
    // record per-datagram dispatch wall time on the server side.
    // ------------------------------------------------------------------
    var done_flood = std.atomic.Value(bool).init(false);
    var lat_mu: std.Io.Mutex = std.Io.Mutex.init;
    var latencies: std.ArrayList(u64) = .empty;
    defer latencies.deinit(allocator);
    var cum_wall = std.atomic.Value(u64).init(0);

    const flood_srv_ctx = ServerCtx{
        .ep = &server_ep,
        .done = &done_flood,
        .allocator = allocator,
        .scratch = scratch,
        .mu = &lat_mu,
        .per_datagram_latencies = &latencies,
        .cumulative_poll_wall_ns = &cum_wall,
    };
    const flood_srv = try std.Thread.spawn(.{}, serverThread, .{flood_srv_ctx});

    const n_flooders: u64 = @max(@as(u64, spec.connection_count), 1);
    const total_budget: u64 = @max(spec.iterations, 1);
    const chunks_per_flooder: u64 = (total_budget + n_flooders - 1) / n_flooders;

    // batch_1 sleeps ~50µs between sends to keep the server RX queue
    // shallow (ideally 1-per-poll). Other variants saturate.
    const inter_chunk_ns: u64 = if (n_flooders == 1) 50_000 else 0;
    const flood_deadline_ns: u64 = common.nowNs() + FLOOD_DEADLINE_MS * std.time.ns_per_ms;

    var fail_counter = std.atomic.Value(u64).init(0);
    var sent_counter = std.atomic.Value(u64).init(0);

    const wall_start = common.nowNs();

    const flooder_threads = try allocator.alloc(std.Thread, n_flooders);
    defer allocator.free(flooder_threads);
    const flooder_ok = try allocator.alloc(bool, n_flooders);
    defer allocator.free(flooder_ok);

    for (flooder_threads, flooder_ok) |*t, *ok| {
        const fctx = FlooderCtx{
            .allocator = allocator,
            .server_addr = server_target,
            .chunks_to_send = chunks_per_flooder,
            .inter_chunk_ns = inter_chunk_ns,
            .deadline_ns = flood_deadline_ns,
            .fail_counter = &fail_counter,
            .sent_counter = &sent_counter,
        };
        if (std.Thread.spawn(.{}, flooderThread, .{fctx})) |spawned| {
            t.* = spawned;
            ok.* = true;
        } else |_| {
            _ = fail_counter.fetchAdd(chunks_per_flooder, .seq_cst);
            ok.* = false;
        }
    }
    for (flooder_threads, flooder_ok) |t, ok| {
        if (ok) t.join();
    }

    // Close pre-populated connections to let them unwind before the
    // server teardown.
    var ci: usize = 0;
    while (ci < pre_actual) : (ci += 1) {
        if (pre_conns[ci]) |c| _ = api.close(c, 0, "") catch {};
    }

    const wall_end = common.nowNs();
    done_flood.store(true, .release);
    flood_srv.join();

    const sent_done = sent_counter.load(.acquire);
    const cum = cum_wall.load(.acquire);
    const latency_slice = try allocator.dupe(u64, latencies.items);

    // If the flood produced zero samples (e.g. handshake storm
    // starved the server), return a placeholder so the harness
    // doesn't divide-by-zero in summarizeLatencies.
    if (latency_slice.len == 0) {
        allocator.free(latency_slice);
        return try placeholderOutput(allocator);
    }

    return .{
        .iterations = @max(sent_done, 1),
        .wall_time_ns = @max(wall_end - wall_start, 1),
        .cpu_time_ns = @max(wall_end - wall_start, 1),
        .latencies_ns = latency_slice,
        .packets_transferred = sent_done,
        // Cumulative poll() wall time in the measurement phase. Serves
        // as an upper-bound proxy for total mutex-hold wall on the
        // server's RX path. With N=100 background conns the lookup
        // cost is nontrivial, so this value captures both mutex
        // acquisition and the O(batch) work under the lock.
        .mutex_hold_wall_ns = cum,
    };
}

// Scenario grid: `connection_count` re-purposed as the concurrent-
// client (flooder) count. `iterations` is the TOTAL chunk budget
// across all flooders. The plan's target is 1024 datagrams; 1024
// splits cleanly across 1, 16, and 64 flooders (1024, 64, 16 chunks
// each respectively).
//
// iteration counts are modest because each chunk is a real QUIC
// packet over loopback, and bench repeat factor is 7 (runRepeated);
// wall-clock per variant is ~4-6s on a typical CI box.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/datagram_batch", .variant = "batch_1", .iterations = 1024, .warmup_iterations = 0, .connection_count = 1 },
    .{ .name = "integration/datagram_batch", .variant = "batch_16", .iterations = 1024, .warmup_iterations = 0, .connection_count = 16 },
    .{ .name = "integration/datagram_batch", .variant = "batch_64", .iterations = 1024, .warmup_iterations = 0, .connection_count = 64 },
    // #126 closure: explicit independent-progress variant. 32 concurrent
    // flooder clients pumping 4096 packets total ensures that the endpoint
    // mutex is contended across many independent connections; the per-
    // datagram p99 stays bounded because mu is released between packets in
    // the post-fix batch loop. This row is the regression evidence
    // documented in PERF_GAP_ANALYSIS.md against a future #126 reopen.
    .{ .name = "integration/datagram_batch", .variant = "concurrent_independent_progress", .iterations = 4096, .warmup_iterations = 0, .connection_count = 32 },
};
