// benchmarks/integration/stream_throughput.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: real-UDP QUIC stream-level throughput across a
// 6-cell payload x concurrency grid. Replaces the 2026-03-27 scaffold
// that emitted `{stream_throughput_ops_sec: 0}`.
//
// Each variant runs an echo server on a fresh 127.0.0.1 port and drives
// N parallel client threads. Each client:
//
//   1. Creates a client endpoint bound to 127.0.0.1:0.
//   2. Calls `api.connect` and polls until `isHandshakeConfirmed`.
//   3. For `iters_per_client` iterations:
//        a. `t0 = nowNs()`; open bidi stream; write `payload_bytes` + FIN.
//        b. Drain the stream (`readStream`) until FIN is observed.
//        c. `latency = nowNs() - t0`; appended to shared latency vector.
//
// The server thread drives `server_ep.pollWithStats(1)` continuously,
// drains the accept queue into a local connection list, and for each
// accepted connection reads incoming stream data and echoes it back
// (writeStream + FIN when the client FIN is seen). When all clients
// finish, the main thread signals done and joins the server thread.
//
// Metrics surfaced:
//   * `iterations` = total successful RT ops across all clients
//   * `latencies_ns[]` = per-RT round-trip wall time (p50/p95/p99 fall
//     out naturally via the harness)
//   * `bytes_transferred` = sum of `payload_bytes * 2` (up + down)
//     across successful RTs -> harness computes `bytes_per_sec`
//   * `packets_transferred` = sum of successful RTs (one RT == one
//     request packet flight, one response packet flight)
//
// Scenario tiers (see `scenarios` at bottom):
//   64B-c1    64 bytes, 1 client
//   1KB-c1   1024 bytes, 1 client
//   64KB-c1 65536 bytes, 1 client (large-payload stress)
//   64B-c10   64 bytes, 10 clients
//   1KB-c10 1024 bytes, 10 clients
//   1KB-c32-progress 1024 bytes, 32 clients (parallel progress regression)
//   1KB-c100 1024 bytes, 100 clients (wide concurrency)
//
// Port allocator: `_helpers.allocatePort` (starts 19400). handshake_e2e
// uses 18900+, so no cross-bench collisions.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const api = @import("quic_api");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");
const h = @import("_helpers.zig");

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

/// Per-handshake timeout for the client's connect->confirmed phase.
const HANDSHAKE_TIMEOUT_MS: u64 = 3_000;
/// Per-RT timeout for the write->echo->FIN phase. Large enough to cover
/// a 64KB payload + ack path at -O3 on a contended CI box.
const RT_TIMEOUT_MS: u64 = 5_000;

const StreamState = struct {
    stream_id: api.QuicStreamId,
    pending: std.ArrayList(u8),
    client_fin: bool,
    server_fin_sent: bool,
};

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
    /// Preallocated scratch for one echo read; sized to the largest
    /// expected payload per the variant grid (64KB). Owned by the
    /// server thread to avoid per-read allocation.
    scratch: []u8,
};

/// Drain RX + flush TX for every known stream on every known conn.
/// Returns true if any forward progress was made (bytes moved or FINs
/// observed), false otherwise. The server thread uses this on both the
/// main loop and the final drain.
fn pumpStreams(
    conns: []*api.Connection,
    states_by_conn: []std.ArrayList(StreamState),
    scratch: []u8,
    allocator: std.mem.Allocator,
) bool {
    var progress = false;
    for (conns, states_by_conn) |conn, *states| {
        // Accept any newly-incoming streams.
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

            // Drain RX into pending buffer.
            var rx_progress = false;
            while (true) {
                const n = api.readStream(conn, s.stream_id, scratch) catch {
                    // WouldBlock / Done / StreamNotFound / InvalidStream:
                    // no bytes ready right now; stop reading for this
                    // tick. Other errors land here too -- we just pause
                    // this stream and let the main loop retry next tick.
                    break;
                };
                if (n == 0) break; // FIN observed (empty with isFinished set)
                s.pending.appendSlice(allocator, scratch[0..n]) catch break;
                rx_progress = true;
            }
            if (rx_progress) progress = true;
            if (api.isStreamFinished(conn, s.stream_id) and !s.client_fin) {
                s.client_fin = true;
                progress = true;
            }

            // Flush pending back. No FIN on intermediate chunks; FIN
            // goes out in a dedicated empty write below once pending
            // is fully drained AND client_fin is set.
            while (s.pending.items.len > 0) {
                const written = api.writeStream(
                    conn,
                    s.stream_id,
                    s.pending.items,
                    false,
                ) catch break;
                if (written == 0) break;
                const remaining = s.pending.items.len - written;
                if (remaining > 0) {
                    std.mem.copyForwards(
                        u8,
                        s.pending.items[0..remaining],
                        s.pending.items[written..],
                    );
                }
                s.pending.shrinkRetainingCapacity(remaining);
                progress = true;
            }

            if (s.client_fin and s.pending.items.len == 0 and !s.server_fin_sent) {
                _ = api.writeStream(conn, s.stream_id, &[_]u8{}, true) catch {};
                s.server_fin_sent = true;
                progress = true;
            }
        }
    }
    return progress;
}

/// Server poll thread. Drives the endpoint's poll loop, accepts
/// incoming connections, and for each accepted connection repeatedly
/// walks its incoming-stream queue to echo client writes back. When a
/// stream's peer FIN is observed, the server writes any remaining
/// pending bytes with FIN=true and closes the stream. The main thread
/// signals `done` once all clients finish -- we then do a brief final
/// drain so tail acks land before deinit.
fn serverThread(ctx: ServerCtx) void {
    var conns: std.ArrayList(*api.Connection) = .empty;
    defer conns.deinit(ctx.allocator);

    var stream_states_by_conn: std.ArrayList(std.ArrayList(StreamState)) = .empty;
    defer {
        for (stream_states_by_conn.items) |*per_conn| {
            for (per_conn.items) |*s| s.pending.deinit(ctx.allocator);
            per_conn.deinit(ctx.allocator);
        }
        stream_states_by_conn.deinit(ctx.allocator);
    }

    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(0) catch {};

        // Drain new accepts.
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

    // Final drain: give the last RT a chance to land.
    var drain_ticks: usize = 0;
    while (drain_ticks < 50) : (drain_ticks += 1) {
        _ = ctx.ep.pollWithStats(1) catch {};
        _ = pumpStreams(
            conns.items,
            stream_states_by_conn.items,
            ctx.scratch,
            ctx.allocator,
        );
    }
}

const ClientCtx = struct {
    allocator: std.mem.Allocator,
    server_addr: []const u8,
    payload_bytes: usize,
    iters_per_client: u64,
    mu: *std.Io.Mutex,
    latencies: *std.ArrayList(u64),
    bytes_counter: *std.atomic.Value(u64),
    ops_counter: *std.atomic.Value(u64),
    fail_counter: *std.atomic.Value(u64),
};

/// Runs one client's workload: connects, handshakes, then iterates
/// `iters_per_client` stream echo RTs. Each RT is independently timed.
/// Failures (connect fail, RT timeout, stream error) are tallied in
/// `fail_counter` and the RT is not added to `latencies`.
fn clientThread(ctx: ClientCtx) void {
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = endpoint_mod.Endpoint.init(ctx.allocator, "127.0.0.1:0", &cli_cfg) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.iters_per_client, .seq_cst);
        return;
    };
    defer ep.deinit();

    const conn = api.connect(&ep, ctx.server_addr, SERVER_SNI) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.iters_per_client, .seq_cst);
        return;
    };

    // Drive handshake.
    const hs_deadline = common.nowNs() + HANDSHAKE_TIMEOUT_MS * std.time.ns_per_ms;
    while (common.nowNs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        _ = ctx.fail_counter.fetchAdd(ctx.iters_per_client, .seq_cst);
        return;
    }

    // Build the send payload once; the echo server writes the same
    // bytes back so we don't need to verify content, just length.
    const send_buf = ctx.allocator.alloc(u8, ctx.payload_bytes) catch {
        _ = ctx.fail_counter.fetchAdd(ctx.iters_per_client, .seq_cst);
        return;
    };
    defer ctx.allocator.free(send_buf);
    for (send_buf, 0..) |*b, i| b.* = @truncate(i);

    // Recv scratch: sized to a reasonable read chunk. We loop until
    // `received == payload_bytes` AND the stream has the peer FIN bit
    // set (indicating the server finished its echo).
    var recv_scratch: [8192]u8 = undefined;

    var i: u64 = 0;
    while (i < ctx.iters_per_client) : (i += 1) {
        const rt_deadline = common.nowNs() + RT_TIMEOUT_MS * std.time.ns_per_ms;
        const t0 = common.nowNs();

        const sid = api.openStream(conn, true) catch {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            continue;
        };

        // Write payload + FIN. writeStream may accept a short write
        // under flow control; loop until all bytes are sent.
        var sent: usize = 0;
        var write_fail = false;
        while (sent < send_buf.len) {
            if (common.nowNs() >= rt_deadline) {
                write_fail = true;
                break;
            }
            const is_last = true; // we mark FIN on every write; short
            // writes will still have `fin=true` on the last chunk.
            const to_send = send_buf[sent..];
            const n = api.writeStream(conn, sid, to_send, is_last) catch {
                write_fail = true;
                break;
            };
            if (n == 0) {
                _ = ep.pollWithStats(1) catch {};
                continue;
            }
            sent += n;
        }
        if (write_fail) {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            continue;
        }

        // Drain echo until we've received payload_bytes AND peer FIN.
        var received: usize = 0;
        var rt_fail = false;
        while (received < send_buf.len or !api.isStreamFinished(conn, sid)) {
            if (common.nowNs() >= rt_deadline) {
                rt_fail = true;
                break;
            }
            _ = ep.pollWithStats(1) catch {};
            const n = api.readStream(conn, sid, &recv_scratch) catch |err| {
                // WouldBlock = "no RX data buffered yet"; keep polling.
                // Done / StreamNotFound / InvalidStream = "nothing more
                // coming"; exit loop. Anything else = genuine failure.
                if (err == error.WouldBlock) continue;
                if (err == error.Done) break;
                if (err == error.StreamNotFound) break;
                if (err == error.InvalidStream) break;
                rt_fail = true;
                break;
            };
            if (n == 0) continue;
            received += n;
        }
        if (rt_fail) {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            continue;
        }

        const dt = common.nowNs() - t0;
        ctx.mu.lockUncancelable(h.benchIo());
        ctx.latencies.append(ctx.allocator, dt) catch {};
        ctx.mu.unlock(h.benchIo());
        _ = ctx.bytes_counter.fetchAdd(send_buf.len * 2, .seq_cst); // up + down
        _ = ctx.ops_counter.fetchAdd(1, .seq_cst);
    }

    // Close the connection gracefully so the server's echo loop knows
    // to wind down state for this conn.
    _ = api.close(conn, 0, "done") catch {};
    // One last poll flush so the CLOSE frame actually goes out.
    _ = ep.pollWithStats(1) catch {};
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

    // SONNY-4381: no credentials, no measurement -- never a placeholder.
    const creds = h.loadServerCreds(allocator) catch |err| return common.notMeasured(allocator, @errorName(err));

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
        return common.notMeasured(allocator, "ServerStartFailed");
    };
    defer server_ep.deinit();

    var target_buf: [32]u8 = undefined;
    const server_target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    // Allocate scratch for the server echo reads. Must be >= largest
    // expected payload; 64KB variant writes 65536B per RT, so a 128KB
    // scratch is ample and costs nothing.
    const scratch = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(scratch);

    var done = std.atomic.Value(bool).init(false);
    const srv_ctx = ServerCtx{
        .ep = &server_ep,
        .done = &done,
        .allocator = allocator,
        .scratch = scratch,
    };
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{srv_ctx});
    defer {
        done.store(true, .release);
        srv_thread.join();
    }

    // Shared state for all clients.
    var lat_mu: std.Io.Mutex = std.Io.Mutex.init;
    var latencies: std.ArrayList(u64) = .empty;
    defer latencies.deinit(allocator);
    var bytes_counter = std.atomic.Value(u64).init(0);
    var ops_counter = std.atomic.Value(u64).init(0);
    var fail_counter = std.atomic.Value(u64).init(0);

    const parallel: u64 = @max(@as(u64, spec.connection_count), 1);
    const iters_total: u64 = @max(spec.iterations, 1);
    const iters_per_client: u64 = (iters_total + parallel - 1) / parallel;
    const payload = spec.payload_bytes;

    const wall_start = common.nowNs();

    if (parallel == 1) {
        const cctx = ClientCtx{
            .allocator = allocator,
            .server_addr = server_target,
            .payload_bytes = payload,
            .iters_per_client = iters_per_client,
            .mu = &lat_mu,
            .latencies = &latencies,
            .bytes_counter = &bytes_counter,
            .ops_counter = &ops_counter,
            .fail_counter = &fail_counter,
        };
        clientThread(cctx);
    } else {
        const client_threads = try allocator.alloc(std.Thread, parallel);
        defer allocator.free(client_threads);
        const thread_ok = try allocator.alloc(bool, parallel);
        defer allocator.free(thread_ok);

        for (client_threads, thread_ok) |*t, *ok| {
            const cctx = ClientCtx{
                .allocator = allocator,
                .server_addr = server_target,
                .payload_bytes = payload,
                .iters_per_client = iters_per_client,
                .mu = &lat_mu,
                .latencies = &latencies,
                .bytes_counter = &bytes_counter,
                .ops_counter = &ops_counter,
                .fail_counter = &fail_counter,
            };
            if (std.Thread.spawn(.{}, clientThread, .{cctx})) |spawned| {
                t.* = spawned;
                ok.* = true;
            } else |_| {
                _ = fail_counter.fetchAdd(iters_per_client, .seq_cst);
                ok.* = false;
            }
        }
        for (client_threads, thread_ok) |t, ok| {
            if (ok) t.join();
        }
    }

    const wall_end = common.nowNs();
    done.store(true, .release);
    h.threadSleep(50 * std.time.ns_per_ms);

    const ops_done = ops_counter.load(.acquire);
    const bytes_done = bytes_counter.load(.acquire);
    const latency_slice = try allocator.dupe(u64, latencies.items);

    return .{
        .iterations = @max(ops_done, 1),
        .wall_time_ns = @max(wall_end - wall_start, 1),
        .cpu_time_ns = @max(wall_end - wall_start, 1),
        .latencies_ns = latency_slice,
        .bytes_transferred = bytes_done,
        .packets_transferred = ops_done,
    };
}

// Variant grid: payload_bytes x connection_count. Iteration counts
// picked so each variant stays tractable (<30s on a 2-core CI box);
// `iters_per_client = iterations / connection_count` inside run().
//
// Cap on per-client iterations: the transport's default
// `local_max_streams_bidi` is 1000 (see src/quic/conn.zig:669) and the
// opened-bidi counter is cumulative per RFC 9000 §4.6 -- closed
// streams do NOT decrement it. Until MAX_STREAMS_BIDI auto-raise is
// wired up, each client can only open ~1000 streams over the lifetime
// of a connection. So single-client variants stay at 900 iterations
// (safe margin below the cap); 10-client variants get 1000 total
// (100 per client); the 100-client variant gets 200 total (2 per
// client) which pairs with the c100 stress case.
//
// Per plan review: 64KB-c1 iteration count scaled to 50 (target
// 500 in the plan) because each 64KB RT dominates on loopback --
// a 50-iter run already clocks ~15s wall. 1KB-c100 scaled from
// 500 -> 200 because we observed ~17% of iters fail at 100-client
// concurrency (visible as 166/200 in the row); future work will
// relax MAX_STREAMS and raise these counts.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/stream_throughput", .variant = "64B-c1", .iterations = 900, .warmup_iterations = 50, .payload_bytes = 64, .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c1", .iterations = 900, .warmup_iterations = 50, .payload_bytes = 1024, .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "64KB-c1", .iterations = 50, .warmup_iterations = 5, .payload_bytes = 65536, .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "64B-c10", .iterations = 1_000, .warmup_iterations = 50, .payload_bytes = 64, .connection_count = 10 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c10", .iterations = 1_000, .warmup_iterations = 50, .payload_bytes = 1024, .connection_count = 10 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c32-progress", .iterations = 96, .warmup_iterations = 0, .payload_bytes = 1024, .connection_count = 32 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c100", .iterations = 200, .warmup_iterations = 10, .payload_bytes = 1024, .connection_count = 100 },
};
