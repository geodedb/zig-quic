// benchmarks/integration/flush_cadence.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: QUIC flush cadence — the latency between a
// client `writeStream()` return and the bytes landing on the wire.
// Motivated by geode graph database's `two_hop` query pattern, whose
// step-4 profile documented ~80% of the remaining 1s p50 query latency
// is wait-bound on QUIC flush cadence inside zig-quic's send path.
//
// This bench establishes the baseline so geode-motivated QUIC work
// (flush-trigger heuristics, pacing tuning, stream-write coalescing)
// can be A/B-tested against the numbers emitted here. Regressions in
// the send-path flush cadence will show up as latency inflation across
// all four variants.
//
// Measurement strategy (Option B — echo-as-proxy):
//   The "bytes on the wire" event is not externally observable without
//   kernel-level tracing. Instead we run a loopback echo server: the
//   client submits a write, the server reads and echoes, the client's
//   read returns when the echo bytes land. On loopback the round-trip
//   decomposes as:
//
//     t_submit ........... client `writeStream()` returns
//     t_wire   ~= t_submit + flush-cadence + network + server-echo
//     t_echo  ............ client `readStream()` returns the echo
//
//   We record `t_echo - t_submit` as the per-op latency. Server echo
//   cost is negligible compared to the flush-cadence portion for small
//   payloads on loopback, so the signal is dominated by QUIC send-path
//   wait behaviour. RATIOS between variants (burst vs single, sustained
//   vs one-shot) surface the pacing/coalescing behaviour cleanly.
//
// Variants (4):
//   small_writes_1_stream — 1 stream, many 128B writes per-write timed.
//                           This is the geode two_hop signature: small
//                           frequent writes on a persistent stream. If
//                           the send path doesn't flush promptly the
//                           p99 here will balloon.
//   fanout_two_hop        — N streams (default 10), one 64B req per
//                           stream, wait for all N 64B echoes. This is
//                           the exact geode two_hop shape: fan out to
//                           peers, fan in responses. Aggregate latency
//                           (fan-in wall time) is what we measure.
//                           `connection_count` is repurposed as the
//                           fanout width (only u32 knob in ScenarioSpec).
//   burst_flush           — Burst of 100 writes on one stream, time to
//                           receive all 100 echoes. Exposes how well
//                           the send path pipelines multiple queued
//                           writes under a single flush trigger.
//   sustained_writes      — Steady writes for up to 10s on one stream,
//                           timed inter-flush — i.e. time between
//                           successive echo-receive events. Flush-to-
//                           flush jitter surfaces pacing irregularity.
//
// Metric repurposing:
//   `RunOutput.mutex_hold_wall_ns` is unused semantically by this bench.
//   We repurpose it to carry cumulative wait-bound time
//   (`wait_bound_total_ns`, the sum of per-op latencies). The interpreta-
//   tion downstream is:
//
//     wait_bound_fraction = mutex_hold_wall_ns / wall_time_ns
//
//   A fraction > 0.8 on any variant = geode-style wait-bound signature.
//   This avoids a schema bump on common.ResultRow/RunOutput; a
//   follow-up patch can add a dedicated `wait_bound_fraction_permille`
//   optional if the overloaded semantics become confusing.
//
// Port allocator: private, starts at 19800 per _helpers.zig's documented
// port-range reservations. 500-port headroom above the stream_throughput
// range (19400+) prevents collisions when --suite=integration sweeps
// both benches back-to-back.
//
// Numeric improvement target (geode-motivated):
//   Baseline (2026-04-20, this commit): burst_flush p50 ~128ms for 100
//   writes vs small_writes_1_stream p50 ~130us for 1 write.
//   Per-write overhead ratio = burst / (small * 100) ~= 9.85x.
//   Post-pipelining fix in the send path: target ratio -> 1.0-1.5x
//   (bursts land in a single aggregate flush). A compare.zig derived
//   gate on this ratio (follow-up) will catch both improvement wins
//   and future regressions.

// Client polling (SONNY-6486): the client used to wait in pollWithStats(1)
// between writes and echoes, so each echo also paid the time for the
// client thread to wake from the poll wait. Up to quic v0.1.50 the
// endpoints answered each other's ACK-only packets with ACKs forever
// (fixed by SONNY-6478), which kept the client socket busy so the thread
// never slept: burst_flush measured ~14.5 bursts/s with that traffic and
// ~10.9 without it, the difference being thread wake-up, not the send path.
// The client now polls without sleeping (pollWithStats(0)), as the echo
// server already did, so the numbers measure the library alone.

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
/// Per-op timeout for the write->echo round trip. Sized for a
/// contested CI box running several integration benches concurrently.
const OP_TIMEOUT_MS: u64 = 2_000;
/// Sustained-writes wall-clock cap. Plan target is 10s; we keep it
/// there. With runRepeated=7 this variant dominates wall time at ~70s.
const SUSTAINED_WALL_NS: u64 = 10 * std.time.ns_per_s;

/// Private port allocator. 19800+ range reserved per _helpers.zig
/// documentation. Fresh port per runRepeated iteration avoids
/// TIME_WAIT collisions during the median-of-6 sweep.
var fc_next_port = std.atomic.Value(u16).init(19800);
fn allocatePort() u16 {
    return fc_next_port.fetchAdd(1, .seq_cst);
}

// ---------------------------------------------------------------------
// Server: echo pump. Mirrors stream_throughput's pattern but simplified
// to a single-connection / multi-stream model since flush_cadence only
// spawns one client.
// ---------------------------------------------------------------------

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
    scratch: []u8,
};

/// Drain RX and echo back for every stream on every conn. Unlike
/// stream_throughput we DON'T rely on client FIN to end the echo; the
/// flush_cadence client keeps streams open and writes many chunks per
/// stream, so the server must echo every chunk as it arrives rather
/// than buffering until FIN.
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

            // Drain RX into pending.
            while (true) {
                const n = api.readStream(conn, s.stream_id, scratch) catch break;
                if (n == 0) break; // FIN or done.
                s.pending.appendSlice(allocator, scratch[0..n]) catch break;
                progress = true;
            }
            if (api.isStreamFinished(conn, s.stream_id) and !s.client_fin) {
                s.client_fin = true;
                progress = true;
            }

            // Flush pending back. No FIN on intermediate chunks; FIN
            // goes out once client_fin is observed AND pending drained.
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

    // Final drain so any last echo lands before teardown.
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

// ---------------------------------------------------------------------
// Client helpers: one-shot send + drain-until-len on a given stream.
// ---------------------------------------------------------------------

/// Write `payload` on `sid` with fin=false. Loops until all bytes are
/// accepted (writeStream may short-write under flow control). Drives
/// `ep.pollWithStats(0)` between retries to advance ACKs. Returns an
/// error on timeout or transport failure.
fn sendChunk(
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    sid: api.QuicStreamId,
    payload: []const u8,
    deadline_ns: u64,
) !void {
    var sent: usize = 0;
    while (sent < payload.len) {
        if (common.nowNs() >= deadline_ns) return error.Timeout;
        const n = api.writeStream(conn, sid, payload[sent..], false) catch |err| {
            return err;
        };
        if (n == 0) {
            // No sleep in the poll: see "Client polling" above.
            _ = ep.pollWithStats(0) catch {};
            continue;
        }
        sent += n;
    }
}

/// Read exactly `want` bytes from `sid` into a discard buffer. Drives
/// `pollWithStats(0)` between reads so echo bytes arrive promptly.
/// Returns an error on timeout or transport failure.
fn recvExact(
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    sid: api.QuicStreamId,
    want: usize,
    scratch: []u8,
    deadline_ns: u64,
) !void {
    var got: usize = 0;
    while (got < want) {
        if (common.nowNs() >= deadline_ns) return error.Timeout;
        // No sleep in the poll: see "Client polling" above.
        _ = ep.pollWithStats(0) catch {};
        const take = @min(scratch.len, want - got);
        const n = api.readStream(conn, sid, scratch[0..take]) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };
        if (n == 0) continue;
        got += n;
    }
}

// ---------------------------------------------------------------------
// Variant enumeration.
// ---------------------------------------------------------------------

const Variant = enum {
    small_writes_1_stream,
    fanout_two_hop,
    burst_flush,
    sustained_writes,
};

fn variantFromString(v: []const u8) Variant {
    if (std.mem.eql(u8, v, "small_writes_1_stream")) return .small_writes_1_stream;
    if (std.mem.eql(u8, v, "fanout_two_hop")) return .fanout_two_hop;
    if (std.mem.eql(u8, v, "burst_flush")) return .burst_flush;
    if (std.mem.eql(u8, v, "sustained_writes")) return .sustained_writes;
    return .small_writes_1_stream;
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

// ---------------------------------------------------------------------
// Variant runners. Each returns the list of per-sample latencies plus
// the "wait-bound total" (sum of per-op waits) which is carried through
// `mutex_hold_wall_ns` as wait_bound_total_ns.
// ---------------------------------------------------------------------

/// small_writes_1_stream: single bidi stream, `iters` writes of
/// `payload_bytes` bytes each, per-write submit→echo latency.
/// Matches geode's "small frequent writes on a persistent RPC stream"
/// signature — if flush cadence is lazy, p99 here balloons.
///
/// What the numbers mean:
///   * p50 = typical submit→echo round-trip on loopback for 128B. On
///     baseline this is tens of µs; a flush-cadence regression here
///     inflates p99 without moving p50 much (the pathological case is
///     long-tail waits for write coalescing).
///   * Expected post-improvement target: p99 within ~2x of p50.
fn runSmallWrites(
    allocator: std.mem.Allocator,
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    spec: common.ScenarioSpec,
    out_latencies: *std.ArrayList(u64),
    wait_bound_total: *u64,
) !void {
    const payload_bytes: usize = if (spec.payload_bytes == 0) 128 else spec.payload_bytes;
    const payload = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const scratch = try allocator.alloc(u8, @max(payload_bytes, 256));
    defer allocator.free(scratch);

    const sid = try api.openStream(conn, true);

    var i: u64 = 0;
    while (i < spec.iterations) : (i += 1) {
        const deadline = common.nowNs() + OP_TIMEOUT_MS * std.time.ns_per_ms;
        const t_submit = common.nowNs();
        sendChunk(ep, conn, sid, payload, deadline) catch break;
        recvExact(ep, conn, sid, payload_bytes, scratch, deadline) catch break;
        const dt = common.nowNs() - t_submit;
        try out_latencies.append(allocator, dt);
        wait_bound_total.* += dt;
    }

    // Close the stream gracefully with an empty FIN so the server's
    // echo pump winds it down before the measurement phase ends.
    _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {};
}

/// fanout_two_hop: `fanout` streams opened per iter, each carrying one
/// req/resp of `payload_bytes` bytes. Per-iter latency = fan-in wall
/// time (submit all N reqs, drain all N echoes). Matches the geode
/// two_hop query shape: one step fans out to N peers, waits for N
/// responses before proceeding to the next step.
///
/// What the numbers mean:
///   * p50/p99 = aggregate fan-in latency for N=connection_count
///     streams. Scales with the SLOWEST stream's flush cadence since
///     the client can't proceed until the last echo lands.
///   * Expected post-improvement target: p99 should scale sub-linearly
///     with fanout if the send path pipelines flushes across streams.
///
/// Notes:
///   - `connection_count` is reused as the fanout width (u32 knob).
///   - We close each stream with FIN after draining its echo so the
///     cumulative stream-id count (default cap 1000 per conn.zig:669)
///     doesn't exhaust. iters=50 * fanout=10 = 500 streams total,
///     well below the cap.
fn runFanout(
    allocator: std.mem.Allocator,
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    spec: common.ScenarioSpec,
    out_latencies: *std.ArrayList(u64),
    wait_bound_total: *u64,
) !void {
    const fanout: usize = @max(@as(usize, spec.connection_count), 1);
    const payload_bytes: usize = if (spec.payload_bytes == 0) 64 else spec.payload_bytes;

    const payload = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const scratch = try allocator.alloc(u8, @max(payload_bytes, 256));
    defer allocator.free(scratch);

    const sids = try allocator.alloc(api.QuicStreamId, fanout);
    defer allocator.free(sids);

    var i: u64 = 0;
    while (i < spec.iterations) : (i += 1) {
        // Open `fanout` fresh bidi streams.
        var ok: usize = 0;
        while (ok < fanout) : (ok += 1) {
            sids[ok] = api.openStream(conn, true) catch break;
        }
        if (ok < fanout) break; // stream budget exhausted

        const deadline = common.nowNs() + OP_TIMEOUT_MS * std.time.ns_per_ms;
        const t_submit = common.nowNs();

        // Submit N requests.
        var any_fail = false;
        for (sids) |sid| {
            sendChunk(ep, conn, sid, payload, deadline) catch {
                any_fail = true;
                break;
            };
        }
        if (any_fail) break;

        // Drain N echoes.
        for (sids) |sid| {
            recvExact(ep, conn, sid, payload_bytes, scratch, deadline) catch {
                any_fail = true;
                break;
            };
        }
        if (any_fail) break;

        const dt = common.nowNs() - t_submit;
        try out_latencies.append(allocator, dt);
        wait_bound_total.* += dt;

        // Retire the streams with FIN so stream-id budget doesn't
        // exhaust over many iterations.
        for (sids) |sid| {
            _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {};
        }
    }
}

/// burst_flush: submit 100 writes back-to-back on one stream, wait for
/// all 100 echoes. Exposes send-path pipelining: if each write triggers
/// its own flush, the aggregate time is ~100x the per-op baseline; if
/// the send path coalesces, it's much closer to the per-op baseline.
///
/// What the numbers mean:
///   * p50/p99 = wall time to echo a 100-write burst. Divide by 100
///     to get per-op cost; compare to small_writes_1_stream p50.
///   * Expected post-improvement target: burst_p50 / 100 ≈
///     small_writes_p50 (perfect pipelining). Pre-improvement the
///     ratio may be >>1x if each write serializes under its own flush.
fn runBurst(
    allocator: std.mem.Allocator,
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    spec: common.ScenarioSpec,
    out_latencies: *std.ArrayList(u64),
    wait_bound_total: *u64,
) !void {
    const burst_size: usize = 100;
    const payload_bytes: usize = if (spec.payload_bytes == 0) 256 else spec.payload_bytes;

    const payload = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const scratch = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(scratch);

    // One long-lived stream; `burst_size` writes per iter, `iters`
    // iters total. All writes happen on ONE stream to stay under the
    // default MAX_STREAMS_BIDI cap. The stream stays open between
    // iters; the server's echo pump keeps draining it.
    const sid = try api.openStream(conn, true);

    var i: u64 = 0;
    while (i < spec.iterations) : (i += 1) {
        // 10x deadline for burst — 100 writes + echoes takes longer
        // on a contested CI box.
        const deadline = common.nowNs() + OP_TIMEOUT_MS * 10 * std.time.ns_per_ms;
        const t_submit = common.nowNs();

        // Burst: 100 writes as fast as possible.
        var any_fail = false;
        var k: usize = 0;
        while (k < burst_size) : (k += 1) {
            sendChunk(ep, conn, sid, payload, deadline) catch {
                any_fail = true;
                break;
            };
        }
        if (any_fail) break;

        // Wait for all 100 echoes.
        recvExact(ep, conn, sid, burst_size * payload_bytes, scratch, deadline) catch break;

        const dt = common.nowNs() - t_submit;
        try out_latencies.append(allocator, dt);
        wait_bound_total.* += dt;
    }

    _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {};
}

/// sustained_writes: write + recv echo in a loop until the 10s wall-
/// clock deadline or `iterations` is hit. Per-sample latency is the
/// INTER-FLUSH interval (time from previous echo-complete to current
/// echo-complete). High jitter in this series = poor pacing.
///
/// What the numbers mean:
///   * p50 = typical steady-state flush interval for this payload.
///   * p99 / p50 ratio = jitter proxy. A well-paced send path stays
///     within ~2x; a bursty one exhibits ratios >10x.
///   * Expected post-improvement target: p99 / p50 < 3x.
fn runSustained(
    allocator: std.mem.Allocator,
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
    spec: common.ScenarioSpec,
    out_latencies: *std.ArrayList(u64),
    wait_bound_total: *u64,
) !void {
    const payload_bytes: usize = if (spec.payload_bytes == 0) 1024 else spec.payload_bytes;
    const payload = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const scratch = try allocator.alloc(u8, payload_bytes);
    defer allocator.free(scratch);

    const sid = try api.openStream(conn, true);

    const wall_deadline = common.nowNs() + SUSTAINED_WALL_NS;
    var prev_flush = common.nowNs();
    var i: u64 = 0;
    while (i < spec.iterations and common.nowNs() < wall_deadline) : (i += 1) {
        const deadline = common.nowNs() + OP_TIMEOUT_MS * std.time.ns_per_ms;
        sendChunk(ep, conn, sid, payload, deadline) catch break;
        recvExact(ep, conn, sid, payload_bytes, scratch, deadline) catch break;
        const now = common.nowNs();
        const dt = now - prev_flush;
        try out_latencies.append(allocator, dt);
        wait_bound_total.* += dt;
        prev_flush = now;
    }

    _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {};
}

// ---------------------------------------------------------------------
// Top-level run(): set up server + client endpoints, dispatch variant.
// ---------------------------------------------------------------------

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) return try placeholderOutput(allocator);

    const creds = h.loadServerCreds(allocator) orelse {
        return try placeholderOutput(allocator);
    };

    const port = allocatePort();
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

    // Server echo scratch, sized for the largest variant payload
    // (burst_flush = 256B * 100 = 25600B, sustained = 1024B).
    const scratch = try allocator.alloc(u8, 64 * 1024);
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

    // Client endpoint + connection.
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var client_ep = endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg) catch {
        return try placeholderOutput(allocator);
    };
    defer client_ep.deinit();

    const conn = api.connect(&client_ep, server_target, SERVER_SNI) catch {
        return try placeholderOutput(allocator);
    };

    // Drive handshake.
    const hs_deadline = common.nowNs() + HANDSHAKE_TIMEOUT_MS * std.time.ns_per_ms;
    while (common.nowNs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        return try placeholderOutput(allocator);
    }

    // ------------------------------------------------------------------
    // Dispatch variant.
    // ------------------------------------------------------------------
    var latencies: std.ArrayList(u64) = .empty;
    // Errors below won't propagate up as failures (we return a
    // placeholder); we just deinit on the way out.
    errdefer latencies.deinit(allocator);

    var wait_bound_total: u64 = 0;
    const wall_start = common.nowNs();

    const variant = variantFromString(spec.variant);
    switch (variant) {
        .small_writes_1_stream => runSmallWrites(
            allocator,
            &client_ep,
            conn,
            spec,
            &latencies,
            &wait_bound_total,
        ) catch {},
        .fanout_two_hop => runFanout(
            allocator,
            &client_ep,
            conn,
            spec,
            &latencies,
            &wait_bound_total,
        ) catch {},
        .burst_flush => runBurst(
            allocator,
            &client_ep,
            conn,
            spec,
            &latencies,
            &wait_bound_total,
        ) catch {},
        .sustained_writes => runSustained(
            allocator,
            &client_ep,
            conn,
            spec,
            &latencies,
            &wait_bound_total,
        ) catch {},
    }

    const wall_end = common.nowNs();
    const wall_ns = @max(wall_end - wall_start, 1);

    // Gracefully close the connection so the server's pump can finish
    // its drain before we signal done + join.
    _ = api.close(conn, 0, "done") catch {};
    _ = client_ep.pollWithStats(1) catch {};

    // If the variant produced no samples, return a placeholder so the
    // harness doesn't divide-by-zero in summarizeLatencies.
    if (latencies.items.len == 0) {
        latencies.deinit(allocator);
        return try placeholderOutput(allocator);
    }

    const latency_slice = try allocator.dupe(u64, latencies.items);
    latencies.deinit(allocator);

    return .{
        .iterations = latency_slice.len,
        .wall_time_ns = wall_ns,
        .cpu_time_ns = wall_ns,
        .latencies_ns = latency_slice,
        // Reused slot: `mutex_hold_wall_ns` carries the cumulative
        // wait-bound time (sum of per-op latencies). The downstream
        // interpretation is wait_bound_fraction = mutex_hold_wall_ns /
        // wall_time_ns. If fraction > 0.8 on any variant, the geode-
        // style wait-bound signature is present.
        .mutex_hold_wall_ns = wait_bound_total,
    };
}

// ---------------------------------------------------------------------
// Scenario grid.
// ---------------------------------------------------------------------
//
// Iteration counts sized per the task-5.4 scale-back guidance:
//   - small_writes_1_stream: 900 iters on ONE stream (default
//     MAX_STREAMS_BIDI=1000 doesn't apply since we don't open new
//     streams per-iter). Plenty for stable p99.
//   - fanout_two_hop: 50 iters × 10 fanout = 500 streams per run;
//     closed with FIN each iter, well under the 1000-per-conn cap.
//   - burst_flush: 10 iters; each iter is 100 writes = 1000 writes
//     total on one stream. Single open stream, stays under cap.
//   - sustained_writes: up to 10_000 samples OR 10s wall, whichever
//     hits first. In practice the wall deadline truncates well
//     before 10k on a CI box.
//
// payload_bytes defaults match the plan's template. connection_count is
// reused as fanout-width for fanout_two_hop; for the other three it's
// fixed at 1 (single client, single persistent stream).
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/flush_cadence", .variant = "small_writes_1_stream", .iterations = 900, .warmup_iterations = 10, .payload_bytes = 128, .connection_count = 1 },
    .{ .name = "integration/flush_cadence", .variant = "fanout_two_hop", .iterations = 50, .warmup_iterations = 2, .payload_bytes = 64, .connection_count = 10 },
    .{ .name = "integration/flush_cadence", .variant = "burst_flush", .iterations = 10, .warmup_iterations = 1, .payload_bytes = 256, .connection_count = 1 },
    .{ .name = "integration/flush_cadence", .variant = "sustained_writes", .iterations = 10_000, .warmup_iterations = 10, .payload_bytes = 1024, .connection_count = 1 },
};
