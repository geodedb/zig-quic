// benchmarks/micro/connection_lookup.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: short-header connection-table routing cost
// (endpoint.findConnectionByDcid) as a function of active connection count.
//
// Motivation (issue #154): short-header lookup used to iterate the entire
// connection hashmap per packet, matching peer_hash + DCID. That's O(N) per
// packet and scales to O(N^2) when N connections each receive one packet.
// The endpoint now uses a peer+DCID hash fast path; this bench keeps the
// regression signature visible. p99 should stay roughly flat from 10
// connections through 20K connections.
//
// Methodology:
//   * Populate the endpoint with N client connections via connectClient.
//     Each client gets a unique 127.0.0.1:<port> target, which gives
//     each connection a distinct peer_hash -- the same distribution the
//     server side sees when routing inbound packets from N peers. The
//     endpoint's internal connection map holds each connection keyed by
//     both peer+peer_initial_dcid and peer+our_scid (see
//     endpoint/client.zig:149-162), so the table is fully populated
//     with real entries prior to measurement.
//   * For each connection, record (peer, our_scid bytes) into a parallel
//     array so the measurement loop picks a random index and can invoke
//     the lookup with the exact key material the endpoint would see on
//     an inbound short-header packet. Using our_scid matches the
//     server-side routing path (short-header DCID == the receiver's
//     previously-advertised SCID, RFC 9000 §5.1).
//   * Synthesize a minimal short-header "packet" buffer per iteration:
//     [0x40, <8 bytes of DCID>]. The 0x40 byte is a valid short-header
//     first octet (bit 0x80 clear). findConnectionByDcid reads DCID
//     starting at packet_bytes[1] for `our_scid.len` bytes, so a 9-byte
//     buffer is sufficient for the 8-byte SCIDs that connectClient
//     generates (endpoint/client.zig:145).
//   * `ep.findConnectionByDcid` is a thin public wrapper (added in the
//     prep commit that precedes this file) around the internal
//     endpoint/lookup.findConnectionByDcid -- pure read, no allocations,
//     no mutex. Single-threaded bench driver + pre-populated endpoint
//     means the table is stable for the duration of the measured loop.
//
// Variants: active connection count sweeps 10 / 100 / 1000 / 10000 / 20000.
// Iteration counts drop at higher N so wall-clock stays bounded if the
// lookup ever regresses.
//
// BATCH amortization: the small variants (10 / 100) today have lookups
// in the tens-to-hundreds of ns range -- comparable to the clock_gettime
// call pair. Inner BATCH_SIZE=256 (mirrors micro/varint + micro/pacing)
// amortizes timer overhead so latency samples reflect the lookup rather
// than the timing harness. For 1K / 10K the lookup is already well
// above clock resolution, but we keep BATCH_SIZE uniform across
// variants for shape consistency -- the only difference is that
// latencies_ns[i] holds (batch_wall_ns / BATCH_SIZE), which matches
// the per-op semantics of the tighter variants.
//
// Cross-platform note: like conn_scale.zig and udp_batch.zig, this bench
// requires a real UDP transport to construct the endpoint. On non-Linux
// targets we emit a placeholder RunOutput so `zig build bench --suite=all`
// remains cross-compilable.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

/// Inner batch size: each `latencies_ns[i]` entry averages this many
/// lookups, so timer overhead (clock_gettime pair) is amortized below
/// single-digit ns per measured op even in the 10-conn variant.
const BATCH_SIZE: u64 = 256;

/// Fixed DCID length matches what endpoint/client.zig:145 assigns to
/// every client-created connection (`c.our_scid.len = 8`). Kept as a
/// compile-time constant so the synthetic short-header packet buffer
/// is trivially stack-sized.
const DCID_LEN: usize = 8;

/// One row per populated connection, capturing the key material the
/// lookup path reads: peer address (for Phase 1 peer_hash match) and
/// our_scid bytes (the DCID inbound packets would carry).
const LookupKey = struct {
    peer: conn_mod.SockAddr,
    dcid: [DCID_LEN]u8,
};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) {
        // Non-Linux placeholder: keeps the full-suite build cross-
        // compilable. Real measurement only runs on Linux where the
        // endpoint's UDP transport is supported.
        const latencies = try allocator.alloc(u64, 1);
        latencies[0] = 0;
        return .{
            .iterations = 1,
            .wall_time_ns = 1_000_000,
            .cpu_time_ns = 0,
            .latencies_ns = latencies,
        };
    }

    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };

    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const n: u64 = spec.connection_count;

    // Parallel array of lookup keys, one per successfully-populated
    // connection. Using ArrayList so we only record entries for
    // connectClient calls that actually succeeded -- at 10K ports the
    // odds of a resolveAny failure are effectively zero, but we keep
    // the defensive skip (matches conn_scale.zig) and size the active
    // key set by what we actually populated.
    var keys: std.ArrayList(LookupKey) = .empty;
    defer keys.deinit(allocator);
    try keys.ensureTotalCapacity(allocator, n);

    var c: u64 = 0;
    while (c < n) : (c += 1) {
        const port: u16 = @intCast((c % 55000) + 10000);
        var addr_buf: [32]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch continue;
        const conn = ep.connectClient(addr) catch continue;

        // Snapshot peer + our_scid so the lookup loop has stable key
        // material even if the connection's own state later mutates
        // (it won't under this bench, but the snapshot keeps the hot
        // path free of pointer indirection through the connection
        // object).
        var k: LookupKey = .{ .peer = conn.peer, .dcid = undefined };
        const scid_len = conn.our_scid.len;
        // Client connections always generate 8-byte SCIDs; guard against
        // a future config change so the bench fails loudly rather than
        // silently producing junk lookups.
        if (scid_len != DCID_LEN) return error.UnexpectedScidLen;
        @memcpy(k.dcid[0..DCID_LEN], conn.our_scid.bytes[0..DCID_LEN]);
        try keys.append(allocator, k);
    }

    if (keys.items.len == 0) return error.NoConnectionsPopulated;
    const active: u32 = @intCast(keys.items.len);

    // Per-sample latency buffer: each sample averages BATCH_SIZE lookups.
    const N_samples: u64 = spec.iterations;
    const latencies = try allocator.alloc(u64, N_samples);

    // Deterministic-enough RNG: seed from nowNs so sweeps across runs
    // don't replay the same index sequence, but within a single run the
    // sequence is reproducible for the warmup -> measure transition.
    var rng = std.Random.DefaultPrng.init(common.nowNs());
    const random = rng.random();

    // Short-header packet buffer: [0x40, dcid[0..8]]. 0x40 sets the
    // fixed bit (bit 6) with form bit 7 clear -> short header form
    // (RFC 9000 §17.3). DCID occupies bytes [1..9].
    var pkt_buf: [1 + DCID_LEN]u8 = undefined;
    pkt_buf[0] = 0x40;

    // Warmup: primes the icache, branch predictor, and TLB for the
    // hashmap iterator + peer/DCID comparison loop.
    var w: u64 = 0;
    while (w < spec.warmup_iterations) : (w += 1) {
        const idx = random.uintLessThan(u32, active);
        const key = keys.items[idx];
        @memcpy(pkt_buf[1..], &key.dcid);
        const found = ep.findConnectionByDcid(key.peer, &pkt_buf);
        std.mem.doNotOptimizeAway(found);
    }

    // Measured loop: per sample, time a batch of BATCH_SIZE lookups and
    // record the batch-averaged latency.
    const wall_start = common.nowNs();
    var sink: usize = 0;
    for (0..N_samples) |i| {
        const t0 = common.nowNs();
        var b: u64 = 0;
        while (b < BATCH_SIZE) : (b += 1) {
            const idx = random.uintLessThan(u32, active);
            const key = keys.items[idx];
            @memcpy(pkt_buf[1..], &key.dcid);
            const found = ep.findConnectionByDcid(key.peer, &pkt_buf);
            // Accumulate a side-effect so the optimizer can't hoist the
            // call out of the loop. Using @intFromPtr keeps this a cheap
            // ALU op; the null-case sentinel (1) is never a valid pointer,
            // so checksum aliasing is harmless for our purposes.
            sink +%= if (found) |f| @intFromPtr(f) else 1;
        }
        const dt = common.nowNs() - t0;
        latencies[i] = dt / BATCH_SIZE;
    }
    const wall_end = common.nowNs();
    std.mem.doNotOptimizeAway(sink);

    return .{
        .iterations = N_samples * BATCH_SIZE,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

// Sweep: 10 / 100 / 1000 / 10000 / 20000 active connections. Iteration counts
// step down at higher N so a lookup regression still fits in bounded wall-clock.
// Warmup is ~10% of iterations in each tier.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/connection_lookup", .variant = "10", .iterations = 10_000, .warmup_iterations = 1_000, .connection_count = 10 },
    .{ .name = "micro/connection_lookup", .variant = "100", .iterations = 10_000, .warmup_iterations = 1_000, .connection_count = 100 },
    .{ .name = "micro/connection_lookup", .variant = "1000", .iterations = 2_000, .warmup_iterations = 200, .connection_count = 1_000 },
    .{ .name = "micro/connection_lookup", .variant = "10000", .iterations = 500, .warmup_iterations = 50, .connection_count = 10_000 },
    .{ .name = "micro/connection_lookup", .variant = "20000", .iterations = 200, .warmup_iterations = 20, .connection_count = 20_000 },
};
