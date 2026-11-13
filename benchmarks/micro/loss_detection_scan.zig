// benchmarks/micro/loss_detection_scan.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: ACK-processing cost (sent_packets scan) as a function of
// sent_packets array length.
//
// Motivation (issue #90): `Recovery.onAckReceived` currently performs a full
// linear scan over `sent_packets` on every ACK -- once to count unprocessed
// entries (line ~290), once to either mark+classify (sequential or parallel
// path), and once more via `compact()` after processing. Marking acked
// packets is O(K log N) by binary search over the pn-sorted list
// (SONNY-6434 removed the `sent_index` hash), and for packets recorded in
// send order loss detection walks only the lost prefix; out-of-order
// recording falls back to the O(N) passes, N being the current
// `sent_packets` length. That cost is invisible when the list is
// small (today's hard-cap is 4096) but dominates when the cap is raised
// or removed in favor of a bounded-but-larger data structure.
//
// This bench captures the baseline O(N) scaling signature so the
// post-#90-fix comparator (O(log N) or O(1)-amortized ring) can be
// detected: today p99 should scale ~10x per 10x N; post-fix it should
// flatten. Four variants sweep N in {100, 1_000, 10_000, 100_000}.
//
// Methodology:
//   1. Construct a Recovery instance with the bench allocator.
//   2. Pre-populate `spaces[Application].sent` with N
//      deterministic entries (sequential PNs 0..N, uniform 1200-byte
//      payload, all ack_eliciting). We bypass the public `onPacketSent`
//      for two reasons:
//        a. It enforces `max_sent_packets = 4096` via compact+drop on
//           overflow; the N=10K / 100K variants would be silently truncated
//           to 4096, defeating the whole point of the sweep.
//        b. It also updates `bytes_in_flight` and schedules loss_time
//           deadlines we don't need for the scan-cost measurement.
//      Direct field access matches the pattern in
//      tests/unit/recovery/test_recovery.zig which reads
//      `rec.spaces[idx].sent.items` freely -- `spaces` on the public
//      `Recovery` struct is reachable through field access without
//      exposing SpaceState as pub.
//   3. Seed `largest_acked = null` and `rtt.have_sample = false` so the
//      first ACK drives the sequential-or-parallel branch purely on
//      `unprocessed_count >= 64`. For N=100 we take the sequential path;
//      N>=1000 takes the parallel path (bounded by par_infos[4096]).
//   4. Build an ACK list covering the middle N/2 range: PNs
//      [N/4 .. 3*N/4). This leaves N/4 head + N/4 tail as unacked so the
//      post-ACK scan still has plenty of entries to traverse.
//   5. Between iterations, reset the Application space and re-populate it
//      -- `onAckReceivedWithEcn` consumes entries (marks them acked,
//      then compaction drops them), so repeating would
//      hit an empty list after iter 1. Repopulation cost is NOT timed;
//      only the `onAckReceivedWithEcn` call is timed per iteration.
//
// Iteration scaling (inverse with N to keep wall-clock bounded):
//   N=100    -> 10_000 iters (fast path, sub-us each)
//   N=1000   -> 5_000 iters  (parallel path starts, us-scale)
//   N=10000  -> 1_000 iters  (us-scale, ~5s wall)
//   N=100000 -> 100 iters    (ms-scale, ~10-50s wall; repop dominates)
//
// BATCH note: unlike pacing (sub-ns per op) and connection_lookup (10s of ns
// per op), even the smallest variant here (N=100) has an onAckReceivedWithEcn
// cost well above the clock_gettime pair. No inner batching is used; each
// iteration records a single measurement.
//
// spec.connection_count repurposed: the sweep N is stored in
// `spec.connection_count` -- it's the only u32 field on ScenarioSpec that
// naturally fits. The row's `connection_count` metadata column in the
// emitted JSON will therefore carry N, not a literal connection count --
// matching the per-scenario contract documented here rather than the
// generic bench_common interpretation.

const std = @import("std");
const common = @import("bench_common");
const rec = @import("quic_recovery");

/// Uniform per-packet size in bytes. Matches the default max_datagram_size
/// (1200) used by NewReno/CUBIC initial cwnd. The exact value does not
/// affect scan cost, only bytes_acked/bytes_lost accounting we don't assert
/// on.
const PKT_SIZE: usize = 1200;

/// Reset the Application space to empty state and populate it with `n`
/// sequential ack-eliciting sent packets (PN 0..n). Does NOT allocate the
/// ACK slice -- callers own that separately so it can be hoisted out of
/// the measured loop.
fn repopulateApplicationSpace(recovery: *rec.Recovery, n: u64) !void {
    const idx: usize = @intFromEnum(rec.PacketNumberSpace.Application);
    const space = &recovery.spaces[idx];

    space.sent.clearRetainingCapacity();
    space.largest_acked = null;
    space.loss_time_ns = null;

    // ensureTotalCapacity before the loop so the N appends+puts don't
    // trigger reallocation mid-iteration (which would add variance to
    // the timed portion via allocator back-pressure even though the
    // repop itself is untimed).
    try space.sent.ensureTotalCapacity(space.allocator, n);

    var i: u64 = 0;
    while (i < n) : (i += 1) {
        // time_ns is monotonic (set to i). With rtt.have_sample = false,
        // the time-threshold loop at the end of onAckReceivedWithEcn
        // short-circuits via `have_rtt` guard, so time_ns values don't
        // affect earliest_loss_time arithmetic.
        try space.sent.append(space.allocator, .{
            .pn = i,
            .time_ns = i,
            .size = PKT_SIZE,
            .ack_eliciting = true,
        });
    }
}

/// Allocate the mid-range ACK slice: PNs [N/4 .. 3*N/4). Caller frees.
fn buildMidRangeAck(allocator: std.mem.Allocator, n: u64) ![]u64 {
    const ack_start: u64 = n / 4;
    const ack_end: u64 = (n * 3) / 4;
    const ack_len: usize = @intCast(ack_end - ack_start);
    const acked = try allocator.alloc(u64, ack_len);
    for (acked, 0..) |*slot, k| slot.* = ack_start + @as(u64, @intCast(k));
    return acked;
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const n: u64 = spec.connection_count;
    const N_samples: u64 = spec.iterations;
    const latencies = try allocator.alloc(u64, N_samples);

    var recovery = rec.Recovery.init(allocator);
    defer recovery.deinit();

    // Disable RTT sample so the time-threshold loss detection pass at the
    // end of onAckReceivedWithEcn short-circuits (earliest_loss_time stays
    // null, no deadline arithmetic per-packet). The scan cost we want to
    // measure -- unprocessed_count count-up + mark/cleanup -- still runs.
    recovery.rtt.have_sample = false;

    // ACK slice: allocated once, reused across all iterations. Sized by
    // N/2 (mid-range coverage). Deterministic content so we don't pay
    // repeated allocs in the loop.
    const acked = try buildMidRangeAck(allocator, n);
    defer allocator.free(acked);

    // Warmup: primes caches, branch predictors, and the HashMap's bucket
    // layout. Each warmup iteration fully resets+repopulates so the
    // measured loop starts from a fresh, cache-warm state.
    var w: u64 = 0;
    while (w < spec.warmup_iterations) : (w += 1) {
        try repopulateApplicationSpace(&recovery, n);
        const now_ns = common.nowNs();
        _ = recovery.onAckReceivedWithEcn(.Application, acked, 0, now_ns, null);
    }

    // Measured loop: per iteration, reset+repopulate (not timed), then time
    // a single onAckReceivedWithEcn call.
    const wall_start = common.nowNs();
    var sink: usize = 0;
    for (0..N_samples) |i| {
        try repopulateApplicationSpace(&recovery, n);

        const now_ns = common.nowNs();
        const t0 = common.nowNs();
        const result = recovery.onAckReceivedWithEcn(.Application, acked, 0, now_ns, null);
        const dt = common.nowNs() - t0;
        latencies[i] = dt;

        // Side-effect accumulator: keep the AckResult live so LLVM can't
        // dead-code the call.
        sink +%= result.bytes_acked +% result.bytes_lost +% @as(usize, @intCast(i));
    }
    const wall_end = common.nowNs();
    std.mem.doNotOptimizeAway(sink);

    return .{
        .iterations = N_samples,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

// Four-variant sweep: 100 / 1K / 10K / 100K sent_packets. Iteration counts
// decrease with N so total wall time (bench harness is median-of-6 across
// 7 runs per variant) stays bounded even at N=100K where each iter is
// millisecond-scale.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/loss_detection_scan", .variant = "100", .iterations = 10_000, .warmup_iterations = 500, .connection_count = 100 },
    .{ .name = "micro/loss_detection_scan", .variant = "1000", .iterations = 5_000, .warmup_iterations = 200, .connection_count = 1_000 },
    .{ .name = "micro/loss_detection_scan", .variant = "10000", .iterations = 1_000, .warmup_iterations = 50, .connection_count = 10_000 },
    .{ .name = "micro/loss_detection_scan", .variant = "100000", .iterations = 100, .warmup_iterations = 10, .connection_count = 100_000 },
};
