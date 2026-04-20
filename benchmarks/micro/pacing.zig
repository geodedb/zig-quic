// benchmarks/micro/pacing.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: QUIC pacing delay computation.
//
// Measurement logic is extracted from bench/main.zig's pacing section. The
// real `computePacingDelayNs` signature in src/quic/recovery/congestion.zig
// is `(cwnd, bytes_in_flight, smoothed_rtt_ns, packet_size) u64` -- 4 args,
// not the 3 the plan template guessed. Inputs mirror bench/main.zig: 100us
// representative RTT, cwnd=12000, mds=1200, sweeping bytes_in_flight across
// 0..1.5*cwnd in a stable pattern so the branch predictor sees every case
// (slow-start exemption, RFC 9002 §7.7 paced path).
//
// The primitive is a couple of branches + divide -- far below clock_gettime
// resolution, so the harness times BATCHes of BATCH_SIZE calls per sample
// and records the amortised ns-per-op (matches legacy bench/main.zig).
//
// Absolute gate (docs/PERFORMANCE_TARGETS.md, benchmarks/compare.zig):
//   micro/pacing delay_compute -> latency_p99_ns <= 400

const std = @import("std");
const common = @import("bench_common");
const rec = @import("quic_recovery");

const BATCH_SIZE: u64 = 1_000;

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const cwnd: usize = 12_000;
    const mds: usize = 1_200;
    const rtt_ns: u64 = 100_000; // 100us, matches bench/main.zig:134
    const sweep_modulus: usize = cwnd + cwnd / 2; // 0..1.5*cwnd

    var sink: u64 = 0;

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const bif = warm_i % sweep_modulus;
        sink +%= rec.computePacingDelayNs(cwnd, bif, rtt_ns, mds);
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        var k: u64 = 0;
        while (k < BATCH_SIZE) : (k += 1) {
            const bif = (i +% @as(usize, @intCast(k))) % sweep_modulus;
            sink +%= rec.computePacingDelayNs(cwnd, bif, rtt_ns, mds);
        }
        const dt = common.nowNs() - t0;
        latencies[i] = dt / BATCH_SIZE;
    }
    const wall_end = common.nowNs();
    std.mem.doNotOptimizeAway(sink);

    return .{
        .iterations = N * BATCH_SIZE,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/pacing", .variant = "delay_compute", .iterations = 200, .warmup_iterations = 1_000 },
};
