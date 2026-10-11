// benchmarks/micro/varint.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: QUIC varint encode.
//
// Measurement logic is extracted from bench/main.zig's varint section. The
// real `varint.encode` signature in src/quic/varint.zig is
// `encode(value: u64, out: []u8) Error!usize` -- the plan template had the
// parameters swapped (`encode(buf, v)`); this file uses the real order.
//
// Because the primitive runs in well under 100 ns, per-iteration
// `clock_gettime` sampling would be pure noise (the syscall dominates).
// The harness instead times BATCHes of BATCH_SIZE inner ops and retains
// each raw batch duration with its operation count. Percentile comparisons
// preserve the fractional ns-per-op instead of truncating each sample.
// `spec.iterations` is the outer sample count.
//
// Absolute gate (docs/PERFORMANCE_TARGETS.md, benchmarks/compare.zig):
//   micro/varint encode -> latency_p99_ns <= 250

const std = @import("std");
const common = @import("bench_common");
const varint = @import("quic_varint");

const BATCH_SIZE: u64 = 1_000;

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    // Sweep representative values from bench/main.zig (16383) plus
    // neighbouring encoding-length boundaries so every varint width (1/2/4/8
    // bytes) is exercised and the JIT-style branch predictor can't fixate on
    // one path.
    const inputs = [_]u64{
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        4_611_686_018_427_387_903,
    };

    var out_buf: [9]u8 = undefined;
    var sink: usize = 0;

    var warm_idx: usize = 0;
    while (warm_idx < spec.warmup_iterations) : (warm_idx += 1) {
        const v = inputs[warm_idx % inputs.len];
        sink +%= varint.encode(v, &out_buf) catch 0;
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        var k: u64 = 0;
        while (k < BATCH_SIZE) : (k += 1) {
            const v = inputs[(i +% @as(usize, @intCast(k))) % inputs.len];
            sink +%= varint.encode(v, &out_buf) catch 0;
        }
        const dt = common.nowNs() - t0;
        latencies[i] = dt;
    }
    const wall_end = common.nowNs();
    std.mem.doNotOptimizeAway(sink);

    return .{
        .iterations = N * BATCH_SIZE,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .latency_sample_operations = BATCH_SIZE,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/varint", .variant = "encode", .iterations = 200, .warmup_iterations = 1_000 },
};
