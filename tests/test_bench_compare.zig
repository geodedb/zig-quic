// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the tier-aware bench comparator helpers.
// Imported via the `bench_compare` module wired in build.zig (the direct
// cross-module import `@import("../benchmarks/compare.zig")` is rejected by
// Zig 0.16's module system).

const std = @import("std");
const compare = @import("bench_compare");

test "classify: micro prefix" {
    try std.testing.expectEqual(@as(compare.Tier, .micro), compare.classify("micro/varint"));
}

test "classify: integration + external + unknown prefixes" {
    try std.testing.expectEqual(@as(compare.Tier, .integration), compare.classify("integration/handshake_e2e"));
    try std.testing.expectEqual(@as(compare.Tier, .external), compare.classify("external/quic-go/throughput"));
    try std.testing.expectEqual(@as(compare.Tier, .unknown), compare.classify("foo/bar"));
}

test "pctChange: positive improvement + regression" {
    // +10% improvement: (110 - 100) / 100 * 100 = +10
    try std.testing.expectApproxEqAbs(@as(f64, 10.0), compare.pctChange(100.0, 110.0), 1e-9);
    // -20% regression: (80 - 100) / 100 * 100 = -20
    try std.testing.expectApproxEqAbs(@as(f64, -20.0), compare.pctChange(100.0, 80.0), 1e-9);
}

test "pctChange: zero baseline returns 0 (divide-by-zero guard)" {
    try std.testing.expectEqual(@as(f64, 0.0), compare.pctChange(0.0, 1234.5));
}

test "computeWaitBoundPermille: null mutex_hold_wall_ns returns null" {
    // Benches that don't populate the field must not show up in wait-bound row.
    try std.testing.expectEqual(
        @as(?u64, null),
        compare.computeWaitBoundPermille(null, 1_000_000_000),
    );
}

test "computeWaitBoundPermille: zero wall_time guards against divide-by-zero" {
    try std.testing.expectEqual(
        @as(?u64, null),
        compare.computeWaitBoundPermille(@as(?u64, 500), 0),
    );
}

test "computeWaitBoundPermille: 25 percent wait-bound yields 250 permille" {
    // 25_000_000 ns hold / 100_000_000 ns wall = 0.25 -> 250 permille.
    try std.testing.expectEqual(
        @as(?u64, 250),
        compare.computeWaitBoundPermille(@as(?u64, 25_000_000), 100_000_000),
    );
}

test "computeWaitBoundPermille: avoids u64 overflow beyond ~18s mutex hold" {
    // hold = 20 s; naive u64 * 1000 would overflow. u128 path returns 1000
    // when hold == wall (100 percent wait-bound).
    const hold: u64 = 20 * std.time.ns_per_s;
    try std.testing.expectEqual(
        @as(?u64, 1000),
        compare.computeWaitBoundPermille(@as(?u64, hold), hold),
    );
}

test "isSkipRow: external_impl ending -SKIP detected" {
    const common_mod = @import("bench_common");
    const skip_row = common_mod.ResultRow{
        .git_sha = "x",
        .run_timestamp_unix_s = 0,
        .zig_version = "0.16.0",
        .os = "linux",
        .arch = "x86_64",
        .cpu = "x86_64",
        .hostname = "h",
        .kernel = "k",
        .scenario_name = "external/aioquic/handshake",
        .variant = "loopback",
        .iterations = 1,
        .throughput_ops_per_sec = 1000.0,
        .latency_p50_ns = 0,
        .latency_p95_ns = 0,
        .latency_p99_ns = 0,
        .cpu_time_ns = 0,
        .wall_time_ns = 1_000_000,
        .external_impl = "aioquic-SKIP",
    };
    try std.testing.expect(compare.isSkipRow(skip_row));
}

test "isSkipRow: normal external row is not a skip" {
    const common_mod = @import("bench_common");
    const real_row = common_mod.ResultRow{
        .git_sha = "x",
        .run_timestamp_unix_s = 0,
        .zig_version = "0.16.0",
        .os = "linux",
        .arch = "x86_64",
        .cpu = "x86_64",
        .hostname = "h",
        .kernel = "k",
        .scenario_name = "external/quic-go/handshake",
        .variant = "loopback",
        .iterations = 20,
        .throughput_ops_per_sec = 9.14,
        .latency_p50_ns = 100_000_000,
        .latency_p95_ns = 110_000_000,
        .latency_p99_ns = 111_000_000,
        .cpu_time_ns = 0,
        .wall_time_ns = 2_000_000_000,
        .external_impl = "quic-go",
    };
    try std.testing.expect(!compare.isSkipRow(real_row));
}

test "isSkipRow: null external_impl is not a skip" {
    const common_mod = @import("bench_common");
    const micro_row = common_mod.ResultRow{
        .git_sha = "x",
        .run_timestamp_unix_s = 0,
        .zig_version = "0.16.0",
        .os = "linux",
        .arch = "x86_64",
        .cpu = "x86_64",
        .hostname = "h",
        .kernel = "k",
        .scenario_name = "micro/varint",
        .variant = "encode",
        .iterations = 200_000,
        .throughput_ops_per_sec = 5_000_000.0,
        .latency_p50_ns = 100,
        .latency_p95_ns = 150,
        .latency_p99_ns = 200,
        .cpu_time_ns = 0,
        .wall_time_ns = 40_000_000,
    };
    try std.testing.expect(!compare.isSkipRow(micro_row));
}
