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
