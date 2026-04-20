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
