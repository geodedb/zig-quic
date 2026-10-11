// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the tier-aware bench comparator helpers.
// Imported via the `bench_compare` module wired in build.zig (the direct
// cross-module import `@import("../benchmarks/compare.zig")` is rejected by
// Zig 0.16's module system).

const std = @import("std");
const compare = @import("bench_compare");
const common = @import("bench_common");

fn latencyRow(raw_ns: u64, operations: ?u32) common.ResultRow {
    const whole_ns = raw_ns / (operations orelse 1);
    return .{
        .git_sha = "synthetic-unit-fixture",
        .run_timestamp_unix_s = 0,
        .zig_version = "0.16.0",
        .os = "linux",
        .arch = "x86_64",
        .cpu = "x86_64",
        .hostname = "unit-test",
        .kernel = "unit-test",
        .scenario_name = "micro/varint",
        .variant = "encode",
        .iterations = 1000,
        .throughput_ops_per_sec = 1e7,
        .latency_p50_ns = whole_ns,
        .latency_p95_ns = whole_ns,
        .latency_p99_ns = whole_ns,
        .latency_batch = if (operations) |n| .{ .operations = n, .p50_ns = raw_ns, .p95_ns = raw_ns, .p99_ns = raw_ns } else null,
        .cpu_time_ns = 100000,
        .wall_time_ns = 100000,
    };
}

test "SONNY-4798 integer boundary does not inflate fractional latency changes" {
    const delta = try compare.latencyChangePercent(latencyRow(2999, 1000), latencyRow(3000, 1000));
    try std.testing.expectApproxEqAbs(@as(f64, 100.0 / 2999.0), delta, 1e-9);
    try std.testing.expect(delta < 10);
    try std.testing.expectApproxEqAbs(@as(f64, 2.999), compare.latencyP95Ns(latencyRow(2999, 1000)), 1e-9);
}

test "SONNY-4798 subnanosecond and ordinary regressions exceed the unchanged limit" {
    const delta = try compare.latencyChangePercent(latencyRow(700, 1000), latencyRow(900, 1000));
    try std.testing.expectApproxEqAbs(@as(f64, 200.0 / 700.0 * 100.0), delta, 1e-9);
    try std.testing.expect(delta > 10);
    try std.testing.expect((try compare.latencyChangePercent(latencyRow(3000, 1000), latencyRow(3400, 1000))) > 10);
}

test "SONNY-4798 fractional absolute breaches and multiplication overflow fail safely" {
    try std.testing.expect(!(try compare.latencyP99Exceeds(latencyRow(250000, 1000), 250)));
    try std.testing.expect(try compare.latencyP99Exceeds(latencyRow(250001, 1000), 250));
    try std.testing.expect(!(try compare.latencyP99Exceeds(latencyRow(std.math.maxInt(u64), std.math.maxInt(u32)), std.math.maxInt(u64))));
}

test "SONNY-4798 mismatched or partial precision cannot silently fall back" {
    const batch = latencyRow(3000, 1000);
    const legacy = latencyRow(3, null);
    try std.testing.expectError(error.IncompatibleLatencySamples, compare.latencyChangePercent(batch, legacy));
    try std.testing.expectError(error.IncompatibleLatencySamples, compare.latencyChangePercent(legacy, batch));
    try std.testing.expectError(error.IncompatibleLatencySamples, compare.latencyChangePercent(batch, latencyRow(3000, 256)));
    var invalid = batch;
    invalid.latency_batch.?.operations = 0;
    try std.testing.expectError(error.InvalidLatencyBatch, compare.latencyChangePercent(batch, invalid));
    invalid = batch;
    invalid.latency_p95_ns = 2;
    try std.testing.expectError(error.InvalidLatencyBatch, compare.latencyChangePercent(batch, invalid));
    invalid = batch;
    invalid.latency_batch.?.p95_ns = 2999;
    try std.testing.expectError(error.InvalidLatencyBatch, compare.latencyP99Exceeds(invalid, 250));
}

test "SONNY-4798 legacy comparisons work and positive latency cannot hide behind zero" {
    try std.testing.expectApproxEqAbs(@as(f64, 20), try compare.latencyChangePercent(latencyRow(100, null), latencyRow(120, null)), 1e-9);
    try std.testing.expectEqual(@as(f64, 0), try compare.latencyChangePercent(latencyRow(0, null), latencyRow(0, null)));
    try std.testing.expectEqual(std.math.inf(f64), try compare.latencyChangePercent(latencyRow(0, null), latencyRow(1, null)));
}

fn checkComparatorCli(base: common.ResultRow, cur: common.ResultRow, expected: u8, marker: []const u8) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    var paths: [2][]const u8 = undefined;
    var completed: usize = 0;
    defer for (paths[0..completed]) |path| allocator.free(path);
    for ([_]common.ResultRow{ base, cur }, [_][]const u8{ "base.json", "current.json" }, 0..) |row, name, index| {
        var rows = [_]common.ResultRow{row};
        const document = common.ResultDocument{
            .generated_at_unix_s = 0,
            .zig_version = "0.16.0",
            .quic_git_sha = "synthetic-comparator-unit-fixture",
            .host = .{ .os = "linux", .arch = "x86_64", .cpu = "x86_64", .hostname = "unit-test", .kernel = "unit-test" },
            .rows = &rows,
        };
        const json = try std.json.Stringify.valueAlloc(allocator, document, .{});
        defer allocator.free(json);
        try temporary.dir.writeFile(io, .{ .sub_path = name, .data = json });
        paths[index] = try std.fs.path.join(allocator, &.{ directory, name });
        completed += 1;
    }
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ @import("bench_compare_options").binary, "--baseline", paths[0], "--current", paths[1] },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    const exit_code = switch (result.term) {
        .exited => |code| code,
        else => return error.ComparatorDidNotExitNormally,
    };
    if (exit_code != expected) std.debug.print("comparator stdout:\n{s}\nstderr:\n{s}\n", .{ result.stdout, result.stderr });
    try std.testing.expectEqual(expected, exit_code);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, marker) != null);
}

test "SONNY-4798 actual comparator preserves precision and existing failure gates" {
    try checkComparatorCli(latencyRow(2999, 1000), latencyRow(3000, 1000), 0, "+0.03%");
    try checkComparatorCli(latencyRow(700, 1000), latencyRow(900, 1000), 1, "+28.57%");
    try checkComparatorCli(latencyRow(3000, 1000), latencyRow(3400, 1000), 1, "FAIL");
    try checkComparatorCli(latencyRow(250000, 1000), latencyRow(250001, 1000), 1, "ABSOLUTE-FAIL");
    try checkComparatorCli(latencyRow(100, null), latencyRow(105, null), 0, "+5.00%");
    try checkComparatorCli(latencyRow(0, null), latencyRow(1, null), 1, "FAIL");
    try checkComparatorCli(latencyRow(3, null), latencyRow(3000, 1000), 1, "INVALID-LATENCY");
    var invalid = latencyRow(3000, 1000);
    invalid.latency_batch.?.operations = 0;
    try checkComparatorCli(latencyRow(3000, 1000), invalid, 1, "INVALID-LATENCY");
}

test "SONNY-4798 legacy JSON defaults to unbatched and incomplete precision fails parsing" {
    const allocator = std.testing.allocator;
    const json = try std.json.Stringify.valueAlloc(allocator, latencyRow(3, null), .{});
    defer allocator.free(json);
    const legacy = try std.mem.replaceOwned(u8, allocator, json, "\"latency_batch\":null,", "");
    defer allocator.free(legacy);
    const decoded = try std.json.parseFromSlice(common.ResultRow, allocator, legacy, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(?common.LatencyBatch, null), decoded.value.latency_batch);
    const partial = try std.mem.replaceOwned(u8, allocator, json, "\"latency_batch\":null", "\"latency_batch\":{\"operations\":1000}");
    defer allocator.free(partial);
    try std.testing.expectError(error.MissingField, std.json.parseFromSlice(common.ResultRow, allocator, partial, .{}));
}

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
