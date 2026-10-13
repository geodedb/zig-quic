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

// ---------------------------------------------------------------------------
// Noise tolerance: absolute floor + reproduction across rounds.
// ---------------------------------------------------------------------------

fn microRow(scenario: []const u8, variant: []const u8, ops: f64, p95: u64) @import("bench_common").ResultRow {
    return .{
        .git_sha = "x",
        .run_timestamp_unix_s = 0,
        .zig_version = "0.16.0",
        .os = "linux",
        .arch = "x86_64",
        .cpu = "x86_64",
        .hostname = "h",
        .kernel = "k",
        .scenario_name = scenario,
        .variant = variant,
        .iterations = 1000,
        .throughput_ops_per_sec = ops,
        .latency_p50_ns = p95,
        .latency_p95_ns = p95,
        .latency_p99_ns = p95,
        .cpu_time_ns = 0,
        .wall_time_ns = 1_000_000,
    };
}

test "floor: a 1 ns quantisation step on a 9 ns row is NOISE, not FAIL" {
    // Job 17111970401 round 2: goaway p95 9 -> 10 ns (+11%), throughput
    // 84.4M -> 71.6M ops/s (-15.1%, i.e. +2.1 ns per op).
    const e = compare.evaluateRow(
        microRow("micro/frame_serialization", "goaway", 84_383_735.0, 9),
        microRow("micro/frame_serialization", "goaway", 71_614_701.7, 10),
    );
    try std.testing.expectEqual(compare.Level.pass, e.level);
    try std.testing.expect(e.noise);
    try std.testing.expectEqualStrings("NOISE", e.status());
}

test "floor: a real regression on a tiny row still FAILs once it clears the floor" {
    // 9 -> 13 ns p95 (+44%, +4 ns) and 11.1 -> 15.4 ns per op.
    const e = compare.evaluateRow(
        microRow("micro/frame_serialization", "goaway", 90_000_000.0, 9),
        microRow("micro/frame_serialization", "goaway", 65_000_000.0, 13),
    );
    try std.testing.expectEqual(compare.Level.fail, e.level);
    try std.testing.expectEqualStrings("FAIL", e.status());
}

test "floor: keeps the 10 percent p95 threshold for meaningful values" {
    // 1000 -> 1110 ns: +11%, +110 ns -> FAIL. 1000 -> 1090: +9% -> WARN.
    const fail = compare.evaluateRow(
        microRow("micro/aead", "aes128_gcm", 1_000_000.0, 1000),
        microRow("micro/aead", "aes128_gcm", 1_000_000.0, 1110),
    );
    try std.testing.expectEqual(compare.Level.fail, fail.level);
    const warn = compare.evaluateRow(
        microRow("micro/aead", "aes128_gcm", 1_000_000.0, 1000),
        microRow("micro/aead", "aes128_gcm", 1_000_000.0, 1090),
    );
    try std.testing.expectEqual(compare.Level.warn, warn.level);
}

test "floor: integration tier keeps a zero floor" {
    try std.testing.expectEqual(@as(u64, 0), compare.thresholds(.integration).latency_floor_ns);
    try std.testing.expectEqual(@as(u64, 3), compare.thresholds(.micro).latency_floor_ns);
}

test "reproduced: majority FAIL and no clean round" {
    const L = compare.Level;
    try std.testing.expect(compare.reproduced(&.{L.fail}));
    try std.testing.expect(!compare.reproduced(&.{L.warn}));
    try std.testing.expect(compare.reproduced(&.{ L.fail, L.fail, L.fail }));
    try std.testing.expect(compare.reproduced(&.{ L.fail, L.warn, L.fail }));
    // One clean round means the regression did not reproduce.
    try std.testing.expect(!compare.reproduced(&.{ L.fail, L.pass, L.fail }));
    // FAIL in only one of three rounds is not a majority.
    try std.testing.expect(!compare.reproduced(&.{ L.fail, L.warn, L.warn }));
    // Two rounds: both must FAIL.
    try std.testing.expect(!compare.reproduced(&.{ L.fail, L.warn }));
    try std.testing.expect(compare.reproduced(&.{ L.fail, L.fail }));
}

const FixtureRow = struct {
    job: []const u8,
    round: usize,
    scenario: []const u8,
    variant: []const u8,
    ops_base: f64,
    ops_cur: f64,
    p95_base: u64,
    p95_cur: u64,
};

fn loadNoiseFixture(allocator: std.mem.Allocator) ![]FixtureRow {
    const text = @embedFile("fixtures/perf_gate_ci_noise.tsv");
    var rows: std.ArrayList(FixtureRow) = .empty;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        try rows.append(allocator, .{
            .job = f.next().?,
            .round = try std.fmt.parseInt(usize, f.next().?, 10),
            .scenario = f.next().?,
            .variant = f.next().?,
            .ops_base = try std.fmt.parseFloat(f64, f.next().?),
            .ops_cur = try std.fmt.parseFloat(f64, f.next().?),
            .p95_base = try std.fmt.parseInt(u64, f.next().?, 10),
            .p95_cur = try std.fmt.parseInt(u64, f.next().?, 10),
        });
    }
    return rows.toOwnedSlice(allocator);
}

/// Replays one CI job's rounds through evaluateRow + aggregate. When
/// `inject` is set, the current side of that scenario/variant gets a
/// regression of `factor` (p95 x factor, throughput / factor) in EVERY
/// round, on top of the recorded runner noise. Returns the number of rows
/// whose aggregate verdict fails, and whether the injected row failed.
fn replayJob(
    allocator: std.mem.Allocator,
    rows: []const FixtureRow,
    job: []const u8,
    inject: ?struct { scenario: []const u8, variant: []const u8, factor: f64 },
) !struct { failed_rows: usize, injected_failed: bool, rows: usize } {
    var by_row: std.StringArrayHashMapUnmanaged(std.ArrayList(compare.RowEval)) = .empty;
    for (rows) |r| {
        if (!std.mem.eql(u8, r.job, job)) continue;
        var ops_cur = r.ops_cur;
        var p95_cur = r.p95_cur;
        if (inject) |inj| {
            if (std.mem.eql(u8, inj.scenario, r.scenario) and std.mem.eql(u8, inj.variant, r.variant)) {
                ops_cur /= inj.factor;
                p95_cur = @intFromFloat(@round(@as(f64, @floatFromInt(p95_cur)) * inj.factor));
            }
        }
        const e = compare.evaluateRow(
            microRow(r.scenario, r.variant, r.ops_base, r.p95_base),
            microRow(r.scenario, r.variant, ops_cur, p95_cur),
        );
        const key = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ r.scenario, r.variant });
        const gop = try by_row.getOrPut(allocator, key);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(allocator, e);
    }
    var failed: usize = 0;
    var injected_failed = false;
    for (by_row.keys(), by_row.values()) |key, evals| {
        try std.testing.expectEqual(@as(usize, 3), evals.items.len);
        const v = compare.aggregate(evals.items);
        if (!v.failed()) continue;
        failed += 1;
        if (inject) |inj| {
            const want = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ inj.scenario, inj.variant });
            if (std.mem.eql(u8, want, key)) injected_failed = true;
        }
    }
    return .{ .failed_rows = failed, .injected_failed = injected_failed, .rows = by_row.count() };
}

const noise_jobs = [_][]const u8{ "17111970401", "17111063471", "17100113155" };

test "self-test: recorded CI runner noise passes the gate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = try loadNoiseFixture(a);
    for (noise_jobs) |job| {
        // Under the old rule (any round FAILs -> gate fails) each of these
        // jobs failed: 19, 11 and 11 FAIL rows across its rounds.
        var old_fails: usize = 0;
        for (rows) |r| {
            if (!std.mem.eql(u8, r.job, job)) continue;
            const pd = compare.pctChange(@floatFromInt(r.p95_base), @floatFromInt(r.p95_cur));
            const td = compare.pctChange(r.ops_base, r.ops_cur);
            if (pd > 10.0 or td < -15.0) old_fails += 1;
        }
        try std.testing.expect(old_fails > 0);

        const res = try replayJob(a, rows, job, null);
        try std.testing.expectEqual(@as(usize, 35), res.rows);
        try std.testing.expectEqual(@as(usize, 0), res.failed_rows);
    }
}

test "self-test: an injected real regression still fails on top of CI noise" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = try loadNoiseFixture(a);
    // Representative rows from every micro family that the noisy runs
    // flagged at least once; a +25% regression in every round must
    // reproduce in each recorded job.
    const targets = [_][2][]const u8{
        .{ "micro/connection_lookup", "10000" },
        .{ "micro/connection_lookup", "100" },
        .{ "micro/loss_detection_scan", "1000" },
        .{ "micro/send_buffer_alloc", "stream_only" },
        .{ "micro/frame_serialization", "stop_sending" },
        .{ "micro/aead", "chacha20_poly1305" },
    };
    for (noise_jobs) |job| {
        for (targets) |t| {
            const res = try replayJob(a, rows, job, .{ .scenario = t[0], .variant = t[1], .factor = 1.25 });
            if (!res.injected_failed) {
                std.debug.print("injected +25% on {s}/{s} not detected in job {s}\n", .{ t[0], t[1], job });
            }
            try std.testing.expect(res.injected_failed);
            try std.testing.expectEqual(@as(usize, 1), res.failed_rows);
        }
    }
}

test "self-test: a +50% regression is detected on most rows above the floor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = try loadNoiseFixture(a);
    var detected: usize = 0;
    var total: usize = 0;
    for (noise_jobs) |job| {
        for (rows) |r| {
            if (!std.mem.eql(u8, r.job, job) or r.round != 1) continue;
            // Rows whose op costs <= 3 ns are guarded by the absolute
            // gates (varint/pacing p99), not by the relative gate.
            if (r.p95_base <= 3) continue;
            total += 1;
            const res = try replayJob(a, rows, job, .{ .scenario = r.scenario, .variant = r.variant, .factor = 1.5 });
            if (res.injected_failed) detected += 1;
        }
    }
    // 98 of 99 at the time of writing: on the one miss, runner noise in a
    // single round outweighed the injected regression.
    if (detected * 100 < total * 85) {
        std.debug.print("+50% injected regression detected on only {d}/{d} rows\n", .{ detected, total });
        return error.TestUnexpectedResult;
    }
}
