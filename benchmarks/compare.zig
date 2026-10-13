// benchmarks/compare.zig
// SPDX-License-Identifier: Apache-2.0
//
// Tier-aware regression comparator. Exits non-zero on any reproduced FAIL.
// Tiers: micro (name prefix "micro/"), integration ("integration/"),
// external ("external/").
//
// Noise handling (see docs/PERFORMANCE_TARGETS.md, "Noise tolerance"):
//
//   1. Relative threshold per tier (micro: throughput -15%, p95 +10%),
//      widened for throughput to 3x the baseline run-to-run stddev.
//   2. Absolute noise floor per tier (`latency_floor_ns`). A regression
//      must ALSO move the p95 latency, or the per-op time derived from
//      throughput (1e9 / ops_per_sec), by more than the floor. Micro
//      latencies are batch-averaged and truncated to whole nanoseconds,
//      so on 5-30 ns rows a +1 ns quantisation step alone is +3-20%.
//      Rows that breach the % threshold but stay inside the floor are
//      reported as NOISE and never gate.
//   3. Reproduction across rounds. Pass several --baseline/--current
//      pairs (scripts/perf-gate.sh does this for PERF_GATE_ROUNDS > 1,
//      alternating capture order between rounds). A row FAILs only when
//      a strict majority of rounds FAIL it AND no round clears it (every
//      round shows at least a WARN-level regression). ABSOLUTE-FAIL and
//      WAIT-BOUND-FAIL need a strict majority of rounds. With a single
//      pair the verdict is exactly that pair's verdict.

const std = @import("std");
const common = @import("bench_common");

pub const Tier = enum { micro, integration, external, unknown };

pub const TierThresholds = struct {
    throughput_pct: f64,
    latency_p95_pct: f64,
    alloc_bytes_pct: ?f64,
    // Max permissible rise in wait-bound fraction (permille = parts per 1000).
    // Applied only when both baseline and current rows populate
    // `mutex_hold_wall_ns` and have non-zero `wall_time_ns`. See
    // `computeWaitBoundPermille` + derived gate in evaluateRow().
    wait_bound_permille: u64,
    // Absolute noise floor in nanoseconds. A latency or throughput
    // regression only counts when p95 grew by MORE than this many ns, or
    // the per-op time (1e9 / throughput) grew by more than this many ns.
    // Micro: 3 ns = three quanta of the 1 ns batch-averaged sample
    // resolution. Shared CI runners move 5-30 ns rows by 1-2 ns between
    // back-to-back runs of the same binary (jobs 17111063471,
    // 17111970401: goaway 9->10 ns, stop_sending 15->17 ns). The other
    // tiers measure microseconds to milliseconds, where the %-threshold
    // already dominates, so their floor stays 0 (previous behaviour).
    latency_floor_ns: u64,
};

pub fn thresholds(t: Tier) TierThresholds {
    return switch (t) {
        .micro => .{ .throughput_pct = 15.0, .latency_p95_pct = 10.0, .alloc_bytes_pct = 0.0, .wait_bound_permille = 100, .latency_floor_ns = 3 },
        .integration => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = 30.0, .wait_bound_permille = 200, .latency_floor_ns = 0 },
        .external => .{ .throughput_pct = 25.0, .latency_p95_pct = 30.0, .alloc_bytes_pct = null, .wait_bound_permille = 300, .latency_floor_ns = 0 },
        .unknown => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = null, .wait_bound_permille = 200, .latency_floor_ns = 0 },
    };
}

/// Derive wait-bound fraction in permille (parts per 1000).
/// Returns null if `mutex_hold_wall_ns` is null or `wall_time_ns` is zero.
/// Uses a u128 intermediate so the multiplication `hold * 1000` cannot
/// overflow (u64 * 1000 would saturate at ~18.4 s of mutex-hold time).
pub fn computeWaitBoundPermille(mutex_hold_wall_ns: ?u64, wall_time_ns: u64) ?u64 {
    const hold = mutex_hold_wall_ns orelse return null;
    if (wall_time_ns == 0) return null;
    const num: u128 = @as(u128, hold) * 1000;
    const den: u128 = @as(u128, wall_time_ns);
    return @intCast(num / den);
}

pub fn classify(name: []const u8) Tier {
    if (std.mem.startsWith(u8, name, "micro/")) return .micro;
    if (std.mem.startsWith(u8, name, "integration/")) return .integration;
    if (std.mem.startsWith(u8, name, "external/")) return .external;
    return .unknown;
}

const AbsoluteGate = struct {
    scenario: []const u8,
    variant: []const u8,
    field: enum { latency_p99_ns, alloc_bytes },
    max: u64,
};

// Preserved from docs/PERFORMANCE_TARGETS.md:30-43
const absolute_gates = [_]AbsoluteGate{
    .{ .scenario = "micro/varint", .variant = "encode", .field = .latency_p99_ns, .max = 250 },
    .{ .scenario = "micro/pacing", .variant = "delay_compute", .field = .latency_p99_ns, .max = 400 },
    .{ .scenario = "micro/header_protection", .variant = "decode", .field = .latency_p99_ns, .max = 400_000 },
    .{ .scenario = "micro/frame_serialization", .variant = "short_header_encode", .field = .alloc_bytes, .max = 0 },
    .{ .scenario = "micro/frame_serialization", .variant = "short_header_decode", .field = .alloc_bytes, .max = 0 },
};

/// Regression level of one row in one baseline/current pair.
pub const Level = enum { pass, warn, fail };

pub const WaitBound = struct {
    base_permille: u64,
    cur_permille: u64,
    delta_permille: i64,
    level: Level,
};

/// Verdict for one row in one round (one baseline/current pair).
pub const RowEval = struct {
    tier: Tier,
    t_delta: f64,
    p95_delta: f64,
    /// Throughput / p95 regression level after the absolute floor.
    level: Level,
    /// A %-threshold was breached, but the absolute change stayed inside
    /// the tier's noise floor, so it does not count.
    noise: bool,
    absolute_fail: bool,
    wait_bound: ?WaitBound,

    pub fn status(self: RowEval) []const u8 {
        if (self.absolute_fail) return "ABSOLUTE-FAIL";
        if (self.wait_bound) |wb| {
            if (wb.level == .fail) return "WAIT-BOUND-FAIL";
        }
        if (self.level == .fail) return "FAIL";
        if (self.level == .warn) return "WARN";
        if (self.wait_bound) |wb| {
            if (wb.level == .warn) return "WARN";
        }
        if (self.noise) return "NOISE";
        return "PASS";
    }
};

/// Nanoseconds per operation implied by a throughput figure.
pub fn perOpNs(ops_per_sec: f64) f64 {
    if (ops_per_sec <= 0) return std.math.inf(f64);
    return 1e9 / ops_per_sec;
}

/// Evaluate one row of one baseline/current pair. Pure function: no I/O.
pub fn evaluateRow(base: common.ResultRow, cur: common.ResultRow) RowEval {
    const tier = classify(cur.scenario_name);
    const thr = thresholds(tier);
    const floor_ns: f64 = @floatFromInt(thr.latency_floor_ns);

    const t_delta = pctChange(base.throughput_ops_per_sec, cur.throughput_ops_per_sec);
    const p95_base: f64 = @floatFromInt(base.latency_p95_ns);
    const p95_cur: f64 = @floatFromInt(cur.latency_p95_ns);
    const p95_delta = pctChange(p95_base, p95_cur);

    const stddev_pct = if (base.throughput_ops_per_sec != 0)
        (base.throughput_stddev_ops_per_sec / base.throughput_ops_per_sec) * 100.0
    else
        0.0;
    const t_gate = @max(thr.throughput_pct, 3.0 * stddev_pct);

    // Absolute size of the change. A zero baseline throughput makes
    // pctChange() report 0, so the per-op delta cannot trip on its own.
    const per_op_grew = base.throughput_ops_per_sec > 0 and
        perOpNs(cur.throughput_ops_per_sec) - perOpNs(base.throughput_ops_per_sec) > floor_ns;
    const p95_grew = p95_cur - p95_base > floor_ns;

    const t_fail_pct = t_delta < -t_gate;
    const p_fail_pct = p95_delta > thr.latency_p95_pct;
    const t_warn_pct = t_delta < -(thr.throughput_pct / 2.0);
    const p_warn_pct = p95_delta > (thr.latency_p95_pct / 2.0);

    var level: Level = .pass;
    if ((t_fail_pct and per_op_grew) or (p_fail_pct and p95_grew)) {
        level = .fail;
    } else if ((t_warn_pct and per_op_grew) or (p_warn_pct and p95_grew)) {
        level = .warn;
    }
    const noise = level != .fail and (t_fail_pct or p_fail_pct);

    var absolute_fail = false;
    for (absolute_gates) |gate| {
        if (!std.mem.eql(u8, gate.scenario, cur.scenario_name)) continue;
        if (!std.mem.eql(u8, gate.variant, cur.variant)) continue;
        const actual: u64 = switch (gate.field) {
            .latency_p99_ns => cur.latency_p99_ns,
            .alloc_bytes => cur.alloc_bytes,
        };
        if (actual > gate.max) absolute_fail = true;
    }

    // Derived wait-bound gate. Flush-cadence + datagram-batch populate
    // `mutex_hold_wall_ns`; compute permille of wall time and flag
    // regressions where the fraction rose by more than the tier budget.
    // Only meaningful when BOTH rows carry the field.
    var wait_bound: ?WaitBound = null;
    const base_permille_opt = computeWaitBoundPermille(base.mutex_hold_wall_ns, base.wall_time_ns);
    const cur_permille_opt = computeWaitBoundPermille(cur.mutex_hold_wall_ns, cur.wall_time_ns);
    if (base_permille_opt != null and cur_permille_opt != null) {
        const base_permille = base_permille_opt.?;
        const cur_permille = cur_permille_opt.?;
        const delta_permille: i64 = @as(i64, @intCast(cur_permille)) - @as(i64, @intCast(base_permille));
        const gate_permille: i64 = @intCast(thr.wait_bound_permille);
        var wb_level: Level = .pass;
        if (delta_permille > gate_permille) {
            wb_level = .fail;
        } else if (delta_permille > @divTrunc(gate_permille, 2)) {
            wb_level = .warn;
        }
        wait_bound = .{
            .base_permille = base_permille,
            .cur_permille = cur_permille,
            .delta_permille = delta_permille,
            .level = wb_level,
        };
    }

    return .{
        .tier = tier,
        .t_delta = t_delta,
        .p95_delta = p95_delta,
        .level = level,
        .noise = noise,
        .absolute_fail = absolute_fail,
        .wait_bound = wait_bound,
    };
}

/// True when `count` of `rounds` is a strict majority.
pub fn isMajority(count: usize, rounds: usize) bool {
    return rounds > 0 and count * 2 > rounds;
}

/// Reproduction rule for relative regressions across rounds: a strict
/// majority of rounds FAIL the row and no round clears it (each round is
/// at least WARN). With one round this is that round's verdict.
pub fn reproduced(levels: []const Level) bool {
    var fails: usize = 0;
    for (levels) |l| switch (l) {
        .pass => return false,
        .warn => {},
        .fail => fails += 1,
    };
    return isMajority(fails, levels.len);
}

/// Aggregate verdict for one row over all rounds it appeared in.
pub const RowVerdict = struct {
    fail_rounds: usize,
    warn_rounds: usize,
    rounds: usize,
    regression: bool,
    absolute_fail: bool,
    wait_bound_fail: bool,

    pub fn failed(self: RowVerdict) bool {
        return self.regression or self.absolute_fail or self.wait_bound_fail;
    }

    pub fn status(self: RowVerdict) []const u8 {
        if (self.absolute_fail) return "ABSOLUTE-FAIL";
        if (self.wait_bound_fail) return "WAIT-BOUND-FAIL";
        if (self.regression) return "FAIL";
        if (self.fail_rounds + self.warn_rounds > 0) return "NOT-REPRODUCED";
        return "PASS";
    }
};

pub fn aggregate(evals: []const RowEval) RowVerdict {
    var levels_buf: [64]Level = undefined;
    var wb_buf: [64]Level = undefined;
    const n = @min(evals.len, levels_buf.len);
    var wb_n: usize = 0;
    var abs_fails: usize = 0;
    var v: RowVerdict = .{
        .fail_rounds = 0,
        .warn_rounds = 0,
        .rounds = n,
        .regression = false,
        .absolute_fail = false,
        .wait_bound_fail = false,
    };
    for (evals[0..n], 0..) |e, i| {
        levels_buf[i] = e.level;
        if (e.absolute_fail) abs_fails += 1;
        const wb_level: Level = if (e.wait_bound) |wb| wb.level else .pass;
        if (e.wait_bound != null) {
            wb_buf[wb_n] = wb_level;
            wb_n += 1;
        }
        const worst: Level = if (e.level == .fail or wb_level == .fail or e.absolute_fail)
            .fail
        else if (e.level == .warn or wb_level == .warn)
            .warn
        else
            .pass;
        switch (worst) {
            .fail => v.fail_rounds += 1,
            .warn => v.warn_rounds += 1,
            .pass => {},
        }
    }
    v.regression = reproduced(levels_buf[0..n]);
    v.absolute_fail = isMajority(abs_fails, n);
    v.wait_bound_fail = wb_n > 0 and reproduced(wb_buf[0..wb_n]);
    return v;
}

const RowHistory = struct {
    scenario: []const u8,
    variant: []const u8,
    evals: std.ArrayList(RowEval),
};

const max_rounds = 64;

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);
    var baseline_paths: std.ArrayList([]const u8) = .empty;
    var current_paths: std.ArrayList([]const u8) = .empty;
    var skip_env_check = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--baseline") and i + 1 < args.len) {
            try baseline_paths.append(allocator, args[i + 1]);
            i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--baseline=")) {
            try baseline_paths.append(allocator, args[i]["--baseline=".len..]);
        } else if (std.mem.eql(u8, args[i], "--current") and i + 1 < args.len) {
            try current_paths.append(allocator, args[i + 1]);
            i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--current=")) {
            try current_paths.append(allocator, args[i]["--current=".len..]);
        } else if (std.mem.eql(u8, args[i], "--skip-env-check")) {
            skip_env_check = true;
        }
    }
    if (baseline_paths.items.len == 0 or baseline_paths.items.len != current_paths.items.len or
        baseline_paths.items.len > max_rounds)
    {
        try std.Io.File.stderr().writeStreamingAll(
            init.io,
            "usage: bench-compare --baseline <file> --current <file> [--baseline <file> --current <file> ...] [--skip-env-check]\n" ++
                "  Repeat --baseline/--current once per round (pairs match by position, at most 64).\n",
        );
        std.process.exit(2);
    }
    const rounds = baseline_paths.items.len;

    const stdout = std.Io.File.stdout();
    var history: std.StringArrayHashMapUnmanaged(RowHistory) = .empty;

    for (baseline_paths.items, current_paths.items, 1..) |baseline_path, current_path, round| {
        const baseline_doc = try readDocument(allocator, init.io, baseline_path);
        const current_doc = try readDocument(allocator, init.io, current_path);

        if (!skip_env_check) {
            const b = baseline_doc.value.host;
            const c = current_doc.value.host;
            if (!std.mem.eql(u8, b.os, c.os) or !std.mem.eql(u8, b.arch, c.arch) or
                !std.mem.eql(u8, b.cpu, c.cpu) or
                !std.mem.eql(u8, baseline_doc.value.zig_version, current_doc.value.zig_version))
            {
                const msg = try std.fmt.allocPrint(
                    allocator,
                    "ENV MISMATCH\n  baseline: os={s} arch={s} cpu={s} zig={s}\n  current:  os={s} arch={s} cpu={s} zig={s}\n  Re-run with --skip-env-check to override (not recommended).\n",
                    .{ b.os, b.arch, b.cpu, baseline_doc.value.zig_version, c.os, c.arch, c.cpu, current_doc.value.zig_version },
                );
                try std.Io.File.stderr().writeStreamingAll(init.io, msg);
                std.process.exit(2);
            }
        }

        if (rounds > 1) {
            const hdr = try std.fmt.allocPrint(
                allocator,
                "\n### Round {d}/{d}: baseline={s} current={s}\n\n",
                .{ round, rounds, baseline_path, current_path },
            );
            try stdout.writeStreamingAll(init.io, hdr);
        }
        try stdout.writeStreamingAll(
            init.io,
            "| scenario | variant | tier | ops/s base | ops/s cur | delta% | p95 base | p95 cur | delta% | status |\n" ++
                "|---|---|---|---:|---:|---:|---:|---:|---:|---|\n",
        );

        var failures: usize = 0;
        var warns: usize = 0;
        var noise_rows: usize = 0;

        for (current_doc.value.rows) |cur| {
            // Skip external rows whose toolchain was unavailable — the placeholder
            // (iterations=1, wall_time_ns=1ms, latencies=[0]) produces garbage
            // numbers that would false-positive against a real baseline.
            if (isSkipRow(cur)) continue;

            const base = findMatch(baseline_doc.value.rows, cur) orelse continue;
            if (isSkipRow(base)) continue;

            const e = evaluateRow(base, cur);
            const status = e.status();
            if (std.mem.endsWith(u8, status, "FAIL")) {
                failures += 1;
            } else if (std.mem.eql(u8, status, "WARN")) {
                warns += 1;
            } else if (e.noise) {
                noise_rows += 1;
            }

            const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ cur.scenario_name, cur.variant });
            const gop = try history.getOrPut(allocator, key);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .scenario = cur.scenario_name, .variant = cur.variant, .evals = .empty };
            }
            try gop.value_ptr.evals.append(allocator, e);

            // Zig 0.16 dropped `+` from format specifiers; emit sign manually.
            const t_sign: u8 = if (e.t_delta >= 0) '+' else '-';
            const p95_sign: u8 = if (e.p95_delta >= 0) '+' else '-';
            const line = try std.fmt.allocPrint(
                allocator,
                "| {s} | {s} | {s} | {d:.1} | {d:.1} | {c}{d:.2}% | {d} | {d} | {c}{d:.2}% | {s} |\n",
                .{
                    cur.scenario_name,           cur.variant,                @tagName(e.tier),
                    base.throughput_ops_per_sec, cur.throughput_ops_per_sec, t_sign,
                    @abs(e.t_delta),             base.latency_p95_ns,        cur.latency_p95_ns,
                    p95_sign,                    @abs(e.p95_delta),          status,
                },
            );
            try stdout.writeStreamingAll(init.io, line);
            if (e.wait_bound) |wb| {
                const thr = thresholds(e.tier);
                const d_sign: u8 = if (wb.delta_permille >= 0) '+' else '-';
                const d_abs: u64 = @intCast(@abs(wb.delta_permille));
                const note = try std.fmt.allocPrint(
                    allocator,
                    "|   wait_bound | {s} | {s} | base {d} permille | cur {d} permille | {c}{d} permille | (gate {d}) | {s} |\n",
                    .{ cur.scenario_name, cur.variant, wb.base_permille, wb.cur_permille, d_sign, d_abs, thr.wait_bound_permille, @tagName(wb.level) },
                );
                try stdout.writeStreamingAll(init.io, note);
            }
        }

        const summary = if (rounds == 1)
            try std.fmt.allocPrint(allocator, "\nSummary: {d} FAIL, {d} WARN, {d} NOISE (inside the absolute floor)\n", .{ failures, warns, noise_rows })
        else
            try std.fmt.allocPrint(allocator, "\nRound {d} summary: {d} FAIL, {d} WARN, {d} NOISE (one round alone does not gate; see the reproduction table)\n", .{ round, failures, warns, noise_rows });
        try stdout.writeStreamingAll(init.io, summary);
    }

    var failures: usize = 0;
    var not_reproduced: usize = 0;
    if (rounds > 1) {
        const hdr = try std.fmt.allocPrint(
            allocator,
            "\n### Reproduction across {d} rounds\n\n" ++
                "A row FAILs only if a strict majority of rounds FAIL it and every round shows at least a WARN-level regression.\n" ++
                "ABSOLUTE-FAIL / WAIT-BOUND-FAIL need a strict majority of rounds. Rows that never left PASS/NOISE are omitted.\n\n" ++
                "| scenario | variant | FAIL rounds | WARN rounds | rounds | verdict |\n|---|---|---:|---:|---:|---|\n",
            .{rounds},
        );
        try stdout.writeStreamingAll(init.io, hdr);
    }
    for (history.values()) |h| {
        const v = aggregate(h.evals.items);
        if (v.failed()) {
            failures += 1;
        } else if (v.fail_rounds + v.warn_rounds > 0) {
            not_reproduced += 1;
        } else continue;
        if (rounds > 1) {
            const line = try std.fmt.allocPrint(
                allocator,
                "| {s} | {s} | {d} | {d} | {d} | {s} |\n",
                .{ h.scenario, h.variant, v.fail_rounds, v.warn_rounds, v.rounds, v.status() },
            );
            try stdout.writeStreamingAll(init.io, line);
        }
    }
    if (rounds > 1) {
        const summary = try std.fmt.allocPrint(
            allocator,
            "\nSummary: {d} FAIL (reproduced), {d} WARN (not reproduced across {d} rounds)\n",
            .{ failures, not_reproduced, rounds },
        );
        try stdout.writeStreamingAll(init.io, summary);
    }
    if (failures > 0) std.process.exit(1);
}

fn readDocument(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(common.ResultDocument) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(bytes);
    return std.json.parseFromSlice(common.ResultDocument, allocator, bytes, .{ .ignore_unknown_fields = true });
}

fn findMatch(rows: []const common.ResultRow, cur: common.ResultRow) ?common.ResultRow {
    for (rows) |row| {
        if (std.mem.eql(u8, row.scenario_name, cur.scenario_name) and
            std.mem.eql(u8, row.variant, cur.variant)) return row;
    }
    return null;
}

/// External rows whose toolchain was unavailable land here with an
/// `external_impl` ending in "-SKIP" and placeholder numbers. Filter
/// them out of comparison so they don't false-positive as regressions.
pub fn isSkipRow(row: common.ResultRow) bool {
    const impl = row.external_impl orelse return false;
    return std.mem.endsWith(u8, impl, "-SKIP");
}

pub fn pctChange(before: f64, after: f64) f64 {
    if (before == 0) return 0;
    return ((after - before) / before) * 100.0;
}
