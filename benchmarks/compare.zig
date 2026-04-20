// benchmarks/compare.zig
// SPDX-License-Identifier: Apache-2.0
//
// Tier-aware regression comparator. Exits non-zero on any FAIL.
// Tiers: micro (name prefix "micro/"), integration ("integration/"),
// external ("external/"). Noise floor: 3x baseline stddev per tier.

const std = @import("std");
const common = @import("bench_common");

pub const Tier = enum { micro, integration, external, unknown };

const TierThresholds = struct {
    throughput_pct: f64,
    latency_p95_pct: f64,
    alloc_bytes_pct: ?f64,
    // Max permissible rise in wait-bound fraction (permille = parts per 1000).
    // Applied only when both baseline and current rows populate
    // `mutex_hold_wall_ns` and have non-zero `wall_time_ns`. See
    // `computeWaitBoundPermille` + derived gate in main().
    wait_bound_permille: u64,
};

fn thresholds(t: Tier) TierThresholds {
    return switch (t) {
        .micro => .{ .throughput_pct = 15.0, .latency_p95_pct = 10.0, .alloc_bytes_pct = 0.0, .wait_bound_permille = 100 },
        .integration => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = 30.0, .wait_bound_permille = 200 },
        .external => .{ .throughput_pct = 25.0, .latency_p95_pct = 30.0, .alloc_bytes_pct = null, .wait_bound_permille = 300 },
        .unknown => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = null, .wait_bound_permille = 200 },
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

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);
    var baseline_path: ?[]const u8 = null;
    var current_path: ?[]const u8 = null;
    var skip_env_check = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--baseline") and i + 1 < args.len) {
            baseline_path = args[i + 1];
            i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--baseline=")) {
            baseline_path = args[i]["--baseline=".len..];
        } else if (std.mem.eql(u8, args[i], "--current") and i + 1 < args.len) {
            current_path = args[i + 1];
            i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--current=")) {
            current_path = args[i]["--current=".len..];
        } else if (std.mem.eql(u8, args[i], "--skip-env-check")) {
            skip_env_check = true;
        }
    }
    if (baseline_path == null or current_path == null) {
        try std.Io.File.stderr().writeStreamingAll(
            init.io,
            "usage: bench-compare --baseline <file> --current <file> [--skip-env-check]\n",
        );
        std.process.exit(2);
    }

    const baseline_doc = try readDocument(allocator, init.io, baseline_path.?);
    const current_doc = try readDocument(allocator, init.io, current_path.?);
    defer baseline_doc.deinit();
    defer current_doc.deinit();

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
            defer allocator.free(msg);
            try std.Io.File.stderr().writeStreamingAll(init.io, msg);
            std.process.exit(2);
        }
    }

    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(
        init.io,
        "| scenario | variant | tier | ops/s base | ops/s cur | delta% | p95 base | p95 cur | delta% | status |\n" ++
            "|---|---|---|---:|---:|---:|---:|---:|---:|---|\n",
    );

    var failures: usize = 0;
    var warns: usize = 0;

    for (current_doc.value.rows) |cur| {
        // Skip external rows whose toolchain was unavailable — the placeholder
        // (iterations=1, wall_time_ns=1ms, latencies=[0]) produces garbage
        // numbers that would false-positive against a real baseline.
        if (isSkipRow(cur)) continue;

        const base = findMatch(baseline_doc.value.rows, cur) orelse continue;
        if (isSkipRow(base)) continue;

        const tier = classify(cur.scenario_name);
        const thr = thresholds(tier);

        const t_delta = pctChange(base.throughput_ops_per_sec, cur.throughput_ops_per_sec);
        const p95_delta = pctChange(
            @as(f64, @floatFromInt(base.latency_p95_ns)),
            @as(f64, @floatFromInt(cur.latency_p95_ns)),
        );

        const stddev_pct = if (base.throughput_ops_per_sec != 0)
            (base.throughput_stddev_ops_per_sec / base.throughput_ops_per_sec) * 100.0
        else
            0.0;
        const t_gate = @max(thr.throughput_pct, 3.0 * stddev_pct);

        var status: []const u8 = "PASS";
        if (t_delta < -t_gate or p95_delta > thr.latency_p95_pct) {
            status = "FAIL";
            failures += 1;
        } else if (t_delta < -(thr.throughput_pct / 2.0) or p95_delta > (thr.latency_p95_pct / 2.0)) {
            status = "WARN";
            warns += 1;
        }

        for (absolute_gates) |gate| {
            if (!std.mem.eql(u8, gate.scenario, cur.scenario_name)) continue;
            if (!std.mem.eql(u8, gate.variant, cur.variant)) continue;
            const actual: u64 = switch (gate.field) {
                .latency_p99_ns => cur.latency_p99_ns,
                .alloc_bytes => cur.alloc_bytes,
            };
            if (actual > gate.max) {
                status = "ABSOLUTE-FAIL";
                failures += 1;
            }
        }

        // Derived wait-bound gate. Flush-cadence + datagram-batch populate
        // `mutex_hold_wall_ns`; compute permille of wall time and flag
        // regressions where the fraction rose by more than the tier budget.
        // Only meaningful when BOTH rows carry the field.
        const base_permille_opt = computeWaitBoundPermille(base.mutex_hold_wall_ns, base.wall_time_ns);
        const cur_permille_opt = computeWaitBoundPermille(cur.mutex_hold_wall_ns, cur.wall_time_ns);
        var wait_bound_note: ?[]u8 = null;
        defer if (wait_bound_note) |n| allocator.free(n);
        if (base_permille_opt != null and cur_permille_opt != null) {
            const base_permille = base_permille_opt.?;
            const cur_permille = cur_permille_opt.?;
            // Signed delta (cur - base) as i64. Permille fits easily in i64.
            const delta_permille: i64 = @as(i64, @intCast(cur_permille)) - @as(i64, @intCast(base_permille));
            const gate_permille: i64 = @intCast(thr.wait_bound_permille);
            var wb_status: []const u8 = "PASS";
            if (delta_permille > gate_permille) {
                wb_status = "FAIL";
                // Upgrade main row status so summary reports the failure.
                if (!std.mem.eql(u8, status, "ABSOLUTE-FAIL")) status = "WAIT-BOUND-FAIL";
                failures += 1;
            } else if (delta_permille > @divTrunc(gate_permille, 2)) {
                wb_status = "WARN";
                if (std.mem.eql(u8, status, "PASS")) status = "WARN";
                warns += 1;
            }
            const d_sign: u8 = if (delta_permille >= 0) '+' else '-';
            const d_abs: u64 = @intCast(@abs(delta_permille));
            wait_bound_note = try std.fmt.allocPrint(
                allocator,
                "|   wait_bound | {s} | {s} | base {d} permille | cur {d} permille | {c}{d} permille | (gate {d}) | {s} |\n",
                .{ cur.scenario_name, cur.variant, base_permille, cur_permille, d_sign, d_abs, thr.wait_bound_permille, wb_status },
            );
        }

        // Zig 0.16 dropped `+` from format specifiers; emit sign manually.
        const t_sign: u8 = if (t_delta >= 0) '+' else '-';
        const p95_sign: u8 = if (p95_delta >= 0) '+' else '-';
        const line = try std.fmt.allocPrint(
            allocator,
            "| {s} | {s} | {s} | {d:.1} | {d:.1} | {c}{d:.2}% | {d} | {d} | {c}{d:.2}% | {s} |\n",
            .{
                cur.scenario_name,           cur.variant,                @tagName(tier),
                base.throughput_ops_per_sec, cur.throughput_ops_per_sec, t_sign,
                @abs(t_delta),               base.latency_p95_ns,        cur.latency_p95_ns,
                p95_sign,                    @abs(p95_delta),            status,
            },
        );
        defer allocator.free(line);
        try stdout.writeStreamingAll(init.io, line);
        if (wait_bound_note) |n| try stdout.writeStreamingAll(init.io, n);
    }

    const summary = try std.fmt.allocPrint(allocator, "\nSummary: {d} FAIL, {d} WARN\n", .{ failures, warns });
    defer allocator.free(summary);
    try stdout.writeStreamingAll(init.io, summary);
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
