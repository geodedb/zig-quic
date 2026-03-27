// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! Benchmark regression detection tool.
//!
//! Reads two JSON benchmark result files (baseline and current), compares
//! metrics, and exits 1 if any metric regresses beyond its threshold.
//!
//! Usage:
//!   zig build bench-compare -- <baseline.json> <current.json> [threshold%]

const std = @import("std");

const MetricKind = enum {
    higher_is_better,
    lower_is_better,
};

const Classification = struct {
    kind: MetricKind,
    threshold: f64,
};

/// Classify a metric by its name suffix to determine whether higher or lower
/// is better and what the default regression threshold is.
///
/// Longer suffixes are checked first so that e.g. `polls_per_sec` matches
/// before the generic `_per_sec`.
fn classifyMetric(name: []const u8) Classification {
    // Higher-is-better metrics (throughput / rate).
    // polls_per_sec must be checked before _per_sec (longer match first).
    const hib_suffixes = [_]struct { suffix: []const u8, threshold: f64 }{
        .{ .suffix = "polls_per_sec", .threshold = 25.0 },
        .{ .suffix = "_ops_sec", .threshold = 15.0 },
        .{ .suffix = "_mbps", .threshold = 15.0 },
        .{ .suffix = "_per_sec", .threshold = 15.0 },
        .{ .suffix = "_pps", .threshold = 15.0 },
    };

    for (hib_suffixes) |entry| {
        if (std.mem.endsWith(u8, name, entry.suffix)) {
            return .{ .kind = .higher_is_better, .threshold = entry.threshold };
        }
    }

    // Lower-is-better metrics (latency / duration).
    const lib_suffixes = [_][]const u8{ "_ns", "_ms", "_us" };
    for (lib_suffixes) |suffix| {
        if (std.mem.endsWith(u8, name, suffix)) {
            return .{ .kind = .lower_is_better, .threshold = 20.0 };
        }
    }

    // Default: lower is better with 20% threshold.
    return .{ .kind = .lower_is_better, .threshold = 20.0 };
}

/// Extract a numeric value from a JSON Value (handles both integer and float).
fn jsonNumber(val: std.json.Value) ?f64 {
    return switch (val) {
        .integer => |i| @as(f64, @floatFromInt(i)),
        .float => |f| f,
        else => null,
    };
}

/// Read a file into memory.
fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        std.debug.print("Usage: bench-compare <baseline.json> <current.json> [threshold%]\n", .{});
        std.process.exit(2);
    }

    const baseline_path = args[1];
    const current_path = args[2];

    // Optional global threshold override.
    var global_threshold: ?f64 = null;
    if (args.len > 3) {
        global_threshold = std.fmt.parseFloat(f64, args[3]) catch {
            std.debug.print("Error: invalid threshold value '{s}'\n", .{args[3]});
            std.process.exit(2);
        };
    }

    // Read and parse both files.
    const baseline_data = try readFile(allocator, baseline_path);
    defer allocator.free(baseline_data);
    const current_data = try readFile(allocator, current_path);
    defer allocator.free(current_data);

    const baseline_parsed = try std.json.parseFromSlice(std.json.Value, allocator, baseline_data, .{});
    defer baseline_parsed.deinit();
    const current_parsed = try std.json.parseFromSlice(std.json.Value, allocator, current_data, .{});
    defer current_parsed.deinit();

    const baseline_root = baseline_parsed.value;
    const current_root = current_parsed.value;

    const baseline_tiers = (baseline_root.object.get("tiers") orelse {
        std.debug.print("Error: baseline JSON missing 'tiers' field\n", .{});
        std.process.exit(2);
    }).array.items;

    const current_tiers = (current_root.object.get("tiers") orelse {
        std.debug.print("Error: current JSON missing 'tiers' field\n", .{});
        std.process.exit(2);
    }).array.items;

    // Print header.
    std.debug.print("  {s:<10} {s:<25} {s:>12} {s:>12} {s:>8} {s:<6}\n", .{
        "Tier", "Metric", "Baseline", "Current", "Delta%", "Status",
    });
    std.debug.print("  {s}\n", .{"-" ** 75});

    var any_fail = false;

    // Iterate baseline tiers.
    for (baseline_tiers) |baseline_tier| {
        const tier_name = baseline_tier.object.get("name") orelse continue;
        const tier_name_str = tier_name.string;

        const baseline_metrics_val = baseline_tier.object.get("metrics") orelse continue;

        // Find matching tier in current.
        var current_metrics_val: ?std.json.Value = null;
        for (current_tiers) |current_tier| {
            const cname = current_tier.object.get("name") orelse continue;
            if (std.mem.eql(u8, cname.string, tier_name_str)) {
                current_metrics_val = current_tier.object.get("metrics");
                break;
            }
        }

        const current_metrics = current_metrics_val orelse {
            std.debug.print("  {s:<10} (tier missing in current)\n", .{tier_name_str});
            continue;
        };

        // Iterate metrics.
        const baseline_metrics = baseline_metrics_val.object;
        const keys = baseline_metrics.keys();
        for (keys) |metric_name| {
            const bval_json = baseline_metrics.get(metric_name) orelse continue;
            const bval = jsonNumber(bval_json) orelse continue;

            const cval_json = current_metrics.object.get(metric_name) orelse {
                std.debug.print("  {s:<10} {s:<25} {d:>12.1} {s:>12} {s:>8} {s:<6}\n", .{
                    tier_name_str, metric_name, bval, "N/A", "N/A", "SKIP",
                });
                continue;
            };
            const cval = jsonNumber(cval_json) orelse continue;

            const classification = classifyMetric(metric_name);
            const threshold = global_threshold orelse classification.threshold;

            // Compute delta%.
            var delta_pct: f64 = 0.0;
            if (bval != 0.0) {
                delta_pct = ((cval - bval) / @abs(bval)) * 100.0;
            }

            // Determine pass/fail.
            // For higher_is_better: regression when current drops (negative delta beyond threshold)
            // For lower_is_better: regression when current increases (positive delta beyond threshold)
            const regressed = switch (classification.kind) {
                .higher_is_better => delta_pct < -threshold,
                .lower_is_better => delta_pct > threshold,
            };

            const status: []const u8 = if (regressed) "FAIL" else "PASS";
            if (regressed) any_fail = true;

            // Format delta with sign.
            const sign: u8 = if (delta_pct >= 0.0) '+' else '-';
            const abs_delta = @abs(delta_pct);

            std.debug.print("  {s:<10} {s:<25} {d:>12.1} {d:>12.1} {c}{d:>5.1}%  {s}\n", .{
                tier_name_str,
                metric_name,
                bval,
                cval,
                sign,
                abs_delta,
                status,
            });
        }
    }

    if (any_fail) {
        std.debug.print("\nRegression detected! One or more metrics exceed threshold.\n", .{});
        std.process.exit(1);
    } else {
        std.debug.print("\nAll metrics within threshold. No regression detected.\n", .{});
    }
}
