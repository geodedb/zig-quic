// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! TLS handshake latency benchmark (scaffold).
//!
//! Measures QUIC handshake latency as a function of parallelism. Five tiers
//! from serial (1 parallel) to 10K parallel handshakes.
//!
//! Note: actual measurement requires TLS certificate generation. This scaffold
//! emits placeholder (zero) metrics using the common benchmark harness.
//!
//! Usage:
//!   zig build bench-handshake             # run all 5 tiers
//!   zig build bench-handshake -- 3        # run first 3 tiers only

const std = @import("std");
const common = @import("bench_common");

const Tier = struct {
    name: []const u8,
    parallel: u64,
    total_handshakes: u64,
};

const tiers = [_]Tier{
    .{ .name = "serial", .parallel = 1, .total_handshakes = 100 },
    .{ .name = "10p", .parallel = 10, .total_handshakes = 100 },
    .{ .name = "100p", .parallel = 100, .total_handshakes = 200 },
    .{ .name = "1Kp", .parallel = 1_000, .total_handshakes = 1_000 },
    .{ .name = "10Kp", .parallel = 10_000, .total_handshakes = 10_000 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse optional max-tier argument from command line.
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var max_tier: usize = tiers.len;
    if (args.len > 1) {
        max_tier = std.fmt.parseInt(usize, args[1], 10) catch tiers.len;
        if (max_tier > tiers.len) max_tier = tiers.len;
    }

    // Collect results for JSON output.
    var results = std.ArrayList(common.TierResult){};
    defer {
        for (results.items) |r| {
            allocator.free(r.params);
            allocator.free(r.metrics);
        }
        results.deinit(allocator);
    }

    std.debug.print("(Full handshake measurement requires TLS cert generation)\n", .{});

    // Print table header to stderr.
    common.printSeparator();
    common.printHeader("  {s:<10} {s:>12} {s:>16} {s:>16}", .{ "Tier", "Parallel", "Handshakes", "avg ms" });
    common.printSeparator();

    for (tiers[0..max_tier]) |tier| {
        // Placeholder: no actual measurement yet.
        const handshake_avg_ms: f64 = 0;

        // Print table row to stderr.
        common.printTableRow("  {s:<10} {d:>12} {d:>16} {d:>16.2}", .{
            tier.name,
            tier.parallel,
            tier.total_handshakes,
            handshake_avg_ms,
        });

        // Store result for JSON.
        const params = try allocator.alloc(common.Param, 1);
        params[0] = .{ .name = "parallel", .value = tier.parallel };

        const metrics = try allocator.alloc(common.Metric, 1);
        metrics[0] = .{ .name = "handshake_avg_ms", .value = handshake_avg_ms };

        try results.append(allocator, .{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    common.printSeparator();

    // Emit JSON to stdout.
    try common.emitJson(allocator, "handshake", results.items);
}
