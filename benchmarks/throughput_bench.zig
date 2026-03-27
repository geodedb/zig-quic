// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! Payload throughput benchmark (scaffold).
//!
//! Measures UDP send/receive throughput as a function of payload size and
//! concurrency. Six tiers from 64B×1 to 1KB×100.
//!
//! Note: actual measurement requires TLS certificate generation. This scaffold
//! emits placeholder (zero) metrics using the common benchmark harness.
//!
//! Usage:
//!   zig build bench-throughput             # run all 6 tiers
//!   zig build bench-throughput -- 3        # run first 3 tiers only

const std = @import("std");
const common = @import("bench_common");

const Tier = struct {
    name: []const u8,
    payload_size: u64,
    concurrency: u64,
    iterations: u64,
};

const tiers = [_]Tier{
    .{ .name = "64B-c1", .payload_size = 64, .concurrency = 1, .iterations = 1_000 },
    .{ .name = "1KB-c1", .payload_size = 1024, .concurrency = 1, .iterations = 1_000 },
    .{ .name = "64KB-c1", .payload_size = 65536, .concurrency = 1, .iterations = 200 },
    .{ .name = "64B-c10", .payload_size = 64, .concurrency = 10, .iterations = 500 },
    .{ .name = "1KB-c10", .payload_size = 1024, .concurrency = 10, .iterations = 500 },
    .{ .name = "1KB-c100", .payload_size = 1024, .concurrency = 100, .iterations = 100 },
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

    std.debug.print("(Full UDP throughput measurement requires TLS cert setup)\n", .{});

    // Print table header to stderr.
    common.printSeparator();
    common.printHeader("  {s:<10} {s:>12} {s:>12} {s:>14} {s:>14}", .{ "Tier", "Payload", "Concurrency", "Mbps", "pkt/s" });
    common.printSeparator();

    for (tiers[0..max_tier]) |tier| {
        // Placeholder: no actual measurement yet.
        const throughput_mbps: f64 = 0;
        const packets_per_sec: f64 = 0;

        // Print table row to stderr.
        common.printTableRow("  {s:<10} {d:>12} {d:>12} {d:>14.2} {d:>14.1}", .{
            tier.name,
            tier.payload_size,
            tier.concurrency,
            throughput_mbps,
            packets_per_sec,
        });

        // Store result for JSON.
        const params = try allocator.alloc(common.Param, 2);
        params[0] = .{ .name = "payload_size", .value = tier.payload_size };
        params[1] = .{ .name = "concurrency", .value = tier.concurrency };

        const metrics = try allocator.alloc(common.Metric, 2);
        metrics[0] = .{ .name = "throughput_mbps", .value = throughput_mbps };
        metrics[1] = .{ .name = "packets_per_sec", .value = packets_per_sec };

        try results.append(allocator, .{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    common.printSeparator();

    // Emit JSON to stdout.
    try common.emitJson(allocator, "throughput", results.items);
}
