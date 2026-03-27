// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! Poll loop overhead benchmark.
//!
//! Measures `pollWithStats()` overhead as a function of connection count
//! using loopback (no real network I/O). Six tiers from 0 to 10K connections.
//!
//! Usage:
//!   zig build bench-poll             # run all 6 tiers
//!   zig build bench-poll -- 3        # run first 3 tiers only (0c, 1c, 10c)

const std = @import("std");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const Tier = struct {
    name: []const u8,
    connections: u64,
    iterations: u64,
};

const tiers = [_]Tier{
    .{ .name = "0c", .connections = 0, .iterations = 20_000 },
    .{ .name = "1c", .connections = 1, .iterations = 20_000 },
    .{ .name = "10c", .connections = 10, .iterations = 10_000 },
    .{ .name = "100c", .connections = 100, .iterations = 5_000 },
    .{ .name = "1Kc", .connections = 1_000, .iterations = 2_000 },
    .{ .name = "10Kc", .connections = 10_000, .iterations = 500 },
};

const test_alpn = [_][]const u8{"h3"};

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

    // Print table header to stderr.
    common.printSeparator();
    common.printHeader("  {s:<10} {s:>12} {s:>12} {s:>14}", .{ "Tier", "Connections", "us/poll", "polls/sec" });
    common.printSeparator();

    for (tiers[0..max_tier]) |tier| {
        var config = cfg.QuicConfig{
            .alpn = &test_alpn,
            .allow_insecure = true,
            .max_connections = 0,
        };

        var ep = try Endpoint.init(allocator, "127.0.0.1:0", &config);
        defer ep.deinit();

        // Create N connections using port = (c % 55000) + 10000 to avoid exhaustion.
        var c: u64 = 0;
        while (c < tier.connections) : (c += 1) {
            const port: u16 = @intCast((c % 55000) + 10000);
            var addr_buf: [22]u8 = undefined;
            const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch continue;
            _ = ep.connectClient(addr) catch continue;
        }

        // Warmup: 10% of iterations.
        const warmup_iters = tier.iterations / 10;
        var w: u64 = 0;
        while (w < warmup_iters) : (w += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }

        // Measure.
        var timer = common.Timer.start();
        var i: u64 = 0;
        while (i < tier.iterations) : (i += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }
        timer.stop();

        const elapsed_ns = timer.elapsed_ns();
        const ns_per_poll = common.nsPerOp(tier.iterations, elapsed_ns);
        const us_per_poll = ns_per_poll / 1_000.0;
        const polls_per_sec = common.opsPerSec(tier.iterations, elapsed_ns);

        // Print table row to stderr.
        common.printTableRow("  {s:<10} {d:>12} {d:>12.2} {d:>14.1}", .{
            tier.name,
            tier.connections,
            us_per_poll,
            polls_per_sec,
        });

        // Store result for JSON.
        const params = try allocator.alloc(common.Param, 1);
        params[0] = .{ .name = "connections", .value = tier.connections };

        const metrics = try allocator.alloc(common.Metric, 2);
        metrics[0] = .{ .name = "us_per_poll", .value = us_per_poll };
        metrics[1] = .{ .name = "polls_per_sec", .value = polls_per_sec };

        try results.append(allocator, .{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    common.printSeparator();

    // Emit JSON to stdout.
    try common.emitJson(allocator, "poll", results.items);
}
