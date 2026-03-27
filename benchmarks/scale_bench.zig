// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! Connection/stream scaling benchmark.
//!
//! Measures connection setup rate, poll overhead, and accept rate as a
//! function of connection and stream count using loopback transport.
//! Seven tiers from 1 connection to 10K connections.
//!
//! Usage:
//!   zig build bench-scale             # run all 7 tiers
//!   zig build bench-scale -- 3        # run first 3 tiers only (1c, 10c, 100c)

const std = @import("std");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const Tier = struct {
    name: []const u8,
    connections: u64,
    streams_per_conn: u64,
    iterations: u64,
};

const tiers = [_]Tier{
    .{ .name = "1c", .connections = 1, .streams_per_conn = 1, .iterations = 5_000 },
    .{ .name = "10c", .connections = 10, .streams_per_conn = 10, .iterations = 2_000 },
    .{ .name = "100c", .connections = 100, .streams_per_conn = 10, .iterations = 500 },
    .{ .name = "1Kc", .connections = 1_000, .streams_per_conn = 10, .iterations = 200 },
    .{ .name = "1Kc-100s", .connections = 1_000, .streams_per_conn = 100, .iterations = 100 },
    .{ .name = "10Kc", .connections = 10_000, .streams_per_conn = 1, .iterations = 50 },
    .{ .name = "10Kc-10s", .connections = 10_000, .streams_per_conn = 10, .iterations = 50 },
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
    common.printHeader("  {s:<12} {s:>8} {s:>10} {s:>12} {s:>12} {s:>12}", .{
        "Tier",
        "Conns",
        "Streams",
        "Setup/s",
        "Poll(us)",
        "Accept/s",
    });
    common.printSeparator();

    for (tiers[0..max_tier]) |tier| {
        // Create fresh config per tier.
        var config = cfg.QuicConfig{
            .alpn = &test_alpn,
            .allow_insecure = true,
            .max_connections = 0,
        };

        var ep = try Endpoint.init(allocator, "127.0.0.1:0", &config);
        defer ep.deinit();

        const total_streams = tier.connections * tier.streams_per_conn;

        // --- Measure connection setup rate ---
        var setup_timer = common.Timer.start();
        var c: u64 = 0;
        while (c < tier.connections) : (c += 1) {
            const port: u16 = @intCast((c % 55000) + 10000);
            var addr_buf: [22]u8 = undefined;
            const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch continue;
            _ = ep.connectClient(addr) catch continue;
        }
        setup_timer.stop();

        const setup_elapsed_ns = setup_timer.elapsed_ns();
        const conn_setup_ops_sec = common.opsPerSec(tier.connections, setup_elapsed_ns);

        // --- Warmup: 20% of iterations calling pollWithStats(0) ---
        const warmup_iters = tier.iterations / 5;
        var w: u64 = 0;
        while (w < warmup_iters) : (w += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }

        // --- Measure poll overhead ---
        var poll_timer = common.Timer.start();
        var i: u64 = 0;
        while (i < tier.iterations) : (i += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }
        poll_timer.stop();

        const poll_elapsed_ns = poll_timer.elapsed_ns();
        const ns_per_poll = common.nsPerOp(tier.iterations, poll_elapsed_ns);
        const poll_us = ns_per_poll / 1_000.0;

        // --- Measure accept rate ---
        var accept_timer = common.Timer.start();
        var accepted: u64 = 0;
        var a: u64 = 0;
        while (a < tier.iterations) : (a += 1) {
            if (ep.popAccepted()) |_| {
                accepted += 1;
            }
        }
        accept_timer.stop();

        const accept_elapsed_ns = accept_timer.elapsed_ns();
        const accept_rate_ops_sec = common.opsPerSec(tier.iterations, accept_elapsed_ns);

        // Print table row to stderr.
        common.printTableRow("  {s:<12} {d:>8} {d:>10} {d:>12.1} {d:>12.2} {d:>12.1}", .{
            tier.name,
            tier.connections,
            total_streams,
            conn_setup_ops_sec,
            poll_us,
            accept_rate_ops_sec,
        });

        // Store result for JSON.
        const params = try allocator.alloc(common.Param, 2);
        params[0] = .{ .name = "connections", .value = tier.connections };
        params[1] = .{ .name = "streams_per_conn", .value = tier.streams_per_conn };

        const metrics = try allocator.alloc(common.Metric, 3);
        metrics[0] = .{ .name = "conn_setup_ops_sec", .value = conn_setup_ops_sec };
        metrics[1] = .{ .name = "poll_us", .value = poll_us };
        metrics[2] = .{ .name = "accept_rate_ops_sec", .value = accept_rate_ops_sec };

        try results.append(allocator, .{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    common.printSeparator();

    // Emit JSON to stdout.
    try common.emitJson(allocator, "scale", results.items);
}
