// benchmarks/integration/poll_overhead.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: QUIC endpoint `pollWithStats()` overhead as a
// function of open connection count on a loopback endpoint (no real
// network I/O).
//
// Measurement core is extracted from the legacy benchmarks/poll_bench.zig
// connection-count sweep (0c, 1c, 10c, 100c, 1Kc, 10Kc, 20Kc). Each variant:
//   1. init a loopback endpoint bound to 127.0.0.1:0 with
//      `allow_insecure = true, max_connections = 0` (client role --
//      no cert configured).
//   2. open N client connections via `connectClient("127.0.0.1:<port>")`
//      using `port = (c % 55000) + 10000` to avoid ephemeral exhaustion
//      when N = 10_000.
//   3. warm up with `warmup_iterations` non-blocking polls.
//   4. measure `iterations` polls, timing each via `common.nowNs()`
//      deltas so `latencies_ns[i]` captures per-poll wall cost.
//
// This benchmark documents endpoint poll overhead after the PTO dirty-set
// fix (#182): clean polls should stay close to O(1) even when the endpoint
// owns tens of thousands of connections. bench-compare uses the recorded
// latencies as the regression baseline.
//
// Cross-platform note: unlike the micro benches, poll_overhead needs a
// real UDP socket (Endpoint.init binds one via UdpTransport). On
// non-Linux targets the quic_endpoint module is compile-gated; rather
// than special-casing that here, we follow the pattern established in
// udp_batch.zig and emit a placeholder RunOutput on non-Linux so
// `zig build bench --suite=all` stays cross-compilable.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) {
        // Non-Linux placeholder: keeps the suite cross-platform
        // compilable. Real measurement only runs on Linux where the
        // endpoint's UDP transport is supported.
        const latencies = try allocator.alloc(u64, 1);
        latencies[0] = 0;
        return .{
            .iterations = 1,
            .wall_time_ns = 1_000_000,
            .cpu_time_ns = 0,
            .latencies_ns = latencies,
        };
    }

    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };

    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Open N client connections using port = (c % 55000) + 10000 to
    // avoid exhausting the ephemeral range when N approaches 10k. These
    // connections never complete a handshake (no server listening on
    // those ports); they just populate the endpoint's connection table
    // so pollWithStats() owns N live connections while clean-poll work
    // should stay bounded.
    const n: u64 = spec.connection_count;
    var c: u64 = 0;
    while (c < n) : (c += 1) {
        const port: u16 = @intCast((c % 55000) + 10000);
        var addr_buf: [32]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    // Warmup: flush transient setup costs (first-time timer insert,
    // initial PTO arming) before we sample.
    var w: u64 = 0;
    while (w < spec.warmup_iterations) : (w += 1) {
        _ = ep.pollWithStats(0) catch {};
    }

    // Measure: per-iteration latency via paired nowNs() reads.
    const iters = spec.iterations;
    const latencies = try allocator.alloc(u64, iters);
    @memset(latencies, 0);

    const wall_start = common.nowNs();
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const t0 = common.nowNs();
        _ = ep.pollWithStats(0) catch {};
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = iters,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

// Connection-count sweep preserved from legacy benchmarks/poll_bench.zig and
// extended to 20Kc for high-parallel contention coverage. Iteration counts drop
// as connection_count rises so wall-clock stays bounded.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/poll_overhead", .variant = "0c", .iterations = 20_000, .warmup_iterations = 2_000, .connection_count = 0 },
    .{ .name = "integration/poll_overhead", .variant = "1c", .iterations = 20_000, .warmup_iterations = 2_000, .connection_count = 1 },
    .{ .name = "integration/poll_overhead", .variant = "10c", .iterations = 10_000, .warmup_iterations = 1_000, .connection_count = 10 },
    .{ .name = "integration/poll_overhead", .variant = "100c", .iterations = 5_000, .warmup_iterations = 500, .connection_count = 100 },
    .{ .name = "integration/poll_overhead", .variant = "1Kc", .iterations = 2_000, .warmup_iterations = 200, .connection_count = 1_000 },
    .{ .name = "integration/poll_overhead", .variant = "10Kc", .iterations = 500, .warmup_iterations = 50, .connection_count = 10_000 },
    .{ .name = "integration/poll_overhead", .variant = "20Kc", .iterations = 200, .warmup_iterations = 20, .connection_count = 20_000 },
};
