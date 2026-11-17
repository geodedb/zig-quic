// benchmarks/integration/conn_scale.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: QUIC endpoint connection/stream scaling sweep
// on a loopback endpoint (no real network I/O).
//
// Scale sweep preserved from the legacy benchmarks/scale_bench.zig
// (2026-03-27) and extended with 20Kc. `Nc` is connection count and `Ms`
// is streams-per-connection (streams_count in v2 is recorded as metadata;
// the legacy file tracked streams only via the total count at report time,
// so we just surface it on the row).
//
// Per variant:
//   1. init a loopback endpoint bound to 127.0.0.1:0 with
//      `allow_insecure = true, max_connections = 0` (client role --
//      no cert configured).
//   2. open N client connections via `connectClient("127.0.0.1:<port>")`
//      using `port = (c % 55000) + 10000` (matches legacy scale_bench
//      + poll_overhead to avoid ephemeral-port exhaustion at N=10Kc).
//      The wall_time_ns returned is the connection-setup elapsed time
//      -- this is the primary metric the legacy "Setup/s" column
//      captured (conn_setup_ops_sec).
//   3. warm up with `warmup_iterations` non-blocking polls.
//   4. measure `iterations` polls, timing each via `common.nowNs()`
//      deltas so `latencies_ns[i]` captures per-poll wall cost.
//
// Scope note vs legacy scale_bench: the legacy tool also emitted
// "Accept/s" via `popAccepted()` spins. That metric is dropped here on
// purpose -- these loopback connections never complete a handshake, so
// the accept counter always drained to zero + a synthetic rate number.
// The meaningful signal captured on each row is:
//   - wall_time_ns = connection-setup elapsed for N connections
//   - throughput_ops_per_sec = iterations / setup_wall_ns (the harness
//     formula in bench_common.RunOutput). This is an *iter-normalized*
//     setup-throughput signal -- useful for regression detection but
//     NOT a true "Setup/s" rate (the legacy conn_setup_ops_sec column
//     was `n_connections / setup_wall_ns`, a different computation).
//     If a literal Setup/s metric is needed later, it should be
//     surfaced via a dedicated QUIC-optional RunOutput field.
//   - latencies_ns[i] = per-poll wall cost (p50/p95/p99).
// If Phase 5 introduces a real-accept benchmark, it belongs next to
// handshake_bench, not here.
//
// Cross-platform note: unlike the micro benches, conn_scale needs a
// real UDP socket (Endpoint.init binds one via UdpTransport). On
// non-Linux targets the quic_endpoint module is compile-gated; we
// follow the udp_batch.zig + poll_overhead.zig convention and emit a
// placeholder RunOutput so `zig build bench --suite=all` stays
// cross-compilable.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // Not measured off Linux, where the endpoint's UDP transport is not
    // supported: a not-measured row, not placeholder numbers (SONNY-6668).
    if (try common.requireLinux(allocator, builtin.os.tag)) |nm| return nm;

    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };

    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Open N client connections using port = (c % 55000) + 10000 to
    // avoid exhausting the ephemeral range at N=20_000. These
    // connections never complete a handshake (no server listening on
    // those ports); they just populate the endpoint's connection table
    // so pollWithStats() sees N live connections, and we can time the
    // setup cost of building N Conn objects. `*-close` variants keep the
    // pointers so a single measured poll can prune a mass close event.
    const n: u64 = spec.connection_count;
    const close_storm = std.mem.containsAtLeast(u8, spec.variant, 1, "close");
    var close_conns: ?[]*conn_mod.Connection = null;
    defer if (close_conns) |items| allocator.free(items);
    if (close_storm) close_conns = try allocator.alloc(*conn_mod.Connection, @intCast(n));

    const setup_start = common.nowNs();
    var c: u64 = 0;
    var opened: usize = 0;
    while (c < n) : (c += 1) {
        const port: u16 = @intCast((c % 55000) + 10000);
        var addr_buf: [32]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port}) catch continue;
        const conn = ep.connectClient(addr) catch continue;
        if (close_conns) |items| items[opened] = conn;
        opened += 1;
    }
    const setup_end = common.nowNs();

    // Warmup: flush transient setup costs (first-time timer insert,
    // initial PTO arming) before we sample poll latencies.
    var w: u64 = 0;
    while (w < spec.warmup_iterations) : (w += 1) {
        _ = ep.pollWithStats(0) catch {};
    }

    // Measure: per-iteration poll latency via paired nowNs() reads.
    const iters = spec.iterations;
    const latencies = try allocator.alloc(u64, iters);
    @memset(latencies, 0);

    if (close_conns) |items| {
        for (items[0..opened]) |conn| conn.markClosed();
    }

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const t0 = common.nowNs();
        _ = ep.pollWithStats(0) catch {};
        latencies[i] = common.nowNs() - t0;
    }

    // wall_time_ns = connection-setup elapsed for N connections.
    // Note: the harness computes throughput_ops_per_sec as
    // iterations / setup_wall_ns -- this is an iter-normalized setup
    // throughput signal, suitable for regression detection but NOT a
    // true Setup/s rate (the legacy scale_bench conn_setup_ops_sec
    // column was `n_connections / setup_wall_ns`, a different ratio).
    const setup_wall_ns = setup_end - setup_start;
    return .{
        .iterations = iters,
        .wall_time_ns = setup_wall_ns,
        .cpu_time_ns = setup_wall_ns,
        .latencies_ns = latencies,
    };
}

// Scale sweep preserved from legacy benchmarks/scale_bench.zig and extended to
// 20Kc for high-parallel contention coverage. Iteration counts drop as
// connection count rises so wall-clock stays bounded.
pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/conn_scale", .variant = "1c", .iterations = 5_000, .warmup_iterations = 500, .connection_count = 1, .streams_count = 1 },
    .{ .name = "integration/conn_scale", .variant = "10c", .iterations = 2_000, .warmup_iterations = 200, .connection_count = 10, .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "100c", .iterations = 500, .warmup_iterations = 50, .connection_count = 100, .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "1Kc", .iterations = 200, .warmup_iterations = 20, .connection_count = 1_000, .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "1Kc-100s", .iterations = 100, .warmup_iterations = 10, .connection_count = 1_000, .streams_count = 100 },
    .{ .name = "integration/conn_scale", .variant = "10Kc", .iterations = 50, .warmup_iterations = 5, .connection_count = 10_000, .streams_count = 1 },
    .{ .name = "integration/conn_scale", .variant = "10Kc-10s", .iterations = 50, .warmup_iterations = 5, .connection_count = 10_000, .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "20Kc", .iterations = 20, .warmup_iterations = 2, .connection_count = 20_000, .streams_count = 1 },
    .{ .name = "integration/conn_scale", .variant = "20Kc-close", .iterations = 1, .warmup_iterations = 2, .connection_count = 20_000, .streams_count = 1 },
};
