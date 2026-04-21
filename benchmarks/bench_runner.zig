// benchmarks/bench_runner.zig
// SPDX-License-Identifier: Apache-2.0
//
// Main entry for all zig-quic benchmarks. Dispatches via --suite=<name>.
// Each scenario is registered in `registry` below; adding a new benchmark
// means adding one import + one SuiteEntry.
//
// Flags:
//   --list                 List available suites and scenarios, then exit.
//   --suite=<name>         Filter scenarios by suite name. Accepts:
//                            "all"                    -> every registered scenario
//                            "micro"|"integration"|"external" -> by tier
//                            "<tier>/<short>"         -> fully-qualified name
//                            "<short>"                -> scenario short name
//                          Defaults to "all" when omitted.
//   --output=<path>        Write ResultDocument JSON to <path> (default: stdout).
//
// Exit codes:
//   0 success
//   3 no scenarios matched the requested suite

const std = @import("std");
const common = @import("bench_common");

// Phase 2+ will add scenario imports here as files arrive.
const varint_bench = @import("micro/varint.zig");
const pacing_bench = @import("micro/pacing.zig");
const hp_bench = @import("micro/header_protection.zig");
const aead_bench = @import("micro/aead.zig");
const tls_keygen_bench = @import("micro/tls_keygen.zig");
const frame_serialization_bench = @import("micro/frame_serialization.zig");
const connection_lookup_bench = @import("micro/connection_lookup.zig");
const loss_detection_scan_bench = @import("micro/loss_detection_scan.zig");
const send_buffer_alloc_bench = @import("micro/send_buffer_alloc.zig");
const udp_batch_bench = @import("integration/udp_batch.zig");
const poll_overhead_bench = @import("integration/poll_overhead.zig");
const conn_scale_bench = @import("integration/conn_scale.zig");
const handshake_e2e_bench = @import("integration/handshake_e2e.zig");
const stream_throughput_bench = @import("integration/stream_throughput.zig");
const datagram_batch_bench = @import("integration/datagram_batch.zig");
const flush_cadence_bench = @import("integration/flush_cadence.zig");
const external_scenarios = @import("external/scenarios.zig");
const external_harness = @import("external/harness.zig");

/// Module-level `std.Io` populated in main() before any registry entry runs.
/// The external-tier harness needs io to drive `std.process.run`, but the
/// `RunFn` signature is `(allocator, spec)` only -- threading io through
/// every bench's signature would churn 15 files for a 3-scenario need.
/// Other tiers ignore this var; they synthesize their own io via
/// `_helpers.benchIo()`.
pub var bench_io: std.Io = undefined;

pub const SuiteEntry = struct {
    name: []const u8, // fully-qualified: "micro/varint"
    tier: []const u8, // "micro" | "integration" | "external"
    scenarios: []const common.ScenarioSpec,
    runFn: common.RunFn,
};

pub const registry: []const SuiteEntry = &.{
    .{ .name = "micro/varint", .tier = "micro", .scenarios = &varint_bench.scenarios, .runFn = varint_bench.run },
    .{ .name = "micro/pacing", .tier = "micro", .scenarios = &pacing_bench.scenarios, .runFn = pacing_bench.run },
    .{ .name = "micro/header_protection", .tier = "micro", .scenarios = &hp_bench.scenarios, .runFn = hp_bench.run },
    .{ .name = "micro/aead", .tier = "micro", .scenarios = &aead_bench.scenarios, .runFn = aead_bench.run },
    .{ .name = "micro/tls_keygen", .tier = "micro", .scenarios = &tls_keygen_bench.scenarios, .runFn = tls_keygen_bench.run },
    .{ .name = "micro/frame_serialization", .tier = "micro", .scenarios = &frame_serialization_bench.scenarios, .runFn = frame_serialization_bench.run },
    .{ .name = "micro/connection_lookup", .tier = "micro", .scenarios = &connection_lookup_bench.scenarios, .runFn = connection_lookup_bench.run },
    .{ .name = "micro/loss_detection_scan", .tier = "micro", .scenarios = &loss_detection_scan_bench.scenarios, .runFn = loss_detection_scan_bench.run },
    .{ .name = "micro/send_buffer_alloc", .tier = "micro", .scenarios = &send_buffer_alloc_bench.scenarios, .runFn = send_buffer_alloc_bench.run },
    .{ .name = "integration/udp_batch", .tier = "integration", .scenarios = &udp_batch_bench.scenarios, .runFn = udp_batch_bench.run },
    .{ .name = "integration/poll_overhead", .tier = "integration", .scenarios = &poll_overhead_bench.scenarios, .runFn = poll_overhead_bench.run },
    .{ .name = "integration/conn_scale", .tier = "integration", .scenarios = &conn_scale_bench.scenarios, .runFn = conn_scale_bench.run },
    .{ .name = "integration/handshake_e2e", .tier = "integration", .scenarios = &handshake_e2e_bench.scenarios, .runFn = handshake_e2e_bench.run },
    .{ .name = "integration/stream_throughput", .tier = "integration", .scenarios = &stream_throughput_bench.scenarios, .runFn = stream_throughput_bench.run },
    .{ .name = "integration/datagram_batch", .tier = "integration", .scenarios = &datagram_batch_bench.scenarios, .runFn = datagram_batch_bench.run },
    .{ .name = "integration/flush_cadence", .tier = "integration", .scenarios = &flush_cadence_bench.scenarios, .runFn = flush_cadence_bench.run },
    .{ .name = "external/quic-go", .tier = "external", .scenarios = &external_scenarios.scenarios_quic_go, .runFn = external_scenarios.runQuicGoHandshake },
    .{ .name = "external/quinn", .tier = "external", .scenarios = &external_scenarios.scenarios_quinn, .runFn = external_scenarios.runQuinnHandshake },
    .{ .name = "external/aioquic", .tier = "external", .scenarios = &external_scenarios.scenarios_aioquic, .runFn = external_scenarios.runAioquicHandshake },
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Publish io to the module-level var so external/harness.zig can read
    // it without refactoring the RunFn signature. Must happen before any
    // registry entry executes.
    bench_io = init.io;

    // Prewarm env-metadata cache before integration benches (handshake_e2e
    // 10Kp spawns 10K threads -> FD exhaustion) can poison subsequent
    // git/hostname/uname subprocess spawns. Without this, ~25% of rows
    // land with quic_git_sha="unknown" in the JSON.
    common.prewarmEnvCache(allocator, init.io) catch {};

    // Same FD-exhaustion rationale: prewarm toolchain-availability checks
    // (go / cargo / python3) so that `zig build bench -- --suite=all` runs
    // external scenarios against real binaries instead of landing SKIP
    // rows when handshake_e2e 10Kp has burned through FDs.
    external_harness.prewarmToolchains(allocator);

    const args = try init.minimal.args.toSlice(allocator);
    const suite = common.parseSuiteArg(args) orelse "all";
    const output = common.parseOutputArg(args);

    for (args) |a| {
        if (std.mem.eql(u8, a, "--list")) {
            const out = std.Io.File.stdout();
            try out.writeStreamingAll(init.io, "Available suites: all, micro, integration, external\n");
            try out.writeStreamingAll(init.io, "Available scenarios:\n");
            for (registry) |e| {
                const line = try std.fmt.allocPrint(allocator, "  {s} [{s}]\n", .{ e.name, e.tier });
                defer allocator.free(line);
                try out.writeStreamingAll(init.io, line);
            }
            return;
        }
    }

    var rows: std.ArrayList(common.ResultRow) = .empty;
    defer rows.deinit(allocator);

    for (registry) |entry| {
        if (!matches(suite, entry)) continue;
        for (entry.scenarios) |spec| {
            const row = try common.runRepeated(allocator, init.io, spec, entry.runFn);
            try rows.append(allocator, row);
        }
    }

    if (rows.items.len == 0) {
        const err_out = std.Io.File.stderr();
        const msg = try std.fmt.allocPrint(allocator, "no scenarios matched suite='{s}'\n", .{suite});
        defer allocator.free(msg);
        try err_out.writeStreamingAll(init.io, msg);
        std.process.exit(3);
    }

    try common.writeDocument(allocator, init.io, rows.items, output);
}

fn matches(suite: []const u8, entry: SuiteEntry) bool {
    if (std.mem.eql(u8, suite, "all")) return true;
    if (std.mem.eql(u8, suite, entry.tier)) return true;
    const last_slash = std.mem.lastIndexOfScalar(u8, entry.name, '/') orelse return false;
    const short = entry.name[last_slash + 1 ..];
    return std.mem.eql(u8, suite, short) or std.mem.eql(u8, suite, entry.name);
}
