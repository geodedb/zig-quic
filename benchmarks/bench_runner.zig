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
const udp_batch_bench = @import("integration/udp_batch.zig");
const poll_overhead_bench = @import("integration/poll_overhead.zig");

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
    .{ .name = "integration/udp_batch", .tier = "integration", .scenarios = &udp_batch_bench.scenarios, .runFn = udp_batch_bench.run },
    .{ .name = "integration/poll_overhead", .tier = "integration", .scenarios = &poll_overhead_bench.scenarios, .runFn = poll_overhead_bench.run },
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

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
