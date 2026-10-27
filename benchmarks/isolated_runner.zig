// benchmarks/isolated_runner.zig
// SPDX-License-Identifier: Apache-2.0
//
// `zig build bench-isolated`: run micro suites, each from its own
// executable, and write one v2 ResultDocument.
//
// The paired perf gate (scripts/perf-gate.sh) compares a baseline commit
// with HEAD. In the single bench_runner binary, every micro suite shares an
// executable with the endpoint, connection and integration-bench code, so a
// change to any of that code moves the micro suites' hot loops to different
// cache-line offsets. For quic !80, which only touches the endpoint's
// pending-handshake retry, micro/aead chacha20_poly1305 then ran 10-17%
// slower in every paired round, on CI and locally, because std's ChaCha20
// loop moved. The gate correctly saw a reproducible difference, but the
// difference came from code layout, not from the change under test.
//
// build.zig compiles one executable per micro suite from
// benchmarks/micro_main.zig. Each contains only its suite and the code that
// suite calls, so it changes only when that code changes. This runner starts
// them in registry order (build.zig passes `--micro-exe=<suite>=<path>`),
// checks that each returned exactly the scenarios it declares, and merges
// their rows. The rows, the JSON schema and the measurement loop
// (common.runRepeated) are the same as `zig build bench`.
//
// Flags:
//   --suite=<name>   "all" or "micro" (every micro suite), "micro/<short>"
//                    or "<short>". Integration and external suites are not
//                    isolated; run them with `zig build bench`.
//   --output=<path>  Write the ResultDocument to <path> (default: stdout).
//
// Exit codes: 0 success, 3 no micro suite matched.

const std = @import("std");
const common = @import("bench_common");

const exe_flag = "--micro-exe=";

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    common.prewarmEnvCache(allocator, init.io) catch {};

    const args = try init.minimal.args.toSlice(allocator);
    const suite = common.parseSuiteArg(args) orelse "all";
    const output = common.parseOutputArg(args);

    var rows: std.ArrayList(common.ResultRow) = .empty;
    defer rows.deinit(allocator);

    var matched: usize = 0;
    for (args) |arg| {
        if (!std.mem.startsWith(u8, arg, exe_flag)) continue;
        const spec = arg[exe_flag.len..];
        const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.InvalidMicroExeFlag;
        const name = spec[0..eq];
        if (!matches(suite, name)) continue;
        matched += 1;
        try runSuite(allocator, init.io, name, spec[eq + 1 ..], &rows);
    }

    if (matched == 0) {
        std.debug.print("no isolated micro suite matched suite='{s}' (integration and external suites run with `zig build bench`)\n", .{suite});
        std.process.exit(3);
    }

    try common.writeDocument(allocator, init.io, rows.items, output);
}

fn matches(suite: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, suite, "all") or std.mem.eql(u8, suite, "micro")) return true;
    if (std.mem.eql(u8, suite, name)) return true;
    const last_slash = std.mem.lastIndexOfScalar(u8, name, '/') orelse return false;
    return std.mem.eql(u8, suite, name[last_slash + 1 ..]);
}

/// Run one isolated suite executable and append its rows. A child that
/// fails, or whose rows do not belong to its suite, is an error: a broken
/// split must never silently drop rows from the gate. (The child itself
/// emits exactly its `scenarios` table, so the row count per suite is the
/// same as `zig build bench`.)
fn runSuite(
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    exe_path: []const u8,
    rows: *std.ArrayList(common.ResultRow),
) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{exe_path},
        .stdout_limit = .limited(16 * 1024 * 1024),
        .stderr_limit = .limited(16 * 1024 * 1024),
    });
    const ok = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("bench-isolated: {s} ({s}) failed: {any}\n{s}\n", .{ name, exe_path, result.term, result.stderr });
        return error.IsolatedSuiteFailed;
    }
    // Arena allocation: the row strings are written out at the end.
    const doc = try std.json.parseFromSliceLeaky(common.ResultDocument, allocator, result.stdout, .{ .ignore_unknown_fields = true });
    if (doc.rows.len == 0) {
        std.debug.print("bench-isolated: {s} returned no rows\n", .{name});
        return error.IsolatedSuiteRowMismatch;
    }
    for (doc.rows) |row| {
        if (!std.mem.eql(u8, row.scenario_name, name)) {
            std.debug.print("bench-isolated: {s} returned a row for {s}\n", .{ name, row.scenario_name });
            return error.IsolatedSuiteRowMismatch;
        }
        try rows.append(allocator, row);
    }
}
