// benchmarks/micro_main.zig
// SPDX-License-Identifier: Apache-2.0
//
// Entry point for one isolated micro-benchmark executable.
//
// build.zig compiles one executable per micro suite (bench-micro-aead,
// bench-micro-varint, ...). Each one imports only its own suite file as
// `micro_suite`, so it contains that suite's code and the code it calls,
// and nothing else.
//
// benchmarks/isolated_runner.zig (`zig build bench-isolated`) runs these
// executables and merges their rows; it explains why the split exists.
//
// Usage: bench-micro-<name> [--output=<path>]
// Runs every scenario of the suite and writes a v2 ResultDocument to
// <path>, or to stdout when --output is omitted.

const std = @import("std");
const common = @import("bench_common");
const suite = @import("micro_suite");

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    common.prewarmEnvCache(allocator, init.io) catch {};

    const args = try init.minimal.args.toSlice(allocator);
    const output = common.parseOutputArg(args);

    var rows: std.ArrayList(common.ResultRow) = .empty;
    defer rows.deinit(allocator);
    for (suite.scenarios) |spec| {
        const row = try common.runRepeated(allocator, std.heap.smp_allocator, init.io, spec, suite.run);
        try rows.append(allocator, row);
    }

    try common.writeDocument(allocator, init.io, rows.items, output);
}
