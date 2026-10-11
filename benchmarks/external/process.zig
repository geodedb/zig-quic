// SPDX-License-Identifier: Apache-2.0
//! Complete-process deadlines and fail-closed external benchmark sampling.
const std = @import("std");
const common = @import("bench_common");

pub const ExternalSpec = struct {
    impl: []const u8,
    argv: []const []const u8,
    timeout_seconds: u32 = 10,
};

fn collect(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: std.process.RunOptions,
    code: *u8,
    report_failure: bool,
) anyerror!void {
    const result = try std.process.run(allocator, io, options);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |value| code.* = value,
        else => return error.ChildFailed,
    }
    if (report_failure and code.* != 0) {
        std.debug.print("external command {s} exited {d}: {s}\n", .{ options.argv[0], code.*, result.stderr });
    }
}

fn boundedExitCode(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: std.process.RunOptions,
    timeout: std.Io.Duration,
    report_failure: bool,
) !u8 {
    if (options.argv.len == 0) return error.InvalidCommand;
    if (timeout.toNanoseconds() <= 0) return error.InvalidTimeout;
    // RunOptions.timeout bounds pipe reads, but not child.wait after EOF.
    // Race the COMPLETE operation; cancelDiscard joins it, so process.run's
    // deferred child.kill has reaped the child before this scope returns.
    const Completion = union(enum) { child: anyerror!void, timer: std.Io.Cancelable!void };
    var buffer: [2]Completion = undefined;
    var tasks = std.Io.Select(Completion).init(io, &buffer);
    defer tasks.cancelDiscard();
    var code: u8 = undefined;
    try tasks.concurrent(.child, collect, .{ allocator, io, options, &code, report_failure });
    try tasks.concurrent(.timer, std.Io.sleep, .{ io, timeout, .awake });
    switch (try tasks.await()) {
        .child => |result| try result,
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    }
    return code;
}

pub fn runCommand(allocator: std.mem.Allocator, io: std.Io, options: std.process.RunOptions, timeout: std.Io.Duration) !void {
    if (try boundedExitCode(allocator, io, options, timeout, true) != 0) return error.ChildFailed;
}

/// Probes may distinguish an absent tool (exit 1) from a failed probe. Spawn,
/// signal, resource and timeout errors still propagate to the benchmark runner.
pub fn probeExitCode(allocator: std.mem.Allocator, io: std.Io, options: std.process.RunOptions) !u8 {
    return boundedExitCode(allocator, io, options, .fromSeconds(10), false);
}

pub fn runSubprocess(allocator: std.mem.Allocator, io: std.Io, spec: common.ScenarioSpec, external: ExternalSpec) !common.RunOutput {
    if (spec.iterations == 0) return error.InvalidIterations;
    const iterations = std.math.cast(usize, spec.iterations) orelse return error.InvalidIterations;
    if (external.timeout_seconds == 0) return error.InvalidTimeout;
    const timeout = std.Io.Duration.fromSeconds(external.timeout_seconds);
    const options: std.process.RunOptions = .{
        .argv = external.argv,
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    };
    const latencies = try allocator.alloc(u64, iterations);
    errdefer allocator.free(latencies);
    const label = try allocator.dupe(u8, external.impl);
    errdefer allocator.free(label);
    for (0..spec.warmup_iterations) |_| try runCommand(allocator, io, options, timeout);
    const start = common.nowNs();
    for (latencies) |*latency| {
        const invocation_start = common.nowNs();
        try runCommand(allocator, io, options, timeout);
        latency.* = @max(common.nowNs() - invocation_start, 1);
    }
    const elapsed = @max(common.nowNs() - start, 1);
    return .{
        .iterations = spec.iterations,
        .wall_time_ns = elapsed,
        .cpu_time_ns = elapsed,
        .latencies_ns = latencies,
        .external_impl = label,
    };
}
