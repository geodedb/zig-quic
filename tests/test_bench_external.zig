// SPDX-License-Identifier: Apache-2.0
const std = @import("std");
const builtin = @import("builtin");
const process = @import("bench_external_process");
const common = @import("bench_common");
const io = std.testing.io;
const allocator = std.testing.allocator;

fn requirePosix() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

fn release(output: common.RunOutput, a: std.mem.Allocator) void {
    a.free(output.latencies_ns);
    if (output.external_impl) |label| a.free(label);
}

fn shell(script: []const u8, iterations: u64, warmup: u64) !common.RunOutput {
    return process.runSubprocess(allocator, io, .{
        .name = "external/fixture",
        .iterations = iterations,
        .warmup_iterations = warmup,
    }, .{ .impl = "fixture", .argv = &.{ "/bin/sh", "-c", script } });
}

test "external subprocess counts only completed successful invocations" {
    try requirePosix();
    const output = try shell("printf response; printf diagnostic >&2", 3, 2);
    defer release(output, allocator);
    try std.testing.expectEqual(@as(u64, 3), output.iterations);
    try std.testing.expectEqual(@as(usize, 3), output.latencies_ns.len);
    try std.testing.expectEqualStrings("fixture", output.external_impl.?);
    for (output.latencies_ns) |latency| try std.testing.expect(latency > 0);
}

test "external subprocess never turns all failed invocations into one success" {
    try requirePosix();
    try std.testing.expectError(error.ChildFailed, shell("exit 7", 3, 0));
}

test "external subprocess rejects signal termination" {
    try requirePosix();
    try std.testing.expectError(error.ChildFailed, shell("kill -TERM $$", 1, 0));
}

test "external subprocess rejects missing executable" {
    try requirePosix();
    try std.testing.expectError(error.FileNotFound, process.runSubprocess(allocator, io, .{
        .name = "external/fixture",
        .iterations = 1,
    }, .{ .impl = "fixture", .argv = &.{"/nonexistent/sonny4788-client"} }));
}

test "external subprocess rejects zero iterations and zero deadline" {
    try requirePosix();
    try std.testing.expectError(error.InvalidIterations, shell("exit 0", 0, 0));
    try std.testing.expectError(error.InvalidTimeout, process.runSubprocess(allocator, io, .{
        .name = "external/fixture",
        .iterations = 1,
    }, .{ .impl = "fixture", .argv = &.{"/bin/true"}, .timeout_seconds = 0 }));
}

fn countedInvocation(script: []const u8, iterations: u64, warmup: u64) !common.RunOutput {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const count_path = try std.fs.path.join(allocator, &.{ directory, "count" });
    defer allocator.free(count_path);
    const output = try process.runSubprocess(allocator, io, .{
        .name = "external/fixture",
        .iterations = iterations,
        .warmup_iterations = warmup,
    }, .{ .impl = "fixture", .argv = &.{ "/bin/sh", "-c", script, "fixture", count_path } });
    errdefer release(output, allocator);
    const count_bytes = try temporary.dir.readFileAlloc(io, "count", allocator, .limited(64));
    defer allocator.free(count_bytes);
    const count = try std.fmt.parseInt(u64, std.mem.trim(u8, count_bytes, " \r\n"), 10);
    try std.testing.expectEqual(iterations + warmup, count);
    return output;
}

test "external subprocess executes the configured number of warmups" {
    try requirePosix();
    const output = try countedInvocation(
        "n=0; if [ -f \"$1\" ]; then read -r n < \"$1\"; fi; n=$((n+1)); printf '%s\\n' \"$n\" > \"$1\"; [ \"$n\" -le 4 ]",
        2,
        2,
    );
    defer release(output, allocator);
    try std.testing.expectEqual(@as(u64, 2), output.iterations);
}

test "external subprocess warmup failure invalidates the scenario" {
    try requirePosix();
    try std.testing.expectError(error.ChildFailed, countedInvocation(
        "if [ ! -f \"$1\" ]; then : > \"$1\"; exit 7; fi; exit 0",
        2,
        1,
    ));
}

test "external subprocess partial success does not produce a result" {
    try requirePosix();
    try std.testing.expectError(error.ChildFailed, countedInvocation(
        "n=0; if [ -f \"$1\" ]; then read -r n < \"$1\"; fi; n=$((n+1)); printf '%s\\n' \"$n\" > \"$1\"; [ \"$n\" -ne 2 ]",
        3,
        0,
    ));
}

fn bounded(script: []const u8) !void {
    try process.runCommand(allocator, io, .{ .argv = &.{ "/bin/sh", "-c", script } }, .fromMilliseconds(50));
}

test "external subprocess deadline includes process wait after closed pipes" {
    try requirePosix();
    const start = std.Io.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, bounded("exec 1>&- 2>&-; exec sleep 2"));
    try std.testing.expect(start.untilNow(io, .awake).toMilliseconds() < 1000);
}

test "external subprocess deadline kills and reaps the actual child" {
    try requirePosix();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const pid_path = try std.fs.path.join(allocator, &.{ directory, "pid" });
    defer allocator.free(pid_path);
    const start = std.Io.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, process.runCommand(allocator, io, .{
        .argv = &.{ "/bin/sh", "-c", "printf '%s\\n' $$ > \"$1\"; exec sleep 5", "fixture", pid_path },
    }, .fromMilliseconds(200)));
    try std.testing.expect(start.untilNow(io, .awake).toMilliseconds() < 2000);
    const pid_bytes = try temporary.dir.readFileAlloc(io, "pid", allocator, .limited(64));
    defer allocator.free(pid_bytes);
    const pid = try std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, pid_bytes, " \r\n"), 10);
    // A zombie still has a /proc entry. Absence proves cancellation waited/reaped.
    const proc_path = try std.fmt.allocPrint(allocator, "/proc/{d}/status", .{pid});
    defer allocator.free(proc_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().openFile(io, proc_path, .{}));
}

test "external subprocess enforces stdout and stderr limits" {
    try requirePosix();
    for ([_][]const u8{
        "i=0; while [ $i -lt 100 ]; do printf 01234567890123456789; i=$((i+1)); done",
        "i=0; while [ $i -lt 100 ]; do printf 01234567890123456789 >&2; i=$((i+1)); done",
    }) |script| {
        try std.testing.expectError(error.StreamTooLong, process.runCommand(allocator, io, .{
            .argv = &.{ "/bin/sh", "-c", script },
            .stdout_limit = .limited(256),
            .stderr_limit = .limited(256),
        }, .fromSeconds(2)));
    }
}

test "external build command uses its working directory and rejects failure" {
    try requirePosix();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(io, .{ .sub_path = "marker", .data = "present" });
    const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    try process.runCommand(allocator, io, .{
        .argv = &.{ "/bin/sh", "-c", "test -f marker" },
        .cwd = .{ .path = directory },
    }, .fromSeconds(2));
    try std.testing.expectError(error.ChildFailed, process.runCommand(allocator, io, .{
        .argv = &.{ "/bin/sh", "-c", "exit 9" },
        .cwd = .{ .path = directory },
    }, .fromSeconds(2)));
}

test "external tool probes retain exit status and propagate spawn errors" {
    try requirePosix();
    try std.testing.expectEqual(@as(u8, 1), try process.probeExitCode(allocator, io, .{
        .argv = &.{ "/bin/sh", "-c", "exit 1" },
    }));
    try std.testing.expectEqual(@as(u8, 42), try process.probeExitCode(allocator, io, .{
        .argv = &.{ "/bin/sh", "-c", "exit 42" },
    }));
    try std.testing.expectError(error.FileNotFound, process.probeExitCode(allocator, io, .{
        .argv = &.{"/nonexistent/sonny4788-probe"},
    }));
}

fn allocationCase(a: std.mem.Allocator) !void {
    const output = try process.runSubprocess(a, io, .{ .name = "external/fixture", .iterations = 2 }, .{
        .impl = "owned-label",
        .argv = &.{ "/bin/sh", "-c", "printf output; printf error >&2" },
    });
    defer release(output, a);
}

test "external subprocess frees all allocations on every allocation failure" {
    try requirePosix();
    try std.testing.checkAllAllocationFailures(allocator, allocationCase, .{});
}

// Exercise the actual production probe and /bin/sh, including dash's exit 127.
// The command is a shell builtin, so these tests need no optional toolchains.
test "external tool discovery accepts an existing command and missing optional tool" {
    try requirePosix();
    try std.testing.expect(try process.checkToolchain(allocator, io, "command"));
    try std.testing.expect(!try process.checkToolchain(allocator, io, "sonny4788-tool-that-does-not-exist"));
}

test "external tool discovery treats tool names literally and rejects probe errors" {
    try requirePosix();
    try std.testing.expect(!try process.checkToolchain(allocator, io, "sonny4788-missing; exit 0"));
    try std.testing.expectError(error.ToolchainProbeFailed, process.checkToolchain(allocator, io, "-?"));
}
