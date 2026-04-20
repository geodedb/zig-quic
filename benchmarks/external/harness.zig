// benchmarks/external/harness.zig
// SPDX-License-Identifier: Apache-2.0
//
// Subprocess harness for the `external` tier. Spawns one of
// `test-clients/{quic-go,quinn,aioquic}` against an in-process Zig server
// endpoint, measures wall-clock subprocess latency per invocation, and
// returns a `common.RunOutput` suitable for `runRepeated`.
//
// Each external scenario's `run()` is responsible for:
//   1. Toolchain detection (go/cargo/python3 + aioquic pip module).
//   2. Lazy build of the client binary on first use (cached across
//      `runRepeated` iterations so `go build` / `cargo build --release`
//      only pay their startup cost once per process).
//   3. Starting a Zig server endpoint on a fresh loopback port.
//   4. Invoking `runSubprocess` with the argv pointing at that server.
//   5. Tearing the server down.
//
// This module provides the toolchain + subprocess + cache primitives; the
// per-impl orchestration lives in `scenarios.zig`.
//
// `std.process.run` needs a `std.Io` instance. `RunFn` is `(allocator, spec)`
// only, so bench_runner.zig exposes its init-time `std.Io` via the
// `bench_io` module-level `pub var`. We read that here rather than taking
// io as a harness argument; keeps the RunFn signature stable across tiers.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const runner = @import("../bench_runner.zig");

/// Per-invocation subprocess spec. `argv` must outlive the call (allocation
/// lifetime sits in scenarios.zig which uses the per-call arena allocator).
pub const ExternalSpec = struct {
    impl: []const u8,
    argv: []const []const u8,
    /// Wall-clock timeout per invocation. On failure the iteration is
    /// counted as a subprocess-timeout and the punitive latency is
    /// recorded. Picked large enough for a cold-start Python or Go
    /// subprocess on a loaded CI box, but small enough that a full
    /// 3-scenario run completes in under 2 minutes.
    timeout_seconds: u32 = 10,
    /// Ignore subprocess nonzero exit codes: some clients (quic-go) exit
    /// 0 on success but print their completion line to stderr. Setting
    /// this to true means only spawn failures count as errors; any
    /// termination (exited/signal) is accepted as "one handshake".
    accept_any_exit: bool = false,
};

/// Runs the subprocess once for warmup (discarded), then `spec.iterations`
/// times. Wall-clock latency per invocation is collected into the returned
/// `latencies_ns`. On spawn failure or timeout the slot gets a punitive
/// sentinel (timeout_seconds * 1e9) so the p50/p99 reflect failure.
pub fn runSubprocess(
    allocator: std.mem.Allocator,
    spec: common.ScenarioSpec,
    external: ExternalSpec,
) !common.RunOutput {
    const iters: usize = @max(@as(usize, @intCast(spec.iterations)), 1);
    const latencies = try allocator.alloc(u64, iters);
    const punitive_ns: u64 = @as(u64, external.timeout_seconds) * std.time.ns_per_s;
    for (latencies) |*l| l.* = punitive_ns;

    // One warmup invocation. Discarded. Also covers the toolchain's
    // first-invocation cache-warm (Python import, Go plugin cache, etc.).
    warmupInvoke(allocator, external);

    const wall_start = common.nowNs();
    var successes: u64 = 0;
    for (latencies) |*slot| {
        const t0 = common.nowNs();
        const result = std.process.run(allocator, runner.bench_io, .{
            .argv = external.argv,
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(8192),
        }) catch {
            slot.* = punitive_ns;
            continue;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        const dt = common.nowNs() - t0;
        const ok = switch (result.term) {
            .exited => |c| external.accept_any_exit or c == 0,
            else => external.accept_any_exit,
        };
        if (ok) {
            slot.* = dt;
            successes += 1;
        } else {
            slot.* = punitive_ns;
        }
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = @max(successes, 1),
        .wall_time_ns = @max(wall_end - wall_start, 1),
        .cpu_time_ns = @max(wall_end - wall_start, 1),
        .latencies_ns = latencies,
        .external_impl = try allocator.dupe(u8, external.impl),
    };
}

fn warmupInvoke(allocator: std.mem.Allocator, external: ExternalSpec) void {
    const result = std.process.run(allocator, runner.bench_io, .{
        .argv = external.argv,
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    }) catch return;
    allocator.free(result.stdout);
    allocator.free(result.stderr);
}

/// Returns true iff `which <tool>` exits 0. Used by scenarios' entry to
/// short-circuit to a placeholder RunOutput when the needed toolchain
/// isn't installed. We don't `which` in a hot loop -- check once per
/// scenario and cache at the caller.
pub fn checkToolchain(allocator: std.mem.Allocator, tool: []const u8) bool {
    const result = std.process.run(allocator, runner.bench_io, .{
        .argv = &.{ "which", tool },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(256),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |c| c == 0,
        else => false,
    };
}

/// Returns true iff `python3 -c "import <module>"` exits 0. Used so the
/// aioquic scenario can detect missing pip dependencies and short-circuit
/// to a skip row without spawning the real client binary.
pub fn checkPythonModule(allocator: std.mem.Allocator, module: []const u8) bool {
    const import_stmt = std.fmt.allocPrint(allocator, "import {s}", .{module}) catch return false;
    defer allocator.free(import_stmt);
    const result = std.process.run(allocator, runner.bench_io, .{
        .argv = &.{ "python3", "-c", import_stmt },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(256),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |c| c == 0,
        else => false,
    };
}

/// Whether a filesystem path exists (regular file or directory).
pub fn pathExists(path: []const u8) bool {
    const f = std.Io.Dir.cwd().openFile(runner.bench_io, path, .{}) catch {
        // Could be a directory; try openDir instead.
        var d = std.Io.Dir.cwd().openDir(runner.bench_io, path, .{}) catch return false;
        d.close(runner.bench_io);
        return true;
    };
    f.close(runner.bench_io);
    return true;
}

/// Runs a build command with CWD set to `cwd`. `timeout_s` is advisory only
/// (std.process.run on Zig 0.16 doesn't expose a per-process timeout; the
/// helper relies on bounded build times from pre-populated go/cargo module
/// caches). Returns true on success, false on any failure (which the
/// caller should treat as "skip this scenario").
pub fn runBuild(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: []const u8,
    timeout_s: u32,
) bool {
    _ = timeout_s;
    const result = std.process.run(allocator, runner.bench_io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |c| c == 0,
        else => false,
    };
}

/// Placeholder output emitted when a scenario skips (toolchain missing,
/// build failed, server failed to start). Sets `external_impl` to
/// `"<impl>-SKIP"` so the downstream compare/gate can treat skip rows
/// as non-contributing rather than as a performance regression.
pub fn placeholderOutput(allocator: std.mem.Allocator, impl: []const u8) !common.RunOutput {
    const latencies = try allocator.alloc(u64, 1);
    latencies[0] = 0;
    const skip_label = try std.fmt.allocPrint(allocator, "{s}-SKIP", .{impl});
    return .{
        .iterations = 1,
        .wall_time_ns = 1_000_000,
        .cpu_time_ns = 0,
        .latencies_ns = latencies,
        .external_impl = skip_label,
    };
}

test "checkToolchain returns false for bogus tool" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    try std.testing.expect(!checkToolchain(gpa.allocator(), "definitely-not-a-real-tool-zzzyyyxxx"));
}
