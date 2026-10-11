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

const process = @import("bench_external_process");
pub const ExternalSpec = process.ExternalSpec;

/// Every configured warmup and measured invocation must complete successfully.
pub fn runSubprocess(allocator: std.mem.Allocator, spec: common.ScenarioSpec, external: ExternalSpec) !common.RunOutput {
    return process.runSubprocess(allocator, runner.bench_io, spec, external);
}

/// Returns true iff the shell can resolve the tool. Used by scenarios' entry to
/// short-circuit to a placeholder RunOutput when the needed toolchain
/// isn't installed. Backed by a module-level cache so that FD pressure
/// from earlier scenarios (notably handshake_e2e 10Kp exhausting the
/// process's file descriptor limit) doesn't cause a false-negative
/// availability probe and land external rows as SKIP despite the toolchain
/// being present. Callers can prewarm via `prewarmToolchains` at
/// bench_runner startup before any FD-heavy integration scenario runs.
const ToolchainCache = struct {
    go: ?bool = null,
    cargo: ?bool = null,
    python3: ?bool = null,
};

var toolchain_cache: ToolchainCache = .{};

fn checkToolchainUncached(allocator: std.mem.Allocator, tool: []const u8) !bool {
    return process.checkToolchain(allocator, runner.bench_io, tool);
}

pub fn checkToolchain(allocator: std.mem.Allocator, tool: []const u8) !bool {
    if (std.mem.eql(u8, tool, "go")) {
        if (toolchain_cache.go) |cached| return cached;
        const fresh = try checkToolchainUncached(allocator, tool);
        toolchain_cache.go = fresh;
        return fresh;
    }
    if (std.mem.eql(u8, tool, "cargo")) {
        if (toolchain_cache.cargo) |cached| return cached;
        const fresh = try checkToolchainUncached(allocator, tool);
        toolchain_cache.cargo = fresh;
        return fresh;
    }
    if (std.mem.eql(u8, tool, "python3")) {
        if (toolchain_cache.python3) |cached| return cached;
        const fresh = try checkToolchainUncached(allocator, tool);
        toolchain_cache.python3 = fresh;
        return fresh;
    }
    // Unknown tool — don't cache; fall through to uncached path.
    return checkToolchainUncached(allocator, tool);
}

/// Prewarm the toolchain cache. Call once at bench_runner entry before
/// any FD-heavy integration scenario runs.
pub fn prewarmToolchains(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .linux) return;
    _ = try checkToolchain(allocator, "go");
    _ = try checkToolchain(allocator, "cargo");
    _ = try checkToolchain(allocator, "python3");
}

/// Returns true iff `python3 -c "import <module>"` exits 0. Used so the
/// aioquic scenario can detect missing pip dependencies and short-circuit
/// to a skip row without spawning the real client binary.
pub fn checkPythonModule(allocator: std.mem.Allocator, module: []const u8) !bool {
    const code = try process.probeExitCode(allocator, runner.bench_io, .{
        .argv = &.{ "python3", "-c", "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec(sys.argv[1]) is not None else 42)", module },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    return switch (code) {
        0 => true,
        42 => false,
        else => error.PythonProbeFailed,
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

/// Build errors and deadlines invalidate the run; they are never SKIP rows.
pub fn runBuild(allocator: std.mem.Allocator, argv: []const []const u8, cwd: []const u8, timeout_s: u32) !void {
    try process.runCommand(allocator, runner.bench_io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }, .fromSeconds(timeout_s));
}

/// Placeholder output only for unsupported platforms or absent toolchains. Sets `external_impl` to
/// `"<impl>-SKIP"` so the downstream compare/gate can treat skip rows
/// as non-contributing rather than as a performance regression.
pub fn placeholderOutput(allocator: std.mem.Allocator, impl: []const u8) !common.RunOutput {
    const latencies = try allocator.alloc(u64, 1);
    errdefer allocator.free(latencies);
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
    try std.testing.expect(!try checkToolchain(gpa.allocator(), "definitely-not-a-real-tool-zzzyyyxxx"));
}
