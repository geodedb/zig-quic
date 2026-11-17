// benchmarks/integration/_helpers.zig
// SPDX-License-Identifier: Apache-2.0
//
// Shared primitives for the integration-tier real-UDP benches:
//
//   - handshake_e2e.zig (Task 5.1)
//   - stream_throughput.zig (Task 5.2)
//   - flush_cadence.zig (Task 5.4)
//
// Every integration bench that binds a localhost UDP endpoint needs the
// same four things:
//   1. An atomic port allocator that hands out fresh ports for each
//      `runRepeated()` invocation (the median-of-6 harness re-runs a
//      scenario 7 times; TIME_WAIT on the prior run's port blocks
//      rebinding without a fresh port).
//   2. A process-global cert cache so we don't reparse
//      `tests/certs/cert.pem` / `key.pem` on every run (7 parses per
//      scenario without caching; one parse per process with it).
//   3. A `std.Io` instance for bench code that touches `std.Io.Dir`,
//      `std.Io.File`, or `std.Io.Mutex`.
//   4. A `nanosleep` wrapper for brief waits (server-thread shutdown
//      drain, RLIMIT_NPROC backoff, etc.).
//
// Port range: starts at 19400. handshake_e2e.zig uses 18900+, so the
// 500-port headroom above avoids collisions on concurrent CI runs.
// 5.2 callers (stream_throughput) use 19400+, 5.4 (flush_cadence) will
// use 19800+ per the plan. The counter is process-wide atomic so if
// two benches run in the same process (e.g. --suite=integration) they
// also don't collide.
//
// All public symbols are imported as e.g. `const h = @import("_helpers.zig");`
// and referenced via `h.loadServerCreds(...)` etc.

const std = @import("std");
const builtin = @import("builtin");
const api = @import("quic_api");

pub const CERT_PATH = "tests/certs/cert.pem";
pub const KEY_PATH = "tests/certs/key.pem";

/// Shorthand: 0.16 removed `std.Thread.Mutex` in favour of `std.Io.Mutex`,
/// which takes a `std.Io` instance on lock/unlock. We grab the single-
/// threaded default IO (same pattern used throughout src/quic/endpoint.zig).
pub fn benchIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Cached parsed-DER cert + private key for the server endpoint. Loaded
/// once per process on first `loadServerCreds` call. Subsequent calls
/// (from this bench or any other integration bench) short-circuit.
var cert_cache_mu: std.Io.Mutex = std.Io.Mutex.init;
var cert_cache_cert_der: ?[]const u8 = null;
var cert_cache_priv_p256: ?[]const u8 = null;

pub const ServerCreds = struct { cert: []const u8, key: []const u8 };

/// Load cert.pem + key.pem, parse to DER / P-256 raw scalar, cache in
/// process-global globals. Subsequent calls short-circuit. Fails with
/// CredsError when the files are missing or invalid; the scenario then
/// reports itself not measured (SONNY-4381).
pub fn loadServerCreds(allocator: std.mem.Allocator) CredsError!ServerCreds {
    cert_cache_mu.lockUncancelable(benchIo());
    defer cert_cache_mu.unlock(benchIo());

    if (cert_cache_cert_der) |cert_der| {
        if (cert_cache_priv_p256) |priv| {
            return .{ .cert = cert_der, .key = priv };
        }
    }

    const creds = try loadServerCredsFrom(allocator, std.Io.Dir.cwd());
    cert_cache_cert_der = creds.cert;
    cert_cache_priv_p256 = creds.key;
    return creds;
}

/// Why server credentials could not be loaded (SONNY-4381). A scenario
/// reports either as not measured (common.notMeasured), never as a
/// placeholder measurement.
pub const CredsError = error{
    /// CERT_PATH or KEY_PATH does not exist or cannot be read.
    CredentialsMissing,
    /// A file exists but does not parse as a certificate / P-256 key.
    CredentialsInvalid,
    OutOfMemory,
};

/// Read and parse CERT_PATH and KEY_PATH relative to `dir`, uncached.
pub fn loadServerCredsFrom(allocator: std.mem.Allocator, dir: std.Io.Dir) CredsError!ServerCreds {
    const cert_pem = try readFile(allocator, dir, CERT_PATH);
    defer allocator.free(cert_pem);
    const key_pem = try readFile(allocator, dir, KEY_PATH);
    defer allocator.free(key_pem);
    const cert_der = api.pem.parseCertificate(allocator, cert_pem) catch return error.CredentialsInvalid;
    errdefer allocator.free(cert_der);
    const priv = api.pem.parsePrivateKey(allocator, key_pem) catch return error.CredentialsInvalid;
    return .{ .cert = cert_der, .key = priv };
}

fn readFile(allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8) CredsError![]u8 {
    const io = benchIo();
    const file = dir.openFile(io, path, .{}) catch return error.CredentialsMissing;
    defer file.close(io);
    const size = (file.stat(io) catch return error.CredentialsMissing).size;
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    _ = file.readPositionalAll(io, buf, 0) catch return error.CredentialsMissing;
    return buf;
}

/// Atomic port allocator. Starts at 19400 -- handshake_e2e.zig uses
/// 18900+ and needs ~7 ports per runRepeated() invocation. The 500-port
/// headroom above the handshake range accommodates its full 5-scenario
/// sweep (7 iters * 5 variants = 35 ports max) and leaves room for
/// future growth. Callers should reserve sub-ranges by convention:
///   stream_throughput (5.2): 19400+
///   flush_cadence     (5.4): 19800+
var next_port = std.atomic.Value(u16).init(19400);

pub fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

/// Linux-only nanosleep wrapper. Matches the helper used across the
/// test suite (tests/test_transport_geode_compat.zig:28-34). Elsewhere it
/// sleeps through the Zig 0.16 `std.Io` clock API (`std.Thread.sleep`,
/// used before, no longer exists; SONNY-6669), so the benches cross-compile
/// even though the real measurement only runs on Linux.
pub fn threadSleep(ns: u64) void {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = .{
            .sec = @intCast(ns / std.time.ns_per_s),
            .nsec = @intCast(ns % std.time.ns_per_s),
        };
        _ = std.os.linux.nanosleep(&ts, &ts);
    } else {
        std.Io.sleep(std.Io.Threaded.global_single_threaded.io(), .fromNanoseconds(ns), .awake) catch {};
    }
}
