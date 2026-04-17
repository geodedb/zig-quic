// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test for the uninitialized-mutex bug in Connection.init.
//
// See /home/benji/src/devnw/codepros/geode/geode/docs/audit/bugfix-quic-deadlock-triage.md
//
// Bug summary:
//
//   `Connection.mu: std.Io.Mutex` has a struct-literal default
//   (`= std.Io.Mutex.init` → state = `.unlocked` = 0). That default is
//   ONLY applied when the struct is built via `Connection{ ... }` literal
//   syntax. Callers such as `createClientConnection` use
//
//       const c = try allocator.create(Connection);   // uninitialized bytes
//       c.init(allocator, role, sock_fd, peer);        // writes every field EXCEPT mu
//
//   Because `Connection.init` at conn.zig:927 does NOT assign `self.mu`,
//   the mutex's `state` atomic retains whatever bytes the allocator returned.
//   In the reproducing build the allocator reliably returns a page where
//   `mu.state.raw` decodes to `State.contended` (raw value 0x02). The
//   first `lockUncancelable` call on that mutex observes
//   `initial_state == .contended` and immediately blocks in
//   `futexWait(expect=contended)` — forever, because no thread will ever
//   post a wake.
//
// This test reproduces that exact byte-pattern deterministically by
// pre-filling the Connection's backing bytes with the smoking-gun
// pattern before calling init(). Pre-fix the assertion fails (mu.state
// remains non-zero). Post-fix the single-line assignment in
// Connection.init (`self.mu = std.Io.Mutex.init;`) zeros the state word
// and the assertion passes.
//
// A secondary "live lock" subtest spawns a background thread that tries
// to actually lock() then unlock() the mutex, and asserts the whole
// round-trip completes inside 500 ms. Pre-fix the thread blocks in
// futexWait forever; a watchdog on the main thread detects the stall
// and fails the test with a deterministic timeout rather than hanging
// CI.

const std = @import("std");
const builtin = @import("builtin");
const conn_mod = @import("quic_conn");

// Zig 0.16.0 removed both `std.Thread.sleep` and `std.time.sleep`. On
// Linux we call nanosleep directly; the watchdog step (5 ms) is well
// under the deadline so a single partial sleep is fine.
fn nanosleep_ns(ns: u64) void {
    if (builtin.os.tag != .linux) return;
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

// Expose the raw u32 backing `mu.state.raw` without triggering an
// invalid-enum trap when the pre-init memory pattern is non-exhaustive
// (e.g. 0xAAAAAAAA). We only care about the bit pattern, not the enum
// interpretation.
fn mutexStateRaw(conn: *const conn_mod.Connection) u32 {
    const state_ptr: *const u32 = @ptrCast(&conn.mu.state.raw);
    return @atomicLoad(u32, state_ptr, .monotonic);
}

test "Connection.init zeroes mu.state even when backing bytes start as contended (0x02)" {
    // Use a raw page-allocator so we can control the initial byte
    // pattern deterministically. The std.heap.page_allocator is fine —
    // we write into the buffer ourselves before calling init().
    const gpa_ref = std.heap.page_allocator;
    var gpa_copy = gpa_ref;
    const alloc_ptr: *std.mem.Allocator = &gpa_copy;

    // Allocate raw bytes of the exact size/alignment of Connection so
    // we can pre-fill them before init() runs. Using `create(Connection)`
    // and then doing a @memset on its byte view is equivalent to the
    // real codepath (allocator.create → per-field init), except we also
    // force the pre-init pattern to the smoking-gun byte value.
    const conn_ptr = try gpa_copy.create(conn_mod.Connection);
    defer gpa_copy.destroy(conn_ptr);

    // Force the worst-case pre-init pattern the triage observed in GDB:
    // every byte = 0x02, which makes mu.state.raw (u32 little-endian)
    // decode to 0x02020202. The low byte (0x02) alone is enough to
    // trigger the stuck-lock path in Io.Mutex.lockUncancelable, because
    // it does cmpxchgStrong(.unlocked → .locked_once) first and only
    // examines initial_state equality against .contended (== 2) on the
    // low 32 bits. A pre-fill of 0x02 guarantees the stuck-lock branch.
    const conn_bytes: [*]u8 = @ptrCast(conn_ptr);
    @memset(conn_bytes[0..@sizeOf(conn_mod.Connection)], 0x02);

    // Sanity check: confirm the pre-init state word really is non-zero
    // (i.e. the memset landed). If this fails, the test setup is broken
    // and the later assertion would be misleading.
    try std.testing.expect(mutexStateRaw(conn_ptr) != 0);

    // Now run the real init() — this is the code under test.
    conn_ptr.init(
        alloc_ptr,
        .Client,
        -1,
        conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433),
    );
    defer conn_ptr.deinit();

    // Primary assertion: after init(), the mutex MUST be in the
    // .unlocked state (raw value 0). Pre-fix this is 0x02020202 (or
    // 0x02 for the low byte depending on endianness) because init
    // never touched mu.state. Post-fix this is 0 because
    // `self.mu = std.Io.Mutex.init;` was added to the body.
    const state_after = mutexStateRaw(conn_ptr);
    if (state_after != 0) {
        std.debug.print(
            "\n  FAIL: Connection.mu.state.raw = 0x{X:0>8} after init (expected 0x00000000)\n" ++
                "  This means Connection.init did not initialize the mutex — the default\n" ++
                "  `mu: std.Io.Mutex = std.Io.Mutex.init` is bypassed by allocator.create()\n" ++
                "  + per-field init().\n",
            .{state_after},
        );
    }
    try std.testing.expectEqual(@as(u32, 0), state_after);
}

test "Connection.init produces a mutex that can actually be locked and unlocked within 500ms" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const gpa_ref = std.heap.page_allocator;
    var gpa_copy = gpa_ref;
    const alloc_ptr: *std.mem.Allocator = &gpa_copy;

    const conn_ptr = try gpa_copy.create(conn_mod.Connection);
    defer gpa_copy.destroy(conn_ptr);

    // Same pre-fill pattern: stamp the raw bytes with 0x02 so that if
    // init() forgets to assign self.mu, the subsequent lockUncancelable
    // call takes the stuck-futex branch (initial_state == .contended).
    const conn_bytes: [*]u8 = @ptrCast(conn_ptr);
    @memset(conn_bytes[0..@sizeOf(conn_mod.Connection)], 0x02);

    conn_ptr.init(
        alloc_ptr,
        .Client,
        -1,
        conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433),
    );
    defer conn_ptr.deinit();

    // Background thread tries to lock + unlock the mutex. Post-fix this
    // completes in microseconds. Pre-fix it blocks indefinitely in
    // futexWait(expect=contended) because the stale byte pattern makes
    // lockUncancelable think the mutex is already contended but no
    // holder exists to post a wake.
    const done = try std.testing.allocator.create(std.atomic.Value(u32));
    defer std.testing.allocator.destroy(done);
    done.* = .init(0);

    const Ctx = struct {
        conn: *conn_mod.Connection,
        done: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            const io = std.Io.Threaded.global_single_threaded.io();
            ctx.conn.mu.lockUncancelable(io);
            ctx.conn.mu.unlock(io);
            ctx.done.store(1, .release);
        }
    };
    var ctx = Ctx{ .conn = conn_ptr, .done = done };

    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    // Poll the completion flag for up to 500 ms with 5 ms granularity.
    // If the mutex is stuck we will still exit this loop in bounded
    // time so CI reports a clean FAIL rather than a process hang.
    const deadline_ns = 500 * std.time.ns_per_ms;
    const step_ns = 5 * std.time.ns_per_ms;
    var waited_ns: u64 = 0;
    while (waited_ns < deadline_ns) : (waited_ns += step_ns) {
        if (done.load(.acquire) == 1) break;
        nanosleep_ns(step_ns);
    }

    const completed = done.load(.acquire) == 1;
    if (!completed) {
        std.debug.print(
            "\n  FAIL: lock/unlock round-trip did not complete within 500ms.\n" ++
                "  Connection.mu.state.raw = 0x{X:0>8} — the mutex is stuck in\n" ++
                "  futexWait(expect=contended) because Connection.init never\n" ++
                "  reset it to .unlocked. The worker thread is blocked forever.\n" ++
                "  We intentionally DETACH rather than join() so the test process\n" ++
                "  can exit cleanly with a FAIL status.\n",
            .{mutexStateRaw(conn_ptr)},
        );
        // Detach the stuck thread — joining it would re-introduce the
        // hang we are trying to detect. The OS will reap it at process
        // exit.
        t.detach();
        return error.LockStalled;
    }
    t.join();
}
