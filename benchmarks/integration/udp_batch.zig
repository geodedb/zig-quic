// benchmarks/integration/udp_batch.zig
// SPDX-License-Identifier: Apache-2.0
//
// Integration benchmark: UDP single sendto() vs batched sendmmsg() on
// a localhost socket pair.
//
// Measurement logic is the send-side core extracted from
// bench/udp_batch_bench.zig (runSingle / runBatch). Legacy bench:
// - bind two sockets to 127.0.0.1:0 (src/dst, ephemeral ports)
// - connect the src to the dst address, then issue 10k * BATCH sends
// - drain the receiver between variants so the kernel buffer doesn't
//   back-pressure the next run
// - compute packets/sec + syscalls/packet and (in --mode=both) print
//   a speedup vs syscall-reduction ratio
// This file preserves the send-side measurement and drops the CLI
// harness; bench_runner dispatches via spec.variant.
//
// Linux-only real path: sendto is a lone syscall per datagram; sendmmsg
// submits up to BATCH=16 datagrams in one syscall. The production hot
// path (src/quic/endpoint/udp_transport.zig:sendBatchFn, used when
// tx_pacer flushes a drained batch) exercises exactly this primitive,
// so the bench is a faithful proxy for UDP tx efficiency under load.
//
// Syscall tuple + struct shapes are the 0.16.0 `std.os.linux` API:
// `linux.socket/bind/getsockname/sendto/recvfrom/sendmmsg/close` return
// `usize` (raw syscall return) with negative values encoding -errno.
// `std.posix.socket` etc. do NOT exist in 0.16.0, so we use
// `std.os.linux.*` directly. `linux.mmsghdr` is non-const (no
// `mmsghdr_const` analogue); payload base is const-cast into
// `iovec_const` and then ptrCast onto the non-const `iov` field,
// mirroring src/quic/endpoint/udp_transport.zig:sendBatchFn.
//
// On non-Linux targets (macOS/Windows) sendmmsg is unavailable, so the
// runner emits a placeholder RunOutput that keeps the suite cross-
// platform-compilable. Phase 7's perf-gate.sh wraps this bench's JSON
// output with the ratio thresholds from scripts/perf_udp_batch_gate.sh
// (syscall reduction >= 4.0x, throughput speedup >= 0.95x); those
// gates are ratio-between-variants, not per-variant, so compare.zig
// doesn't enforce absolutes here.
//
// PACKET_COUNT = 10_000 matches the legacy bench's default `iters`
// inner loop size (legacy used iters * batch = 20_000 * 16 = 320k
// packets per variant at BATCH=16; we run a single 10k send loop per
// variant, scaled to keep wall-clock around a second on localhost).

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");

const PACKET_COUNT: u64 = 10_000;
const PAYLOAD_LEN: usize = 1200;
const BATCH: usize = 16;

/// Convert a raw Linux syscall return (`usize`) into a signed count or
/// an errno-derived error. Mirrors legacy bench/udp_batch_bench.zig's
/// expectOk shim.
fn linuxExpectOk(rc: usize) !usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        const errno: u32 = @intCast(-signed);
        const e: std.posix.E = @enumFromInt(errno);
        switch (e) {
            .SUCCESS => return rc,
            .AGAIN => return error.WouldBlock,
            else => return error.SyscallFailed,
        }
    }
    return rc;
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // Not measured off Linux, where the endpoint's UDP transport is not
    // supported: a not-measured row, not placeholder numbers (SONNY-6668).
    if (try common.requireLinux(allocator, builtin.os.tag)) |nm| return nm;

    const linux = std.os.linux;
    const use_batch = std.mem.eql(u8, spec.variant, "batch");

    // Create receiver socket, bind to 127.0.0.1:0 (ephemeral port).
    const recv_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    _ = try linuxExpectOk(recv_rc);
    const recv_fd: i32 = @intCast(recv_rc);
    defer _ = linux.close(recv_fd);

    var bind_addr: linux.sockaddr.in = .{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
    const bind_rc = linux.bind(recv_fd, @ptrCast(&bind_addr), @sizeOf(linux.sockaddr.in));
    _ = try linuxExpectOk(bind_rc);

    // Query bound port; legacy uses sockaddr.storage + getsockname so
    // the kernel-assigned ephemeral port is observable. We re-use the
    // in-place sockaddr.in since we only bind AF_INET.
    var actual_addr: linux.sockaddr.in = bind_addr;
    var actual_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const getname_rc = linux.getsockname(recv_fd, @ptrCast(&actual_addr), &actual_len);
    _ = try linuxExpectOk(getname_rc);

    // Create sender socket (connectionless; we pass dst addr per send).
    const send_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    _ = try linuxExpectOk(send_rc);
    const send_fd: i32 = @intCast(send_rc);
    defer _ = linux.close(send_fd);

    var payload: [PAYLOAD_LEN]u8 = undefined;
    @memset(&payload, 0x55);
    const latencies = try allocator.alloc(u64, PACKET_COUNT);
    @memset(latencies, 0);

    const wall_start = common.nowNs();
    if (use_batch) {
        // Pre-build BATCH worth of iovec_const + mmsghdr pointing at the
        // shared payload. Kernel reads, never writes, so the const-cast
        // into the non-const iov field is safe (same pattern as
        // src/quic/endpoint/udp_transport.zig:sendBatchFn).
        var iovs: [BATCH]std.posix.iovec_const = undefined;
        var mhdrs: [BATCH]linux.mmsghdr = undefined;
        for (&iovs, &mhdrs) |*iov, *mh| {
            iov.* = .{ .base = &payload, .len = PAYLOAD_LEN };
            mh.* = .{
                .hdr = .{
                    .name = @ptrCast(&actual_addr),
                    .namelen = @sizeOf(linux.sockaddr.in),
                    .iov = @ptrCast(iov),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }

        var sent: u64 = 0;
        while (sent < PACKET_COUNT) {
            // Each syscall submits up to BATCH datagrams. We amortize
            // the measured wall time across the actual count returned
            // so per-packet latency reflects the syscall cost, not the
            // per-datagram work (which the kernel batches internally).
            const chunk: u32 = @intCast(@min(BATCH, PACKET_COUNT - sent));
            const t0 = common.nowNs();
            const rc = linux.sendmmsg(send_fd, &mhdrs, chunk, 0);
            const dt = common.nowNs() - t0;
            const signed: isize = @bitCast(rc);
            if (signed <= 0) break; // errno or zero-progress -> bail
            const n: u64 = @intCast(signed);
            const per_packet = dt / @max(n, 1);
            var i: u64 = 0;
            while (i < n and sent + i < PACKET_COUNT) : (i += 1) {
                latencies[sent + i] = per_packet;
            }
            sent += n;
        }
    } else {
        // Single-send path: one sendto per datagram. This is the
        // baseline the batched path has to beat on syscall-count
        // efficiency.
        for (0..PACKET_COUNT) |i| {
            const t0 = common.nowNs();
            const rc = linux.sendto(
                send_fd,
                &payload,
                PAYLOAD_LEN,
                0,
                @ptrCast(&actual_addr),
                @sizeOf(linux.sockaddr.in),
            );
            const dt = common.nowNs() - t0;
            _ = linuxExpectOk(rc) catch {
                latencies[i] = dt;
                continue;
            };
            latencies[i] = dt;
        }
    }
    const wall_end = common.nowNs();

    // Drain the receiver between runs. Without this, the kernel's
    // per-socket receive buffer fills and sendto/sendmmsg start
    // returning ENOBUFS. Legacy bench recvfrom's every packet; for the
    // send-focused measurement we only need to drain to avoid cross-
    // variant interference (runRepeated calls run() 7 times).
    var drain_buf: [PAYLOAD_LEN * 2]u8 = undefined;
    while (true) {
        const rc = linux.recvfrom(
            recv_fd,
            &drain_buf,
            drain_buf.len,
            linux.MSG.DONTWAIT,
            null,
            null,
        );
        _ = linuxExpectOk(rc) catch break;
    }

    return .{
        .iterations = PACKET_COUNT,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .packets_transferred = PACKET_COUNT,
        .bytes_transferred = PACKET_COUNT * PAYLOAD_LEN,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/udp_batch", .variant = "single", .iterations = PACKET_COUNT, .payload_bytes = PAYLOAD_LEN },
    .{ .name = "integration/udp_batch", .variant = "batch", .iterations = PACKET_COUNT, .payload_bytes = PAYLOAD_LEN },
};
