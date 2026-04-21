// benchmarks/micro/send_buffer_alloc.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: packet-assembly "send buffer" heap allocations.
//
// Motivated by issue #163 ("per-frame heap alloc sites"). Task 4.1's
// `micro/frame_serialization.zig` covered `Frame.write(anywriter)`,
// which writes into a fixed stack buffer and allocates zero bytes by
// design. However, the actual alloc sites live one layer up in the
// packet-assembly path that WRAPS `Frame.write` with a growing
// `std.ArrayList(u8)` send buffer:
//
//   - src/quic/endpoint/handshake_integration.zig:741-770  (server Initial flight)
//   - src/quic/endpoint/client.zig:251-332                  (client Initial probe)
//   - src/quic/endpoint/pto.zig:194-231                     (PTO probe)
//   - src/quic/connection/methods_a.zig:220-294             (sendInitialCrypto / sendHandshakeCrypto)
//
// All five sites share the same pattern:
//   1. Declare `var frames: std.ArrayList(u8) = .empty;` (zero-cap).
//   2. Wrap it via `compat.arrayListWriter(&frames, allocator)` and
//      feed `Frame.write(w)` for each frame to send. Each `writeAll`
//      boils down to `frames.appendSlice(...)` -> ArrayList grows.
//   3. (Client Initial only) Pad with `appendNTimes(PADDING, pad_needed)`
//      to reach the 1200-byte RFC 9000 §14.1 minimum -- another resize.
//   4. Call `packet.encodeInitialProtected(...)` which INTERNALLY spins up
//      ANOTHER `std.ArrayList(u8) = .empty` for the protected packet
//      output (see src/quic/packet.zig:522), allocating ~1.4 KiB more.
//
// This bench models the per-send-call alloc budget that would have to
// drop to zero (or a single fixed-cap allocation) for a #163 fix to be
// measurable. Unlike frame_serialization, we expect alloc_bytes to be
// NON-ZERO at the current baseline; the bench is shaped as a
// regression-test gate rather than an absolute upper bound.
//
// Variants (6 total, each shaped after a real call-site workload):
//   stream_only         - 1 STREAM frame carrying 64B payload, no padding
//   stream_plus_ack     - 1 STREAM + 1 ACK frame (typical 1-RTT send)
//   crypto_handshake    - 1 CRYPTO frame carrying 256B TLS handshake chunk
//   initial_padded      - CRYPTO + PADDING to 1200B (client-Initial pattern,
//                         models sendInitialProbe + encodeInitialProtected)
//   pto_probe           - PING + PADDING to 1200B (PTO probe pattern,
//                         models sendPtoProbe Initial path)
//   multi_stream_batch  - 4 STREAM frames back-to-back (coalesce pattern,
//                         models a flush that drains multiple stream writes)

const std = @import("std");
const common = @import("bench_common");
const frame = @import("quic_frame");
const pkt = @import("quic_packet");
const compat = @import("compat");

const BATCH_SIZE: u64 = 16;

// ---------------------------------------------------------------------------
// CountingAllocator: tracks raw allocator calls inside the measured loop.
// Structurally identical to the one in micro/frame_serialization.zig; kept
// in-file to match the established "each micro bench owns its counter"
// pattern rather than cross-coupling via bench_common.
// ---------------------------------------------------------------------------

const CountingAllocator = struct {
    child: std.mem.Allocator,
    alloc_calls: usize = 0,
    resize_calls: usize = 0,
    remap_calls: usize = 0,
    free_calls: usize = 0,
    alloc_bytes: u64 = 0,

    const Self = @This();

    const vtable = std.mem.Allocator.VTable{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    pub fn init(child: std.mem.Allocator) Self {
        return .{ .child = child };
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn reset(self: *Self) void {
        self.alloc_calls = 0;
        self.resize_calls = 0;
        self.remap_calls = 0;
        self.free_calls = 0;
        self.alloc_bytes = 0;
    }

    fn fromPtr(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self = fromPtr(ctx);
        self.alloc_calls += 1;
        self.alloc_bytes += len;
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self = fromPtr(ctx);
        self.resize_calls += 1;
        if (new_len > memory.len) self.alloc_bytes += (new_len - memory.len);
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self = fromPtr(ctx);
        self.remap_calls += 1;
        if (new_len > memory.len) self.alloc_bytes += (new_len - memory.len);
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self = fromPtr(ctx);
        self.free_calls += 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

const Scenario = enum {
    stream_only,
    stream_plus_ack,
    crypto_handshake,
    initial_padded,
    pto_probe,
    multi_stream_batch,
};

fn classify(variant: []const u8) ?Scenario {
    inline for (@typeInfo(Scenario).@"enum".fields) |f| {
        if (std.mem.eql(u8, variant, f.name)) return @enumFromInt(f.value);
    }
    return null;
}

const STREAM_PAYLOAD = [_]u8{0x5a} ** 64;
const CRYPTO_PAYLOAD = [_]u8{0xc1} ** 256;
const DCID = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
const SCID = [_]u8{ 0x5c, 0x5d, 0x5e, 0x5f };
const ZERO_KEYS = pkt.InitialKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

/// Drives one complete "assemble and encode a send packet" pass using the
/// allocator provided by the caller (which will be the CountingAllocator).
/// Mirrors the call-site pattern: empty ArrayList -> frame writes grow it ->
/// encodeInitialProtected allocates the protected output buffer.
fn runOnce(alloc: std.mem.Allocator, scenario: Scenario, seed: u64) !void {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(alloc);
    const w = compat.arrayListWriter(&frames, alloc);

    switch (scenario) {
        .stream_only => {
            const f = frame.Frame{
                .stream = .{
                    .stream_id = (seed & 0x3f) | 0x04,
                    .offset = seed * 64,
                    .fin = false,
                    .data = &STREAM_PAYLOAD,
                },
            };
            _ = try f.write(w);
        },
        .stream_plus_ack => {
            const sf = frame.Frame{
                .stream = .{
                    .stream_id = (seed & 0x3f) | 0x04,
                    .offset = seed * 64,
                    .fin = false,
                    .data = &STREAM_PAYLOAD,
                },
            };
            _ = try sf.write(w);
            const af = frame.Frame{
                .ack = .{
                    .largest = seed & 0xffff,
                    .ack_delay = seed & 0x1f,
                    .first_range = seed & 0x0f,
                    .ranges = &[_]frame.AckRange{},
                    .ecn = null,
                },
            };
            _ = try af.write(w);
        },
        .crypto_handshake => {
            const f = frame.Frame{
                .crypto = .{ .offset = seed * 256, .data = &CRYPTO_PAYLOAD },
            };
            _ = try f.write(w);
        },
        .initial_padded => {
            // Mirror sendInitialProbe (client.zig:281, 328-332):
            //   1. CRYPTO frame carrying ClientHello-ish 256-byte chunk
            //   2. PADDING appendNTimes to reach the 1200-byte plaintext floor
            //      (exact floor math would require header-overhead awareness;
            //      1024 bytes is within the same growth-class for this bench).
            const cf = frame.Frame{
                .crypto = .{ .offset = 0, .data = &CRYPTO_PAYLOAD },
            };
            _ = try cf.write(w);
            const pad_target: usize = 1024;
            if (frames.items.len < pad_target) {
                const pad_needed = pad_target - frames.items.len;
                try frames.appendNTimes(alloc, @intFromEnum(frame.FrameType.PADDING), pad_needed);
            }
        },
        .pto_probe => {
            // Mirror sendPtoProbe Initial path (pto.zig:194-231):
            //   PING frame + PADDING to 1200-byte plaintext floor.
            const pf = frame.Frame{ .ping = {} };
            _ = try pf.write(w);
            const pad_target: usize = 1024;
            if (frames.items.len < pad_target) {
                const pad_needed = pad_target - frames.items.len;
                try frames.appendNTimes(alloc, @intFromEnum(frame.FrameType.PADDING), pad_needed);
            }
        },
        .multi_stream_batch => {
            // Four STREAM frames back-to-back: models a flush coalescing
            // several pending stream writes into one packet. Each iteration
            // grows the ArrayList; hitting zero allocs post-#163 would
            // require a preallocated / reusable buffer.
            var i: u64 = 0;
            while (i < 4) : (i += 1) {
                const f = frame.Frame{
                    .stream = .{
                        .stream_id = ((seed +% i) & 0x3f) | 0x04,
                        .offset = (seed +% i) * 64,
                        .fin = false,
                        .data = &STREAM_PAYLOAD,
                    },
                };
                _ = try f.write(w);
            }
        },
    }

    // All five call sites culminate in an encodeInitialProtected /
    // encodeHandshakeProtected invocation which allocates another
    // ArrayList(u8) internally for the protected output. For scenarios
    // that map to an Initial-tier flight (crypto_handshake, initial_padded,
    // pto_probe), include that allocation in the budget so the measurement
    // reflects the full per-send-call cost.
    switch (scenario) {
        .crypto_handshake, .initial_padded, .pto_probe => {
            const out = try pkt.encodeInitialProtected(
                alloc,
                0x00000001, // QUIC v1
                &DCID,
                &SCID,
                &[_]u8{}, // no token
                @as(u32, @truncate(seed)),
                2, // pn_len
                frames.items,
                ZERO_KEYS,
            );
            alloc.free(out);
        },
        // stream_only / stream_plus_ack / multi_stream_batch are 1-RTT-class
        // workloads; the short-header encoder is stack-based (see
        // frame_serialization short_header_encode variant which hits zero
        // allocs). Those variants therefore only measure the ArrayList
        // growth of the send buffer itself.
        .stream_only, .stream_plus_ack, .multi_stream_batch => {},
    }
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const scenario = classify(spec.variant) orelse return error.UnknownVariant;
    const N = spec.iterations;

    // `latencies` is a harness artefact; keep it OUTSIDE the counting scope.
    const latencies = try allocator.alloc(u64, N);

    // Warmup (primes icache / branch predictor / allocator freelists).
    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        runOnce(allocator, scenario, warm_i) catch {};
    }

    var ca = CountingAllocator.init(allocator);
    ca.reset();
    const counted = ca.allocator();

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        var k: u64 = 0;
        while (k < BATCH_SIZE) : (k += 1) {
            const seed: u64 = i *% BATCH_SIZE +% k;
            runOnce(counted, scenario, seed) catch {};
        }
        const dt = common.nowNs() - t0;
        latencies[i] = dt / BATCH_SIZE;
    }
    const wall_end = common.nowNs();

    // Normalize alloc_count / alloc_bytes to per-op (matches how the rest of
    // the suite reports these fields: "per-iteration" in bench_common).
    const total_ops: u64 = N * BATCH_SIZE;
    const per_op_count: u64 = @intCast(@divTrunc(ca.alloc_calls + ca.resize_calls + ca.remap_calls, total_ops));
    const per_op_bytes: u64 = @divTrunc(ca.alloc_bytes, total_ops);

    return .{
        .iterations = total_ops,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .alloc_count = per_op_count,
        .alloc_bytes = per_op_bytes,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/send_buffer_alloc", .variant = "stream_only", .iterations = 500, .warmup_iterations = 100 },
    .{ .name = "micro/send_buffer_alloc", .variant = "stream_plus_ack", .iterations = 500, .warmup_iterations = 100 },
    .{ .name = "micro/send_buffer_alloc", .variant = "crypto_handshake", .iterations = 500, .warmup_iterations = 100 },
    .{ .name = "micro/send_buffer_alloc", .variant = "initial_padded", .iterations = 500, .warmup_iterations = 100 },
    .{ .name = "micro/send_buffer_alloc", .variant = "pto_probe", .iterations = 500, .warmup_iterations = 100 },
    .{ .name = "micro/send_buffer_alloc", .variant = "multi_stream_batch", .iterations = 500, .warmup_iterations = 100 },
};
