// benchmarks/micro/frame_serialization.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: QUIC frame encode/decode hot paths with per-op
// heap allocation accounting. Motivated by issue #163 ("per-frame
// heap alloc sites"): every STREAM/ACK/... encode should stay on the
// stack (zero `alloc_bytes`), and the short-header encode/decode path
// MUST be allocation-free to preserve the 4th absolute gate in
// docs/PERFORMANCE_TARGETS.md:33-34.
//
// Methodology:
//   * Each iteration wraps the outer benchmark allocator with a
//     CountingAllocator that records `alloc_calls` and `alloc_bytes`
//     across the measured loop. Scratch allocations performed by the
//     harness BEFORE the loop (e.g., `latencies` buffer, protected
//     sample packets for decode) go through the raw allocator so they
//     do not contaminate the budget.
//   * Per-call encode for tiny frames (padding/ping/window_update) is
//     far below clock_gettime resolution, so we sample BATCH_SIZE ops
//     per latency entry (matches pacing/varint micro-benches).
//   * short_header_encode/decode use the INTO forms:
//       - `encodeShortProtectedInto(stack_buf, ...)` writes the full
//         protected 1-RTT packet into a caller-owned slice.
//       - `decodeShortProtectedInto(..., stack_payload_buf)` writes
//         the decrypted payload into caller-owned storage.
//     Both bypass the allocating wrappers (`encodeShortProtected` /
//     `decodeShortProtected`) that allocate a new `[]u8`.
//
// Variants (13 total):
//   Frame-type encode (stack writer, zero allocs expected):
//     stream, ack, padding, crypto, reset_stream, stop_sending, ping,
//     goaway, window_update, max_stream_id, connection_close
//   Short-header protected path (allocation-free by contract):
//     short_header_encode, short_header_decode
//
// Mapping notes (plan uses generic names; QUIC has no exact match for
// HTTP/2-style frames):
//   goaway        -> HANDSHAKE_DONE   (closest "session shutdown"
//                                     signal in QUIC; RFC 9000 §19.20)
//   window_update -> MAX_DATA         (connection-level flow-control
//                                     window update; RFC 9000 §19.9)
//   max_stream_id -> MAX_STREAMS_BIDI (concurrent bidi stream ceiling;
//                                     RFC 9000 §19.11)

const std = @import("std");
const common = @import("bench_common");
const frame = @import("quic_frame");
const pkt = @import("quic_packet");

const BATCH_SIZE: u64 = 256;

/// Wraps a parent std.mem.Allocator and counts every raw allocator call
/// plus the bytes requested on `alloc`/`resize`/`remap`. The signature
/// mirrors the std.mem.Allocator.VTable layout required by Zig 0.16
/// (alignment is `std.mem.Alignment`, not `u8`).
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

const FrameKind = enum {
    stream,
    ack,
    padding,
    crypto,
    reset_stream,
    stop_sending,
    ping,
    goaway, // -> HANDSHAKE_DONE (QUIC has no GOAWAY; §19.20)
    window_update, // -> MAX_DATA (§19.9)
    max_stream_id, // -> MAX_STREAMS_BIDI (§19.11)
    connection_close,
    short_header_encode,
    short_header_decode,
};

fn classify(variant: []const u8) ?FrameKind {
    inline for (@typeInfo(FrameKind).@"enum".fields) |f| {
        if (std.mem.eql(u8, variant, f.name)) return @enumFromInt(f.value);
    }
    return null;
}

/// Encode a single frame of the given kind into `buf` using a fixed-size
/// stack writer. Returns the number of bytes written. No heap allocations.
fn encodeFrameInto(kind: FrameKind, buf: []u8, seed: u64) !usize {
    var w: std.Io.Writer = .fixed(buf);
    const payload_static = [_]u8{ 'Z', 'Q', 'F', 'B' };
    switch (kind) {
        .stream => {
            const f = frame.Frame{
                .stream = .{
                    .stream_id = (seed & 0x3f) | 0x04,
                    .offset = seed * 4,
                    .fin = (seed & 1) == 0,
                    .data = &payload_static,
                },
            };
            _ = try f.write(&w);
        },
        .ack => {
            // ACK with largest varying across the sweep; empty ranges
            // (no gap/length pairs) keeps the frame deterministic and
            // avoids slice allocations for the `ranges` field.
            const f = frame.Frame{
                .ack = .{
                    .largest = seed & 0xffff,
                    .ack_delay = seed & 0x1f,
                    .first_range = seed & 0x0f,
                    .ranges = &[_]frame.AckRange{},
                    .ecn = null,
                },
            };
            _ = try f.write(&w);
        },
        .padding => {
            const f = frame.Frame{ .padding = 16 };
            _ = try f.write(&w);
        },
        .crypto => {
            const f = frame.Frame{
                .crypto = .{ .offset = seed * 4, .data = &payload_static },
            };
            _ = try f.write(&w);
        },
        .reset_stream => {
            const f = frame.Frame{
                .reset_stream = .{
                    .stream_id = (seed & 0x3f) | 0x04,
                    .error_code = seed & 0xff,
                    .final_size = seed * 16,
                },
            };
            _ = try f.write(&w);
        },
        .stop_sending => {
            const f = frame.Frame{
                .stop_sending = .{
                    .stream_id = (seed & 0x3f) | 0x04,
                    .error_code = seed & 0xff,
                },
            };
            _ = try f.write(&w);
        },
        .ping => {
            const f = frame.Frame{ .ping = {} };
            _ = try f.write(&w);
        },
        .goaway => {
            // Closest QUIC analog: HANDSHAKE_DONE (1-byte, server-only
            // "handshake complete / shutdown permitted" marker).
            const f = frame.Frame{ .handshake_done = {} };
            _ = try f.write(&w);
        },
        .window_update => {
            // QUIC equivalent: MAX_DATA (connection-level window).
            const f = frame.Frame{
                .max_data = .{ .max = seed * 1024 },
            };
            _ = try f.write(&w);
        },
        .max_stream_id => {
            // QUIC equivalent: MAX_STREAMS_BIDI (concurrent stream ceiling).
            const f = frame.Frame{
                .max_streams_bidi = .{ .max = seed & 0xffff },
            };
            _ = try f.write(&w);
        },
        .connection_close => {
            const f = frame.Frame{
                .connection_close = .{
                    .error_code = seed & 0xffff,
                    .frame_type = 0,
                    .reason = "bench",
                },
            };
            _ = try f.write(&w);
        },
        .short_header_encode, .short_header_decode => unreachable,
    }
    return w.end;
}

fn runFrameEncode(
    allocator: std.mem.Allocator,
    spec: common.ScenarioSpec,
    kind: FrameKind,
) !common.RunOutput {
    const N = spec.iterations;
    // `latencies` lives OUTSIDE the counting scope -- its allocation is
    // a harness artefact, not a per-op cost.
    const latencies = try allocator.alloc(u64, N);

    var frame_buf: [256]u8 = undefined;

    // Warmup (also outside counting scope; primes icache/branch predictor).
    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        _ = encodeFrameInto(kind, &frame_buf, warm_i) catch 0;
    }

    // Counting wrapper: tracks allocations attributable to the measured loop.
    // The frame encode path takes no allocator parameter and writes into a
    // stack buffer, so we expect zero allocations. The wrapper still runs so
    // any future regression (e.g., a writeX variant that allocates an ArrayList
    // internally) lights up as non-zero alloc_bytes.
    var ca = CountingAllocator.init(allocator);
    ca.reset();

    const wall_start = common.nowNs();
    var sink: usize = 0;
    for (0..N) |i| {
        const t0 = common.nowNs();
        var k: u64 = 0;
        while (k < BATCH_SIZE) : (k += 1) {
            const seed: u64 = i *% BATCH_SIZE +% k;
            const n = encodeFrameInto(kind, &frame_buf, seed) catch 0;
            sink +%= n;
        }
        const dt = common.nowNs() - t0;
        latencies[i] = dt;
    }
    const wall_end = common.nowNs();
    std.mem.doNotOptimizeAway(sink);
    std.mem.doNotOptimizeAway(frame_buf[0]);

    return .{
        .iterations = N * BATCH_SIZE,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .latency_sample_operations = BATCH_SIZE,
        .alloc_count = @intCast(ca.alloc_calls + ca.resize_calls + ca.remap_calls),
        .alloc_bytes = ca.alloc_bytes,
    };
}

fn runShortHeaderEncode(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const dcid = "HPBM";
    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    const payload = [_]u8{0x01};

    var out_buf: [128]u8 = undefined;

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const pn: u32 = @intCast((warm_i & 0xFFFFFFFF) + 1);
        _ = pkt.encodeShortProtectedInto(&out_buf, dcid, pn, 2, &payload, keys, false) catch continue;
    }

    var ca = CountingAllocator.init(allocator);
    ca.reset();
    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        const pn: u32 = @intCast((i & 0xFFFFFFFF) + 1);
        const n = pkt.encodeShortProtectedInto(&out_buf, dcid, pn, 2, &payload, keys, (i & 1) == 1) catch {
            latencies[i] = common.nowNs() - t0;
            continue;
        };
        const lat = common.nowNs() - t0;
        std.mem.doNotOptimizeAway(n);
        std.mem.doNotOptimizeAway(out_buf[0]);
        latencies[i] = lat;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .alloc_count = @intCast(ca.alloc_calls + ca.resize_calls + ca.remap_calls),
        .alloc_bytes = ca.alloc_bytes,
    };
}

fn runShortHeaderDecode(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const dcid = "HPBM";
    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    const payload = [_]u8{0x01};

    // Build two protected sample packets (one per key phase) OUTSIDE the
    // counting scope. These are harness artefacts, not per-op costs.
    var pkt0_buf: [128]u8 = undefined;
    var pkt1_buf: [128]u8 = undefined;
    const pkt0_len = try pkt.encodeShortProtectedInto(&pkt0_buf, dcid, 1, 2, &payload, keys, false);
    const pkt1_len = try pkt.encodeShortProtectedInto(&pkt1_buf, dcid, 2, 2, &payload, keys, true);
    const sp0 = pkt0_buf[0..pkt0_len];
    const sp1 = pkt1_buf[0..pkt1_len];

    var payload_out: [128]u8 = undefined;

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const bytes = if ((warm_i & 1) == 0) sp0 else sp1;
        _ = pkt.decodeShortProtectedInto(bytes, dcid.len, keys, 0, &payload_out) catch continue;
    }

    var ca = CountingAllocator.init(allocator);
    ca.reset();
    const wall_start = common.nowNs();
    for (0..N) |i| {
        const bytes = if ((i & 1) == 0) sp0 else sp1;
        const t0 = common.nowNs();
        const d = pkt.decodeShortProtectedInto(bytes, dcid.len, keys, 0, &payload_out) catch {
            latencies[i] = common.nowNs() - t0;
            continue;
        };
        const lat = common.nowNs() - t0;
        std.mem.doNotOptimizeAway(d.packet_number);
        std.mem.doNotOptimizeAway(payload_out[0]);
        latencies[i] = lat;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .alloc_count = @intCast(ca.alloc_calls + ca.resize_calls + ca.remap_calls),
        .alloc_bytes = ca.alloc_bytes,
    };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const kind = classify(spec.variant) orelse return error.UnknownVariant;
    return switch (kind) {
        .short_header_encode => runShortHeaderEncode(allocator, spec),
        .short_header_decode => runShortHeaderDecode(allocator, spec),
        else => runFrameEncode(allocator, spec, kind),
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/frame_serialization", .variant = "stream", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "ack", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "padding", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "crypto", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "reset_stream", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "stop_sending", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "ping", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "goaway", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "window_update", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "max_stream_id", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "connection_close", .iterations = 200, .warmup_iterations = 500 },
    .{ .name = "micro/frame_serialization", .variant = "short_header_encode", .iterations = 2_000, .warmup_iterations = 200 },
    .{ .name = "micro/frame_serialization", .variant = "short_header_decode", .iterations = 2_000, .warmup_iterations = 200 },
};
