// benchmarks/micro/header_protection.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: QUIC short-header protection encode/decode hot path.
//
// Measurement logic is extracted from bench/main.zig's hp section
// (~lines 287-330). The plan template referenced a non-existent
// `crypto.hpDecode`; the real hot-path primitives exposed via
// `quic_packet` are `decodeShortProtected` and `encodeShortProtected`
// (from src/quic/packet.zig, re-exported through src/quic/packet/packet.zig).
// This is what bench/main.zig measured, so the absolute gate numbers
// remain comparable.
//
// Inputs mirror bench/main.zig: 4-byte dcid "HPBM", zero'd AEAD keys,
// a 1-byte plaintext payload, and two protected packets covering both
// key phases (0 and 1) so the branch predictor is not biased.
//
// Absolute gate (docs/PERFORMANCE_TARGETS.md, benchmarks/compare.zig):
//   micro/header_protection decode -> latency_p99_ns <= 400_000

const std = @import("std");
const common = @import("bench_common");
const pkt = @import("quic_packet");

const dcid_static = "HPBM";
const payload_static = [_]u8{0x01};

fn runDecode(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    // Two protected packets, one per key phase, per bench/main.zig:300-304.
    const sp0 = try pkt.encodeShortProtected(allocator, dcid_static, 1, 2, &payload_static, keys, false);
    defer allocator.free(sp0);
    const sp1 = try pkt.encodeShortProtected(allocator, dcid_static, 2, 2, &payload_static, keys, true);
    defer allocator.free(sp1);

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const bytes = if ((warm_i & 1) == 0) sp0 else sp1;
        const d = pkt.decodeShortProtected(allocator, bytes, dcid_static.len, keys, 0) catch continue;
        allocator.free(d.payload);
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const bytes = if ((i & 1) == 0) sp0 else sp1;
        const t0 = common.nowNs();
        const d = pkt.decodeShortProtected(allocator, bytes, dcid_static.len, keys, 0) catch {
            latencies[i] = common.nowNs() - t0;
            continue;
        };
        const lat = common.nowNs() - t0;
        std.mem.doNotOptimizeAway(d.packet_number);
        allocator.free(d.payload);
        latencies[i] = lat;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

fn runEncode(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const pn: u32 = @intCast((warm_i & 0xFFFFFFFF) + 1);
        const out = pkt.encodeShortProtected(allocator, dcid_static, pn, 2, &payload_static, keys, false) catch continue;
        allocator.free(out);
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const pn: u32 = @intCast((i & 0xFFFFFFFF) + 1);
        const t0 = common.nowNs();
        const out = pkt.encodeShortProtected(allocator, dcid_static, pn, 2, &payload_static, keys, false) catch {
            latencies[i] = common.nowNs() - t0;
            continue;
        };
        const lat = common.nowNs() - t0;
        std.mem.doNotOptimizeAway(out.ptr);
        allocator.free(out);
        latencies[i] = lat;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (std.mem.eql(u8, spec.variant, "encode")) {
        return runEncode(allocator, spec);
    }
    return runDecode(allocator, spec);
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/header_protection", .variant = "decode", .iterations = 2_000, .warmup_iterations = 200 },
    .{ .name = "micro/header_protection", .variant = "encode", .iterations = 2_000, .warmup_iterations = 200 },
};
