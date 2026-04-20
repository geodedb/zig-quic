// benchmarks/micro/aead.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: AEAD encrypt hot path (1200-byte payload).
//
// Measurement logic is extracted from bench/bench_tls_aead.zig's encrypt
// loop (payload_size=1024/1500; this bench fixes 1200 to match QUIC MTU).
// The plan template referenced `crypto.aesGcmEncrypt` /
// `crypto.chacha20Poly1305Encrypt`; the real primitive exported by
// `src/quic/crypto_quic.zig` is `aeadEncrypt(suite, key, iv, pn, aad, pt, out)`
// with suite ∈ {aes_128_gcm, aes_256_gcm, chacha20_poly1305}. Using the
// quic_crypto entry point here (rather than std.crypto directly) keeps the
// bench aligned with the hot path exercised in production (connection.rs
// -> crypto_quic.aeadEncrypt -> crypto_zig.aeadEncrypt).
//
// AEAD encrypt of 1200 bytes is ~0.5-5 µs depending on arch/AES-NI, well
// above clock_gettime resolution, so per-op timing is accurate without the
// BATCH_SIZE trick used in varint/pacing. This matches the
// header_protection template.
//
// No absolute gate (docs/PERFORMANCE_TARGETS.md lists only varint,
// pacing, and hp_decode). Regression detection is via compare.zig's
// tiered ratio thresholds.

const std = @import("std");
const common = @import("bench_common");
const crypto = @import("quic_crypto");

const PAYLOAD_LEN: usize = 1200;

fn runVariant(
    allocator: std.mem.Allocator,
    spec: common.ScenarioSpec,
    suite: crypto.AeadSuite,
    key: []const u8,
) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    const iv = [_]u8{0x33} ** 12;
    const aad = [_]u8{0x44} ** 16;
    var pt: [PAYLOAD_LEN]u8 = undefined;
    @memset(&pt, 0x55);
    var out_buf: [PAYLOAD_LEN + 16]u8 = undefined;

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        const pn: u64 = warm_i + 1;
        _ = crypto.aeadEncrypt(suite, key, &iv, pn, &aad, &pt, &out_buf) catch 0;
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const pn: u64 = i + 1;
        const t0 = common.nowNs();
        const n = crypto.aeadEncrypt(suite, key, &iv, pn, &aad, &pt, &out_buf) catch {
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
        .bytes_transferred = N * PAYLOAD_LEN,
    };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (std.mem.eql(u8, spec.variant, "chacha20_poly1305")) {
        const key = [_]u8{0x22} ** 32;
        return runVariant(allocator, spec, .chacha20_poly1305, &key);
    }
    // Default + explicit "aes128_gcm"
    const key = [_]u8{0x11} ** 16;
    return runVariant(allocator, spec, .aes_128_gcm, &key);
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/aead", .variant = "aes128_gcm", .iterations = 10_000, .warmup_iterations = 500, .payload_bytes = PAYLOAD_LEN },
    .{ .name = "micro/aead", .variant = "chacha20_poly1305", .iterations = 10_000, .warmup_iterations = 500, .payload_bytes = PAYLOAD_LEN },
};
