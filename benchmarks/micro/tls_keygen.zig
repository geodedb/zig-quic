// benchmarks/micro/tls_keygen.zig
// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark: TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
//
// Measurement logic is extracted from bench/bench_tls_handshake.zig's
// benchmarkKeyDerivation + benchmarkHandshakeSecrets loops. The plan
// template referenced `tls13.hkdfExpandLabel`; the real public API
// exposed by the `tls` dep's `quic_tls` module (src/key_schedule.zig)
// is `expandLabel(prk, label, context, out)` -- this is the primitive
// that QUIC's packet protection and TLS 1.3 key derivation sit on top
// of (bench/bench_tls_handshake.zig calls it indirectly via
// deriveHandshakeTraffic / extract).
//
// HKDF-Expand-Label is HMAC-SHA256 over a small label buffer; it runs
// in the low-hundreds-of-ns range -- faster than clock_gettime can
// reliably resolve per call. The primitive is still fast enough that
// per-op sampling picks up real signal, but noise is high.
// We match the header_protection template (straight per-op timing)
// rather than the varint/pacing BATCH_SIZE pattern because the plan
// template calls for one sample per iteration; the extra noise is
// absorbed by the harness's median-of-6 sampler in common.runRepeated.
//
// Output length 32 bytes = SHA-256 digest length = typical TLS traffic
// secret / QUIC AEAD-key derivation path (RFC 9001 §5.1).
//
// No absolute gate (docs/PERFORMANCE_TARGETS.md). Regression detection
// via compare.zig's tiered ratio thresholds.

const std = @import("std");
const common = @import("bench_common");
const ks = @import("quic_tls");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    const latencies = try allocator.alloc(u64, N);

    // 32-byte PRK = SHA-256 digest length; matches TLS 1.3 HKDF state
    // feeding expand-label at the traffic-secret layer.
    const prk = [_]u8{0x11} ** 32;
    const context = [_]u8{0x22} ** 32;
    // "c hs traffic" is the real RFC 8446 §7.1 label used during the
    // client-handshake-traffic-secret derivation.
    const label = "c hs traffic";

    var out: [32]u8 = undefined;

    var warm_i: usize = 0;
    while (warm_i < spec.warmup_iterations) : (warm_i += 1) {
        ks.expandLabel(&prk, label, &context, &out) catch {};
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        ks.expandLabel(&prk, label, &context, &out) catch {
            latencies[i] = common.nowNs() - t0;
            continue;
        };
        const lat = common.nowNs() - t0;
        std.mem.doNotOptimizeAway(out[0]);
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

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/tls_keygen", .variant = "hkdf_expand_label", .iterations = 50_000, .warmup_iterations = 2_000 },
};
