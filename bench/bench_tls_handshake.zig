// TLS 1.3 Handshake Performance Benchmark
// Measures key derivation, transcript hashing, and secret installation
const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

const BenchConfig = struct {
    iterations: usize = 10000,
    warmup: usize = 1000,
};

// Zig 0.16 removed std.time.nanoTimestamp; inline the Io.Clock equivalent.
fn nanoTimestamp() i128 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const config = BenchConfig{};

    std.debug.print("TLS 1.3 Handshake Benchmarks\n", .{});
    std.debug.print("=============================\n", .{});
    std.debug.print("Iterations: {}\n\n", .{config.iterations});

    try benchmarkKeyDerivation(config);
    try benchmarkTranscriptHash(config);
    try benchmarkHandshakeSecrets(config);
    try benchmarkContextCreation(alloc, config);
}

fn benchmarkKeyDerivation(config: BenchConfig) !void {
    const ikm = [_]u8{0xAB} ** 32;
    const salt = [_]u8{0xCD} ** 20;

    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        _ = ks.extract(&salt, &ikm);
    }

    const start = nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        _ = ks.extract(&salt, &ikm);
    }
    const end = nanoTimestamp();

    const total_ns = @as(u64, @intCast(end - start));
    const per_op_ns = total_ns / config.iterations;

    std.debug.print("HKDF-Extract:        {} ns/op ({d:.2} µs)\n", .{
        per_op_ns,
        @as(f64, @floatFromInt(per_op_ns)) / 1000.0,
    });
}

fn benchmarkTranscriptHash(config: BenchConfig) !void {
    const message = [_]u8{ 0x01, 0x00, 0x00, 0x10 } ++ ([_]u8{0xFF} ** 16);

    var transcript = tls13.Transcript.init();
    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        transcript.update(&message);
    }

    transcript = tls13.Transcript.init();
    const start = nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        transcript.update(&message);
    }
    const end = nanoTimestamp();

    const total_ns = @as(u64, @intCast(end - start));
    const per_op_ns = total_ns / config.iterations;

    std.debug.print("Transcript Update:   {} ns/op ({d:.2} µs)\n", .{
        per_op_ns,
        @as(f64, @floatFromInt(per_op_ns)) / 1000.0,
    });
}

fn benchmarkHandshakeSecrets(config: BenchConfig) !void {
    const hash = ks.Hash.sha256; // Use SHA-256 for the benchmark
    const ecdhe_secret = [_]u8{0x11} ** 32;
    const transcript_hash_data = [_]u8{0x22} ** 32;
    const transcript_hash = ks.Secret.fromSlice(hash, &transcript_hash_data);
    const early_secret = tls13.deriveEarlySecret(hash, null);

    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        _ = tls13.deriveHandshakeTraffic(hash, &ecdhe_secret, transcript_hash, &early_secret);
    }

    const start = nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        _ = tls13.deriveHandshakeTraffic(hash, &ecdhe_secret, transcript_hash, &early_secret);
    }
    const end = nanoTimestamp();

    const total_ns = @as(u64, @intCast(end - start));
    const per_op_ns = total_ns / config.iterations;

    std.debug.print("Handshake Secrets:   {} ns/op ({d:.2} µs)\n", .{
        per_op_ns,
        @as(f64, @floatFromInt(per_op_ns)) / 1000.0,
    });
}

fn benchmarkContextCreation(alloc: std.mem.Allocator, config: BenchConfig) !void {
    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Server }, .{});
        ctx.deinit();
    }

    const start = nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Server }, .{});
        ctx.deinit();
    }
    const end = nanoTimestamp();

    const total_ns = @as(u64, @intCast(end - start));
    const per_op_ns = total_ns / config.iterations;

    std.debug.print("Context Init/Deinit: {} ns/op ({d:.2} µs)\n", .{
        per_op_ns,
        @as(f64, @floatFromInt(per_op_ns)) / 1000.0,
    });
}
