// TLS 1.3 AEAD Performance Benchmark
// Measures AES-128-GCM and ChaCha20-Poly1305 encryption/decryption
const std = @import("std");

const BenchConfig = struct {
    iterations: usize = 10000,
    warmup: usize = 1000,
    payload_sizes: []const usize = &.{ 64, 256, 1024, 1500 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    const config = BenchConfig{};
    
    std.debug.print("TLS 1.3 AEAD Benchmarks\n", .{});
    std.debug.print("=======================\n", .{});
    std.debug.print("Iterations: {}\n\n", .{config.iterations});
    
    for (config.payload_sizes) |size| {
        std.debug.print("Payload size: {} bytes\n", .{size});
        std.debug.print("----------------------\n", .{});
        try benchmarkAesGcm(alloc, config, size);
        try benchmarkChaCha20Poly1305(alloc, config, size);
        std.debug.print("\n", .{});
    }
}

fn benchmarkAesGcm(alloc: std.mem.Allocator, config: BenchConfig, payload_size: usize) !void {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 12;
    const aad = [_]u8{0x00} ** 13;
    
    const plaintext = try alloc.alloc(u8, payload_size);
    defer alloc.free(plaintext);
    @memset(plaintext, 0xFF);
    
    const ciphertext = try alloc.alloc(u8, payload_size + 16); // +tag
    defer alloc.free(ciphertext);
    
    // Warmup
    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16],
            plaintext,
            &aad,
            nonce,
            key,
        );
    }
    
    // Benchmark encryption
    const enc_start = std.time.nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16],
            plaintext,
            &aad,
            nonce,
            key,
        );
    }
    const enc_end = std.time.nanoTimestamp();
    
    // Benchmark decryption
    const dec_start = std.time.nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
            plaintext,
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16].*,
            &aad,
            nonce,
            key,
        ) catch {};
    }
    const dec_end = std.time.nanoTimestamp();
    
    const enc_ns = @as(u64, @intCast(enc_end - enc_start)) / config.iterations;
    const dec_ns = @as(u64, @intCast(dec_end - dec_start)) / config.iterations;
    const enc_mbps = (@as(f64, @floatFromInt(payload_size)) * 8.0 * 1000.0) / @as(f64, @floatFromInt(enc_ns));
    const dec_mbps = (@as(f64, @floatFromInt(payload_size)) * 8.0 * 1000.0) / @as(f64, @floatFromInt(dec_ns));
    
    std.debug.print("  AES-128-GCM Encrypt: {} ns/op ({d:.2} Mbps)\n", .{ enc_ns, enc_mbps });
    std.debug.print("  AES-128-GCM Decrypt: {} ns/op ({d:.2} Mbps)\n", .{ dec_ns, dec_mbps });
}

fn benchmarkChaCha20Poly1305(alloc: std.mem.Allocator, config: BenchConfig, payload_size: usize) !void {
    const key = [_]u8{0x00} ** 32;
    const nonce = [_]u8{0x00} ** 12;
    const aad = [_]u8{0x00} ** 13;
    
    const plaintext = try alloc.alloc(u8, payload_size);
    defer alloc.free(plaintext);
    @memset(plaintext, 0xFF);
    
    const ciphertext = try alloc.alloc(u8, payload_size + 16);
    defer alloc.free(ciphertext);
    
    // Warmup
    var i: usize = 0;
    while (i < config.warmup) : (i += 1) {
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16],
            plaintext,
            &aad,
            nonce,
            key,
        );
    }
    
    // Benchmark encryption
    const enc_start = std.time.nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16],
            plaintext,
            &aad,
            nonce,
            key,
        );
    }
    const enc_end = std.time.nanoTimestamp();
    
    // Benchmark decryption
    const dec_start = std.time.nanoTimestamp();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext[0..payload_size],
            ciphertext[payload_size..][0..16].*,
            &aad,
            nonce,
            key,
        ) catch {};
    }
    const dec_end = std.time.nanoTimestamp();
    
    const enc_ns = @as(u64, @intCast(enc_end - enc_start)) / config.iterations;
    const dec_ns = @as(u64, @intCast(dec_end - dec_start)) / config.iterations;
    const enc_mbps = (@as(f64, @floatFromInt(payload_size)) * 8.0 * 1000.0) / @as(f64, @floatFromInt(enc_ns));
    const dec_mbps = (@as(f64, @floatFromInt(payload_size)) * 8.0 * 1000.0) / @as(f64, @floatFromInt(dec_ns));
    
    std.debug.print("  ChaCha20-Poly1305 Encrypt: {} ns/op ({d:.2} Mbps)\n", .{ enc_ns, enc_mbps });
    std.debug.print("  ChaCha20-Poly1305 Decrypt: {} ns/op ({d:.2} Mbps)\n", .{ dec_ns, dec_mbps });
}
