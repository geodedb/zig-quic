// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel QUIC operations using thread-pool scheduling.
//!
//! Provides high-performance parallel implementations of compute-intensive
//! QUIC operations including AEAD encryption/decryption and header protection.
//!
//! ## Overview
//!
//! This module enables parallel processing of QUIC cryptographic operations
//! using the devnw thread-pool with submitBatch/WaitGroup. Operations
//! automatically fall back to sequential processing when the pool is
//! unavailable or input sizes are below thresholds.
//!
//! ## Build Configuration
//!
//! Enable parallel processing with `-Dthread_pool=true` (default: enabled).
//! Disable with `-Dthread_pool=false` for sequential-only execution.
//!
//! ## Usage Example
//!
//! ```zig
//! const parallel = @import("parallel.zig");
//!
//! // Encrypt multiple packets in parallel
//! var inputs: [8]parallel.AeadEncryptInput = undefined;
//! var outputs: [8][]u8 = undefined;
//! var results: [8]parallel.AeadEncryptResult = undefined;
//!
//! // Initialize inputs with keys, IVs, plaintext...
//! parallel.parallelAeadEncrypt(.aes_128_gcm, &inputs, &outputs, &results);
//!
//! // Check results
//! for (results) |result| {
//!     if (result.success) {
//!         // Use encrypted data
//!     }
//! }
//!
//! // Cleanup: call deinitPool() when done with parallel operations
//! parallel.deinitPool();
//! ```
//!
//! ## Performance Thresholds
//!
//! | Operation          | Threshold | Sequential Below |
//! |--------------------|-----------|------------------|
//! | AEAD Encrypt       | 4 packets | Yes              |
//! | AEAD Decrypt       | 4 packets | Yes              |
//! | Header Protection  | 8 packets | Yes              |
//! | Loss Detection     | 64 packets| Yes              |

const std = @import("std");
const crypto_zig = @import("quic_crypto");
const backend = @import("crypto_backend");
const tp = @import("thread_pool");

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of chunks for flat parallel dispatch. Stack-allocated.
const MAX_CHUNKS = 64;

// ============================================================================
// Global Thread Pool
// ============================================================================

var global_pool: ?tp.ThreadPool = null;
var pool_mutex: std.Io.Mutex = std.Io.Mutex.init;

pub fn getPool() ?*tp.ThreadPool {
    pool_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    defer pool_mutex.unlock(std.Io.Threaded.global_single_threaded.io());

    if (global_pool == null) {
        global_pool = tp.ThreadPool.init(std.heap.page_allocator, .{}) catch return null;
    }
    return &global_pool.?;
}

pub fn deinitPool() void {
    pool_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    defer pool_mutex.unlock(std.Io.Threaded.global_single_threaded.io());

    if (global_pool) |*pool| {
        pool.deinit();
        global_pool = null;
    }
}

// ============================================================================
// Parallel AEAD Encryption
// ============================================================================

/// Input for a single AEAD encryption operation
pub const AeadEncryptInput = struct {
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    plaintext: []const u8,
};

/// Result of a single AEAD encryption operation
pub const AeadEncryptResult = struct {
    success: bool,
    length: usize,
};

/// Context for parallel AEAD encryption (one chunk)
const AeadEncryptChunk = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadEncryptInput,
    outputs: [][]u8,
    results: []AeadEncryptResult,
};

fn aeadEncryptChunkFn(ctx: *anyopaque, _: *tp.TaskContext) void {
    const chunk: *AeadEncryptChunk = @ptrCast(@alignCast(ctx));
    for (chunk.inputs, 0..) |input, i| {
        const len = crypto_zig.aeadEncrypt(
            chunk.suite,
            input.key,
            input.iv,
            input.packet_number,
            input.aad,
            input.plaintext,
            chunk.outputs[i],
        ) catch {
            chunk.results[i] = .{ .success = false, .length = 0 };
            continue;
        };
        chunk.results[i] = .{ .success = true, .length = len };
    }
}

/// Encrypt multiple QUIC packets in parallel.
///
/// Each packet is encrypted independently using the specified cipher suite.
/// This is ideal for batching outgoing packets before transmission.
///
/// Parameters:
/// - suite: AEAD cipher suite (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
/// - inputs: Array of encryption inputs (key, iv, pn, aad, plaintext)
/// - outputs: Array of output buffers for ciphertext+tag
/// - results: Array to store operation results
///
/// Threshold: Uses parallel processing for 4+ packets
pub fn parallelAeadEncrypt(
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadEncryptInput,
    outputs: [][]u8,
    results: []AeadEncryptResult,
) void {
    std.debug.assert(inputs.len == outputs.len);
    std.debug.assert(inputs.len == results.len);

    const pool = if (inputs.len >= 4) getPool() else null;

    if (pool == null or inputs.len < 4) {
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadEncrypt(
                suite,
                input.key,
                input.iv,
                input.packet_number,
                input.aad,
                input.plaintext,
                outputs[i],
            ) catch {
                results[i] = .{ .success = false, .length = 0 };
                continue;
            };
            results[i] = .{ .success = true, .length = len };
        }
        return;
    }

    const n_chunks = @min(inputs.len, MAX_CHUNKS);
    var chunks: [MAX_CHUNKS]AeadEncryptChunk = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    const chunk_size = (inputs.len + n_chunks - 1) / n_chunks;
    var n: usize = 0;
    var start: usize = 0;
    while (start < inputs.len) : (n += 1) {
        const end = @min(start + chunk_size, inputs.len);
        chunks[n] = .{
            .suite = suite,
            .inputs = inputs[start..end],
            .outputs = outputs[start..end],
            .results = results[start..end],
        };
        batch[n] = .{ .task_fn = aeadEncryptChunkFn, .ctx = &chunks[n] };
        start = end;
    }

    var wg = pool.?.waitGroup();
    _ = pool.?.submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // On submit failure, fall back to sequential
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadEncrypt(
                suite,
                input.key,
                input.iv,
                input.packet_number,
                input.aad,
                input.plaintext,
                outputs[i],
            ) catch {
                results[i] = .{ .success = false, .length = 0 };
                continue;
            };
            results[i] = .{ .success = true, .length = len };
        }
        return;
    };
    wg.wait();
}

// ============================================================================
// Parallel AEAD Decryption
// ============================================================================

/// Input for a single AEAD decryption operation
pub const AeadDecryptInput = struct {
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    ciphertext_and_tag: []const u8,
};

/// Result of a single AEAD decryption operation
pub const AeadDecryptResult = struct {
    success: bool,
    length: usize,
    auth_failed: bool,
};

/// Context for parallel AEAD decryption (one chunk)
const AeadDecryptChunk = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadDecryptInput,
    outputs: [][]u8,
    results: []AeadDecryptResult,
};

fn aeadDecryptChunkFn(ctx: *anyopaque, _: *tp.TaskContext) void {
    const chunk: *AeadDecryptChunk = @ptrCast(@alignCast(ctx));
    for (chunk.inputs, 0..) |input, i| {
        const len = crypto_zig.aeadDecrypt(
            chunk.suite,
            input.key,
            input.iv,
            input.packet_number,
            input.aad,
            input.ciphertext_and_tag,
            chunk.outputs[i],
        ) catch |err| {
            chunk.results[i] = .{
                .success = false,
                .length = 0,
                .auth_failed = err == error.AuthenticationFailed,
            };
            continue;
        };
        chunk.results[i] = .{ .success = true, .length = len, .auth_failed = false };
    }
}

/// Decrypt multiple QUIC packets in parallel.
///
/// Each packet is decrypted independently with authentication verification.
/// Failed authentications are marked in results without stopping other decryptions.
///
/// Parameters:
/// - suite: AEAD cipher suite
/// - inputs: Array of decryption inputs (key, iv, pn, aad, ciphertext+tag)
/// - outputs: Array of output buffers for plaintext
/// - results: Array to store operation results
///
/// Threshold: Uses parallel processing for 4+ packets
pub fn parallelAeadDecrypt(
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadDecryptInput,
    outputs: [][]u8,
    results: []AeadDecryptResult,
) void {
    std.debug.assert(inputs.len == outputs.len);
    std.debug.assert(inputs.len == results.len);

    const pool = if (inputs.len >= 4) getPool() else null;

    if (pool == null or inputs.len < 4) {
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadDecrypt(
                suite,
                input.key,
                input.iv,
                input.packet_number,
                input.aad,
                input.ciphertext_and_tag,
                outputs[i],
            ) catch |err| {
                results[i] = .{
                    .success = false,
                    .length = 0,
                    .auth_failed = err == error.AuthenticationFailed,
                };
                continue;
            };
            results[i] = .{ .success = true, .length = len, .auth_failed = false };
        }
        return;
    }

    const n_chunks = @min(inputs.len, MAX_CHUNKS);
    var chunks: [MAX_CHUNKS]AeadDecryptChunk = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    const chunk_size = (inputs.len + n_chunks - 1) / n_chunks;
    var n: usize = 0;
    var start: usize = 0;
    while (start < inputs.len) : (n += 1) {
        const end = @min(start + chunk_size, inputs.len);
        chunks[n] = .{
            .suite = suite,
            .inputs = inputs[start..end],
            .outputs = outputs[start..end],
            .results = results[start..end],
        };
        batch[n] = .{ .task_fn = aeadDecryptChunkFn, .ctx = &chunks[n] };
        start = end;
    }

    var wg = pool.?.waitGroup();
    _ = pool.?.submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // On submit failure, fall back to sequential
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadDecrypt(
                suite,
                input.key,
                input.iv,
                input.packet_number,
                input.aad,
                input.ciphertext_and_tag,
                outputs[i],
            ) catch |err| {
                results[i] = .{
                    .success = false,
                    .length = 0,
                    .auth_failed = err == error.AuthenticationFailed,
                };
                continue;
            };
            results[i] = .{ .success = true, .length = len, .auth_failed = false };
        }
        return;
    };
    wg.wait();
}

// ============================================================================
// Parallel Header Protection
// ============================================================================

/// Input for header protection mask generation
pub const HeaderProtectInput = struct {
    hp_key: []const u8,
    sample: [16]u8,
};

/// Context for parallel header protection (one chunk)
const HeaderProtectChunk = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const HeaderProtectInput,
    masks: [][5]u8,
};

fn headerProtectChunkFn(ctx: *anyopaque, _: *tp.TaskContext) void {
    const chunk: *HeaderProtectChunk = @ptrCast(@alignCast(ctx));
    for (chunk.inputs, 0..) |input, i| {
        chunk.masks[i] = generateHeaderMask(chunk.suite, input.hp_key, input.sample);
    }
}

/// Generate header protection masks for multiple packets in parallel.
///
/// The mask is used to protect the first byte and packet number bytes
/// of QUIC packet headers (RFC 9001 §5.4).
///
/// Parameters:
/// - suite: Cipher suite (determines AES-ECB or ChaCha20 mask generation)
/// - inputs: Array of (hp_key, sample) pairs
/// - masks: Array to store 5-byte masks
///
/// Threshold: Uses parallel processing for 8+ packets
pub fn parallelHeaderProtect(
    suite: crypto_zig.AeadSuite,
    inputs: []const HeaderProtectInput,
    masks: [][5]u8,
) void {
    std.debug.assert(inputs.len == masks.len);

    const pool = if (inputs.len >= 8) getPool() else null;

    if (pool == null or inputs.len < 8) {
        for (inputs, 0..) |input, i| {
            masks[i] = generateHeaderMask(suite, input.hp_key, input.sample);
        }
        return;
    }

    const n_chunks = @min(inputs.len, MAX_CHUNKS);
    var chunks: [MAX_CHUNKS]HeaderProtectChunk = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    const chunk_size = (inputs.len + n_chunks - 1) / n_chunks;
    var n: usize = 0;
    var start: usize = 0;
    while (start < inputs.len) : (n += 1) {
        const end = @min(start + chunk_size, inputs.len);
        chunks[n] = .{
            .suite = suite,
            .inputs = inputs[start..end],
            .masks = masks[start..end],
        };
        batch[n] = .{ .task_fn = headerProtectChunkFn, .ctx = &chunks[n] };
        start = end;
    }

    var wg = pool.?.waitGroup();
    _ = pool.?.submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // On submit failure, fall back to sequential
        for (inputs, 0..) |input, i| {
            masks[i] = generateHeaderMask(suite, input.hp_key, input.sample);
        }
        return;
    };
    wg.wait();
}

fn generateHeaderMask(suite: crypto_zig.AeadSuite, hp_key: []const u8, sample: [16]u8) [5]u8 {
    // Zero-initialized so the short-key fall-through (hp_key too small) is
    // well-defined rather than returning garbage.
    var mask: [5]u8 = [_]u8{0} ** 5;

    switch (suite) {
        .aes_128_gcm => {
            // fips-exempt: non-security — RFC 9001 §5.4 AES-ECB header-protection mask (AES is FIPS-approved).
            if (hp_key.len >= 16) {
                const aes = std.crypto.core.aes.Aes128.initEnc(hp_key[0..16].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, &sample);
                @memcpy(&mask, block[0..5]);
            }
        },
        .aes_256_gcm => {
            // fips-exempt: non-security — RFC 9001 §5.4 AES-ECB header-protection mask (AES is FIPS-approved).
            if (hp_key.len >= 32) {
                const aes = std.crypto.core.aes.Aes256.initEnc(hp_key[0..32].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, &sample);
                @memcpy(&mask, block[0..5]);
            }
        },
        .chacha20_poly1305 => {
            if (backend.fips_enabled) {
                // Comptime-eliminated under -Dfips=true: ChaCha20 header
                // protection is non-FIPS. The AEAD seam (crypto_zig.zig,
                // Task 3) returns error.Unsupported for every ChaCha suite
                // BEFORE the pipeline computes any header mask, so a ChaCha
                // packet can never reach this arm in a fips build. This
                // function has no error channel ([5]u8 return), so the
                // correct expression of "cannot happen" is `unreachable`,
                // not a zero-mask return.
                unreachable;
            }
            if (hp_key.len >= 32) {
                // ChaCha20 header protection uses counter from sample
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                var nonce: [12]u8 = undefined;
                @memcpy(&nonce, sample[4..16]);
                var output: [5]u8 = undefined;
                var key32: [32]u8 = undefined;
                @memcpy(&key32, hp_key[0..32]);
                std.crypto.stream.chacha.ChaCha20IETF.xor(&output, &[_]u8{0} ** 5, counter, key32, nonce);
                mask = output;
            }
        },
    }

    return mask;
}

/// Test-only re-export of the private header-mask generator.
pub fn generateHeaderMaskForTest(suite: crypto_zig.AeadSuite, hp_key: []const u8, sample: [16]u8) [5]u8 {
    return generateHeaderMask(suite, hp_key, sample);
}

// ============================================================================
// Parallel Loss Detection
// ============================================================================

/// Sent packet info for loss detection
pub const SentPacketInfo = struct {
    packet_number: u64,
    size: usize,
    time_sent_ns: u64,
    ack_eliciting: bool,
    declared_lost: bool,
};

/// Result of loss detection scan
pub const LossDetectResult = struct {
    lost_count: usize,
    bytes_lost: usize,
};

/// Context for one parallel loss detection chunk.
/// Stores partial results that are merged after wg.wait().
const LossDetectChunk = struct {
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: u64,
    now_ns: u64,
    // partial results written by the task function
    lost_count: usize = 0,
    bytes_lost: usize = 0,
};

fn lossDetectChunkFn(ctx: *anyopaque, _: *tp.TaskContext) void {
    const chunk: *LossDetectChunk = @ptrCast(@alignCast(ctx));
    var lost_count: usize = 0;
    var bytes_lost: usize = 0;

    for (chunk.sent_packets) |*sp| {
        if (sp.declared_lost) continue;

        // Packet threshold loss
        if (sp.packet_number + chunk.packet_threshold <= chunk.largest_acked) {
            sp.declared_lost = true;
            lost_count += 1;
            bytes_lost += sp.size;
            continue;
        }

        // Time threshold loss
        const deadline = sp.time_sent_ns + chunk.time_threshold_ns;
        if (chunk.now_ns >= deadline and sp.packet_number < chunk.largest_acked) {
            sp.declared_lost = true;
            lost_count += 1;
            bytes_lost += sp.size;
        }
    }

    chunk.lost_count = lost_count;
    chunk.bytes_lost = bytes_lost;
}

/// Scan sent packets for losses in parallel.
///
/// Implements RFC 9002 loss detection using both packet threshold
/// and time threshold. Packets are marked as lost in place.
///
/// Parameters:
/// - sent_packets: Mutable array of sent packet info
/// - largest_acked: Largest acknowledged packet number
/// - packet_threshold: Packet reordering threshold (typically 3)
/// - time_threshold_ns: Time-based loss threshold in nanoseconds
/// - now_ns: Current time in nanoseconds
///
/// Returns: Count and total bytes of newly detected lost packets
///
/// Threshold: Uses parallel processing for 64+ sent packets
pub fn parallelLossDetect(
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: u64,
    now_ns: u64,
) LossDetectResult {
    const pool = if (sent_packets.len >= 64) getPool() else null;

    if (pool == null or sent_packets.len < 64) {
        return sequentialLossDetect(sent_packets, largest_acked, packet_threshold, time_threshold_ns, now_ns);
    }

    const n_chunks = @min(sent_packets.len, MAX_CHUNKS);
    var chunks: [MAX_CHUNKS]LossDetectChunk = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    const chunk_size = (sent_packets.len + n_chunks - 1) / n_chunks;
    var n: usize = 0;
    var start: usize = 0;
    while (start < sent_packets.len) : (n += 1) {
        const end = @min(start + chunk_size, sent_packets.len);
        chunks[n] = .{
            .sent_packets = sent_packets[start..end],
            .largest_acked = largest_acked,
            .packet_threshold = packet_threshold,
            .time_threshold_ns = time_threshold_ns,
            .now_ns = now_ns,
        };
        batch[n] = .{ .task_fn = lossDetectChunkFn, .ctx = &chunks[n] };
        start = end;
    }

    var wg = pool.?.waitGroup();
    _ = pool.?.submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        return sequentialLossDetect(sent_packets, largest_acked, packet_threshold, time_threshold_ns, now_ns);
    };
    wg.wait();

    // Merge partial results
    var total = LossDetectResult{ .lost_count = 0, .bytes_lost = 0 };
    for (chunks[0..n]) |*chunk| {
        total.lost_count += chunk.lost_count;
        total.bytes_lost += chunk.bytes_lost;
    }
    return total;
}

fn sequentialLossDetect(
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: u64,
    now_ns: u64,
) LossDetectResult {
    var lost_count: usize = 0;
    var bytes_lost: usize = 0;

    for (sent_packets) |*sp| {
        if (sp.declared_lost) continue;

        // Packet threshold loss
        if (sp.packet_number + packet_threshold <= largest_acked) {
            sp.declared_lost = true;
            lost_count += 1;
            bytes_lost += sp.size;
            continue;
        }

        // Time threshold loss
        const deadline = sp.time_sent_ns + time_threshold_ns;
        if (now_ns >= deadline and sp.packet_number < largest_acked) {
            sp.declared_lost = true;
            lost_count += 1;
            bytes_lost += sp.size;
        }
    }

    return LossDetectResult{
        .lost_count = lost_count,
        .bytes_lost = bytes_lost,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parallel aead encrypt" {
    const allocator = std.testing.allocator;
    const count = 8;

    var inputs: [count]AeadEncryptInput = undefined;
    var outputs: [count][]u8 = undefined;
    var results: [count]AeadEncryptResult = undefined;

    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const aad = "header";
    const plaintext = "test data";

    for (&inputs, 0..) |*input, i| {
        input.* = .{
            .key = &key,
            .iv = &iv,
            .packet_number = @intCast(i),
            .aad = aad,
            .plaintext = plaintext,
        };
        outputs[i] = try allocator.alloc(u8, plaintext.len + 16);
    }
    defer for (&outputs) |out| allocator.free(out);

    parallelAeadEncrypt(.aes_128_gcm, &inputs, &outputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
        try std.testing.expectEqual(plaintext.len + 16, result.length);
    }
}

test "parallel loss detect" {
    var sent_packets: [100]SentPacketInfo = undefined;
    for (&sent_packets, 0..) |*sp, i| {
        sp.* = .{
            .packet_number = @intCast(i),
            .size = 1200,
            .time_sent_ns = @intCast(i * 1_000_000),
            .ack_eliciting = true,
            .declared_lost = false,
        };
    }

    const result = parallelLossDetect(
        &sent_packets,
        95, // largest_acked
        3, // packet_threshold
        100_000_000, // 100ms
        200_000_000, // now = 200ms
    );

    // Packets 0-92 should be lost (95 - 3 = 92)
    try std.testing.expect(result.lost_count > 0);
}

test "parallel aead encrypt - empty input" {
    var inputs: [0]AeadEncryptInput = undefined;
    var outputs: [0][]u8 = undefined;
    var results: [0]AeadEncryptResult = undefined;

    parallelAeadEncrypt(.aes_128_gcm, &inputs, &outputs, &results);
    // Should handle empty arrays without error
}

test "parallel aead encrypt - single item below threshold" {
    const allocator = std.testing.allocator;
    const count = 1;

    var inputs: [count]AeadEncryptInput = undefined;
    var outputs: [count][]u8 = undefined;
    var results: [count]AeadEncryptResult = undefined;

    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const plaintext = "test";

    inputs[0] = .{
        .key = &key,
        .iv = &iv,
        .packet_number = 0,
        .aad = "aad",
        .plaintext = plaintext,
    };
    outputs[0] = try allocator.alloc(u8, plaintext.len + 16);
    defer allocator.free(outputs[0]);

    parallelAeadEncrypt(.aes_128_gcm, &inputs, &outputs, &results);
    try std.testing.expect(results[0].success);
}

test "parallel aead encrypt - at threshold boundary" {
    const allocator = std.testing.allocator;
    const count = 4; // Exactly at threshold

    var inputs: [count]AeadEncryptInput = undefined;
    var outputs: [count][]u8 = undefined;
    var results: [count]AeadEncryptResult = undefined;

    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const plaintext = "test data";

    for (&inputs, 0..) |*input, i| {
        input.* = .{
            .key = &key,
            .iv = &iv,
            .packet_number = @intCast(i),
            .aad = "header",
            .plaintext = plaintext,
        };
        outputs[i] = try allocator.alloc(u8, plaintext.len + 16);
    }
    defer for (&outputs) |out| allocator.free(out);

    parallelAeadEncrypt(.aes_128_gcm, &inputs, &outputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

test "parallel aead decrypt - basic" {
    const allocator = std.testing.allocator;
    const count = 8;

    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const plaintext = "test data";
    const aad = "header";

    // First encrypt
    var ciphertexts: [count][]u8 = undefined;
    for (&ciphertexts) |*ct| {
        ct.* = try allocator.alloc(u8, plaintext.len + 16);
    }
    defer for (&ciphertexts) |ct| allocator.free(ct);

    var enc_inputs: [count]AeadEncryptInput = undefined;
    var enc_results: [count]AeadEncryptResult = undefined;
    for (&enc_inputs, 0..) |*input, i| {
        input.* = .{
            .key = &key,
            .iv = &iv,
            .packet_number = @intCast(i),
            .aad = aad,
            .plaintext = plaintext,
        };
    }
    parallelAeadEncrypt(.aes_128_gcm, &enc_inputs, &ciphertexts, &enc_results);

    // Now decrypt
    var dec_inputs: [count]AeadDecryptInput = undefined;
    var dec_outputs: [count][]u8 = undefined;
    var dec_results: [count]AeadDecryptResult = undefined;

    for (&dec_inputs, 0..) |*input, i| {
        input.* = .{
            .key = &key,
            .iv = &iv,
            .packet_number = @intCast(i),
            .aad = aad,
            .ciphertext_and_tag = ciphertexts[i],
        };
        dec_outputs[i] = try allocator.alloc(u8, plaintext.len);
    }
    defer for (&dec_outputs) |out| allocator.free(out);

    parallelAeadDecrypt(.aes_128_gcm, &dec_inputs, &dec_outputs, &dec_results);

    for (dec_results) |result| {
        try std.testing.expect(result.success);
        try std.testing.expect(!result.auth_failed);
    }
}

test "parallel header protect - basic" {
    var inputs: [16]HeaderProtectInput = undefined;
    var masks: [16][5]u8 = undefined;

    const hp_key = [_]u8{0x01} ** 16;
    const sample = [_]u8{0x02} ** 16;

    for (&inputs) |*input| {
        input.* = .{
            .hp_key = &hp_key,
            .sample = sample,
        };
    }

    parallelHeaderProtect(.aes_128_gcm, &inputs, &masks);

    // Verify masks are computed (non-zero for valid keys)
    for (masks) |mask| {
        var non_zero = false;
        for (mask) |b| {
            if (b != 0) {
                non_zero = true;
                break;
            }
        }
        try std.testing.expect(non_zero);
    }
}

test "parallel header protect - chacha20" {
    var inputs: [8]HeaderProtectInput = undefined;
    var masks: [8][5]u8 = undefined;

    const hp_key = [_]u8{0x01} ** 32;
    const sample = [_]u8{0x02} ** 16;

    for (&inputs) |*input| {
        input.* = .{
            .hp_key = &hp_key,
            .sample = sample,
        };
    }

    parallelHeaderProtect(.chacha20_poly1305, &inputs, &masks);

    for (masks) |mask| {
        var non_zero = false;
        for (mask) |b| {
            if (b != 0) {
                non_zero = true;
                break;
            }
        }
        try std.testing.expect(non_zero);
    }
}

test "parallel loss detect - no losses" {
    var sent_packets: [64]SentPacketInfo = undefined;
    for (&sent_packets, 0..) |*sp, i| {
        sp.* = .{
            .packet_number = @intCast(i),
            .size = 1200,
            .time_sent_ns = @intCast(i * 1_000_000),
            .ack_eliciting = true,
            .declared_lost = false,
        };
    }

    const result = parallelLossDetect(
        &sent_packets,
        0, // largest_acked = 0, no losses possible
        3,
        100_000_000,
        0, // now = 0
    );

    try std.testing.expectEqual(@as(usize, 0), result.lost_count);
}

test "parallel loss detect - below threshold uses sequential" {
    var sent_packets: [32]SentPacketInfo = undefined;
    for (&sent_packets, 0..) |*sp, i| {
        sp.* = .{
            .packet_number = @intCast(i),
            .size = 1200,
            .time_sent_ns = @intCast(i * 1_000_000),
            .ack_eliciting = true,
            .declared_lost = false,
        };
    }

    const result = parallelLossDetect(
        &sent_packets,
        30,
        3,
        100_000_000,
        200_000_000,
    );

    try std.testing.expect(result.lost_count > 0);
}
