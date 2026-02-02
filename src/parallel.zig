// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel QUIC operations using spice heartbeat scheduling.
//!
//! Provides high-performance parallel implementations of compute-intensive
//! QUIC operations including AEAD encryption/decryption and header protection.
//!
//! ## Overview
//!
//! This module enables parallel processing of QUIC cryptographic operations
//! using the spice thread pool with fork/join work-stealing. Operations
//! automatically fall back to sequential processing when spice is disabled
//! or input sizes are below thresholds.
//!
//! ## Build Configuration
//!
//! Enable parallel processing with `-Dspice=true` (default: enabled).
//! Disable with `-Dspice=false` for sequential-only execution.
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
const build_options = @import("build_options");
const crypto_zig = @import("quic/crypto_zig.zig");

const spice = if (build_options.enable_spice) @import("spice") else struct {
    pub const ThreadPool = void;
    pub const Task = void;
    pub fn Future(comptime I: type, comptime O: type) type {
        _ = I;
        _ = O;
        return void;
    }
};

// ============================================================================
// Global Thread Pool
// ============================================================================

var global_pool: if (build_options.enable_spice) ?spice.ThreadPool else void = if (build_options.enable_spice) null else {};
var pool_mutex: std.Thread.Mutex = .{};

pub fn getPool() if (build_options.enable_spice) *spice.ThreadPool else void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool == null) {
        global_pool = spice.ThreadPool.init(std.heap.page_allocator);
        global_pool.?.start(.{});
    }
    return &global_pool.?;
}

pub fn deinitPool() void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

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

/// Context for parallel AEAD encryption
pub const AeadEncryptContext = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadEncryptInput,
    outputs: [][]u8,
    results: []AeadEncryptResult,
};

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

    // Use sequential for small batches or when spice is disabled
    if (!build_options.enable_spice or inputs.len < 4) {
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

    const pool = getPool();
    const ctx = AeadEncryptContext{
        .suite = suite,
        .inputs = inputs,
        .outputs = outputs,
        .results = results,
    };
    _ = pool.call(void, parallelAeadEncryptTask, ctx);
}

fn parallelAeadEncryptTask(t: *spice.Task, ctx: AeadEncryptContext) void {
    const inputs = ctx.inputs;
    const outputs = ctx.outputs;
    const results = ctx.results;

    // Base case - process sequentially
    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadEncrypt(
                ctx.suite,
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

    // Fork/join - split work
    const mid = inputs.len / 2;
    const left_ctx = AeadEncryptContext{
        .suite = ctx.suite,
        .inputs = inputs[0..mid],
        .outputs = outputs[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = AeadEncryptContext{
        .suite = ctx.suite,
        .inputs = inputs[mid..],
        .outputs = outputs[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(AeadEncryptContext, void).init();
    fut.fork(t, parallelAeadEncryptTask, right_ctx);

    t.call(void, parallelAeadEncryptTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelAeadEncryptTask, right_ctx);
    }
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

/// Context for parallel AEAD decryption
pub const AeadDecryptContext = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const AeadDecryptInput,
    outputs: [][]u8,
    results: []AeadDecryptResult,
};

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

    if (!build_options.enable_spice or inputs.len < 4) {
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

    const pool = getPool();
    const ctx = AeadDecryptContext{
        .suite = suite,
        .inputs = inputs,
        .outputs = outputs,
        .results = results,
    };
    _ = pool.call(void, parallelAeadDecryptTask, ctx);
}

fn parallelAeadDecryptTask(t: *spice.Task, ctx: AeadDecryptContext) void {
    const inputs = ctx.inputs;
    const outputs = ctx.outputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            const len = crypto_zig.aeadDecrypt(
                ctx.suite,
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

    const mid = inputs.len / 2;
    const left_ctx = AeadDecryptContext{
        .suite = ctx.suite,
        .inputs = inputs[0..mid],
        .outputs = outputs[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = AeadDecryptContext{
        .suite = ctx.suite,
        .inputs = inputs[mid..],
        .outputs = outputs[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(AeadDecryptContext, void).init();
    fut.fork(t, parallelAeadDecryptTask, right_ctx);

    t.call(void, parallelAeadDecryptTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelAeadDecryptTask, right_ctx);
    }
}

// ============================================================================
// Parallel Header Protection
// ============================================================================

/// Input for header protection mask generation
pub const HeaderProtectInput = struct {
    hp_key: []const u8,
    sample: [16]u8,
};

/// Context for parallel header protection
pub const HeaderProtectContext = struct {
    suite: crypto_zig.AeadSuite,
    inputs: []const HeaderProtectInput,
    masks: [][5]u8,
};

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

    if (!build_options.enable_spice or inputs.len < 8) {
        for (inputs, 0..) |input, i| {
            masks[i] = generateHeaderMask(suite, input.hp_key, input.sample);
        }
        return;
    }

    const pool = getPool();
    const ctx = HeaderProtectContext{
        .suite = suite,
        .inputs = inputs,
        .masks = masks,
    };
    _ = pool.call(void, parallelHeaderProtectTask, ctx);
}

fn parallelHeaderProtectTask(t: *spice.Task, ctx: HeaderProtectContext) void {
    const inputs = ctx.inputs;
    const masks = ctx.masks;

    if (inputs.len < 4) {
        for (inputs, 0..) |input, i| {
            masks[i] = generateHeaderMask(ctx.suite, input.hp_key, input.sample);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = HeaderProtectContext{
        .suite = ctx.suite,
        .inputs = inputs[0..mid],
        .masks = masks[0..mid],
    };
    const right_ctx = HeaderProtectContext{
        .suite = ctx.suite,
        .inputs = inputs[mid..],
        .masks = masks[mid..],
    };

    var fut = spice.Future(HeaderProtectContext, void).init();
    fut.fork(t, parallelHeaderProtectTask, right_ctx);

    t.call(void, parallelHeaderProtectTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelHeaderProtectTask, right_ctx);
    }
}

fn generateHeaderMask(suite: crypto_zig.AeadSuite, hp_key: []const u8, sample: [16]u8) [5]u8 {
    var mask: [5]u8 = undefined;

    switch (suite) {
        .aes_128_gcm => {
            if (hp_key.len >= 16) {
                const aes = std.crypto.core.aes.Aes128.initEnc(hp_key[0..16].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, &sample);
                @memcpy(&mask, block[0..5]);
            }
        },
        .aes_256_gcm => {
            if (hp_key.len >= 32) {
                const aes = std.crypto.core.aes.Aes256.initEnc(hp_key[0..32].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, &sample);
                @memcpy(&mask, block[0..5]);
            }
        },
        .chacha20_poly1305 => {
            if (hp_key.len >= 32) {
                // ChaCha20 header protection uses counter from sample
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                var nonce: [12]u8 = undefined;
                @memcpy(&nonce, sample[4..16]);
                var output: [5]u8 = undefined;
                std.crypto.stream.chacha.ChaCha20IETF.xor(&output, &[_]u8{0} ** 5, counter, nonce, hp_key[0..32].*);
                mask = output;
            }
        },
    }

    return mask;
}

// ============================================================================
// Parallel Loss Detection
// ============================================================================

/// Sent packet info for loss detection
pub const SentPacketInfo = struct {
    packet_number: u64,
    size: usize,
    time_sent_ns: i128,
    ack_eliciting: bool,
    declared_lost: bool,
};

/// Context for parallel loss detection
pub const LossDetectContext = struct {
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: i128,
    now_ns: i128,
    start_idx: usize,
    end_idx: usize,
};

/// Result of loss detection scan
pub const LossDetectResult = struct {
    lost_count: usize,
    bytes_lost: usize,
};

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
    time_threshold_ns: i128,
    now_ns: i128,
) LossDetectResult {
    if (!build_options.enable_spice or sent_packets.len < 64) {
        return sequentialLossDetect(sent_packets, largest_acked, packet_threshold, time_threshold_ns, now_ns);
    }

    const pool = getPool();
    const ctx = LossDetectContext{
        .sent_packets = sent_packets,
        .largest_acked = largest_acked,
        .packet_threshold = packet_threshold,
        .time_threshold_ns = time_threshold_ns,
        .now_ns = now_ns,
        .start_idx = 0,
        .end_idx = sent_packets.len,
    };
    return pool.call(LossDetectResult, parallelLossDetectTask, ctx);
}

fn parallelLossDetectTask(t: *spice.Task, ctx: LossDetectContext) LossDetectResult {
    const len = ctx.end_idx - ctx.start_idx;

    if (len < 32) {
        return sequentialLossDetectRange(
            ctx.sent_packets,
            ctx.largest_acked,
            ctx.packet_threshold,
            ctx.time_threshold_ns,
            ctx.now_ns,
            ctx.start_idx,
            ctx.end_idx,
        );
    }

    const mid = ctx.start_idx + len / 2;
    const left_ctx = LossDetectContext{
        .sent_packets = ctx.sent_packets,
        .largest_acked = ctx.largest_acked,
        .packet_threshold = ctx.packet_threshold,
        .time_threshold_ns = ctx.time_threshold_ns,
        .now_ns = ctx.now_ns,
        .start_idx = ctx.start_idx,
        .end_idx = mid,
    };
    const right_ctx = LossDetectContext{
        .sent_packets = ctx.sent_packets,
        .largest_acked = ctx.largest_acked,
        .packet_threshold = ctx.packet_threshold,
        .time_threshold_ns = ctx.time_threshold_ns,
        .now_ns = ctx.now_ns,
        .start_idx = mid,
        .end_idx = ctx.end_idx,
    };

    var fut = spice.Future(LossDetectContext, LossDetectResult).init();
    fut.fork(t, parallelLossDetectTask, right_ctx);

    const left_result = t.call(LossDetectResult, parallelLossDetectTask, left_ctx);
    const right_result = if (fut.join(t)) |val| val else t.call(LossDetectResult, parallelLossDetectTask, right_ctx);

    return LossDetectResult{
        .lost_count = left_result.lost_count + right_result.lost_count,
        .bytes_lost = left_result.bytes_lost + right_result.bytes_lost,
    };
}

fn sequentialLossDetect(
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: i128,
    now_ns: i128,
) LossDetectResult {
    return sequentialLossDetectRange(sent_packets, largest_acked, packet_threshold, time_threshold_ns, now_ns, 0, sent_packets.len);
}

fn sequentialLossDetectRange(
    sent_packets: []SentPacketInfo,
    largest_acked: u64,
    packet_threshold: u64,
    time_threshold_ns: i128,
    now_ns: i128,
    start_idx: usize,
    end_idx: usize,
) LossDetectResult {
    var lost_count: usize = 0;
    var bytes_lost: usize = 0;

    for (sent_packets[start_idx..end_idx]) |*sp| {
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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
    if (!build_options.enable_spice) return error.SkipZigTest;

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
