const std = @import("std");
const crypto_quic = @import("src/quic/crypto_quic.zig");

// Test AEAD encrypt/decrypt round-trip
pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Test key and IV (16-byte key for AES-128-GCM, 12-byte IV)
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const packet_number: u64 = 42;

    // Test AAD and plaintext
    const aad = "test associated data";
    const plaintext = "Hello, QUIC!";

    // Encrypt
    var ciphertext_buf: [1024]u8 = undefined;
    const ct_len = try crypto_quic.aeadEncrypt(
        .aes_128_gcm,
        &key,
        &iv,
        packet_number,
        aad,
        plaintext,
        &ciphertext_buf,
    );

    std.debug.print("Encrypted {} bytes\n", .{ct_len});
    std.debug.print("Ciphertext + tag (hex): ", .{});
    for (ciphertext_buf[0..ct_len]) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});

    // Decrypt
    var plaintext_buf: [1024]u8 = undefined;
    const pt_len = crypto_quic.aeadDecrypt(
        .aes_128_gcm,
        &key,
        &iv,
        packet_number,
        aad,
        ciphertext_buf[0..ct_len],
        &plaintext_buf,
    ) catch |err| {
        std.debug.print("Decryption failed: {}\n", .{err});
        return err;
    };

    std.debug.print("Decrypted {} bytes\n", .{pt_len});
    std.debug.print("Plaintext: {s}\n", .{plaintext_buf[0..pt_len]});

    // Verify it matches
    if (!std.mem.eql(u8, plaintext, plaintext_buf[0..pt_len])) {
        std.debug.print("ERROR: Plaintext mismatch!\n", .{});
        return error.PlaintextMismatch;
    }

    std.debug.print("SUCCESS: AEAD round-trip test passed!\n", .{});

    // Now test with wrong key - should fail
    const wrong_key = [_]u8{0x03} ** 16;
    const result = crypto_quic.aeadDecrypt(
        .aes_128_gcm,
        &wrong_key,
        &iv,
        packet_number,
        aad,
        ciphertext_buf[0..ct_len],
        &plaintext_buf,
    );

    if (result) |_| {
        std.debug.print("ERROR: Decryption with wrong key should have failed!\n", .{});
        return error.WrongKeyAccepted;
    } else |err| {
        std.debug.print("SUCCESS: Wrong key correctly rejected with error: {}\n", .{err});
    }

    return;
}