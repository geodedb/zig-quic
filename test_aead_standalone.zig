const std = @import("std");
const crypto = std.crypto;

// Test AEAD encrypt/decrypt round-trip with AES-128-GCM
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    _ = allocator;

    // Test key and IV (16-byte key for AES-128-GCM, 12-byte IV)
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;

    // Test AAD and plaintext
    const aad = "test associated data";
    const plaintext = "Hello, QUIC!";

    // Create AES-GCM cipher
    const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

    // Encrypt
    var ciphertext_buf: [1024]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;

    Aes128Gcm.encrypt(ciphertext_buf[0..plaintext.len], &tag, plaintext, aad, iv, key);

    std.debug.print("Encrypted {} bytes\n", .{plaintext.len});
    std.debug.print("Tag (hex): ", .{});
    for (tag) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});

    // Decrypt
    var plaintext_buf: [1024]u8 = undefined;

    Aes128Gcm.decrypt(plaintext_buf[0..plaintext.len], ciphertext_buf[0..plaintext.len], tag, aad, iv, key) catch |err| {
        std.debug.print("Decryption failed: {}\n", .{err});
        return err;
    };

    std.debug.print("Decrypted {} bytes\n", .{plaintext.len});
    std.debug.print("Plaintext: {s}\n", .{plaintext_buf[0..plaintext.len]});

    // Verify it matches
    if (!std.mem.eql(u8, plaintext, plaintext_buf[0..plaintext.len])) {
        std.debug.print("ERROR: Plaintext mismatch!\n", .{});
        return error.PlaintextMismatch;
    }

    std.debug.print("SUCCESS: AEAD round-trip test passed!\n", .{});

    // Now test with wrong key - should fail
    const wrong_key = [_]u8{0x03} ** 16;
    const result = Aes128Gcm.decrypt(plaintext_buf[0..plaintext.len], ciphertext_buf[0..plaintext.len], tag, aad, iv, wrong_key);

    if (result) |_| {
        std.debug.print("ERROR: Decryption with wrong key should have failed!\n", .{});
        return error.WrongKeyAccepted;
    } else |err| {
        std.debug.print("SUCCESS: Wrong key correctly rejected with error: {}\n", .{err});
    }

    // Now test QUIC-style AEAD where packet number is XORed into IV
    std.debug.print("\n=== Testing QUIC-style AEAD with packet number ===\n", .{});

    const packet_number: u64 = 42;
    var quic_iv = iv; // Copy the base IV

    // XOR packet number into IV (QUIC style - right-aligned)
    const pn_bytes = std.mem.asBytes(&packet_number);
    var i: usize = 0;
    while (i < @min(pn_bytes.len, quic_iv.len)) : (i += 1) {
        quic_iv[quic_iv.len - 1 - i] ^= pn_bytes[i];
    }

    std.debug.print("Base IV: ", .{});
    for (iv) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});

    std.debug.print("QUIC IV (PN={}): ", .{packet_number});
    for (quic_iv) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});

    // Encrypt with QUIC IV
    var quic_ciphertext: [1024]u8 = undefined;
    var quic_tag: [Aes128Gcm.tag_length]u8 = undefined;

    Aes128Gcm.encrypt(quic_ciphertext[0..plaintext.len], &quic_tag, plaintext, aad, quic_iv, key);

    // Decrypt with QUIC IV
    var quic_plaintext: [1024]u8 = undefined;
    Aes128Gcm.decrypt(quic_plaintext[0..plaintext.len], quic_ciphertext[0..plaintext.len], quic_tag, aad, quic_iv, key) catch |err| {
        std.debug.print("QUIC decryption failed: {}\n", .{err});
        return err;
    };

    if (!std.mem.eql(u8, plaintext, quic_plaintext[0..plaintext.len])) {
        std.debug.print("ERROR: QUIC plaintext mismatch!\n", .{});
        return error.QuicPlaintextMismatch;
    }

    std.debug.print("SUCCESS: QUIC-style AEAD test passed!\n", .{});

    return;
}