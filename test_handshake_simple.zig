const std = @import("std");

// Simple test to verify Handshake packet encryption/decryption
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    _ = gpa.allocator();

    // Test data
    const plaintext = "Test Handshake payload data";
    const key = [_]u8{0x01} ** 16; // AES-128 key
    const iv = [_]u8{0x02} ** 12;  // 12-byte IV for GCM
    const pn: u64 = 42;

    // Build nonce by XORing packet number with IV
    var nonce: [12]u8 = iv;
    // XOR packet number (big-endian) into last 8 bytes of nonce
    for (0..8) |i| {
        nonce[11 - i] ^= @as(u8, @truncate(pn >> @intCast(i * 8)));
    }

    std.log.info("Test key: {x}", .{key});
    std.log.info("Test IV:  {x}", .{iv});
    std.log.info("Nonce:    {x}", .{nonce});
    std.log.info("Plaintext: '{s}'", .{plaintext});

    // Test AAD (simplified header)
    const aad = [_]u8{
        0xE2, // Long header, Handshake type (0b11000010)
        0x00, 0x00, 0x00, 0x01, // Version (QUIC v1)
        0x08, // DCID length
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // DCID
        0x04, // SCID length
        0xAA, 0xBB, 0xCC, 0xDD, // SCID
        0x40, 0x1C, // Length (28 bytes payload + tag)
        0x00, 0x2A, // Packet number (42, 2 bytes)
    };

    // Encrypt using AES-128-GCM
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    Aes128Gcm.encrypt(&ciphertext, &tag, plaintext, &aad, nonce, key);

    std.log.info("Ciphertext: {x}", .{ciphertext});
    std.log.info("Tag:        {x}", .{tag});

    // Now try to decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    Aes128Gcm.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key) catch |err| {
        std.log.err("Decryption failed: {}", .{err});
        return err;
    };

    std.log.info("Decrypted:  '{s}'", .{decrypted});

    if (std.mem.eql(u8, &decrypted, plaintext)) {
        std.log.info("✅ Encryption/decryption successful!", .{});
    } else {
        std.log.err("❌ Decryption mismatch!", .{});
    }

    // Test header protection
    const hp_key = [_]u8{0x03} ** 16;

    // Sample for header protection (first 16 bytes of ciphertext)
    var sample: [16]u8 = undefined;
    if (ciphertext.len >= 16) {
        @memcpy(&sample, ciphertext[0..16]);
    } else {
        @memcpy(sample[0..ciphertext.len], &ciphertext);
        @memset(sample[ciphertext.len..], 0);
    }

    // Compute mask using AES-ECB
    const AesBlock = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128);
    const aes_block = AesBlock.init(hp_key);

    var mask_block: [16]u8 = undefined;
    aes_block.encrypt(&mask_block, &sample);

    // Use first 5 bytes as mask
    const mask = mask_block[0..5];
    std.log.info("HP sample:  {x}", .{sample});
    std.log.info("HP mask:    {x}", .{mask.*});

    // Apply header protection
    var protected_header = aad;
    protected_header[0] ^= mask[0] & 0x0F; // Long header: mask lower 4 bits
    for (0..2) |i| { // 2-byte packet number
        protected_header[aad.len - 2 + i] ^= mask[1 + i];
    }

    std.log.info("Protected header[0]: 0x{X:0>2} (was 0x{X:0>2})", .{ protected_header[0], aad[0] });

    // Remove protection
    var unprotected_header = protected_header;
    unprotected_header[0] ^= mask[0] & 0x0F;
    for (0..2) |i| {
        unprotected_header[aad.len - 2 + i] ^= mask[1 + i];
    }

    if (std.mem.eql(u8, &unprotected_header, &aad)) {
        std.log.info("✅ Header protection/removal successful!", .{});
    } else {
        std.log.err("❌ Header protection failed!", .{});
    }
}