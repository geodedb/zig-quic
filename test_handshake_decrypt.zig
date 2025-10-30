const std = @import("std");
const crypto = @import("src/quic/crypto_quic.zig");
const packet = @import("src/quic/packet.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Create a simple Handshake packet with known keys
    const test_keys = packet.InitialKeys{
        .key = [_]u8{0x01} ** 16,
        .iv = [_]u8{0x02} ** 12,
        .hp = [_]u8{0x03} ** 16,
    };

    // Create a test payload
    const payload = "Test Handshake payload";

    // Encode a Handshake packet
    const encoded = try packet.encodeHandshakeProtected(
        alloc,
        0x00000001, // QUIC v1
        &[_]u8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, // DCID
        &[_]u8{0xAA, 0xBB, 0xCC, 0xDD}, // SCID
        42, // packet number
        2, // packet number length
        payload,
        test_keys
    );
    defer alloc.free(encoded);

    std.log.info("Encoded Handshake packet: {} bytes", .{encoded.len});
    std.log.info("First 20 bytes: {x}", .{std.fmt.fmtSliceHexLower(encoded[0..@min(20, encoded.len)])});

    // Now try to decrypt it
    var header_first = encoded[0];
    const pn_offset = 1 + 4 + 1 + 8 + 1 + 4 + 4; // first + version + dcid_len + dcid + scid_len + scid + length(varint)

    // Remove header protection
    const sample_offset = pn_offset + (4 - 2); // 4 - pn_len for AES
    if (sample_offset + 16 > encoded.len) {
        std.log.err("Packet too short for sample extraction", .{});
        return;
    }

    const sample = encoded[sample_offset..sample_offset + 16];
    var mask: [5]u8 = undefined;
    crypto.computeHeaderMask(.aes_128_gcm, &test_keys.hp, sample.*, &mask);

    // Apply mask to recover original header
    header_first ^= mask[0] & 0x0f; // Only lower 4 bits for long header
    const pn_len = (header_first & 0x03) + 1;

    std.log.info("Recovered PN length: {}", .{pn_len});

    // XOR packet number bytes
    var pn_bytes: [4]u8 = [_]u8{0} ** 4;
    for (0..pn_len) |i| {
        pn_bytes[i] = encoded[pn_offset + i] ^ mask[1 + i];
    }

    // Reconstruct packet number
    var pn: u32 = 0;
    for (0..pn_len) |i| {
        pn = (pn << 8) | pn_bytes[i];
    }

    std.log.info("Recovered packet number: {}", .{pn});

    if (pn != 42) {
        std.log.err("Packet number mismatch! Expected 42, got {}", .{pn});
    } else {
        std.log.info("✅ Packet number matches!", .{});
    }

    // Now try to decrypt the payload
    const ciphertext_offset = pn_offset + pn_len;
    const ciphertext = encoded[ciphertext_offset..];

    // Build AAD
    var aad_buf: [256]u8 = undefined;
    aad_buf[0] = header_first;
    const header_len = pn_offset + pn_len;
    @memcpy(aad_buf[1..header_len], encoded[1..header_len]);
    const aad = aad_buf[0..header_len];

    // Decrypt
    var plaintext_buf: [1024]u8 = undefined;
    const plaintext_len = crypto.decryptPacket(
        .aes_128_gcm,
        &test_keys.key,
        &test_keys.iv,
        pn,
        aad,
        ciphertext,
        &plaintext_buf
    ) catch |err| {
        std.log.err("Decryption failed: {}", .{err});
        return;
    };

    std.log.info("Decrypted {} bytes", .{plaintext_len});
    std.log.info("Decrypted payload: {s}", .{plaintext_buf[0..plaintext_len]});

    if (std.mem.eql(u8, plaintext_buf[0..plaintext_len], payload)) {
        std.log.info("✅ Payload matches!", .{});
    } else {
        std.log.err("❌ Payload mismatch!", .{});
    }
}