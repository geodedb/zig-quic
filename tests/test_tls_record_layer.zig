const std = @import("std");
const record = @import("tls_record");

// Ensure TLSPlaintext framing obeys RFC 8446 §5.1 semantics.
test "record_plaintext_roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const payload = "client hello";
    const encoded = try record.encodePlaintext(alloc, .handshake, payload);
    defer alloc.free(encoded);
    try std.testing.expectEqual(@as(usize, 5 + payload.len), encoded.len);
    try std.testing.expectEqual(@as(u8, @intFromEnum(record.ContentType.handshake)), encoded[0]);

    const parsed = try record.decodePlaintext(encoded);
    try std.testing.expectEqual(record.ContentType.handshake, parsed.content_type);
    try std.testing.expectEqual(record.default_legacy_version, parsed.legacy_version);
    try std.testing.expectEqualSlices(u8, payload, parsed.fragment);
}

// Validate TLSInnerPlaintext packing/unpacking with padding (RFC 8446 §5.4).
test "inner_plaintext_pack_unpack" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const content = "finished";
    const padding_len: usize = 6;
    const inner = try record.packInnerPlaintext(alloc, .handshake, content, padding_len);
    defer alloc.free(inner);
    try std.testing.expectEqual(@as(usize, content.len + 1 + padding_len), inner.len);
    try std.testing.expectEqual(@as(u8, @intFromEnum(record.ContentType.handshake)), inner[content.len]);

    const unpacked = try record.unpackInnerPlaintext(inner);
    try std.testing.expectEqual(record.ContentType.handshake, unpacked.content_type);
    try std.testing.expectEqual(padding_len, unpacked.padding_len);
    try std.testing.expectEqualSlices(u8, content, unpacked.content);
}

// Reject malformed records and invalid padding boundaries.
test "record_validation_errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Length mismatch (declared length larger than available bytes)
    var truncated = [_]u8{ @intFromEnum(record.ContentType.handshake), 0x03, 0x03, 0x00, 0xFF };
    try std.testing.expectError(record.RecordError.LengthMismatch, record.decodePlaintext(&truncated));

    // Padding too large relative to RFC 8446 limit
    try std.testing.expectError(record.RecordError.PaddingTooLarge, record.packInnerPlaintext(alloc, .application_data, "", record.max_inner_padding + 1));

    // Missing content type (all padding bytes)
    const all_zeros = [_]u8{ 0, 0, 0 };
    try std.testing.expectError(record.RecordError.MissingContentType, record.unpackInnerPlaintext(&all_zeros));

    // Unsupported legacy version
    var bad_version = [_]u8{ @intFromEnum(record.ContentType.handshake), 0x03, 0x04, 0x00, 0x00 };
    try std.testing.expectError(record.RecordError.UnsupportedLegacyVersion, record.decodePlaintext(&bad_version));
}

// AEAD round-trip with deterministic key/IV (RFC 8446 §5.2, §5.3).
test "aead_cipher_seal_open_roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const iv = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab };
    const aad = "tls13-record";
    const payload = "inner plaintext";

    var cipher = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const ciphertext = try cipher.seal(alloc, 0x0000_0000_0000_0001, aad, payload);
    defer alloc.free(ciphertext);

    const recovered = try cipher.open(alloc, 0x0000_0000_0000_0001, aad, ciphertext);
    defer alloc.free(recovered);

    try std.testing.expectEqualSlices(u8, payload, recovered);
}

// Enforce confidentiality limit and integrity failure accounting per RFC 8446 §5.5.
test "aead_usage_limits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    var cipher_conf = try record.AeadCipher.init(
        .TLS_AES_128_GCM_SHA256,
        &key,
        &iv,
        .{ .confidentiality = 1, .integrity = 1 },
    );
    defer cipher_conf.wipe();

    const aad = "aad";
    const payload = "payload";

    const first = try cipher_conf.seal(alloc, 7, aad, payload);
    defer alloc.free(first);
    try std.testing.expectError(record.RecordError.AeadLimitExceeded, cipher_conf.seal(alloc, 8, aad, payload));

    var cipher_int = try record.AeadCipher.init(
        .TLS_AES_128_GCM_SHA256,
        &key,
        &iv,
        .{ .confidentiality = 0, .integrity = 1 },
    );
    defer cipher_int.wipe();

    const ciphertext = try cipher_int.seal(alloc, 42, aad, payload);
    defer alloc.free(ciphertext);

    var tampered = try alloc.dupe(u8, ciphertext);
    defer alloc.free(tampered);
    tampered[0] ^= 0x01;
    try std.testing.expectError(record.RecordError.AuthenticationFailed, cipher_int.open(alloc, 42, aad, tampered));

    var tampered_again = try alloc.dupe(u8, ciphertext);
    defer alloc.free(tampered_again);
    tampered_again[tampered_again.len - 1] ^= 0x80;
    try std.testing.expectError(record.RecordError.AeadLimitExceeded, cipher_int.open(alloc, 42, aad, tampered_again));
}

test "xor_nonce_derivation" {
    const base = [_]u8{ 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44 };
    var derived = base;
    try record.xorNonce(derived[0..], base[0..], 0x0102030405060708);

    const expected = [_]u8{
        0x10,        0x32,        0x54,        0x76,
        0x98 ^ 0x01, 0xba ^ 0x02, 0xdc ^ 0x03, 0xfe ^ 0x04,
        0x11 ^ 0x05, 0x22 ^ 0x06, 0x33 ^ 0x07, 0x44 ^ 0x08,
    };

    try std.testing.expectEqualSlices(u8, expected[0..], derived[0..]);

    var short = [_]u8{ 0, 0, 0 };
    try std.testing.expectError(record.RecordError.InvalidIvLength, record.xorNonce(short[0..2], short[0..], 1));
}
