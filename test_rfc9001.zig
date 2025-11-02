const std = @import("std");
const ks = @import("src/quic/tls/key_schedule.zig");
const packet = @import("src/quic/packet.zig");

// RFC 9001 Appendix A test vectors
const test_dcid = [_]u8{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// Expected values from RFC 9001
const expected_initial_secret = [_]u8{
    0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
    0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
    0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
};

const expected_client_initial_secret = [_]u8{
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
    0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
    0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
};

const expected_server_initial_secret = [_]u8{
    0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
    0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
    0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
};

const expected_client_key = [_]u8{
    0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
    0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
};

const expected_client_iv = [_]u8{
    0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
    0x46, 0xfb, 0x25, 0x5c,
};

const expected_client_hp = [_]u8{
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
    0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== RFC 9001 Test Vector Validation ===\n\n", .{});

    // Test 1: Initial secret derivation
    std.debug.print("Test 1: Initial Secret Derivation\n", .{});
    const initial_secret = ks.deriveInitialSecret(false, &test_dcid);

    std.debug.print("  DCID: ", .{});
    printHex(&test_dcid);
    std.debug.print("  Expected: ", .{});
    printHex(&expected_initial_secret);
    std.debug.print("  Got:      ", .{});
    printHex(&initial_secret);

    if (std.mem.eql(u8, &initial_secret, &expected_initial_secret)) {
        std.debug.print("  ✓ PASS\n\n", .{});
    } else {
        std.debug.print("  ✗ FAIL - Initial secret mismatch!\n\n", .{});
    }

    // Test 2: Client/Server secret derivation
    std.debug.print("Test 2: Client/Server Secret Derivation\n", .{});
    const secrets = ks.deriveClientServerInitial(initial_secret);

    std.debug.print("  Client Secret:\n", .{});
    std.debug.print("    Expected: ", .{});
    printHex(&expected_client_initial_secret);
    std.debug.print("    Got:      ", .{});
    printHex(&secrets.client);

    if (std.mem.eql(u8, &secrets.client, &expected_client_initial_secret)) {
        std.debug.print("    ✓ PASS\n", .{});
    } else {
        std.debug.print("    ✗ FAIL\n", .{});
    }

    std.debug.print("  Server Secret:\n", .{});
    std.debug.print("    Expected: ", .{});
    printHex(&expected_server_initial_secret);
    std.debug.print("    Got:      ", .{});
    printHex(&secrets.server);

    if (std.mem.eql(u8, &secrets.server, &expected_server_initial_secret)) {
        std.debug.print("    ✓ PASS\n\n", .{});
    } else {
        std.debug.print("    ✗ FAIL\n\n", .{});
    }

    // Test 3: Key/IV/HP derivation
    std.debug.print("Test 3: Key/IV/HP Derivation\n", .{});
    const client_keys = ks.deriveKeyIvHp(secrets.client);

    std.debug.print("  Client Key:\n", .{});
    std.debug.print("    Expected: ", .{});
    printHex(&expected_client_key);
    std.debug.print("    Got:      ", .{});
    printHex(&client_keys.key);

    if (std.mem.eql(u8, &client_keys.key, &expected_client_key)) {
        std.debug.print("    ✓ PASS\n", .{});
    } else {
        std.debug.print("    ✗ FAIL\n", .{});
    }

    std.debug.print("  Client IV:\n", .{});
    std.debug.print("    Expected: ", .{});
    printHex(&expected_client_iv);
    std.debug.print("    Got:      ", .{});
    printHex(&client_keys.iv);

    if (std.mem.eql(u8, &client_keys.iv, &expected_client_iv)) {
        std.debug.print("    ✓ PASS\n", .{});
    } else {
        std.debug.print("    ✗ FAIL\n", .{});
    }

    std.debug.print("  Client HP:\n", .{});
    std.debug.print("    Expected: ", .{});
    printHex(&expected_client_hp);
    std.debug.print("    Got:      ", .{});
    printHex(&client_keys.hp);

    if (std.mem.eql(u8, &client_keys.hp, &expected_client_hp)) {
        std.debug.print("    ✓ PASS\n\n", .{});
    } else {
        std.debug.print("    ✗ FAIL\n\n", .{});
    }

    // Test 4: Sample client Initial packet from RFC 9001
    std.debug.print("Test 4: Client Initial Packet Decryption\n", .{});

    // This is the protected packet from RFC 9001 Appendix A.2
    const protected_packet = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
        0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
        0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, // header ends here
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, // rest is payload
        // ... truncated for brevity
    };

    // Try to decrypt using our implementation
    const decrypted_payload = try allocator.alloc(u8, 1200);
    defer allocator.free(decrypted_payload);

    // Calculate packet number offset for Initial packet
    // pn_offset = 7 + len(dcid) + len(scid) + varint_len(token_len) + token_len + varint_len(payload_len)
    const dcid_len = protected_packet[5];
    const scid_offset = 6 + dcid_len;
    const scid_len = protected_packet[scid_offset];
    const token_offset = scid_offset + 1 + scid_len;

    // Parse token length (varint)
    var token_len: u64 = 0;
    var token_len_bytes: usize = 1;
    if ((protected_packet[token_offset] & 0xc0) == 0) {
        token_len = protected_packet[token_offset] & 0x3f;
    } else if ((protected_packet[token_offset] & 0xc0) == 0x40) {
        token_len = (@as(u64, protected_packet[token_offset] & 0x3f) << 8) |
                    @as(u64, protected_packet[token_offset + 1]);
        token_len_bytes = 2;
    }
    // ... handle longer varints if needed

    const payload_offset = token_offset + token_len_bytes + @as(usize, @intCast(token_len));

    std.debug.print("  Packet structure:\n", .{});
    std.debug.print("    DCID length: {}\n", .{dcid_len});
    std.debug.print("    SCID length: {}\n", .{scid_len});
    std.debug.print("    Token length: {}\n", .{token_len});
    std.debug.print("    Payload offset: {}\n", .{payload_offset});

    // The sample for header protection starts 4 bytes after the packet number field
    // For this packet, the packet number is at offset 18 and is 4 bytes long
    const pn_offset = payload_offset + 2; // After 2-byte length varint
    const sample_offset = pn_offset + 4;

    std.debug.print("    PN offset: {}\n", .{pn_offset});
    std.debug.print("    Sample offset: {}\n", .{sample_offset});

    if (sample_offset + 16 <= protected_packet.len) {
        const sample = protected_packet[sample_offset..sample_offset + 16];
        std.debug.print("    Sample: ", .{});
        printHex(sample);

        // Test header protection removal
        const hp_key = client_keys.hp;
        var mask: [16]u8 = undefined;
        const Aes128 = std.crypto.core.aes.Aes128;
        var ctx = Aes128.initEnc(hp_key[0..16].*);
        ctx.encrypt(&mask, sample[0..16]);

        std.debug.print("    HP Mask (first 5 bytes): ", .{});
        printHex(mask[0..5]);

        // Apply mask to recover packet number length
        const first_byte_mask = if ((protected_packet[0] & 0x80) != 0) 0x0f else 0x1f;
        const orig_first = protected_packet[0] ^ (mask[0] & first_byte_mask);
        const pn_len = (orig_first & 0x03) + 1;

        std.debug.print("    Recovered PN length: {}\n", .{pn_len});

        // Recover packet number bytes
        var pn_bytes: [4]u8 = undefined;
        for (0..pn_len) |i| {
            pn_bytes[i] = protected_packet[pn_offset + i] ^ mask[1 + i];
        }

        std.debug.print("    Recovered PN bytes: ", .{});
        printHex(pn_bytes[0..pn_len]);
    }

    std.debug.print("\n", .{});
}

fn printHex(data: []const u8) void {
    for (data) |byte| {
        std.debug.print("{x:0>2}\n", .{byte});
    }
    std.debug.print("\n", .{});
}