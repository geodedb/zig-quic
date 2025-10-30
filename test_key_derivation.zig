const std = @import("std");
const tls13 = @import("src/quic/tls/tls13.zig");
const ks = @import("src/quic/tls/key_schedule.zig");

pub fn main() !void {
    // Test vector from RFC 8448 or similar
    // Using a known handshake secret to derive QUIC keys

    // Example handshake secret (32 bytes)
    const test_secret = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    std.log.info("Testing QUIC key derivation from handshake secret", .{});
    std.log.info("Input secret: {x}", .{std.fmt.fmtSliceHexLower(&test_secret)});

    // Derive QUIC v1 keys
    const keys = ks.deriveKeyIvHp(test_secret);

    std.log.info("Derived key: {x}", .{std.fmt.fmtSliceHexLower(&keys.key)});
    std.log.info("Derived IV:  {x}", .{std.fmt.fmtSliceHexLower(&keys.iv)});
    std.log.info("Derived HP:  {x}", .{std.fmt.fmtSliceHexLower(&keys.hp)});

    // Now test with actual handshake secret from logs
    const actual_secret = [_]u8{
        0xbc, 0xd9, 0x0c, 0x21, // First 4 bytes from log
        // Fill in rest with zeros for now
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    };

    std.log.info("\nTesting with actual secret from logs:", .{});
    const actual_keys = ks.deriveKeyIvHp(actual_secret);
    std.log.info("Key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        actual_keys.key[0], actual_keys.key[1], actual_keys.key[2], actual_keys.key[3]
    });
}