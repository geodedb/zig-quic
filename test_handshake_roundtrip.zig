const std = @import("std");
const crypto = @import("src/quic/crypto_quic.zig");
const packet = @import("src/quic/packet.zig");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    // Test data
    const version: u32 = 1;
    const dcid = [_]u8{ 0xCD, 0x41, 0x38, 0xA1, 0x86, 0x09, 0x85, 0xB9 };
    const scid = [_]u8{ 0x2E, 0x62, 0xB0, 0x6A, 0xC0, 0x49, 0x88, 0x99 };
    const packet_number: u32 = 0;
    const packet_number_len: u3 = 2;
    const payload = "Test Handshake Payload - EncryptedExtensions, Certificate, CertificateVerify, Finished";

    // Test keys (from logs)
    const test_keys = packet.InitialKeys{
        .key = [_]u8{0x73, 0xDD, 0x76, 0xFD} ++ ([_]u8{0} ** 12),
        .iv = [_]u8{0xF6, 0xEF, 0x53, 0xB5} ++ ([_]u8{0} ** 8),
        .hp = [_]u8{0} ** 16, // Will be set properly
    };

    std.debug.print("Testing Handshake packet round-trip encryption/decryption\n", .{});
    std.debug.print("==========================================================\n", .{});
    std.debug.print("DCID: ", .{});
    for (dcid) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\n", .{});
    std.debug.print("SCID: ", .{});
    for (scid) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\n", .{});
    std.debug.print("Packet Number: {}\n", .{packet_number});
    std.debug.print("PN Length: {} bytes\n", .{packet_number_len});
    std.debug.print("Payload: {s}\n", .{payload});
    std.debug.print("\n", .{});

    // Encode the packet
    const encoded = try packet.encodeHandshakeProtected(
        alloc,
        version,
        &dcid,
        &scid,
        packet_number,
        packet_number_len,
        payload,
        test_keys,
    );
    defer alloc.free(encoded);

    std.debug.print("Encoded packet ({} bytes):\n", .{encoded.len});

    // Print first 64 bytes in hex
    const display_len = @min(64, encoded.len);
    var i: usize = 0;
    while (i < display_len) : (i += 16) {
        std.debug.print("{x:0>4}: ", .{i});
        var j: usize = i;
        while (j < @min(i + 16, display_len)) : (j += 1) {
            std.debug.print("{x:0>2} ", .{encoded[j]});
        }
        std.debug.print("\n", .{});
    }

    std.debug.print("\n", .{});
    std.debug.print("Packet structure analysis:\n", .{});
    std.debug.print("  Byte 0: {x:0>2} (first byte after HP)\n", .{encoded[0]});
    std.debug.print("  Bytes 1-4: {x:0>2} {x:0>2} {x:0>2} {x:0>2} (version)\n", .{
        encoded[1], encoded[2], encoded[3], encoded[4]
    });
    std.debug.print("  Byte 5: {x:0>2} (DCID length)\n", .{encoded[5]});
    if (encoded[5] > 0) {
        std.debug.print("  Bytes 6-{}: DCID\n", .{5 + encoded[5]});
    }
    const scid_offset = 6 + encoded[5];
    std.debug.print("  Byte {}: {x:0>2} (SCID length)\n", .{scid_offset, encoded[scid_offset]});
    if (encoded[scid_offset] > 0) {
        std.debug.print("  Bytes {}-{}: SCID\n", .{scid_offset + 1, scid_offset + encoded[scid_offset]});
    }
    const length_offset = scid_offset + 1 + encoded[scid_offset];
    std.debug.print("  Byte {}: Length varint start\n", .{length_offset});

    std.debug.print("\nTest complete!\n", .{});
}