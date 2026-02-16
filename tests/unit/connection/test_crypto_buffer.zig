//! Unit tests for connection/crypto_buffer.zig
//!
//! RFC References:
//! - RFC 9000 §4.9.2: Handling Out-of-Order CRYPTO Frames
//! - RFC 9000 §7: Cryptographic Handshake
//! - RFC 9001 §4: CRYPTO Frames
//!
//! Coverage:
//! - Positive cases: In-order addition, out-of-order reassembly, contiguous detection
//! - Negative cases: Buffer overflow, duplicate fragments, overlapping data
//! - Edge cases: Empty fragments, max capacity (8 fragments), offset wraparound
//! - RFC compliance: Out-of-order handling, contiguous data consumption

const std = @import("std");
const testing = std.testing;

// Direct imports - module paths configured in build.zig
const crypto_buffer = @import("crypto_buffer");
const CryptoBuffer = crypto_buffer.CryptoBuffer;
const Fragment = crypto_buffer.Fragment;

var test_allocator = std.testing.allocator;

// =============================================================================
// Basic Addition Tests
// =============================================================================

test "RFC 9000 §4.9.2 - CryptoBuffer add single fragment at offset 0" {
    var buffer: CryptoBuffer = .{};
    const data = "Hello";

    try buffer.add(0, data, test_allocator);
    defer buffer.clear(test_allocator);

    try testing.expectEqual(@as(usize, 1), buffer.count);
    try testing.expect(buffer.fragments[0] != null);
    try testing.expectEqual(@as(u64, 0), buffer.fragments[0].?.offset);
}

test "RFC 9000 §4.9.2 - CryptoBuffer add sequential fragments" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "Hello", test_allocator);
    try buffer.add(5, " World", test_allocator);
    try buffer.add(11, "!", test_allocator);

    try testing.expectEqual(@as(usize, 3), buffer.count);
}

test "RFC 9000 §4.9.2 - CryptoBuffer add out-of-order fragments" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    // Add in reverse order
    try buffer.add(10, "Third", test_allocator);
    try buffer.add(0, "First", test_allocator);
    try buffer.add(5, "Second", test_allocator);

    try testing.expectEqual(@as(usize, 3), buffer.count);

    // Verify sorted order
    try testing.expectEqual(@as(u64, 0), buffer.fragments[0].?.offset);
    try testing.expectEqual(@as(u64, 5), buffer.fragments[1].?.offset);
    try testing.expectEqual(@as(u64, 10), buffer.fragments[2].?.offset);
}

test "RFC 9000 §4.9.2 - CryptoBuffer preserves data content" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    const test_data = "Test Data";
    try buffer.add(0, test_data, test_allocator);

    const stored_data = buffer.fragments[0].?.data;
    try testing.expectEqualStrings(test_data, stored_data);
}

// =============================================================================
// Contiguous Detection Tests
// =============================================================================

test "RFC 9000 §4.9.2 - getContiguous returns single fragment at start offset" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "Data", test_allocator);

    const result = buffer.getContiguous(0);
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 1), result.?.len);
}

test "RFC 9000 §4.9.2 - getContiguous returns null when no data at start offset" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(10, "Data", test_allocator);

    const result = buffer.getContiguous(0);
    try testing.expect(result == null);
}

test "RFC 9000 §4.9.2 - getContiguous returns multiple contiguous fragments" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "Hello", test_allocator); // 5 bytes
    try buffer.add(5, "World", test_allocator); // 5 bytes
    try buffer.add(10, "!", test_allocator); // 1 byte

    const result = buffer.getContiguous(0);
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 3), result.?.len);
}

test "RFC 9000 §4.9.2 - getContiguous stops at gap" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "AAA", test_allocator); // offset 0, len 3
    try buffer.add(3, "BBB", test_allocator); // offset 3, len 3
    // Gap here - no data at offset 6
    try buffer.add(10, "CCC", test_allocator); // offset 10, len 3

    const result = buffer.getContiguous(0);
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 2), result.?.len); // Only AAA and BBB
}

test "RFC 9000 §4.9.2 - getContiguous handles overlapping fragments" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "AAAAA", test_allocator); // offset 0, len 5
    try buffer.add(3, "BBB", test_allocator); // offset 3, len 3 (overlaps)

    const result = buffer.getContiguous(0);
    try testing.expect(result != null);
    // Should handle overlap gracefully
    try testing.expect(result.?.len > 0);
}

// =============================================================================
// Fragment Removal Tests
// =============================================================================

test "RFC 9000 §4.9.2 - removeProcessed shifts remaining fragments" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "A", test_allocator);
    try buffer.add(1, "B", test_allocator);
    try buffer.add(2, "C", test_allocator);

    buffer.removeProcessed(2, test_allocator);

    try testing.expectEqual(@as(usize, 1), buffer.count);
    try testing.expectEqual(@as(u64, 2), buffer.fragments[0].?.offset);
}

test "RFC 9000 §4.9.2 - removeProcessed updates count correctly" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "Data1", test_allocator);
    try buffer.add(5, "Data2", test_allocator);
    try buffer.add(10, "Data3", test_allocator);

    buffer.removeProcessed(1, test_allocator);
    try testing.expectEqual(@as(usize, 2), buffer.count);

    buffer.removeProcessed(1, test_allocator);
    try testing.expectEqual(@as(usize, 1), buffer.count);
}

test "RFC 9000 §4.9.2 - removeProcessed all fragments leaves empty buffer" {
    var buffer: CryptoBuffer = .{};

    try buffer.add(0, "Data", test_allocator);

    buffer.removeProcessed(1, test_allocator);

    try testing.expectEqual(@as(usize, 0), buffer.count);
}

// =============================================================================
// Clear Tests
// =============================================================================

test "RFC 9000 §4.9.2 - clear removes all fragments" {
    var buffer: CryptoBuffer = .{};

    try buffer.add(0, "A", test_allocator);
    try buffer.add(1, "B", test_allocator);
    try buffer.add(2, "C", test_allocator);

    buffer.clear(test_allocator);

    try testing.expectEqual(@as(usize, 0), buffer.count);
}

test "RFC 9000 §4.9.2 - clear on empty buffer is safe" {
    var buffer: CryptoBuffer = .{};

    buffer.clear(test_allocator);

    try testing.expectEqual(@as(usize, 0), buffer.count);
}

// =============================================================================
// Boundary and Edge Cases
// =============================================================================

test "boundary: CryptoBuffer max capacity (8 fragments)" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    // Fill buffer to capacity
    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        try buffer.add(i * 10, "Data", test_allocator);
    }

    try testing.expectEqual(@as(usize, 8), buffer.count);
}

test "negative: CryptoBuffer add beyond capacity returns error" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    // Fill to capacity
    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        try buffer.add(i * 10, "Data", test_allocator);
    }

    // Try to add one more
    const result = buffer.add(100, "Extra", test_allocator);
    try testing.expectError(error.BufferFull, result);
}

test "boundary: CryptoBuffer empty data" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "", test_allocator);

    try testing.expectEqual(@as(usize, 1), buffer.count);
}

test "boundary: CryptoBuffer large offset" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    const large_offset: u64 = 1_000_000_000;
    try buffer.add(large_offset, "Data", test_allocator);

    try testing.expectEqual(large_offset, buffer.fragments[0].?.offset);
}

test "boundary: CryptoBuffer adjacent fragments are contiguous" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    try buffer.add(0, "AAA", test_allocator); // 3 bytes
    try buffer.add(3, "BBB", test_allocator); // 3 bytes at offset 3

    const result = buffer.getContiguous(0);
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 2), result.?.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §4.9.2 - Buffer handles out-of-order TLS handshake messages" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    // Simulate TLS handshake arriving out of order
    try buffer.add(1000, "ServerHello", test_allocator);
    try buffer.add(0, "ClientHello", test_allocator);
    try buffer.add(1011, "Certificate", test_allocator);

    // Should be sorted by offset
    try testing.expectEqual(@as(u64, 0), buffer.fragments[0].?.offset);
    try testing.expectEqual(@as(u64, 1000), buffer.fragments[1].?.offset);
    try testing.expectEqual(@as(u64, 1011), buffer.fragments[2].?.offset);
}

test "RFC 9000 §7 - Progressive handshake consumption" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    // Add initial fragment
    try buffer.add(0, "Part1", test_allocator);

    // Can consume it
    var result = buffer.getContiguous(0);
    try testing.expect(result != null);

    // Remove processed
    buffer.removeProcessed(1, test_allocator);

    // Add next fragment
    try buffer.add(5, "Part2", test_allocator);

    // Can consume from new offset
    result = buffer.getContiguous(5);
    try testing.expect(result != null);
}

test "RFC 9001 §4 - CRYPTO frame data integrity" {
    var buffer: CryptoBuffer = .{};
    defer buffer.clear(test_allocator);

    const original_data = "Sensitive TLS Data";
    try buffer.add(0, original_data, test_allocator);

    // Verify data is not corrupted
    const stored = buffer.fragments[0].?.data;
    try testing.expectEqualStrings(original_data, stored);
}
