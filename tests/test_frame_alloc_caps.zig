// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Fuzz-style tests for frame allocation caps.
//!
//! These tests verify that the reader-based frame.decode() rejects oversized
//! frames with error.FrameTooLarge BEFORE any heap allocation occurs.
//!
//! Caps under test (from frame.zig):
//!   - max_frame_data_len   = 65536  (CRYPTO, STREAM, DATAGRAM)
//!   - max_ack_ranges       = 256    (ACK range_count)
//!   - max_reason_or_token_len = 1024 (CONNECTION_CLOSE reason, NEW_TOKEN token)
//!   - CID length > 20             (NEW_CONNECTION_ID, RFC 9000 section 19.15)
//!
//! Each test constructs minimal wire bytes with an oversized varint in the
//! length / count field, wraps them in a fixedBufferStream reader, and calls
//! frame.decode(). The allocator is std.testing.failing_allocator so that any
//! allocation attempt would itself fail -- proving the cap check fires first.

const std = @import("std");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const testing = std.testing;

/// Helper: encode a QUIC varint value into a caller-provided buffer slice.
/// Returns the number of bytes written.
fn encodeVarint(value: u64, out: []u8) !usize {
    return varint.encode(value, out);
}

// ============================================================================
// CRYPTO frame: data length = 65537 exceeds max_frame_data_len (65536)
// ============================================================================

test "alloc cap: CRYPTO frame with data length 65537 returns FrameTooLarge" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    // Frame type: CRYPTO = 0x06
    buf[pos] = 0x06;
    pos += 1;

    // Offset: 0 (1-byte varint)
    const off_len = try encodeVarint(0, buf[pos..]);
    pos += off_len;

    // Length: 65537 (exceeds cap of 65536)
    const data_len = try encodeVarint(65537, buf[pos..]);
    pos += data_len;

    // No actual data bytes needed -- the cap check fires before reading data.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    // Use failing_allocator: any allocation attempt = immediate test failure.
    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// ACK frame: range_count = 257 exceeds max_ack_ranges (256)
// ============================================================================

test "alloc cap: ACK frame with range_count 257 returns FrameTooLarge" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Frame type: ACK = 0x02
    buf[pos] = 0x02;
    pos += 1;

    // Largest Acknowledged: 100
    pos += try encodeVarint(100, buf[pos..]);

    // ACK Delay: 0
    pos += try encodeVarint(0, buf[pos..]);

    // ACK Range Count: 257 (exceeds cap of 256)
    pos += try encodeVarint(257, buf[pos..]);

    // First ACK Range: 0
    pos += try encodeVarint(0, buf[pos..]);

    // No actual range pairs needed -- the cap check fires before reading ranges.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// STREAM frame: data length = 65537 exceeds max_frame_data_len (65536)
// ============================================================================

test "alloc cap: STREAM frame with data length 65537 returns FrameTooLarge" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Frame type: STREAM with OFF + LEN bits set = 0x08 | 0x04 | 0x02 = 0x0e
    buf[pos] = 0x0e;
    pos += 1;

    // Stream ID: 1
    pos += try encodeVarint(1, buf[pos..]);

    // Offset: 0
    pos += try encodeVarint(0, buf[pos..]);

    // Length: 65537 (exceeds cap of 65536)
    pos += try encodeVarint(65537, buf[pos..]);

    // No actual data bytes needed.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// DATAGRAM frame: data length = 65537 exceeds max_frame_data_len (65536)
// ============================================================================

test "alloc cap: DATAGRAM frame with data length 65537 returns FrameTooLarge" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    // Frame type: DATAGRAM = 0x30
    buf[pos] = 0x30;
    pos += 1;

    // Length: 65537 (exceeds cap of 65536)
    pos += try encodeVarint(65537, buf[pos..]);

    // No actual data bytes needed.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// CONNECTION_CLOSE frame: reason length = 1025 exceeds max_reason_or_token_len
// ============================================================================

test "alloc cap: CONNECTION_CLOSE frame with reason length 1025 returns FrameTooLarge" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Frame type: CONNECTION_CLOSE = 0x1c
    buf[pos] = 0x1c;
    pos += 1;

    // Error Code: 0
    pos += try encodeVarint(0, buf[pos..]);

    // Frame Type: 0
    pos += try encodeVarint(0, buf[pos..]);

    // Reason Phrase Length: 1025 (exceeds cap of 1024)
    pos += try encodeVarint(1025, buf[pos..]);

    // No actual reason bytes needed.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// NEW_TOKEN frame: token length = 1025 exceeds max_reason_or_token_len (1024)
// ============================================================================

test "alloc cap: NEW_TOKEN frame with token length 1025 returns FrameTooLarge" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    // Frame type: NEW_TOKEN = 0x07
    buf[pos] = 0x07;
    pos += 1;

    // Token Length: 1025 (exceeds cap of 1024)
    pos += try encodeVarint(1025, buf[pos..]);

    // No actual token bytes needed.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// NEW_CONNECTION_ID frame: CID length = 21 exceeds RFC 9000 max of 20
// ============================================================================

test "alloc cap: NEW_CONNECTION_ID frame with CID length 21 returns FrameTooLarge" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    // Frame type: NEW_CONNECTION_ID = 0x18
    buf[pos] = 0x18;
    pos += 1;

    // Sequence Number: 1
    pos += try encodeVarint(1, buf[pos..]);

    // Retire Prior To: 0
    pos += try encodeVarint(0, buf[pos..]);

    // CID Length: 21 (single byte, exceeds RFC 9000 max of 20)
    buf[pos] = 21;
    pos += 1;

    // No actual CID bytes or stateless reset token needed.

    var fbs = std.io.fixedBufferStream(buf[0..pos]);
    const r = fbs.reader();

    const result = frame.decode(r, std.testing.failing_allocator);
    try testing.expectError(error.FrameTooLarge, result);
}

// ============================================================================
// Boundary verification: values AT the cap should succeed (not FrameTooLarge)
// ============================================================================

test "alloc cap: CRYPTO frame with data length exactly 65536 does not return FrameTooLarge" {
    // Build wire bytes: frame type + offset varint + length varint + 65536 data bytes
    var buf_list = std.ArrayList(u8).init(testing.allocator);
    defer buf_list.deinit();
    const w = buf_list.writer();

    // Frame type: CRYPTO = 0x06
    try w.writeByte(0x06);

    // Offset: 0
    var tmp: [8]u8 = undefined;
    const off_len = try encodeVarint(0, &tmp);
    try w.writeAll(tmp[0..off_len]);

    // Length: 65536 (exactly at cap, should be accepted)
    const data_varint_len = try encodeVarint(65536, &tmp);
    try w.writeAll(tmp[0..data_varint_len]);

    // Append 65536 zero bytes as data payload
    try buf_list.appendNTimes(0xAA, 65536);

    var fbs = std.io.fixedBufferStream(buf_list.items);
    const r = fbs.reader();

    // This should succeed (value is at cap, not over it)
    const decoded = try frame.decode(r, testing.allocator);
    const data_len = decoded.crypto.data.len;
    const offset = decoded.crypto.offset;
    // Clean up the allocated data
    testing.allocator.free(decoded.crypto.data);
    try testing.expectEqual(@as(u64, 0), offset);
    try testing.expectEqual(@as(usize, 65536), data_len);
}

test "alloc cap: ACK frame with range_count exactly 256 does not return FrameTooLarge" {
    // Build wire bytes for ACK with 256 ranges
    var buf_list = std.ArrayList(u8).init(testing.allocator);
    defer buf_list.deinit();
    const w = buf_list.writer();

    // Frame type: ACK = 0x02
    try w.writeByte(0x02);

    var tmp: [8]u8 = undefined;

    // Largest Acknowledged: 1000
    var n = try encodeVarint(1000, &tmp);
    try w.writeAll(tmp[0..n]);

    // ACK Delay: 0
    n = try encodeVarint(0, &tmp);
    try w.writeAll(tmp[0..n]);

    // ACK Range Count: 256 (at cap)
    n = try encodeVarint(256, &tmp);
    try w.writeAll(tmp[0..n]);

    // First ACK Range: 0
    n = try encodeVarint(0, &tmp);
    try w.writeAll(tmp[0..n]);

    // Write 256 range pairs (gap=0, len=0 each)
    for (0..256) |_| {
        n = try encodeVarint(0, &tmp);
        try w.writeAll(tmp[0..n]); // gap
        n = try encodeVarint(0, &tmp);
        try w.writeAll(tmp[0..n]); // len
    }

    var fbs = std.io.fixedBufferStream(buf_list.items);
    const r = fbs.reader();

    const decoded = try frame.decode(r, testing.allocator);
    const ranges_len = decoded.ack.ranges.len;
    testing.allocator.free(decoded.ack.ranges);
    try testing.expectEqual(@as(usize, 256), ranges_len);
}

test "alloc cap: NEW_CONNECTION_ID with CID length exactly 20 does not return FrameTooLarge" {
    var buf_list = std.ArrayList(u8).init(testing.allocator);
    defer buf_list.deinit();
    const w = buf_list.writer();

    // Frame type: NEW_CONNECTION_ID = 0x18
    try w.writeByte(0x18);

    var tmp: [8]u8 = undefined;

    // Sequence Number: 1
    var n = try encodeVarint(1, &tmp);
    try w.writeAll(tmp[0..n]);

    // Retire Prior To: 0
    n = try encodeVarint(0, &tmp);
    try w.writeAll(tmp[0..n]);

    // CID Length: 20 (exactly at RFC 9000 max)
    try w.writeByte(20);

    // 20 bytes of CID
    try w.writeByteNTimes(0xCC, 20);

    // 16-byte stateless reset token
    try w.writeByteNTimes(0xDD, 16);

    var fbs = std.io.fixedBufferStream(buf_list.items);
    const r = fbs.reader();

    const decoded = try frame.decode(r, testing.allocator);
    const cid_len = decoded.new_connection_id.connection_id.len;
    testing.allocator.free(decoded.new_connection_id.connection_id);
    try testing.expectEqual(@as(usize, 20), cid_len);
}
