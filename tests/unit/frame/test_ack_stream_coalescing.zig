//! Unit tests for ACK+STREAM frame coalescing.
//!
//! RFC References:
//! - RFC 9000 S13.2.1: An endpoint SHOULD send an ACK frame with every
//!   ACK-eliciting packet.  STREAM frames are ACK-eliciting, so including
//!   an ACK frame alongside a STREAM frame is the recommended behavior.
//!
//! These tests validate that ACK and STREAM frames can be serialized
//! sequentially into a single buffer (as done by writeStreamUnlocked's
//! ACK piggybacking) and decoded back correctly.
//!
//! Coverage:
//! - Positive: ACK followed by STREAM in single buffer decodes correctly
//! - Positive: ACK_ECN followed by STREAM decodes correctly
//! - Edge: ACK with ranges followed by STREAM decodes correctly
//! - Boundary: Buffer fits both frames within 2048-byte packet limit

const std = @import("std");
const testing = std.testing;

const frame = @import("quic_frame");

// =============================================================================
// ACK + STREAM Coalescing Tests
// =============================================================================

test "RFC 9000 S13.2.1 - ACK piggyback: ACK then STREAM in single buffer" {
    // Simulate what writeStreamUnlocked does: write ACK frame then STREAM frame
    // into a single fixedBufferStream, then decode both frames back.
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Write ACK frame (largest=42, delay=10, first_range=2, no extra ranges)
    const ack_bytes = try (frame.Frame{ .ack = .{
        .largest = 42,
        .ack_delay = 10,
        .first_range = 2,
        .ranges = &[_]frame.AckRange{},
        .ecn = null,
    } }).write(w);

    try testing.expect(ack_bytes > 0);

    // Write STREAM frame (stream_id=0, offset=0, data="hello")
    const stream_bytes = try (frame.Frame{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } }).write(w);

    try testing.expect(stream_bytes > 0);

    const total = fbs.getWritten();
    try testing.expectEqual(ack_bytes + stream_bytes, total.len);

    // Decode first frame: should be ACK
    const dec1 = try frame.decodeOne(total);
    switch (dec1.f) {
        .ack => |a| {
            try testing.expectEqual(@as(u64, 42), a.largest);
            try testing.expectEqual(@as(u64, 10), a.ack_delay);
            try testing.expectEqual(@as(u64, 2), a.first_range);
            try testing.expect(a.ecn == null);
        },
        else => return error.ExpectedAckFrame,
    }

    // Decode second frame: should be STREAM
    const dec2 = try frame.decodeOne(total[dec1.n..]);
    switch (dec2.f) {
        .stream => |s| {
            try testing.expectEqual(@as(u64, 0), s.stream_id);
            try testing.expectEqual(@as(u64, 0), s.offset);
            try testing.expect(!s.fin);
            try testing.expectEqualStrings("hello", s.data);
        },
        else => return error.ExpectedStreamFrame,
    }

    // No more frames
    try testing.expectEqual(total.len, dec1.n + dec2.n);
}

test "RFC 9000 S13.2.1 - ACK_ECN piggyback: ACK_ECN then STREAM" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Write ACK_ECN frame with ECN counters
    const ack_bytes = try (frame.Frame{ .ack = .{
        .largest = 100,
        .ack_delay = 5,
        .first_range = 0,
        .ranges = &[_]frame.AckRange{},
        .ecn = .{ .ect0 = 3, .ect1 = 1, .ce = 0 },
    } }).write(w);

    // Write STREAM frame with FIN
    const stream_bytes = try (frame.Frame{ .stream = .{
        .stream_id = 4,
        .offset = 1024,
        .fin = true,
        .data = "world",
    } }).write(w);

    const total = fbs.getWritten();
    try testing.expectEqual(ack_bytes + stream_bytes, total.len);

    // Decode ACK_ECN
    const dec1 = try frame.decodeOne(total);
    switch (dec1.f) {
        .ack => |a| {
            try testing.expectEqual(@as(u64, 100), a.largest);
            try testing.expect(a.ecn != null);
            try testing.expectEqual(@as(u64, 3), a.ecn.?.ect0);
            try testing.expectEqual(@as(u64, 1), a.ecn.?.ect1);
            try testing.expectEqual(@as(u64, 0), a.ecn.?.ce);
        },
        else => return error.ExpectedAckFrame,
    }

    // Decode STREAM
    const dec2 = try frame.decodeOne(total[dec1.n..]);
    switch (dec2.f) {
        .stream => |s| {
            try testing.expectEqual(@as(u64, 4), s.stream_id);
            try testing.expectEqual(@as(u64, 1024), s.offset);
            try testing.expect(s.fin);
            try testing.expectEqualStrings("world", s.data);
        },
        else => return error.ExpectedStreamFrame,
    }
}

test "RFC 9000 S13.2.1 - ACK with ranges then STREAM" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // ACK with additional ranges: [90-100] gap=2 [85-87]
    const ranges = [_]frame.AckRange{
        .{ .gap = 2, .len = 2 },
    };
    const ack_bytes = try (frame.Frame{ .ack = .{
        .largest = 100,
        .ack_delay = 0,
        .first_range = 10,
        .ranges = &ranges,
        .ecn = null,
    } }).write(w);

    const stream_bytes = try (frame.Frame{ .stream = .{
        .stream_id = 8,
        .offset = 500,
        .fin = false,
        .data = "data-with-ack-ranges",
    } }).write(w);

    const total = fbs.getWritten();
    try testing.expectEqual(ack_bytes + stream_bytes, total.len);

    const dec1 = try frame.decodeOne(total);
    switch (dec1.f) {
        .ack => |a| {
            try testing.expectEqual(@as(u64, 100), a.largest);
            try testing.expectEqual(@as(u64, 10), a.first_range);
            try testing.expectEqual(@as(usize, 1), a.ranges.len);
            try testing.expectEqual(@as(u64, 2), a.ranges[0].gap);
            try testing.expectEqual(@as(u64, 2), a.ranges[0].len);
        },
        else => return error.ExpectedAckFrame,
    }

    const dec2 = try frame.decodeOne(total[dec1.n..]);
    switch (dec2.f) {
        .stream => |s| {
            try testing.expectEqual(@as(u64, 8), s.stream_id);
            try testing.expectEqual(@as(u64, 500), s.offset);
            try testing.expectEqualStrings("data-with-ack-ranges", s.data);
        },
        else => return error.ExpectedStreamFrame,
    }
}

test "RFC 9000 S13.2.1 - coalesced ACK+STREAM fits within packet limit" {
    // Verify that a typical ACK + max-size STREAM fits in the 2048-byte
    // frame_storage buffer used by writeStreamUnlocked.
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Worst-case ACK: large PN values, multiple ranges
    var ranges: [8]frame.AckRange = undefined;
    for (&ranges) |*r| {
        r.* = .{ .gap = 100, .len = 50 };
    }
    const ack_bytes = try (frame.Frame{ .ack = .{
        .largest = 1_000_000,
        .ack_delay = 25000,
        .first_range = 100,
        .ranges = &ranges,
        .ecn = .{ .ect0 = 500, .ect1 = 200, .ce = 10 },
    } }).write(w);

    // The remaining space should accommodate a STREAM frame with typical payload.
    // writeStreamUnlocked caps to_send at ~1350 bytes.
    const remaining = 2048 - ack_bytes;
    try testing.expect(remaining >= 1400); // At least 1400 bytes left for STREAM

    // Write a STREAM frame with 1200 bytes of data (typical MTU payload)
    var payload: [1200]u8 = undefined;
    @memset(&payload, 0x42);
    const stream_bytes = try (frame.Frame{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = &payload,
    } }).write(w);

    const total = fbs.getWritten();
    try testing.expectEqual(ack_bytes + stream_bytes, total.len);
    try testing.expect(total.len <= 2048);
}
