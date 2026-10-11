// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC frame types and common structures.
//!
//! RFC 9000 §19: Frame Types and Formats
//! RFC 9221: DATAGRAM Extension

const std = @import("std");

/// Known QUIC frame type bytes (subset).
/// RFC 9000 §19 defines frame types with specific byte values.
pub const FrameType = enum(u8) {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    ACK_ECN = 0x03,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    STREAM = 0x08, // 0x08-0x0f with flags
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    NEW_CONNECTION_ID = 0x18,
    RETIRE_CONNECTION_ID = 0x19,
    PATH_CHALLENGE = 0x1a,
    PATH_RESPONSE = 0x1b,
    CONNECTION_CLOSE = 0x1c,
    APPLICATION_CLOSE = 0x1d, // RFC 9000 §19.19 - application-level close (no frame_type field)
    HANDSHAKE_DONE = 0x1e,
    DATAGRAM = 0x30, // RFC 9221 (optional) - LEN=0: data runs to end of packet
    DATAGRAM_LEN = 0x31, // RFC 9221 - LEN=1: explicit Length varint precedes data
};

/// Ack range element used inside ACK frames (gap,len VarInts).
/// RFC 9000 §19.3: ACK Frame format includes ACK ranges.
pub const AckRange = struct {
    gap: u64,
    len: u64,
};

/// Validated, inclusive ACK intervals, in descending packet-number order.
/// Numeric range width never determines the amount of work or storage.
pub const AckIntervals = struct {
    pub const max_additional_ranges = 64;
    const Interval = struct { lower: u64, upper: u64 };
    intervals: [max_additional_ranges + 1]Interval = undefined,
    len: usize = 0,

    pub fn init(largest: u64, first_range: u64, ranges: []const AckRange) !AckIntervals {
        if (largest > std.math.maxInt(u62) or first_range > largest or ranges.len > max_additional_ranges)
            return error.InvalidAckRange;
        var result = AckIntervals{};
        var lower = largest - first_range;
        result.intervals[0] = .{ .lower = lower, .upper = largest };
        result.len = 1;
        for (ranges) |range| {
            const skip = std.math.add(u64, range.gap, 2) catch return error.InvalidAckRange;
            if (lower < skip) return error.InvalidAckRange;
            const upper = lower - skip;
            if (range.len > upper) return error.InvalidAckRange;
            lower = upper - range.len;
            result.intervals[result.len] = .{ .lower = lower, .upper = upper };
            result.len += 1;
        }
        return result;
    }

    pub fn contains(self: *const AckIntervals, pn: u64) bool {
        for (self.intervals[0..self.len]) |interval| {
            if (pn > interval.upper) return false;
            if (pn >= interval.lower) return true;
        }
        return false;
    }

    /// Keep the direct-index fast path for small ACKs. A larger ACK must be
    /// matched against tracked packets, never truncated or fully expanded.
    pub fn packetNumbers(self: *const AckIntervals, storage: []u64) ?[]const u64 {
        var count: usize = 0;
        for (self.intervals[0..self.len]) |interval| {
            const width = interval.upper - interval.lower + 1;
            if (width > storage.len - count) return null;
            count += @intCast(width);
        }
        var index: usize = 0;
        for (self.intervals[0..self.len]) |interval| {
            var pn = interval.upper;
            while (true) {
                storage[index] = pn;
                index += 1;
                if (pn == interval.lower) break;
                pn -= 1;
            }
        }
        return storage[0..count];
    }
};

/// ECN counters carried by ACK_ECN frame.
/// RFC 9000 §19.3.2: ACK_ECN includes ECT0, ECT1, and CE counts.
pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};
