// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! ACK and ACK_ECN frames for acknowledgment.
//!
//! RFC 9000 §19.3: ACK Frame
//! RFC 9000 §19.3.2: ACK_ECN Frame (ACK with ECN counts)
//! RFC 3168: Explicit Congestion Notification

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// Encode ACK or ACK_ECN frame.
/// RFC 9000 §19.3: ACK frames acknowledge received packets with ranges.
pub fn writeAck(
    w: anytype,
    largest: u64,
    ack_delay: u64,
    first_range: u64,
    ranges: []const types.AckRange,
    ecn: ?types.EcnCounts,
) !usize {
    // Choose type based on ECN presence
    const ty: u8 = if (ecn != null)
        @intFromEnum(types.FrameType.ACK_ECN)
    else
        @intFromEnum(types.FrameType.ACK);

    try w.writeByte(ty);
    var written: usize = 1;
    var tmp: [16]u8 = undefined;

    // Largest Acknowledged
    const la = try varint.encode(largest, &tmp);
    try w.writeAll(tmp[0..la]);
    written += la;

    // ACK Delay
    const ad = try varint.encode(ack_delay, &tmp);
    try w.writeAll(tmp[0..ad]);
    written += ad;

    // ACK Range Count
    const rc_val: u64 = @intCast(ranges.len);
    const rc = try varint.encode(rc_val, &tmp);
    try w.writeAll(tmp[0..rc]);
    written += rc;

    // First ACK Range
    const fr = try varint.encode(first_range, &tmp);
    try w.writeAll(tmp[0..fr]);
    written += fr;

    // Additional ACK Ranges (gap, length pairs)
    for (ranges) |r| {
        const g = try varint.encode(r.gap, &tmp);
        try w.writeAll(tmp[0..g]);
        written += g;

        const rl = try varint.encode(r.len, &tmp);
        try w.writeAll(tmp[0..rl]);
        written += rl;
    }

    // ECN Counts (only for ACK_ECN)
    if (ecn) |e| {
        const e0 = try varint.encode(e.ect0, &tmp);
        try w.writeAll(tmp[0..e0]);
        written += e0;

        const e1 = try varint.encode(e.ect1, &tmp);
        try w.writeAll(tmp[0..e1]);
        written += e1;

        const ce = try varint.encode(e.ce, &tmp);
        try w.writeAll(tmp[0..ce]);
        written += ce;
    }

    return written;
}

/// Decode ACK or ACK_ECN frame with embedded ranges buffer.
/// RFC 9000 §19.3: Returns ACK fields with ranges stored in internal buffer.
pub fn decodeAck(buf: []const u8) !struct {
    largest: u64,
    ack_delay: u64,
    first_range: u64,
    ranges: []const types.AckRange,
    ecn: ?types.EcnCounts,
    ranges_buf: [16]types.AckRange, // Internal storage for ranges
    ranges_len: usize,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;

    const t = buf[0];
    if (t != @intFromEnum(types.FrameType.ACK) and
        t != @intFromEnum(types.FrameType.ACK_ECN))
    {
        return error.InvalidFrameType;
    }

    var i: usize = 1;

    // Largest Acknowledged
    const largest = try varint.decode(buf[i..]);
    i += largest.n;

    // ACK Delay
    const ack_delay = try varint.decode(buf[i..]);
    i += ack_delay.n;

    // ACK Range Count
    const range_count = try varint.decode(buf[i..]);
    i += range_count.n;

    // First ACK Range
    const first_range = try varint.decode(buf[i..]);
    i += first_range.n;

    // Parse additional ACK ranges (gap, length pairs)
    var ranges_buf: [16]types.AckRange = undefined;
    var out_len: usize = 0;
    var rc_left: u64 = range_count.value;

    while (rc_left > 0) : (rc_left -= 1) {
        const gap = try varint.decode(buf[i..]);
        i += gap.n;

        const lenv = try varint.decode(buf[i..]);
        i += lenv.n;

        if (i > buf.len) return error.Truncated;

        // Store up to buffer capacity
        if (out_len < ranges_buf.len) {
            ranges_buf[out_len] = .{
                .gap = gap.value,
                .len = lenv.value,
            };
            out_len += 1;
        }
    }

    // ECN Counts (only for ACK_ECN)
    var ecn_counts: ?types.EcnCounts = null;
    if (t == @intFromEnum(types.FrameType.ACK_ECN)) {
        const ect0 = try varint.decode(buf[i..]);
        i += ect0.n;

        const ect1 = try varint.decode(buf[i..]);
        i += ect1.n;

        const ce = try varint.decode(buf[i..]);
        i += ce.n;

        ecn_counts = .{
            .ect0 = ect0.value,
            .ect1 = ect1.value,
            .ce = ce.value,
        };
    }

    return .{
        .largest = largest.value,
        .ack_delay = ack_delay.value,
        .first_range = first_range.value,
        .ranges = ranges_buf[0..out_len], // Will point to caller's storage
        .ecn = ecn_counts,
        .ranges_buf = ranges_buf,
        .ranges_len = out_len,
        .n = i,
    };
}
