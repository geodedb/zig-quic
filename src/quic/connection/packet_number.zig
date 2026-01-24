// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Packet number management and expansion.
//!
//! RFC 9000 §12.3: Packet Number Encoding and Decoding
//! RFC 9000 §13.2: Generating Acknowledgements

const std = @import("std");
const frame = @import("quic_frame");

/// Sliding ACK tracking window constrained to the most recent 256 packet
/// numbers. RFC 9000 §13.2 recommends maintaining acknowledgement state per
/// packet number space, while §19.3 defines how ACK ranges are encoded. This
/// helper maps received packet numbers into the limited ACK range encoding
/// window used by the connection object.
pub const PnWindow = struct {
    max: u64 = 0,
    have_any: bool = false,
    win: std.bit_set.IntegerBitSet(256) = std.bit_set.IntegerBitSet(256).initEmpty(),

    /// Track a received packet number in this window.
    pub fn track(this: *PnWindow, pn: u64) void {
        const span: u64 = 256;
        const had_any = this.have_any;
        const prev_max = this.max;
        const prev_base: u64 = if (had_any and prev_max + 1 >= span) prev_max + 1 - span else 0;

        if (!had_any or pn > this.max) {
            this.max = pn;
            this.have_any = true;
        }

        const new_max = this.max;
        const new_base: u64 = if (this.have_any and new_max + 1 >= span) new_max + 1 - span else 0;

        if (!had_any) {
            this.win = std.bit_set.IntegerBitSet(256).initEmpty();
        } else if (new_base != prev_base) {
            var new_win = std.bit_set.IntegerBitSet(256).initEmpty();
            var idx: usize = 0;
            while (idx < span) : (idx += 1) {
                if (this.win.isSet(@intCast(idx))) {
                    const pn_val: u64 = prev_base + idx;
                    if (pn_val >= new_base) {
                        const shifted: u64 = pn_val - new_base;
                        if (shifted < span) {
                            new_win.set(@intCast(shifted));
                        }
                    }
                }
            }
            this.win = new_win;
        }

        if (pn < new_base) {
            // RFC 9000 §13.2 allows omitting acknowledgements that fall outside
            // the tracked ranges; we simply drop packet numbers that are older
            // than the sliding window permits.
            return;
        }

        const offset: u64 = pn - new_base;
        if (offset >= span) return;
        const idx: u8 = @intCast(offset);
        this.win.set(idx);
    }

    /// Build ACK ranges from the tracked packet numbers.
    /// Returns the first_range and populates out_buf with additional ranges.
    pub fn buildAckRanges(this: *const PnWindow, out_buf: []frame.AckRange) struct { first_range: u64, ranges_len: usize } {
        if (!this.have_any) return .{ .first_range = 0, .ranges_len = 0 };
        const largest: u64 = this.max;
        const span: u64 = 256;
        const base: u64 = if (largest + 1 >= span) largest + 1 - span else 0;
        const largest_idx: usize = @intCast(largest - base);
        // RFC 9000 §19.3: first_range encodes the number of contiguous packet
        // numbers (minus one) acknowledged up to Largest Acknowledged.
        var first_len: u64 = 0;
        var i_desc: i64 = @intCast(largest_idx);
        while (i_desc >= 0) : (i_desc -= 1) {
            if (this.win.isSet(@intCast(i_desc))) first_len += 1 else break;
        }
        const first_range: u64 = if (first_len == 0) 0 else (first_len - 1);
        var out_len: usize = 0;
        var pos: i64 = i_desc;
        while (pos >= 0 and out_len < out_buf.len) {
            var zeros: u64 = 0;
            while (pos >= 0 and !this.win.isSet(@intCast(pos))) : (pos -= 1) zeros += 1;
            if (pos < 0) break;
            var ones: u64 = 0;
            while (pos >= 0 and this.win.isSet(@intCast(pos))) : (pos -= 1) ones += 1;
            // RFC 9000 §19.3: gap encodes the number of missing packet numbers
            // between ACK ranges minus one, and len encodes the size of the
            // following contiguous ACK range minus one.
            const gap_val: u64 = if (zeros == 0) 0 else (zeros - 1);
            const len_val: u64 = if (ones == 0) 0 else (ones - 1);
            out_buf[out_len] = .{ .gap = gap_val, .len = len_val };
            out_len += 1;
        }
        return .{ .first_range = first_range, .ranges_len = out_len };
    }
};

/// Expand truncated packet number using the expected next packet number.
/// RFC 9000 §12.3: Packet Number Encoding and Decoding
///
/// The packet number is encoded as a truncated value to save space.
/// This function recovers the full packet number based on the expected value.
pub fn expandTruncatedPn(trunc_val: u64, pn_len: u3, expected: u64) u64 {
    // RFC 9000 §12.3. Avoid under/overflow for edge cases.
    const nbits: u6 = @as(u6, pn_len) * 8;
    const pn_win: u64 = @as(u64, 1) << nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;
    var candidate: u64 = (expected & ~pn_mask) | trunc_val;

    // If no history, return truncation as-is (expected == 0), matching first-packet semantics.
    if (expected == 0) return trunc_val;

    // Compare using thresholds to avoid overflow in candidate + pn_hwin and expected + pn_hwin
    var threshold_low: u64 = 0;
    const em1: u64 = expected - 1; // safe because expected > 0 here
    if (em1 >= pn_hwin) {
        threshold_low = em1 - pn_hwin;
    } else {
        threshold_low = 0;
    }

    if (candidate <= threshold_low) {
        candidate += pn_win;
    } else {
        const max_u64: u64 = std.math.maxInt(u64);
        const threshold_high: u64 = if (expected > max_u64 - pn_hwin) max_u64 else expected + pn_hwin;
        if (candidate > threshold_high) {
            candidate -= pn_win;
        }
    }
    return candidate;
}
