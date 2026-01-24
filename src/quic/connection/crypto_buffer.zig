// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Buffer for reassembling out-of-order CRYPTO frames.
//!
//! RFC 9000 §4.9.2 requires endpoints to handle out-of-order CRYPTO data until
//! it becomes contiguous. This helper keeps fragments sorted so handshake
//! processing can consume them in order without reallocation churn.

const std = @import("std");
const logger = @import("quic_logger");

/// Fragment representing a piece of CRYPTO data at a specific offset.
pub const Fragment = struct {
    offset: u64,
    data: []u8,
};

/// CryptoBuffer manages out-of-order CRYPTO frame reassembly.
///
/// Maintains up to 8 fragments in sorted order by offset, allowing
/// handshake processing to consume contiguous data as it becomes available.
pub const CryptoBuffer = struct {
    // Static array to avoid allocations - max 8 out-of-order fragments
    fragments: [8]?Fragment = [_]?Fragment{null} ** 8,
    count: usize = 0,
    // Result buffer to avoid returning stack-allocated memory
    result_buffer: [8]Fragment = undefined,

    /// Add a fragment to the buffer at the specified offset.
    /// Returns error.BufferFull if the fragment array is full.
    pub fn add(self: *CryptoBuffer, offset: u64, data: []const u8, allocator: std.mem.Allocator) !void {
        // If buffer is full, skip adding this fragment to prevent memory corruption
        // In normal operation with in-order CRYPTO frames, this should never happen
        if (self.count >= self.fragments.len) {
            logger.debugPrint("WARNING: CryptoBuffer full (count={}, max={}), skipping fragment at offset {}\n", .{ self.count, self.fragments.len, offset });
            return error.BufferFull;
        }

        // Copy data
        const data_copy = try allocator.alloc(u8, data.len);
        @memcpy(data_copy, data);

        // Find the correct position to insert (sorted by offset)
        var insert_pos: usize = 0;
        var found_pos = false;

        // Find first null slot or position where offset should be inserted
        var i: usize = 0;
        while (i < self.fragments.len) : (i += 1) {
            if (self.fragments[i]) |frag| {
                if (frag.offset > offset) {
                    insert_pos = i;
                    found_pos = true;
                    break;
                }
            } else {
                // Found a null slot, we can use this
                if (!found_pos) {
                    insert_pos = i;
                    found_pos = true;
                }
            }
        }

        // If no position found, use the first available null slot
        if (!found_pos) {
            i = 0;
            while (i < self.fragments.len) : (i += 1) {
                if (self.fragments[i] == null) {
                    insert_pos = i;
                    break;
                }
            }
        }

        // If we need to shift elements right, do so
        if (self.fragments[insert_pos] != null) {
            // Find first null slot after insert_pos
            var null_pos: ?usize = null;
            i = insert_pos;
            while (i < self.fragments.len) : (i += 1) {
                if (self.fragments[i] == null) {
                    null_pos = i;
                    break;
                }
            }

            // Shift elements right to make room
            if (null_pos) |np| {
                i = np;
                while (i > insert_pos) : (i -= 1) {
                    self.fragments[i] = self.fragments[i - 1];
                }
            }
        }

        self.fragments[insert_pos] = Fragment{ .offset = offset, .data = data_copy };
        self.count += 1;
    }

    /// Check if we have contiguous data starting from the given offset.
    /// Returns the fragments that can be processed, or null if no contiguous data exists.
    pub fn getContiguous(self: *CryptoBuffer, start_offset: u64) ?[]const Fragment {
        var result_count: usize = 0;
        var expected_offset = start_offset;

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                if (frag.offset == expected_offset) {
                    self.result_buffer[result_count] = frag;
                    expected_offset += frag.data.len;
                    result_count += 1;
                } else if (frag.offset < expected_offset) {
                    // Overlapping or duplicate fragment - skip
                    continue;
                } else {
                    // Gap found
                    break;
                }
            }
        }

        if (result_count == 0) return null;

        // Return slice of contiguous fragments
        return self.result_buffer[0..result_count];
    }

    /// Remove processed fragments from the buffer.
    /// Frees the memory for the specified number of fragments and shifts remaining ones.
    pub fn removeProcessed(self: *CryptoBuffer, count: usize, allocator: std.mem.Allocator) void {
        // Free memory for processed fragments
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                allocator.free(frag.data);
                self.fragments[i] = null;
            }
        }

        // Shift remaining fragments left
        i = 0;
        while (i < self.count - count) : (i += 1) {
            self.fragments[i] = self.fragments[i + count];
            self.fragments[i + count] = null;
        }

        self.count -= count;
    }

    /// Clear all buffered fragments and free their memory.
    pub fn clear(self: *CryptoBuffer, allocator: std.mem.Allocator) void {
        // Only iterate up to count, not the full array length
        // This avoids attempting to free already-freed fragments
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.fragments[i]) |frag| {
                // Only free non-empty allocations
                if (frag.data.len > 0) {
                    allocator.free(frag.data);
                }
                self.fragments[i] = null;
            }
        }
        self.count = 0;
    }
};
