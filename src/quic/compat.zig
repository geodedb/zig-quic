// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Zig 0.16 compatibility helpers.
//!
//! Provides shims for APIs removed between Zig 0.14 and 0.16, including:
//! - ArrayList writer adapter (replaces removed .writer() method)
//! - fixedBufferStream writer adapter

const std = @import("std");

/// Writer adapter for unmanaged ArrayList(u8).
/// Replaces the removed `std.ArrayList(u8).writer(allocator)` method.
pub const ArrayListWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn writeByte(self: *ArrayListWriter, byte: u8) !void {
        try self.list.append(self.allocator, byte);
    }

    pub fn writeAll(self: *ArrayListWriter, data: []const u8) !void {
        try self.list.appendSlice(self.allocator, data);
    }

    pub fn writeByteNTimes(self: *ArrayListWriter, byte: u8, n: usize) !void {
        try self.list.appendNTimes(self.allocator, byte, n);
    }

    pub fn print(self: *ArrayListWriter, comptime fmt: []const u8, args: anytype) !void {
        try self.list.print(self.allocator, fmt, args);
    }
};

/// Create a writer adapter for an unmanaged ArrayList(u8).
pub fn arrayListWriter(list: *std.ArrayList(u8), allocator: std.mem.Allocator) ArrayListWriter {
    return .{ .list = list, .allocator = allocator };
}

/// Writer adapter for a fixed buffer (replaces removed fixedBufferStream).
pub const FixedBufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn writeByte(self: *FixedBufWriter, byte: u8) !void {
        if (self.pos >= self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedBufWriter, data: []const u8) !void {
        if (self.pos + data.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    pub fn writeByteNTimes(self: *FixedBufWriter, byte: u8, n: usize) !void {
        if (self.pos + n > self.buf.len) return error.NoSpaceLeft;
        @memset(self.buf[self.pos..][0..n], byte);
        self.pos += n;
    }

    pub fn print(self: *FixedBufWriter, comptime fmt: []const u8, args: anytype) !void {
        const slice = std.fmt.bufPrint(self.buf[self.pos..], fmt, args) catch return error.NoSpaceLeft;
        self.pos += slice.len;
    }

    pub fn getWritten(self: *const FixedBufWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Create a fixed buffer writer (replaces removed std.io.fixedBufferStream).
pub fn fixedBufWriter(buf: []u8) FixedBufWriter {
    return .{ .buf = buf };
}
