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

    pub fn writeByte(self: ArrayListWriter, byte: u8) !void {
        try self.list.append(self.allocator, byte);
    }

    pub fn writeAll(self: ArrayListWriter, data: []const u8) !void {
        try self.list.appendSlice(self.allocator, data);
    }

    pub fn writeByteNTimes(self: ArrayListWriter, byte: u8, n: usize) !void {
        try self.list.appendNTimes(self.allocator, byte, n);
    }

    pub fn print(self: ArrayListWriter, comptime fmt: []const u8, args: anytype) !void {
        try self.list.print(self.allocator, fmt, args);
    }
};

/// Create a writer adapter for an unmanaged ArrayList(u8).
pub fn arrayListWriter(list: *std.ArrayList(u8), allocator: std.mem.Allocator) ArrayListWriter {
    return .{ .list = list, .allocator = allocator };
}

/// Writer adapter for a fixed buffer (replaces removed fixedBufferStream).
/// Uses a pointer to external position counter so mutations are visible
/// when the writer is passed by value to anytype parameters.
pub const FixedBufWriter = struct {
    buf: []u8,
    pos_ptr: *usize,

    pub fn writeByte(self: FixedBufWriter, byte: u8) !void {
        if (self.pos_ptr.* >= self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos_ptr.*] = byte;
        self.pos_ptr.* += 1;
    }

    pub fn writeAll(self: FixedBufWriter, data: []const u8) !void {
        if (self.pos_ptr.* + data.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos_ptr.*..][0..data.len], data);
        self.pos_ptr.* += data.len;
    }

    pub fn writeByteNTimes(self: FixedBufWriter, byte: u8, n: usize) !void {
        if (self.pos_ptr.* + n > self.buf.len) return error.NoSpaceLeft;
        @memset(self.buf[self.pos_ptr.*..][0..n], byte);
        self.pos_ptr.* += n;
    }

    pub fn print(self: FixedBufWriter, comptime fmt: []const u8, args: anytype) !void {
        const slice = std.fmt.bufPrint(self.buf[self.pos_ptr.*..], fmt, args) catch return error.NoSpaceLeft;
        self.pos_ptr.* += slice.len;
    }
};

/// Reader adapter for a fixed buffer.
pub const FixedBufReader = struct {
    buf: []const u8,
    pos_ptr: *usize,

    pub fn readByte(self: FixedBufReader) !u8 {
        if (self.pos_ptr.* >= self.buf.len) return error.EndOfStream;
        const byte = self.buf[self.pos_ptr.*];
        self.pos_ptr.* += 1;
        return byte;
    }

    pub fn readNoEof(self: FixedBufReader, out: []u8) !void {
        if (self.pos_ptr.* + out.len > self.buf.len) return error.EndOfStream;
        @memcpy(out, self.buf[self.pos_ptr.*..][0..out.len]);
        self.pos_ptr.* += out.len;
    }

    pub fn readAllAlloc(self: FixedBufReader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        const remaining = self.buf.len - self.pos_ptr.*;
        if (remaining > max_size) return error.StreamTooLong;
        const out = try allocator.alloc(u8, remaining);
        @memcpy(out, self.buf[self.pos_ptr.*..]);
        self.pos_ptr.* = self.buf.len;
        return out;
    }
};

/// Owning wrapper for fixed buffer reader/writer state.
pub const FixedBufStream = struct {
    buf: []u8,
    pos: usize,

    pub fn writer(self: *FixedBufStream) FixedBufWriter {
        return .{ .buf = self.buf, .pos_ptr = &self.pos };
    }

    pub fn reader(self: *FixedBufStream) FixedBufReader {
        return .{ .buf = self.buf, .pos_ptr = &self.pos };
    }

    pub fn getWritten(self: *const FixedBufStream) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Create a fixed buffer stream (replaces removed std.io.fixedBufferStream).
pub fn fixedBufWriter(buf: []u8) FixedBufStream {
    return .{ .buf = buf, .pos = 0 };
}

/// Compatibility alias matching the removed std.io.fixedBufferStream name.
pub fn fixedBufferStream(buf: []u8) FixedBufStream {
    return fixedBufWriter(buf);
}

/// Zig 0.16 compatibility replacement for removed std.time.nanoTimestamp().
pub fn nanoTimestamp() i128 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

/// Zig 0.16 compatibility replacement for removed std.time.milliTimestamp().
pub fn milliTimestamp() i64 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

/// Zig 0.16 compatibility replacement for removed std.Thread.sleep().
pub fn threadSleep(ns: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

/// Lock a Zig 0.16 std.Io.Mutex using the global test I/O context.
pub fn mutexLock(mu: *std.Io.Mutex) void {
    mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
}

/// Unlock a Zig 0.16 std.Io.Mutex using the global test I/O context.
pub fn mutexUnlock(mu: *std.Io.Mutex) void {
    mu.unlock(std.Io.Threaded.global_single_threaded.io());
}

/// Zig 0.16 compatibility replacement for removed std.crypto.random.bytes().
pub fn randomBytes(buf: []u8) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    io.random(buf);
}
