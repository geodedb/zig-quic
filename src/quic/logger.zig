// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Simple logging module for QUIC library with environment variable control.
//!
//! While not a full qlog implementation, the hooks support diagnostics similar
//! to those described in RFC 9308 when integrating with external tooling.

const std = @import("std");
const builtin = @import("builtin");

/// Compile-time flag to enable/disable verbose debug prints.
/// Set to false for production builds to eliminate all QUIC debug output.
/// This controls the std.debug.print calls throughout the QUIC library.
pub const enable_debug_prints: bool = builtin.mode == .Debug;

/// Debug print wrapper - compiles to nothing when debug prints are disabled.
/// Use this instead of std.debug.print for QUIC library debugging.
pub inline fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (comptime !enable_debug_prints) return;
    if (!levelEnabled(.debug)) return;
    std.debug.print(fmt, args);
}

/// Debug print for hex bytes - compiles to nothing when debug prints are disabled.
pub inline fn debugPrintHex(comptime prefix: []const u8, bytes: []const u8) void {
    if (comptime !enable_debug_prints) return;
    if (!levelEnabled(.debug)) return;
    std.debug.print("{s}", .{prefix});
    for (bytes) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});
}

/// Log level enumeration for controlling verbosity
pub const Level = enum(u8) {
    debug,
    info,
    warn,
    err,

    fn fromInt(val: u8) Level {
        return switch (val) {
            0 => .debug,
            1 => .info,
            2 => .warn,
            3 => .err,
            else => .err,
        };
    }
};

// Global log level - defaults to error
var g_level: Level = .err;
var g_initialized: bool = false;

/// Initialize the logger from LOG_LEVEL environment variable
fn ensureInitialized() void {
    if (g_initialized) return;
    g_initialized = true;

    // Try to read LOG_LEVEL environment variable
    if (std.c.getenv("LOG_LEVEL")) |v| {
        const level_str = std.mem.span(v);
        g_level = parseLevel(level_str);
    } else {
        // If we can't get env var, stick with default (error)
    }
}

/// Parse log level from string (case-insensitive)
pub fn parseLevel(s: []const u8) Level {
    var buf: [16]u8 = undefined;
    const n = if (s.len > buf.len) buf.len else s.len;
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = s[i];
    // lowercase in place
    for (buf[0..n]) |*c| c.* = std.ascii.toLower(c.*);
    const lower = buf[0..n];

    if (std.mem.eql(u8, lower, "debug")) return .debug;
    if (std.mem.eql(u8, lower, "info")) return .info;
    if (std.mem.eql(u8, lower, "warn") or std.mem.eql(u8, lower, "warning")) return .warn;
    if (std.mem.eql(u8, lower, "error") or std.mem.eql(u8, lower, "err")) return .err;

    // Default to error for unknown values
    return .err;
}

/// Set the log level programmatically
pub fn setLevel(level: Level) void {
    g_level = level;
    g_initialized = true;
}

/// Get current log level
pub fn getLevel() Level {
    ensureInitialized();
    return g_level;
}

/// Check if a level is enabled
inline fn levelEnabled(l: Level) bool {
    ensureInitialized();
    return @intFromEnum(l) >= @intFromEnum(g_level);
}

/// Get the string token for a level
fn levelToken(l: Level) []const u8 {
    return switch (l) {
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
    };
}

/// Core logging function
pub fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
    if (!levelEnabled(level)) return;

    // Build the log message in a buffer using bufPrint
    var buf: [2048]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buf, "{s}: ", .{levelToken(level)}) catch return;
    const prefix_len = prefix.len;
    const msg = std.fmt.bufPrint(buf[prefix_len..], fmt, args) catch return;
    const total_len = prefix_len + msg.len;
    if (total_len < buf.len) {
        buf[total_len] = '\n';
        const out_slice = buf[0 .. total_len + 1];
        // Write to stderr via Linux syscall
        _ = std.os.linux.write(2, out_slice.ptr, out_slice.len);
    }
}

/// Log a debug message
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

/// Log an info message
pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

/// Log a warning message
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}

/// Log an error message
pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

test "logger.parseLevel basic" {
    try std.testing.expect(parseLevel("INFO") == .info);
    try std.testing.expect(parseLevel("warn") == .warn);
    try std.testing.expect(parseLevel("ERROR") == .err);
    try std.testing.expect(parseLevel("debug") == .debug);
    try std.testing.expect(parseLevel("unknown") == .err); // fallback
}
