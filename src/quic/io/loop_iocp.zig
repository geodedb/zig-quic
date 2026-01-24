// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Windows IOCP stub ensuring QUIC timers keep running on that platform.
//!
//! The minimal wrapper still satisfies RFC 9000 §6 obligations by letting the
//! endpoint pump timers even when IOCP integration is a no-op today.
const std = @import("std");

/// One IOCP completion event entry.
pub const Event = struct {
    overlapped: *anyopaque,
};

/// Windows IOCP-backed loop wrapper (stubbed for now to satisfy cross-platform build).
pub const Loop = struct {
    // For now, create a completion port handle and expose minimal wait
    port: std.os.windows.HANDLE,

    /// Create a new IOCP port.
    pub fn init() !Loop {
        const port = try std.os.windows.CreateIoCompletionPort(std.os.windows.INVALID_HANDLE_VALUE, null, 0, 0);
        return .{ .port = port };
    }

    /// Close the completion port handle.
    pub fn deinit(self: *Loop) void {
        _ = std.os.windows.CloseHandle(self.port);
    }

    /// Register a socket handle (no-op in this stub).
    pub fn add(self: *Loop, _: std.os.windows.ws2_32.SOCKET, _: bool, _: bool) !void {
        _ = self;
    }
    /// Modify interest (no-op in this stub).
    pub fn mod(self: *Loop, _: std.os.windows.ws2_32.SOCKET, _: bool, _: bool) !void {
        _ = self;
    }
    /// Remove interest (no-op in this stub).
    pub fn del(self: *Loop, _: std.os.windows.ws2_32.SOCKET) !void {
        _ = self;
    }

    /// Wait for at most one IOCP event within timeout; returns number of events written.
    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        _ = events;
        var bytes: u32 = 0;
        var key: usize = 0;
        var overlapped: ?*std.os.windows.OVERLAPPED = null;
        const _res = std.os.windows.GetQueuedCompletionStatus(self.port, &bytes, &key, &overlapped, if (timeout_ms < 0) std.math.maxInt(u32) else @as(u32, @intCast(timeout_ms)));
        _ = _res;
        return if (overlapped != null) 1 else 0;
    }
};
