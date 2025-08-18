// MIT License
// IOCP-based event loop abstraction (Windows) — minimal stub for build
const std = @import("std");

pub const Event = struct {
    overlapped: *anyopaque,
};

pub const Loop = struct {
    // For now, create a completion port handle and expose minimal wait
    port: std.os.windows.HANDLE,

    pub fn init() !Loop {
        const port = try std.os.windows.CreateIoCompletionPort(std.os.windows.INVALID_HANDLE_VALUE, null, 0, 0);
        return .{ .port = port };
    }

    pub fn deinit(self: *Loop) void {
        _ = std.os.windows.CloseHandle(self.port);
    }

    pub fn add(self: *Loop, _: i32, _: bool, _: bool) !void {
        _ = self;
    }
    pub fn mod(self: *Loop, _: i32, _: bool, _: bool) !void {
        _ = self;
    }
    pub fn del(self: *Loop, _: i32) !void {
        _ = self;
    }

    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        _ = events;
        var bytes: u32 = 0;
        var key: usize = 0;
        var overlapped: ?*std.os.windows.OVERLAPPED = null;
        const ok = std.os.windows.GetQueuedCompletionStatus(self.port, &bytes, &key, &overlapped, if (timeout_ms < 0) std.math.maxInt(u32) else @as(u32, @intCast(timeout_ms)));
        if (!ok and overlapped == null) return 0; // timeout or error w/o event
        return if (overlapped != null) 1 else 0;
    }
};
