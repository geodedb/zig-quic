// MIT License
// epoll-based event loop abstraction (Linux)
const std = @import("std");

pub const Event = struct {
    fd: i32,
    readable: bool,
    writable: bool,
};

pub const Loop = struct {
    ep: std.os.linux.epoll.fd_t,

    pub fn init() !Loop {
        const fd = try std.os.linux.epoll_create1(std.os.linux.EPOLL.CLOEXEC);
        return .{ .ep = fd };
    }

    pub fn deinit(self: *Loop) void {
        _ = std.posix.close(self.ep);
    }

    pub fn add(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: std.os.linux.epoll.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= std.os.linux.EPOLL.IN;
        if (write) ev.events |= std.os.linux.EPOLL.OUT;
        try std.os.linux.epoll_ctl(self.ep, std.os.linux.EPOLL.CTL_ADD, fd, &ev);
    }

    pub fn mod(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: std.os.linux.epoll.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= std.os.linux.EPOLL.IN;
        if (write) ev.events |= std.os.linux.EPOLL.OUT;
        try std.os.linux.epoll_ctl(self.ep, std.os.linux.EPOLL.CTL_MOD, fd, &ev);
    }

    pub fn del(self: *Loop, fd: i32) !void {
        try std.os.linux.epoll_ctl(self.ep, std.os.linux.EPOLL.CTL_DEL, fd, null);
    }

    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        var raw: [64]std.os.linux.epoll.epoll_event = undefined;
        const n = try std.os.linux.epoll_wait(self.ep, &raw, timeout_ms);
        const out_n = @min(events.len, @as(usize, @intCast(n)));
        var i: usize = 0;
        while (i < out_n) : (i += 1) {
            events[i] = .{
                .fd = raw[i].data.fd,
                .readable = (raw[i].events & std.os.linux.EPOLL.IN) != 0,
                .writable = (raw[i].events & std.os.linux.EPOLL.OUT) != 0,
            };
        }
        return out_n;
    }
};
