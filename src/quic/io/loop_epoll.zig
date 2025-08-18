// MIT License
// epoll-based event loop abstraction (Linux)
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const Event = struct {
    fd: i32,
    readable: bool,
    writable: bool,
};

pub const Loop = struct {
    ep: posix.fd_t,

    pub fn init() !Loop {
        const fd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
        return .{ .ep = fd };
    }

    pub fn deinit(self: *Loop) void {
        _ = posix.close(self.ep);
    }

    pub fn add(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: linux.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= linux.EPOLL.IN;
        if (write) ev.events |= linux.EPOLL.OUT;
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_ADD, fd, &ev);
    }

    pub fn mod(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: linux.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= linux.EPOLL.IN;
        if (write) ev.events |= linux.EPOLL.OUT;
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_MOD, fd, &ev);
    }

    pub fn del(self: *Loop, fd: i32) !void {
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_DEL, fd, null);
    }

    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        var raw: [64]linux.epoll_event = undefined;
        const n: usize = posix.epoll_wait(self.ep, raw[0..], timeout_ms);
        const out_n = @min(events.len, n);
        var i: usize = 0;
        while (i < out_n) : (i += 1) {
            events[i] = .{
                .fd = raw[i].data.fd,
                .readable = (raw[i].events & linux.EPOLL.IN) != 0,
                .writable = (raw[i].events & linux.EPOLL.OUT) != 0,
            };
        }
        return out_n;
    }
};
