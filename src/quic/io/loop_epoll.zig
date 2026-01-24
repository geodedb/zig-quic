// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Linux epoll backend feeding QUIC timers and IO.
//!
//! RFC 9000 §6 highlights the need to promptly service network events and
//! PTO timers; this wrapper exposes the minimal operations the endpoint needs
//! when running on Linux.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

/// One readiness event for a monitored fd.
pub const Event = struct {
    fd: i32,
    readable: bool,
    writable: bool,
};

/// epoll-backed event loop wrapper matching the generic Loop API shape.
pub const Loop = struct {
    ep: posix.fd_t,

    /// Create an epoll instance.
    pub fn init() !Loop {
        const fd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
        return .{ .ep = fd };
    }

    /// Close the epoll fd.
    pub fn deinit(self: *Loop) void {
        _ = posix.close(self.ep);
    }

    /// Register interest in read/write readiness for fd.
    pub fn add(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: linux.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= linux.EPOLL.IN;
        if (write) ev.events |= linux.EPOLL.OUT;
        var pev: posix.system.epoll_event = ev; // same memory layout
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_ADD, fd, &pev);
    }

    /// Modify interest for fd.
    pub fn mod(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var ev: linux.epoll_event = .{ .events = 0, .data = .{ .fd = fd } };
        if (read) ev.events |= linux.EPOLL.IN;
        if (write) ev.events |= linux.EPOLL.OUT;
        var pev: posix.system.epoll_event = ev;
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_MOD, fd, &pev);
    }

    /// Remove interest for fd.
    pub fn del(self: *Loop, fd: i32) !void {
        try posix.epoll_ctl(self.ep, linux.EPOLL.CTL_DEL, fd, null);
    }

    /// Wait for readiness and populate up to events.len results; returns count.
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
