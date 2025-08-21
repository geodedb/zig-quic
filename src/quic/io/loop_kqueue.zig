// MIT License
// kqueue-based event loop abstraction (BSD/macOS)
const std = @import("std");

/// One readiness event returned by the loop.
pub const Event = struct {
    ident: usize,
    readable: bool,
    writable: bool,
};

/// kqueue-backed event loop wrapper matching the generic Loop API shape.
pub const Loop = struct {
    kq: std.posix.fd_t,

    /// Create a new kqueue handle.
    pub fn init() !Loop {
        const fd = try std.posix.kqueue();
        return .{ .kq = fd };
    }

    /// Close the kqueue descriptor.
    pub fn deinit(self: *Loop) void {
        _ = std.posix.close(self.kq);
    }

    fn evSet(ch: *std.posix.Kevent, ident: usize, filter: i16, flags: u16) void {
        ch.* = .{ .ident = ident, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = 0 };
    }

    /// Register interest in read/write readiness for fd.
    pub fn add(self: *Loop, fd: i32, read: bool, write: bool) !void {
        var changes: [2]std.posix.Kevent = undefined;
        var n: usize = 0;
        if (read) {
            evSet(&changes[n], @as(usize, @intCast(fd)), std.posix.EVFILT_READ, std.posix.EV_ADD | std.posix.EV_ENABLE);
            n += 1;
        }
        if (write) {
            evSet(&changes[n], @as(usize, @intCast(fd)), std.posix.EVFILT_WRITE, std.posix.EV_ADD | std.posix.EV_ENABLE);
            n += 1;
        }
        _ = try std.posix.kevent(self.kq, changes[0..n], &[_]std.posix.Kevent{}, null);
    }

    /// Modify readiness interest; implemented as re-add.
    pub fn mod(self: *Loop, fd: i32, read: bool, write: bool) !void {
        return add(self, fd, read, write);
    }

    /// Remove all interests for fd.
    pub fn del(self: *Loop, fd: i32) !void {
        var changes: [2]std.posix.Kevent = undefined;
        evSet(&changes[0], @as(usize, @intCast(fd)), std.posix.EVFILT_READ, std.posix.EV_DELETE);
        evSet(&changes[1], @as(usize, @intCast(fd)), std.posix.EVFILT_WRITE, std.posix.EV_DELETE);
        _ = try std.posix.kevent(self.kq, &changes, &[_]std.posix.Kevent{}, null);
    }

    /// Wait for readiness and write up to events.len entries; returns count.
    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        var evs: [64]std.posix.Kevent = undefined;
        var ts: ?std.posix.timespec = null;
        if (timeout_ms >= 0) {
            ts = .{ .tv_sec = timeout_ms / 1000, .tv_nsec = (@as(i64, timeout_ms % 1000)) * 1_000_000 };
        }
        const n = try std.posix.kevent(self.kq, &[_]std.posix.Kevent{}, &evs, if (ts) |*p| p else null);
        const out_n = @min(events.len, @as(usize, @intCast(n)));
        var i: usize = 0;
        while (i < out_n) : (i += 1) {
            events[i] = .{
                .ident = evs[i].ident,
                .readable = evs[i].filter == std.posix.EVFILT_READ,
                .writable = evs[i].filter == std.posix.EVFILT_WRITE,
            };
        }
        return out_n;
    }
};
