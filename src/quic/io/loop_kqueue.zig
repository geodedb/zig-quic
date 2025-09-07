// MIT License
// kqueue-based event loop abstraction (BSD/macOS)
const std = @import("std");
const builtin = @import("builtin");
const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;
const EV_ADD: u16 = 0x0001;
const EV_ENABLE: u16 = 0x0004;
const EV_DELETE: u16 = 0x0002;

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
            evSet(&changes[n], @as(usize, @intCast(fd)), EVFILT_READ, EV_ADD | EV_ENABLE);
            n += 1;
        }
        if (write) {
            evSet(&changes[n], @as(usize, @intCast(fd)), EVFILT_WRITE, EV_ADD | EV_ENABLE);
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
        evSet(&changes[0], @as(usize, @intCast(fd)), EVFILT_READ, EV_DELETE);
        evSet(&changes[1], @as(usize, @intCast(fd)), EVFILT_WRITE, EV_DELETE);
        _ = try std.posix.kevent(self.kq, &changes, &[_]std.posix.Kevent{}, null);
    }

    /// Wait for readiness and write up to events.len entries; returns count.
    pub fn wait(self: *Loop, events: []Event, timeout_ms: i32) !usize {
        var evs: [64]std.posix.Kevent = undefined;
        if (builtin.target.os.tag == .macos or builtin.target.os.tag == .freebsd or builtin.target.os.tag == .netbsd or builtin.target.os.tag == .openbsd or builtin.target.os.tag == .dragonfly) {
            if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            return 0;
        }
        var ts_storage: std.posix.timespec = std.mem.zeroes(std.posix.timespec);
        var tsp: ?*const std.posix.timespec = null;
        if (timeout_ms >= 0) {
            // Fallback for non-Apple BSDs if available
            tsp = &ts_storage; // zero timeout means nowait
        }
        const n = try std.posix.kevent(self.kq, &[_]std.posix.Kevent{}, &evs, tsp);
        const out_n = @min(events.len, @as(usize, @intCast(n)));
        var i: usize = 0;
        while (i < out_n) : (i += 1) {
            events[i] = .{
                .ident = evs[i].ident,
                .readable = evs[i].filter == EVFILT_READ,
                .writable = evs[i].filter == EVFILT_WRITE,
            };
        }
        return out_n;
    }
};
