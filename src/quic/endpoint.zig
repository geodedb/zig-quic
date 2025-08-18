//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
//! MIT License
const std = @import("std");
const api = @import("api.zig");

const Timer = struct { deadline_ms: i64, id: u64 };

pub const Endpoint = struct {
    sock: std.net.UDPConnection,
    loop_backend: api.LoopBackend,
    allocator: *std.mem.Allocator,
    timers: std.ArrayList(Timer),

    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8) !Endpoint {
        var address = try std.net.Address.parseIp4(bind_addr, 0);
        // If port is included as host:port, parse that:
        var parts = std.mem.splitScalar(u8, bind_addr, ':');
        const host = parts.next() orelse bind_addr;
        const port_s = parts.next() orelse "0";
        const port = std.fmt.parseInt(u16, port_s, 10) catch 0;
        address = try std.net.Address.resolveIp(host, port);
        const sock = try std.net.udp.connect(address);
        return .{ .sock = sock, .loop_backend = api.defaultLoopBackend(), .allocator = alloc, .timers = std.ArrayList(Timer).init(alloc.*) };
    }

    pub fn deinit(self: *Endpoint) void {
        self.timers.deinit();
        self.sock.deinit();
    }

    pub fn sendTo(self: *Endpoint, addr: std.net.Address, data: []const u8) !usize {
        return try self.sock.sendTo(addr, data);
    }

    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, addr: std.net.Address } {
        var addr: std.net.Address = undefined;
        const n = try self.sock.receiveFrom(&addr, buf);
        return .{ .n = n, .addr = addr };
    }

    /// Schedule a timer to fire after delay_ms. Returns assigned id.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        const now_ms: i64 = std.time.milliTimestamp();
        const id: u64 = @intCast(self.timers.items.len + 1);
        try self.timers.append(.{ .deadline_ms = now_ms + @as(i64, delay_ms), .id = id });
        return id;
    }

    /// Cancel a previously scheduled timer by id. Returns true if found and removed.
    pub fn cancelTimer(self: *Endpoint, id: u64) bool {
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            if (self.timers.items[i].id == id) {
                _ = self.timers.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    fn nextTimeoutFromTimers(self: *Endpoint, now_ms: i64, requested_timeout_ms: i32) i32 {
        var eff = requested_timeout_ms;
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            const t = self.timers.items[i];
            const diff: i64 = t.deadline_ms - now_ms;
            const t_ms: i32 = if (diff <= 0) 0 else @intCast(@min(diff, @as(i64, std.math.maxInt(i32))));
            if (eff < 0) {
                eff = t_ms;
            } else if (t_ms < eff) {
                eff = t_ms;
            }
        }
        return eff;
    }

    fn processExpiredTimers(self: *Endpoint, now_ms: i64) void {
        // Simple linear removal of expired timers; keep others.
        var i: usize = 0;
        while (i < self.timers.items.len) {
            if (self.timers.items[i].deadline_ms <= now_ms) {
                // In a future slice, dispatch to connection-level handlers.
                _ = self.timers.orderedRemove(i);
                // do not increment i, as items shift left
            } else {
                i += 1;
            }
        }
    }

    /// Drive IO using platform loop backend. timeout_ms < 0 means infinite.
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        const now_ms: i64 = std.time.milliTimestamp();
        const eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        switch (self.loop_backend) {
            .epoll => try poll_epoll(self, eff_timeout),
            .kqueue => try poll_kqueue(self, eff_timeout),
            .iocp => try poll_iocp(self, eff_timeout),
        }
        // After IO wait, process timers that have expired.
        self.processExpiredTimers(std.time.milliTimestamp());
    }
};

fn poll_epoll(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_epoll.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(self.sock.fd, true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_kqueue(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_kqueue.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(self.sock.fd, true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}

fn poll_iocp(self: *Endpoint, timeout_ms: i32) !void {
    const io = @import("io/loop_iocp.zig");
    var lp = try io.Loop.init();
    defer lp.deinit();
    try lp.add(self.sock.fd, true, false);
    var events: [16]io.Event = undefined;
    _ = try lp.wait(&events, timeout_ms);
}
