//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
// MIT License
const std = @import("std");

pub const Endpoint = struct {
    sock: std.net.UDPConnection,

    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8) !Endpoint {
        _ = alloc;
        var address = try std.net.Address.parseIp4(bind_addr, 0);
        // If port is included as host:port, parse that:
        var parts = std.mem.splitScalar(u8, bind_addr, ':');
        const host = parts.next() orelse bind_addr;
        const port_s = parts.next() orelse "0";
        const port = std.fmt.parseInt(u16, port_s, 10) catch 0;
        address = try std.net.Address.resolveIp(host, port);
        const sock = try std.net.udp.connect(address);
        return .{ .sock = sock };
    }

    pub fn deinit(self: *Endpoint) void {
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
};
