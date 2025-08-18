// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;

pub const Role = enum { Client, Server };

pub const SockAddr = struct {
    storage: posix.sockaddr.storage = undefined,
    len: u32 = 0,

    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

    pub fn eq(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.len != b.len) return false;
        if (a.storage.family != b.storage.family) return false;
        const pa = @as([*]const u8, @ptrCast(&a.storage))[0..a.len];
        const pb = @as([*]const u8, @ptrCast(&b.storage))[0..b.len];
        return std.mem.eql(u8, pa, pb);
    }
};

pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
    peer: SockAddr,

    /// Send a datagram to the connection's peer.
    pub fn send(self: *const Connection, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&self.peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, self.peer.len);
    }
};
