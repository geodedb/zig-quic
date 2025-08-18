// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("tls/tls13.zig");

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

    /// Helper to build an IPv4 sockaddr for tests.
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port_host: u16) SockAddr {
        var s: SockAddr = .{};
        var sin: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port_host),
            .addr = std.mem.nativeToBig(u32, (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d)),
            .zero = .{0} ** 8,
        };
        s.len = @intCast(@sizeOf(posix.sockaddr.in));
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..s.len], @as([*]const u8, @ptrCast(&sin))[0..s.len]);
        return s;
    }
};

pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    tls: tls13.Engine,
    // Derived handshake traffic secrets (once both hellos present)
    hs_client: ?[tls13.H.digest_length]u8 = null,
    hs_server: ?[tls13.H.digest_length]u8 = null,

    pub fn init(self: *Connection, alloc: *std.mem.Allocator, role: Role, sock_fd: posix.fd_t, peer: SockAddr) void {
        self.id = 0;
        self.role = role;
        self.sock_fd = sock_fd;
        self.peer = peer;
        self.tls_inbox = std.ArrayList(u8).init(alloc.*);
        self.tls = tls13.Engine.init(alloc.*, if (role == .Client) .Client else .Server);
        self.hs_client = null;
        self.hs_server = null;
    }

    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit();
        self.tls.deinit();
    }

    /// Send a datagram to the connection's peer.
    pub fn send(self: *const Connection, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&self.peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, self.peer.len);
    }

    /// Append CRYPTO stream bytes into the inbox and feed TLS engine.
    pub fn pushCrypto(self: *Connection, data: []const u8) !void {
        try self.tls_inbox.appendSlice(data);
        self.tls.onCryptoRecv(data);
        // Attempt to compute handshake secrets if test ecdhe_secret has been set
        if (self.tls.computeHandshakeSecrets()) |hs| {
            self.hs_client = hs.client;
            self.hs_server = hs.server;
        }
    }
};
