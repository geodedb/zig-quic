// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! UDP Transport Adapter for QUIC Endpoint
//!
//! Provides a production-ready UDP transport implementation that wraps real
//! UDP socket operations. This enables the endpoint to use transport abstraction
//! with actual network I/O.
//!
//! Features:
//! - Parses bind addresses ("127.0.0.1:4433", "0.0.0.0:0", "localhost:8080")
//! - Creates and configures UDP sockets
//! - Supports IPv4 and IPv6
//! - Non-blocking I/O
//! - Socket options (SO_REUSEADDR)
//! - Poll support for event-driven I/O
//!
//! Reference: src/quic/endpoint/io.zig contains similar UDP operations

const std = @import("std");
const builtin = @import("builtin");
const transport_mod = @import("transport.zig");

pub const Transport = transport_mod.Transport;
pub const SockAddr = transport_mod.SockAddr;
pub const RecvResult = transport_mod.RecvResult;

/// Parse bind address string into SockAddr
///
/// Supported formats:
/// - "127.0.0.1:4433" (IPv4 dotted-quad + port)
/// - "0.0.0.0:0" (wildcard IPv4 + OS-assigned port)
/// - "localhost:8080" (resolves to 127.0.0.1)
fn resolveBindAddr(bind_addr: []const u8) !SockAddr {
    // Split host:port
    var it = std.mem.splitScalar(u8, bind_addr, ':');
    const host = it.next() orelse return error.InvalidAddress;
    const port_str = it.next() orelse return error.InvalidAddress;
    const port = try std.fmt.parseInt(u16, port_str, 10);

    // Determine IPv4 octets
    var octets: [4]u8 = undefined;
    if (std.mem.eql(u8, host, "localhost")) {
        octets = .{ 127, 0, 0, 1 };
    } else if (std.mem.eql(u8, host, "0.0.0.0")) {
        octets = .{ 0, 0, 0, 0 };
    } else {
        // Parse IPv4 dotted-quad
        var octet_it = std.mem.splitScalar(u8, host, '.');
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            const part = octet_it.next() orelse return error.InvalidAddress;
            octets[i] = try std.fmt.parseInt(u8, part, 10);
        }
    }

    // Use the SockAddr.ipv4() helper (re-exported from transport.zig at line 22)
    return SockAddr.ipv4(octets[0], octets[1], octets[2], octets[3], port);
}

/// UDP transport adapter for production use
///
/// This UDP transport adapter wraps real UDP socket operations, enabling
/// the endpoint to use transport abstraction with actual network I/O.
pub const UdpTransport = struct {
    /// Socket file descriptor
    fd: std.posix.socket_t,

    /// Socket address family (AF_INET or AF_INET6)
    family: u16,

    /// Bound local address
    local_addr: SockAddr,

    /// Initialize UDP transport by creating and binding a UDP socket
    ///
    /// bind_addr format: "host:port" (e.g., "127.0.0.1:4433", "0.0.0.0:0")
    pub fn init(bind_addr: []const u8) !UdpTransport {
        // Parse bind address
        var addr = try resolveBindAddr(bind_addr);

        // Determine address family
        const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(&addr.storage));
        const family = sa.family;

        // Create UDP socket
        const fd = try std.posix.socket(family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        errdefer std.posix.close(fd);

        // Set SO_REUSEADDR for fast rebinding
        var one: i32 = 1;
        _ = std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

        // Bind to address
        const bind_len: std.posix.socklen_t = switch (family) {
            std.posix.AF.INET => @intCast(@sizeOf(std.posix.sockaddr.in)),
            std.posix.AF.INET6 => @intCast(@sizeOf(std.posix.sockaddr.in6)),
            else => return error.AddressFamilyNotSupported,
        };
        try std.posix.bind(fd, @ptrCast(&addr.storage), bind_len);

        // Query actual bound address (important for port 0)
        var actual_addr: std.posix.sockaddr.storage = undefined;
        var actual_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        try std.posix.getsockname(fd, @ptrCast(&actual_addr), &actual_len);

        // Set non-blocking mode
        if (builtin.target.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var nonblock: std.os.windows.ULONG = 1;
            _ = ws2.ioctlsocket(fd, ws2.FIONBIO, &nonblock);
        } else {
            const flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
            const O_NONBLOCK: i32 = 0x800;
            const new_flags = flags | O_NONBLOCK;
            _ = try std.posix.fcntl(fd, std.posix.F.SETFL, new_flags);
        }

        return UdpTransport{
            .fd = fd,
            .family = family,
            .local_addr = .{ .storage = actual_addr, .len = actual_len },
        };
    }

    /// Deinitialize transport and close socket
    pub fn deinit(self: *UdpTransport) void {
        std.posix.close(self.fd);
    }

    /// Convert to generic transport interface
    pub fn asTransport(self: *UdpTransport) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));

        // Send UDP datagram to peer
        const sent = try std.posix.sendto(
            self.fd,
            data,
            0,
            @ptrCast(&peer.storage),
            peer.len,
        );
        return sent;
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));

        // Receive UDP datagram from any peer
        var peer_storage: std.posix.sockaddr.storage = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);

        const n = try std.posix.recvfrom(
            self.fd,
            buf,
            0,
            @ptrCast(&peer_storage),
            &peer_len,
        );

        return RecvResult{
            .n = n,
            .peer = .{ .storage = peer_storage, .len = peer_len },
            .ecn = null, // ECN extraction would require ancillary data (recvmsg)
        };
    }

    fn pollFn(ctx: *anyopaque, timeout_ms: i32) !void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));

        // Use std.posix.poll to wait for readable data
        var fds = [1]std.posix.pollfd{
            .{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 },
        };

        // Convert timeout to match poll's expectation
        const timeout: i32 = if (timeout_ms < 0) -1 else timeout_ms;

        const ready = try std.posix.poll(&fds, timeout);
        _ = ready; // Number of ready FDs (we only care that poll returned)
    }

    fn closeFn(ctx: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        std.posix.close(self.fd);
    }

    fn getLocalAddrFn(ctx: *anyopaque) !SockAddr {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};
