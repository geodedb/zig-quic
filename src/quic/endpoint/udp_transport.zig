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
const posix = std.posix;

pub const Transport = transport_mod.Transport;
pub const SockAddr = transport_mod.SockAddr;
pub const RecvResult = transport_mod.RecvResult;
pub const RecvBatchSlot = transport_mod.RecvBatchSlot;
pub const SendBatchItem = transport_mod.SendBatchItem;

/// Maximum number of UDP datagrams processed per batched syscall.
pub const UdpBatchCap: usize = 16;

/// Parse bind address string into SockAddr
///
/// Supported formats:
/// - "127.0.0.1:4433" (IPv4 dotted-quad + port)
/// - "0.0.0.0:0" (wildcard IPv4 + OS-assigned port)
/// - "[::]:4433" (IPv6 + port)
/// - "localhost:8080" (resolves to 127.0.0.1)
fn splitHostPort(hostport: []const u8) !struct { host: []const u8, port: u16 } {
    if (hostport.len == 0) return error.InvalidAddress;

    if (hostport[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, hostport, ']') orelse return error.InvalidAddress;
        if (close_idx + 1 >= hostport.len or hostport[close_idx + 1] != ':') return error.InvalidAddress;
        const host = hostport[1..close_idx];
        const port_str = hostport[close_idx + 2 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        return .{ .host = host, .port = port };
    }

    const colon_idx = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.InvalidAddress;
    if (colon_idx == 0 or colon_idx + 1 >= hostport.len) return error.InvalidAddress;
    // Require bracket notation for IPv6 literals.
    if (std.mem.indexOfScalar(u8, hostport[0..colon_idx], ':') != null) return error.InvalidAddress;

    const host = hostport[0..colon_idx];
    const port_str = hostport[colon_idx + 1 ..];
    const port = try std.fmt.parseInt(u16, port_str, 10);
    return .{ .host = host, .port = port };
}

fn netAddressToSockAddr(addr: std.net.Address) SockAddr {
    var out: SockAddr = .{};
    const addr_len: usize = addr.getOsSockLen();
    @memcpy(
        @as([*]u8, @ptrCast(&out.storage))[0..addr_len],
        @as([*]const u8, @ptrCast(&addr.any))[0..addr_len],
    );
    out.len = @intCast(addr_len);
    return out;
}

fn resolveBindAddr(bind_addr: []const u8) !SockAddr {
    // Fast path for numeric IP literals with port (supports bracketed IPv6).
    if (std.net.Address.parseIpAndPort(bind_addr)) |addr| {
        return netAddressToSockAddr(addr);
    } else |_| {}

    const hp = try splitHostPort(bind_addr);
    const host = if (std.mem.eql(u8, hp.host, "localhost")) "127.0.0.1" else hp.host;
    const addr = std.net.Address.parseIp(host, hp.port) catch return error.InvalidAddress;
    return netAddressToSockAddr(addr);
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
            .sendBatchFn = sendBatchFn,
            .recvFn = recvFn,
            .recvBatchFn = recvBatchFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    fn linuxResultToCount(rc: usize) !usize {
        const linux = std.os.linux;
        return switch (linux.E.init(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => |err| std.posix.unexpectedErrno(err),
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

    fn sendBatchFallback(self: *UdpTransport, items: []const SendBatchItem) !usize {
        var sent_items: usize = 0;
        while (sent_items < items.len) : (sent_items += 1) {
            const it = items[sent_items];
            const sent = try posix.sendto(
                self.fd,
                it.data,
                0,
                @ptrCast(&it.peer.storage),
                it.peer.len,
            );
            if (sent != it.data.len) return error.ShortWrite;
        }
        return sent_items;
    }

    fn sendBatchFn(ctx: *anyopaque, items: []const SendBatchItem) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        if (items.len == 0) return 0;
        if (builtin.target.os.tag != .linux) {
            return self.sendBatchFallback(items);
        }

        const linux = std.os.linux;
        var sent_total: usize = 0;
        while (sent_total < items.len) {
            const chunk_len = @min(items.len - sent_total, UdpBatchCap);

            var iovecs: [UdpBatchCap]posix.iovec_const = undefined;
            var msgs: [UdpBatchCap]linux.mmsghdr_const = undefined;

            var i: usize = 0;
            while (i < chunk_len) : (i += 1) {
                const it = items[sent_total + i];
                iovecs[i] = .{
                    .base = it.data.ptr,
                    .len = it.data.len,
                };
                msgs[i] = .{
                    .hdr = .{
                        .name = @ptrCast(&it.peer.storage),
                        .namelen = it.peer.len,
                        .iov = @ptrCast(&iovecs[i]),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }

            const rc = linux.sendmmsg(@intCast(self.fd), &msgs, @intCast(chunk_len), 0);
            const sent = try linuxResultToCount(rc);
            if (sent == 0) break;
            sent_total += sent;
            if (sent < chunk_len) break;
        }
        return sent_total;
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

    fn recvBatchFallback(self: *UdpTransport, slots: []RecvBatchSlot) !usize {
        var received: usize = 0;
        while (received < slots.len) : (received += 1) {
            var peer_storage: posix.sockaddr.storage = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = posix.recvfrom(
                self.fd,
                slots[received].buf,
                @intCast(posix.MSG.DONTWAIT),
                @ptrCast(&peer_storage),
                &peer_len,
            ) catch |err| {
                if (err == error.WouldBlock) {
                    if (received == 0) return error.WouldBlock;
                    return received;
                }
                return err;
            };

            slots[received].n = n;
            slots[received].peer = .{ .storage = peer_storage, .len = peer_len };
            slots[received].ecn = null;
        }
        return received;
    }

    fn recvBatchFn(ctx: *anyopaque, slots: []RecvBatchSlot) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        if (slots.len == 0) return 0;
        if (builtin.target.os.tag != .linux) {
            return self.recvBatchFallback(slots);
        }

        const linux = std.os.linux;
        var received_total: usize = 0;
        while (received_total < slots.len) {
            const chunk_len = @min(slots.len - received_total, UdpBatchCap);

            var iovecs: [UdpBatchCap]posix.iovec = undefined;
            var addrs: [UdpBatchCap]posix.sockaddr.storage = undefined;
            var msgs: [UdpBatchCap]linux.mmsghdr = undefined;

            var i: usize = 0;
            while (i < chunk_len) : (i += 1) {
                iovecs[i] = .{
                    .base = slots[received_total + i].buf.ptr,
                    .len = slots[received_total + i].buf.len,
                };
                msgs[i] = .{
                    .hdr = .{
                        .name = @ptrCast(&addrs[i]),
                        .namelen = @sizeOf(posix.sockaddr.storage),
                        .iov = @ptrCast(&iovecs[i]),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }

            const rc = linux.recvmmsg(
                @intCast(self.fd),
                &msgs,
                @intCast(chunk_len),
                @intCast(posix.MSG.DONTWAIT),
                null,
            );
            const got = linuxResultToCount(rc) catch |err| {
                if (err == error.WouldBlock) {
                    if (received_total == 0) return error.WouldBlock;
                    return received_total;
                }
                return err;
            };
            if (got == 0) break;

            var j: usize = 0;
            while (j < got) : (j += 1) {
                slots[received_total + j].n = msgs[j].len;
                slots[received_total + j].peer = .{
                    .storage = addrs[j],
                    .len = msgs[j].hdr.namelen,
                };
                slots[received_total + j].ecn = null;
            }

            received_total += got;
            if (got < chunk_len) break;
        }

        if (received_total == 0) return error.WouldBlock;
        return received_total;
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
