// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! UDP I/O operations and platform-specific event loops for QUIC endpoints.
//!
//! RFC References:
//! - RFC 9000 §13.3: Datagrams
//! - RFC 3168: Explicit Congestion Notification (ECN)
//! - RFC 9000 §14.2: Path MTU Discovery (ICMP PTB handling)
//!
//! This module provides:
//! - UDP send/receive operations with ECN support
//! - Platform-specific event loop backends (epoll/kqueue/IOCP)
//! - ICMP error queue processing for PMTUD
//! - Connection routing callbacks

const std = @import("std");
const logger = @import("quic_logger");
const posix = std.posix;
const builtin = @import("builtin");
const conn_mod = @import("quic_conn");

/// Result of a recvFrom operation.
pub const RecvResult = struct {
    n: usize,
    peer: conn_mod.SockAddr,
    ecn_bits: u8 = 0,
};

/// Context for I/O operations - contains only what's needed.
/// Avoids passing full Endpoint pointer to enable modular testing.
pub const IoContext = struct {
    sock_fd: posix.socket_t,
    /// Callback to process incoming datagrams
    process_fn: ProcessDatagramFn,
    /// Callback to handle ICMP PTB for PMTUD
    icmp_ptb_fn: IcmpPtbFn,
    /// Optional: epoll file descriptor for Linux
    epoll_fd: ?posix.fd_t = null,
};

/// Function signature for processing incoming datagrams.
pub const ProcessDatagramFn = *const fn (peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void;

/// Function signature for handling ICMP Packet Too Big messages.
pub const IcmpPtbFn = *const fn (peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void;

/// Send data to a peer via UDP.
/// Returns the number of bytes sent, or an error.
pub fn sendTo(sock_fd: posix.socket_t, peer: conn_mod.SockAddr, data: []const u8) !usize {
    const sent = try posix.sendto(
        sock_fd,
        data,
        0,
        @ptrCast(&peer.storage),
        peer.len,
    );
    return sent;
}

/// Receive data from UDP socket.
/// Returns number of bytes received, peer address, and ECN bits.
pub fn recvFrom(sock_fd: posix.socket_t, buf: []u8) !RecvResult {
    var peer_storage: posix.sockaddr.storage = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    const n = try posix.recvfrom(
        sock_fd,
        buf,
        0,
        @ptrCast(&peer_storage),
        &peer_len,
    );

    var peer: conn_mod.SockAddr = .{};
    peer.storage = peer_storage;
    peer.len = peer_len;

    // ECN bits would be extracted from ancillary data (IP_TOS/IPV6_TCLASS)
    // For now, return 0 (Not-ECT)
    const ecn_bits: u8 = 0;

    return RecvResult{
        .n = n,
        .peer = peer,
        .ecn_bits = ecn_bits,
    };
}

/// Extract network byte order port to host byte order.
fn portFromNetwork(port: u16) u16 {
    return @byteSwap(port);
}

/// Drain all readable datagrams from socket and process them.
/// RFC 9000 §13.3: Endpoints MUST process all available datagrams.
///
/// This function reads all available UDP packets from the socket in a loop
/// until EAGAIN/EWOULDBLOCK is returned. Each packet is passed to the
/// process_fn callback for handling.
pub fn drainReadable(ctx: *const IoContext) void {
    // Increase buffer size to handle larger Handshake packets (can be up to ~3000 bytes with certificates)
    var buf: [4096]u8 = undefined;
    var read_count: usize = 0;

    while (true) {
        var peer = conn_mod.SockAddr{};
        peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
        const flags: u32 = 0;

        // Linux: prefer recvmsg to extract ECN via ancillary when available; fallback elsewhere.
        // NOTE: Disabled recvmsg for now due to missing types in std.posix
        if (false and builtin.target.os.tag == .linux) {
            logger.debugPrint("Calling recvmsg on socket fd={}\n", .{ctx.sock_fd});
            var iov = [1]posix.iovec{.{ .base = buf[0..].ptr, .len = buf.len }};
            var ctrl: [64]u8 = undefined;
            var msg: posix.msghdr = .{
                .name = @ptrCast(&peer.storage),
                .namelen = peer.len,
                .iov = &iov,
                .iovlen = 1,
                .control = &ctrl,
                .controllen = ctrl.len,
                .flags = 0,
            };
            const linux = std.os.linux;
            const n_raw = linux.recvmsg(@intCast(ctx.sock_fd), &msg, flags);

            // Check if error occurred (-1 is returned on error)
            if (n_raw == @as(usize, @bitCast(@as(isize, -1)))) {
                // recvmsg returns -1 on error, errno is set
                // For non-blocking sockets, EAGAIN/EWOULDBLOCK is expected
                return;
            }

            const n = n_raw;
            if (n > 0) {
                logger.debugPrint("recvmsg got {} bytes!\n", .{n});
                // Extract ECN from ancillary: IP_TOS (level IPPROTO_IP, type IP_TOS)
                var ecn_bits: ?u8 = null;
                var off: usize = 0;
                while (off + @sizeOf(posix.cmsghdr) <= msg.controllen) {
                    const cmsg_ptr: *const posix.cmsghdr = @ptrCast(@alignCast(@as(*const anyopaque, @ptrFromInt(@intFromPtr(msg.control) + off))));
                    const clen = cmsg_ptr.len;
                    if (clen < @sizeOf(posix.cmsghdr) or off + clen > msg.controllen) break;
                    const level = cmsg_ptr.level;
                    const ctype = cmsg_ptr.type;
                    // CMSG data starts immediately after header
                    const data_ptr = @as([*]const u8, @ptrFromInt(@intFromPtr(cmsg_ptr) + @sizeOf(posix.cmsghdr)));
                    // IPPROTO_IP == posix.IPPROTO.IP; IP_TOS constant is 1 on Linux
                    if (level == posix.IPPROTO.IP and ctype == 1 and clen >= @sizeOf(posix.cmsghdr) + 1) {
                        const tos = data_ptr[0];
                        ecn_bits = tos & 0x03; // low 2 bits per RFC 3168
                    }
                    // IPv6: level IPPROTO_IPV6 with type IPV6_TCLASS (67) carries traffic class
                    if (level == posix.IPPROTO.IPV6 and ctype == 67 and clen >= @sizeOf(posix.cmsghdr) + 1) {
                        const tclass = data_ptr[0];
                        ecn_bits = tclass & 0x03;
                    }
                    // Align to next header (CMSG_ALIGN)
                    const align_sz: usize = 8;
                    const adv = (clen + (align_sz - 1)) & ~(align_sz - 1);
                    off += adv;
                }
                ctx.process_fn(peer, buf[0..@intCast(n)], ecn_bits);
            }
        } else {
            logger.debugPrint("Calling recvfrom on socket fd={}, flags={}\n", .{ ctx.sock_fd, flags });
            const n_or_err = posix.recvfrom(ctx.sock_fd, buf[0..], flags, @ptrCast(@alignCast(&peer.storage)), &peer.len);
            if (n_or_err) |n| {
                logger.debugPrint(">>> recvfrom got {} bytes (read #{} in this drain)!\n", .{ n, read_count + 1 });
                // Debug: Log all received packets with source address
                if (peer.storage.family == posix.AF.INET) {
                    const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&peer.storage));
                    const addr_bytes = @as([4]u8, @bitCast(sin.addr));
                    logger.debugPrint("recvfrom {} bytes from {}.{}.{}.{}:{}\n", .{ n, addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], portFromNetwork(sin.port) });
                } else {
                    logger.debugPrint("recvfrom got {} bytes from socket {}\n", .{ n, ctx.sock_fd });
                }
                read_count += 1;
                logger.debugPrint(">>> About to call process callback with {} bytes\n", .{n});
                ctx.process_fn(peer, buf[0..n], null);
                logger.debugPrint(">>> Returned from process callback\n", .{});
            } else |err| {
                switch (err) {
                    error.WouldBlock => {
                        // This is normal for non-blocking sockets
                        logger.debugPrint("recvfrom returned WouldBlock\n", .{});
                        break; // Exit the while loop
                    },
                    error.ConnectionResetByPeer => {
                        logger.debugPrint("connection reset by peer\n", .{});
                        return;
                    },
                    else => {
                        logger.debugPrint("recvfrom error: {}\n", .{err});
                        return;
                    },
                }
            }
        }
    }
}

/// Linux-only: drain MSG_ERRQUEUE to handle ICMP PTB and apply DPLPMTUD clamps.
/// RFC 9000 §14.2: Path MTU Discovery using ICMP Packet Too Big messages.
pub fn drainErrorQueue(ctx: *const IoContext) void {
    if (builtin.target.os.tag != .linux) return;
    if (!@hasDecl(posix, "recvmsg")) return;

    // Constants for extended error origin and ICMP types
    const SO_EE_ORIGIN_ICMP: u8 = 2;
    const SO_EE_ORIGIN_ICMP6: u8 = 3;
    const ICMP_DEST_UNREACH: u8 = 3; // IPv4
    const ICMP_FRAG_NEEDED: u8 = 4; // IPv4 code for PTB
    const ICMPV6_PKT_TOOBIG: u8 = 2; // IPv6 type

    // Linux struct sock_extended_err
    const ExtendedErr = extern struct {
        ee_errno: i32,
        ee_origin: u8,
        ee_type: u8,
        ee_code: u8,
        ee_pad: u8,
        ee_info: u32, // MTU for EMSGSIZE
        ee_data: u32,
    };

    while (true) {
        var peer = conn_mod.SockAddr{};
        peer.len = @intCast(@sizeOf(posix.sockaddr.storage));
        var iov_buf: [2048]u8 = undefined;
        var iov = [1]posix.iovec{.{ .base = &iov_buf, .len = iov_buf.len }};
        var ctrl: [128]u8 = undefined;
        var msg: posix.msghdr = .{
            .name = @ptrCast(&peer.storage),
            .namelen = peer.len,
            .iov = &iov,
            .iovlen = 1,
            .control = &ctrl,
            .controllen = ctrl.len,
            .flags = 0,
        };
        const flags: u32 = 0x2000; // MSG_ERRQUEUE
        const n_or_err = posix.recvmsg(ctx.sock_fd, &msg, flags);
        if (n_or_err) |n| {
            _ = n;
            var mtu: ?u16 = null;
            var origin_icmp: bool = false;
            // Walk control headers to find extended error
            var off: usize = 0;
            while (off + @sizeOf(posix.cmsghdr) <= msg.controllen) {
                const cmsg_ptr: *const posix.cmsghdr = @ptrCast(@alignCast(@as(*const anyopaque, @ptrFromInt(@intFromPtr(msg.control) + off))));
                const clen = cmsg_ptr.len;
                if (clen < @sizeOf(posix.cmsghdr) or off + clen > msg.controllen) break;
                const level = cmsg_ptr.level;
                const ctype = cmsg_ptr.type;
                const data_ptr = @as([*]const u8, @ptrFromInt(@intFromPtr(cmsg_ptr) + @sizeOf(posix.cmsghdr)));
                if ((level == posix.IPPROTO.IP and ctype == 11) or (level == posix.IPPROTO.IPV6 and ctype == 25)) {
                    // IP_RECVERR/IPV6_RECVERR data is sock_extended_err
                    if (clen >= @sizeOf(posix.cmsghdr) + @sizeOf(ExtendedErr)) {
                        const ee: *const ExtendedErr = @ptrCast(@alignCast(data_ptr));
                        if (ee.ee_origin == SO_EE_ORIGIN_ICMP and ee.ee_type == ICMP_DEST_UNREACH and ee.ee_code == ICMP_FRAG_NEEDED) {
                            origin_icmp = true;
                            mtu = @intCast(@min(ee.ee_info, @as(u32, 0xFFFF)));
                        } else if (ee.ee_origin == SO_EE_ORIGIN_ICMP6 and ee.ee_type == ICMPV6_PKT_TOOBIG) {
                            origin_icmp = true;
                            mtu = @intCast(@min(ee.ee_info, @as(u32, 0xFFFF)));
                        }
                    }
                }
                // Align to next header
                const align_sz: usize = 8;
                const adv = (clen + (align_sz - 1)) & ~(align_sz - 1);
                off += adv;
            }
            if (origin_icmp and mtu) |mtu_v| {
                // Pass quoted packet to ICMP handler
                const quoted = iov_buf[0..];
                ctx.icmp_ptb_fn(peer, quoted, mtu_v);
            }
        } else |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return,
            }
        }
    }
}

/// Linux epoll backend for event loop.
/// RFC 9000 §13.3: Endpoints should efficiently wait for incoming datagrams.
pub fn pollEpollBackend(ctx: *const IoContext, timeout_ms: i32) !void {
    logger.debugPrint("poll_epoll_backend called, timeout={}, epoll_fd={?}\n", .{ timeout_ms, ctx.epoll_fd });

    // On non-Linux platforms, fallback to a simple sleep + drain
    if (builtin.target.os.tag != .linux or ctx.epoll_fd == null) {
        logger.debugPrint("Falling back to sleep+drain\n", .{});
        if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
        drainReadable(ctx);
        return;
    }

    // Always try to drain first - UDP packets might be buffered
    drainReadable(ctx);

    // Verify FD is still valid
    var check_addr = conn_mod.SockAddr{};
    check_addr.len = @intCast(@sizeOf(posix.sockaddr.storage));
    if (posix.getsockname(ctx.sock_fd, @ptrCast(&check_addr.storage), &check_addr.len)) |_| {
        logger.debugPrint("Socket fd={} is still valid\n", .{ctx.sock_fd});
    } else |err| {
        logger.debugPrint("Socket fd={} is INVALID: {}\n", .{ ctx.sock_fd, err });
        return;
    }

    const linux = std.os.linux;

    // Try manually checking if data is available with MSG_PEEK
    var peek_buf: [1]u8 = undefined;
    var peek_addr: posix.sockaddr.storage = undefined;
    var peek_len: posix.socklen_t = @sizeOf(@TypeOf(peek_addr));
    const peek_flags = posix.MSG.DONTWAIT | posix.MSG.PEEK;
    if (posix.recvfrom(ctx.sock_fd, &peek_buf, @intCast(peek_flags), @ptrCast(&peek_addr), &peek_len)) |peek_n| {
        logger.debugPrint("!!!! recvfrom PEEK shows {} bytes waiting!\n", .{peek_n});
    } else |peek_err| {
        if (peek_err != error.WouldBlock) {
            logger.debugPrint("recvfrom PEEK error: {}\n", .{peek_err});
        }
    }

    var events: [16]linux.epoll_event = undefined;
    logger.debugPrint("Calling epoll_wait on fd={} with timeout={}\n", .{ ctx.epoll_fd.?, timeout_ms });
    const n = posix.epoll_wait(ctx.epoll_fd.?, &events, timeout_ms);

    if (n > 0) {
        logger.debugPrint("epoll_wait returned {} events\n", .{n});
        for (0..n) |i| {
            const ev = events[i];
            logger.debugPrint("Event {}: fd={}, events=0x{x}\n", .{ i, ev.data.fd, ev.events });

            const expected_fd = @as(i32, @intCast(ctx.sock_fd));
            logger.debugPrint("Checking ev.data.fd={} vs expected_fd={}\n", .{ ev.data.fd, expected_fd });
            // Handle both EPOLLIN (data ready) and EPOLLERR (error condition)
            if (ev.data.fd == expected_fd and ((ev.events & linux.EPOLL.IN) != 0 or (ev.events & linux.EPOLL.ERR) != 0)) {
                logger.debugPrint("Socket {} is readable or has error - calling drainReadable\n", .{ctx.sock_fd});
                drainReadable(ctx);
            } else {
                logger.debugPrint("Not our socket or not readable/error\n", .{});
            }
        }
    } else if (n == 0) {
        logger.debugPrint("epoll_wait timed out (no events)\n", .{});
    }

    // Always try to drain after epoll_wait
    drainReadable(ctx);
}

/// Readiness-driven fallback used by non-epoll backends on Unix-like targets.
fn waitReadableFallback(sock_fd: posix.socket_t, timeout_ms: i32) !void {
    if (sock_fd < 0) {
        return;
    }

    var fds = [1]posix.pollfd{
        .{
            .fd = sock_fd,
            .events = posix.POLL.IN | posix.POLL.ERR | posix.POLL.HUP,
            .revents = 0,
        },
    };
    const timeout = if (timeout_ms < 0) -1 else timeout_ms;
    _ = try posix.poll(&fds, timeout);
}

/// BSD/macOS kqueue backend for event loop.
pub fn pollKqueueBackend(ctx: *const IoContext, timeout_ms: i32) !void {
    // Phase 26: avoid sleep polling; block on fd readiness with bounded timeout.
    try waitReadableFallback(ctx.sock_fd, timeout_ms);
    drainReadable(ctx);
}

/// Windows IOCP backend for event loop.
pub fn pollIocpBackend(ctx: *const IoContext, timeout_ms: i32) !void {
    if (builtin.target.os.tag != .windows) {
        try waitReadableFallback(ctx.sock_fd, timeout_ms);
        drainReadable(ctx);
        return;
    }
    // TODO: Import IOCP loop when module dependencies are resolved
    // For now, just use sleep-based fallback
    if (timeout_ms > 0) std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
    drainReadable(ctx);
}
