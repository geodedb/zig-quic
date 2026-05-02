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
const logger = @import("quic_logger");
const transport_mod = @import("transport.zig");
const posix = std.posix;

pub const Transport = transport_mod.Transport;
pub const SockAddr = transport_mod.SockAddr;
pub const RecvResult = transport_mod.RecvResult;
pub const RecvBatchSlot = transport_mod.RecvBatchSlot;
pub const SendBatchItem = transport_mod.SendBatchItem;

/// Maximum number of UDP datagrams processed per batched syscall.
pub const UdpBatchCap: usize = 16;

/// Coerce a `std.c.F.<X>` value to `c_int` for `fcntl(2)`.
///
/// Zig 0.16's stdlib defines `std.c.F` differently per OS:
///   * Linux (and emscripten): `linux.F`/`emscripten.F` — an enum;
///     `@intFromEnum` produces the integer value.
///   * macOS/iOS/tvOS/visionOS/watchOS/driverkit/wasi: a `struct` of
///     `pub const <NAME> = <comptime_int>;` constants that coerce
///     directly via `@as`.
///
/// `@intFromEnum(std.c.F.GETFL)` therefore compiles on Linux but
/// errors on macOS with "expected enum or tagged union, found
/// 'comptime_int'". This helper unifies both shapes so the fcntl
/// cmd argument is constructed correctly under cross-compile.
inline fn fcntlCmd(comptime tag: anytype) c_int {
    return switch (@typeInfo(@TypeOf(tag))) {
        .@"enum" => @intCast(@intFromEnum(tag)),
        .comptime_int, .int => @as(c_int, tag),
        else => @compileError("std.c.F member must be an enum or integer; got " ++ @typeName(@TypeOf(tag))),
    };
}

fn cmsgAlign(len: usize) usize {
    const align_to = @sizeOf(usize);
    const mask: usize = align_to - 1;
    return (len + mask) & ~mask;
}

fn ecnFromAncillary(control: []const u8, controllen: usize) ?u8 {
    const linux = std.os.linux;
    const hdr_len = @sizeOf(linux.cmsghdr);
    const max_len = @min(control.len, controllen);
    var off: usize = 0;
    while (off + hdr_len <= max_len) {
        const hdr = control[off..];
        const cmsg_len = std.mem.readInt(usize, hdr[0..@sizeOf(usize)], .native);
        if (cmsg_len < hdr_len or off + cmsg_len > max_len) break;
        const level_off = @sizeOf(usize);
        const type_off = level_off + @sizeOf(i32);
        const level = std.mem.readInt(i32, hdr[level_off..][0..@sizeOf(i32)], .native);
        const ctype = std.mem.readInt(i32, hdr[type_off..][0..@sizeOf(i32)], .native);
        const data_off = off + cmsgAlign(hdr_len);
        if (data_off < off + cmsg_len) {
            const traffic_class = control[data_off];
            if (level == linux.SOL.IP and ctype == linux.IP.TOS) return traffic_class & 0x03;
            if (level == linux.SOL.IPV6 and ctype == linux.IPV6.TCLASS) return traffic_class & 0x03;
        }
        off += cmsgAlign(cmsg_len);
    }
    return null;
}

fn configureEcnSocket(fd: posix.socket_t, family: u16) void {
    if (builtin.target.os.tag != .linux) return;
    const linux = std.os.linux;
    var one: i32 = 1;
    var ect0: i32 = 0x02;
    switch (family) {
        posix.AF.INET => {
            _ = linux.setsockopt(fd, linux.SOL.IP, linux.IP.RECVTOS, @ptrCast(std.mem.asBytes(&one)), @sizeOf(i32));
            _ = linux.setsockopt(fd, linux.SOL.IP, linux.IP.TOS, @ptrCast(std.mem.asBytes(&ect0)), @sizeOf(i32));
        },
        posix.AF.INET6 => {
            _ = linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.RECVTCLASS, @ptrCast(std.mem.asBytes(&one)), @sizeOf(i32));
            _ = linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.TCLASS, @ptrCast(std.mem.asBytes(&ect0)), @sizeOf(i32));
        },
        else => {},
    }
}

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

fn netAddressToSockAddr(addr: std.Io.net.IpAddress) SockAddr {
    switch (addr) {
        .ip4 => |ip4| {
            var out: SockAddr = .{};
            out.storage = std.mem.zeroes(posix.sockaddr.storage);
            var sin: posix.sockaddr.in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = std.mem.readInt(u32, &ip4.bytes, .little),
                .zero = .{0} ** 8,
            };
            out.len = @intCast(@sizeOf(posix.sockaddr.in));
            @memcpy(@as([*]u8, @ptrCast(&out.storage))[0..out.len], @as([*]const u8, @ptrCast(&sin))[0..out.len]);
            return out;
        },
        .ip6 => |ip6| {
            var out: SockAddr = .{};
            out.storage = std.mem.zeroes(posix.sockaddr.storage);
            var sin6: posix.sockaddr.in6 = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            out.len = @intCast(@sizeOf(posix.sockaddr.in6));
            @memcpy(@as([*]u8, @ptrCast(&out.storage))[0..out.len], @as([*]const u8, @ptrCast(&sin6))[0..out.len]);
            return out;
        },
    }
}

fn resolveBindAddr(bind_addr: []const u8) !SockAddr {
    // Fast path for numeric IP literals with port (supports bracketed IPv6).
    // Split the bind address into host and port, then use parse().
    if (splitHostPort(bind_addr)) |hp| {
        if (std.Io.net.IpAddress.parse(hp.host, hp.port)) |addr| {
            return netAddressToSockAddr(addr);
        } else |_| {}
    } else |_| {}

    const hp = try splitHostPort(bind_addr);
    const host = if (std.mem.eql(u8, hp.host, "localhost")) "127.0.0.1" else hp.host;
    const addr = std.Io.net.IpAddress.parse(host, hp.port) catch return error.InvalidAddress;
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
    ///
    /// Platform support:
    ///   - Linux:        full path including ECN (IP_TOS / IPV6_TCLASS) and sendmmsg/recvmmsg
    ///   - macOS/BSD:    posix fallback (no ECN, no batched send/recv); see docs/PLATFORM_SUPPORT.md
    ///   - Windows:      not supported by this transport (use IO completion ports separately)
    pub fn init(bind_addr: []const u8) !UdpTransport {
        if (builtin.target.os.tag != .linux) {
            return initPosix(bind_addr);
        }

        // Parse bind address
        var addr = try resolveBindAddr(bind_addr);

        // Determine address family
        const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(&addr.storage));
        const family = sa.family;

        const linux = std.os.linux;
        // Create UDP socket
        const sock_rc = linux.socket(family, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
        if (linux.errno(sock_rc) != .SUCCESS) return error.SocketCreateFailed;
        const fd: posix.socket_t = @intCast(sock_rc);
        errdefer _ = linux.close(fd);

        // Set SO_REUSEADDR for fast rebinding
        var one: i32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(std.mem.asBytes(&one)), @sizeOf(i32));
        configureEcnSocket(fd, family);

        // Bind to address
        const bind_len: posix.socklen_t = switch (family) {
            posix.AF.INET => @intCast(@sizeOf(posix.sockaddr.in)),
            posix.AF.INET6 => @intCast(@sizeOf(posix.sockaddr.in6)),
            else => return error.AddressFamilyNotSupported,
        };
        const bind_rc = linux.bind(fd, @ptrCast(&addr.storage), bind_len);
        if (linux.errno(bind_rc) != .SUCCESS) return error.BindFailed;

        // Query actual bound address (important for port 0)
        var actual_addr: posix.sockaddr.storage = undefined;
        var actual_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const gsn_rc = linux.getsockname(fd, @ptrCast(&actual_addr), &actual_len);
        if (linux.errno(gsn_rc) != .SUCCESS) return error.GetSockNameFailed;

        // Set non-blocking mode
        {
            const flags_rc = linux.fcntl(fd, linux.F.GETFL, 0);
            if (linux.errno(flags_rc) != .SUCCESS) return error.FcntlFailed;
            const flags: i32 = @intCast(flags_rc);
            const O_NONBLOCK: i32 = 0x800;
            const new_flags = flags | O_NONBLOCK;
            const set_rc = linux.fcntl(fd, linux.F.SETFL, @intCast(@as(u32, @bitCast(new_flags))));
            if (linux.errno(set_rc) != .SUCCESS) return error.FcntlFailed;
        }

        return UdpTransport{
            .fd = fd,
            .family = family,
            .local_addr = .{ .storage = actual_addr, .len = actual_len },
        };
    }

    /// Cross-platform fallback init using libc directly via std.c.*.
    /// ECN is unsupported here - recvFn returns null ECN and
    /// configureEcnSocket is a Linux-only no-op.
    ///
    /// 2026-05-01 (Zig 0.16): switched from `std.posix.{socket,close,bind,
    /// getsockname,fcntl}` to `std.c.*` because std.posix dropped those
    /// wrappers in 0.16 (only socket_t and setsockopt remain there). This
    /// path runs on macOS/BSD which always link libc; std.c.socket etc.
    /// dispatch to the correct platform syscalls. Surfaced by geode CI
    /// pipeline #1011 cross-compiling to x86_64-macos.
    fn initPosix(bind_addr: []const u8) !UdpTransport {
        var addr = try resolveBindAddr(bind_addr);
        const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(&addr.storage));
        const family = sa.family;

        const sock_rc = std.c.socket(family, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        if (sock_rc < 0) return error.SocketCreateFailed;
        const fd: posix.socket_t = @intCast(sock_rc);
        errdefer _ = std.c.close(fd);

        var one: i32 = 1;
        _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

        const bind_len: posix.socklen_t = switch (family) {
            posix.AF.INET => @intCast(@sizeOf(posix.sockaddr.in)),
            posix.AF.INET6 => @intCast(@sizeOf(posix.sockaddr.in6)),
            else => return error.AddressFamilyNotSupported,
        };
        if (std.c.bind(fd, @ptrCast(&addr.storage), bind_len) < 0) return error.BindFailed;

        var actual_addr: posix.sockaddr.storage = undefined;
        var actual_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        if (std.c.getsockname(fd, @ptrCast(&actual_addr), &actual_len) < 0) return error.GetSockNameFailed;

        // Best-effort non-blocking via fcntl; some platforms expose only SOCK_NONBLOCK
        // at socket() time which is not portable to all targets we care about.
        // `fcntlCmd` handles the per-OS shape divergence of `std.c.F`
        // (enum on Linux; struct of `pub const comptime_int` on macOS/BSD).
        const flags = std.c.fcntl(fd, fcntlCmd(std.c.F.GETFL), @as(c_int, 0));
        if (flags >= 0) {
            _ = std.c.fcntl(fd, fcntlCmd(std.c.F.SETFL), flags | @as(c_int, @intCast(posix.SOCK.NONBLOCK)));
        }

        return UdpTransport{
            .fd = fd,
            .family = family,
            .local_addr = .{ .storage = actual_addr, .len = actual_len },
        };
    }

    /// Deinitialize transport and close socket
    pub fn deinit(self: *UdpTransport) void {
        if (builtin.target.os.tag != .linux) {
            // Zig 0.16 dropped std.posix.close; use libc directly. The
            // initPosix path above already opens via std.c.socket so
            // closing via std.c.close keeps the fd ownership symmetric.
            _ = std.c.close(self.fd);
            return;
        }
        _ = std.os.linux.close(self.fd);
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
        // Note: returning error.Unexpected directly (rather than going through
        // std.posix.unexpectedErrno) keeps this helper cross-compilable. On
        // non-Linux targets std.posix.E maps to the host libc's errno enum
        // (e.g. c.darwin.E), so passing a std.os.linux.E there would fail to
        // compile. This helper is only referenced from Linux-gated call sites.
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.Unexpected,
        };
    }

    // Posix-based send for non-Linux platforms. Maps platform errno to error.WouldBlock
    // for EAGAIN and propagates other errors as error.Unexpected. ECN/cmsg paths are not
    // exercised here — ECN extraction is Linux-only via recvmsg ancillary data; non-Linux
    // returns null ECN.
    //
    // Zig 0.16 dropped `std.posix.sendto`/`std.posix.recvfrom` (only `socket_t` and
    // `setsockopt` remain). We call the libc `sendto(2)`/`recvfrom(2)` directly via
    // `std.c` and map errno manually, mirroring the prior std.posix error contract.
    fn posixSendTo(fd: posix.socket_t, peer: SockAddr, data: []const u8) !usize {
        const rc = std.c.sendto(
            fd,
            data.ptr,
            data.len,
            0,
            @ptrCast(&peer.storage),
            peer.len,
        );
        if (rc < 0) {
            return switch (std.c.errno(rc)) {
                .AGAIN => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        return @intCast(rc);
    }

    fn posixRecvFrom(fd: posix.socket_t, buf: []u8) !RecvResult {
        var peer_storage: posix.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const rc = std.c.recvfrom(
            fd,
            buf.ptr,
            buf.len,
            0,
            @ptrCast(&peer_storage),
            &peer_len,
        );
        if (rc < 0) {
            return switch (std.c.errno(rc)) {
                .AGAIN => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        return RecvResult{
            .n = @intCast(rc),
            .peer = .{ .storage = peer_storage, .len = peer_len },
            .ecn = null, // ECN extraction is Linux-only; non-Linux callers see null
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        if (builtin.target.os.tag != .linux) {
            return posixSendTo(self.fd, peer, data);
        }
        const linux = std.os.linux;
        const rc = linux.sendto(
            self.fd,
            data.ptr,
            data.len,
            0,
            @ptrCast(&peer.storage),
            peer.len,
        );
        return try linuxResultToCount(rc);
    }

    fn sendBatchFallback(self: *UdpTransport, items: []const SendBatchItem) !usize {
        // Cross-platform per-packet fallback used when sendmmsg is unavailable
        // (non-Linux) or when batch capacity is exceeded.
        var sent_items: usize = 0;
        while (sent_items < items.len) : (sent_items += 1) {
            const it = items[sent_items];
            const sent = try posixSendTo(self.fd, it.peer, it.data);
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
            var msgs: [UdpBatchCap]linux.mmsghdr = undefined;

            var i: usize = 0;
            while (i < chunk_len) : (i += 1) {
                const it = items[sent_total + i];
                iovecs[i] = .{
                    .base = it.data.ptr,
                    .len = it.data.len,
                };
                msgs[i] = .{
                    .hdr = .{
                        .name = @ptrCast(@constCast(&it.peer.storage)),
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
        if (builtin.target.os.tag != .linux) {
            return posixRecvFrom(self.fd, buf);
        }
        const linux = std.os.linux;

        var peer_storage: posix.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        var iov = [1]posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
        var control: [64]u8 = undefined;
        var msg: linux.msghdr = .{
            .name = @ptrCast(&peer_storage),
            .namelen = peer_len,
            .iov = @ptrCast(&iov),
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };

        const rc = linux.recvmsg(
            self.fd,
            &msg,
            0,
        );
        const n = try linuxResultToCount(rc);
        peer_len = msg.namelen;

        return RecvResult{
            .n = n,
            .peer = .{ .storage = peer_storage, .len = peer_len },
            .ecn = ecnFromAncillary(&control, msg.controllen),
        };
    }

    fn recvBatchFallback(self: *UdpTransport, slots: []RecvBatchSlot) !usize {
        // Cross-platform per-packet fallback used when recvmmsg is unavailable
        // (non-Linux) or when the underlying batch syscall returned WouldBlock.
        var received: usize = 0;
        while (received < slots.len) : (received += 1) {
            const r = posixRecvFrom(self.fd, slots[received].buf) catch |err| {
                if (err == error.WouldBlock) {
                    if (received == 0) return error.WouldBlock;
                    return received;
                }
                return err;
            };
            slots[received].n = r.n;
            slots[received].peer = r.peer;
            slots[received].ecn = r.ecn; // null on non-Linux
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
            var controls: [UdpBatchCap][64]u8 = undefined;
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
                        .control = &controls[i],
                        .controllen = controls[i].len,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }

            const rc = linux.recvmmsg(
                @intCast(self.fd),
                &msgs,
                @intCast(chunk_len),
                @intCast(linux.MSG.DONTWAIT),
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
                slots[received_total + j].ecn = ecnFromAncillary(&controls[j], msgs[j].hdr.controllen);
            }

            received_total += got;
            if (got < chunk_len) break;
        }

        if (received_total == 0) return error.WouldBlock;
        return received_total;
    }

    fn pollFn(ctx: *anyopaque, timeout_ms: i32) !void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        if (builtin.target.os.tag != .linux) {
            // Cross-platform poll: use std.posix.poll which dispatches to the host's poll()
            var fds = [1]posix.pollfd{
                .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
            };
            const timeout: i32 = if (timeout_ms < 0) -1 else timeout_ms;
            _ = posix.poll(&fds, timeout) catch {};
            return;
        }
        const linux = std.os.linux;
        var fds = [1]linux.pollfd{
            .{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const timeout: i32 = if (timeout_ms < 0) -1 else timeout_ms;
        const rc = linux.poll(&fds, 1, timeout);
        _ = rc; // Number of ready FDs (we only care that poll returned)
    }

    fn closeFn(ctx: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        if (builtin.target.os.tag != .linux) {
            // Zig 0.16: std.posix.close removed; std.c.close is the
            // libc passthrough for non-Linux paths.
            _ = std.c.close(self.fd);
            return;
        }
        _ = std.os.linux.close(self.fd);
    }

    fn getLocalAddrFn(ctx: *anyopaque) !SockAddr {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};

// Platform abstraction tests for #172. The cross-platform fallback path is
// type-checked at comptime under both branches of the `builtin.target.os.tag`
// switch; the runtime exercise here covers the Linux production path. See
// docs/PLATFORM_SUPPORT.md for the full matrix.
test "udp_transport: bind on Linux exposes non-zero port" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;

    var transport = try UdpTransport.init("127.0.0.1:0");
    defer transport.deinit();

    try std.testing.expectEqual(@as(u16, posix.AF.INET), transport.family);

    const sa: *const posix.sockaddr.in = @ptrCast(@alignCast(&transport.local_addr.storage));
    try std.testing.expect(sa.port != 0);
}

test "udp_transport: posix fallback symbols compile under non-linux branch" {
    // This test forces the compiler to materialize references to `initPosix`
    // and the `posixSendTo` / `posixRecvFrom` helpers so any signature drift
    // surfaces at compile time on Linux CI even though the branch is cold here.
    const init_ptr: *const fn ([]const u8) anyerror!UdpTransport = &UdpTransport.initPosix;
    const send_ptr: *const fn (posix.socket_t, SockAddr, []const u8) anyerror!usize = &UdpTransport.posixSendTo;
    const recv_ptr: *const fn (posix.socket_t, []u8) anyerror!RecvResult = &UdpTransport.posixRecvFrom;
    _ = init_ptr;
    _ = send_ptr;
    _ = recv_ptr;
}

test "udp_transport: ECN cmsg parser returns null on empty control buffer" {
    var control: [0]u8 = .{};
    try std.testing.expectEqual(@as(?u8, null), ecnFromAncillary(&control, 0));
}
