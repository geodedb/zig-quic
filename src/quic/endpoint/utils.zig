// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Endpoint utility functions.
//!
//! Shared utilities used across endpoint modules including:
//! - Hashing functions for connection routing
//! - Address normalization
//! - Socket utilities
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection ID routing
//! - RFC 9000 §5.2: Matching Packets to Connections

const std = @import("std");
const conn_mod = @import("quic_conn");
const posix = std.posix;

/// Hash arbitrary bytes using Wyhash.
/// Used for connection routing by DCID.
/// RFC 9000 §5.2: "Servers route packets to connections using the DCID."
pub fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

/// Hash a socket address for connection routing.
/// Normalizes IPv4-mapped IPv6 addresses to IPv4 for consistent hashing.
pub fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const normalized = normalizeAddr(sa, len);
    // Hash the raw bytes of the normalized address
    const bytes = std.mem.asBytes(&normalized.storage)[0..@intCast(normalized.len)];
    return hashBytes(bytes);
}

/// Normalize IPv4-mapped IPv6 address to IPv4 for consistent hashing.
/// This ensures that ::ffff:127.0.0.1 and 127.0.0.1 hash to the same value.
pub fn normalizeAddr(sa: *const posix.sockaddr.storage, len: u32) conn_mod.SockAddr {
    // Canonicalize native IPv4/IPv6 sockaddr lengths so hash/equality checks don't
    // depend on kernel-provided padding bytes.
    if (sa.family == posix.AF.INET) {
        var out: conn_mod.SockAddr = .{};
        out.storage = std.mem.zeroes(posix.sockaddr.storage);
        out.len = @sizeOf(posix.sockaddr.in);
        @memcpy(
            @as([*]u8, @ptrCast(&out.storage))[0..out.len],
            @as([*]const u8, @ptrCast(sa))[0..out.len],
        );
        return out;
    }
    if (sa.family == posix.AF.INET6) {
        const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
        // Check if this is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
        const addr_bytes = @as(*const [16]u8, @ptrCast(&sin6.addr)).*;
        const is_v4_mapped =
            addr_bytes[0] == 0 and addr_bytes[1] == 0 and
            addr_bytes[2] == 0 and addr_bytes[3] == 0 and
            addr_bytes[4] == 0 and addr_bytes[5] == 0 and
            addr_bytes[6] == 0 and addr_bytes[7] == 0 and
            addr_bytes[8] == 0 and addr_bytes[9] == 0 and
            addr_bytes[10] == 0xFF and addr_bytes[11] == 0xFF;

        if (is_v4_mapped) {
            // Extract the IPv4 address from bytes 12-15
            const a = addr_bytes[12];
            const b = addr_bytes[13];
            const c = addr_bytes[14];
            const d = addr_bytes[15];
            const port = portFromNetwork(sin6.port);
            return conn_mod.SockAddr.ipv4(a, b, c, d, port);
        }

        var out: conn_mod.SockAddr = .{};
        out.storage = std.mem.zeroes(posix.sockaddr.storage);
        out.len = @sizeOf(posix.sockaddr.in6);
        @memcpy(
            @as([*]u8, @ptrCast(&out.storage))[0..out.len],
            @as([*]const u8, @ptrCast(sa))[0..out.len],
        );
        return out;
    }
    // Return as-is for unknown families.
    var result = conn_mod.SockAddr{};
    result.storage = sa.*;
    result.len = len;
    return result;
}

/// Convert network byte order u16 to host byte order.
pub fn portFromNetwork(value: u16) u16 {
    return std.mem.bigToNative(u16, value);
}

/// Convert host byte order u16 to network byte order.
pub fn portToNetwork(value: u16) u16 {
    return std.mem.nativeToBig(u16, value);
}

/// Convert host byte order u32 to network byte order.
pub fn addrToNetwork(value: u32) u32 {
    return std.mem.nativeToBig(u32, value);
}

/// Convert socket_t to isize for Connection struct.
/// On POSIX systems, socket_t is an integer (fd).
/// On Windows, socket_t is a pointer (SOCKET handle).
pub fn sockToIsize(sock: posix.socket_t) isize {
    if (comptime @import("builtin").os.tag == .windows) {
        // Windows: socket_t is a pointer type, convert via intFromPtr
        // Use bitCast to preserve bit pattern (handles invalid socket ~0 correctly)
        return @bitCast(@intFromPtr(sock));
    } else {
        // POSIX: socket_t is already an integer
        return @as(isize, @intCast(sock));
    }
}

/// Cross-platform invalid socket value.
/// On POSIX systems, this is -1.
/// On Windows, this is INVALID_SOCKET (null pointer).
pub fn invalidSocket() posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) {
        // Windows INVALID_SOCKET is ~0 cast to SOCKET (pointer type)
        return @ptrFromInt(~@as(usize, 0));
    } else {
        return -1;
    }
}

/// Parse IPv4 dotted-quad string to network byte order u32.
/// Returns address suitable for sockaddr.in.s_addr.
pub fn parseIpv4(s: []const u8) !u32 {
    var it = std.mem.splitScalar(u8, s, '.');
    var octets: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const part = it.next() orelse return error.InvalidAddress;
        const v = try std.fmt.parseInt(u8, part, 10);
        octets[i] = v;
    }
    const host_val: u32 = (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
    return addrToNetwork(host_val);
}

fn splitHostPort(hostport: []const u8) !struct { host: []const u8, port: u16 } {
    if (hostport.len == 0) return error.InvalidAddress;

    if (hostport[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, hostport, ']') orelse return error.InvalidAddress;
        if (close_idx + 1 >= hostport.len or hostport[close_idx + 1] != ':') return error.InvalidAddress;
        const host = hostport[1..close_idx];
        const port_str = hostport[close_idx + 2 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;
        return .{ .host = host, .port = port };
    }

    const colon_idx = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.InvalidAddress;
    if (colon_idx == 0 or colon_idx + 1 >= hostport.len) return error.InvalidAddress;
    // Require bracket notation for IPv6 literals.
    if (std.mem.indexOfScalar(u8, hostport[0..colon_idx], ':') != null) return error.InvalidAddress;

    const host = hostport[0..colon_idx];
    const port_str = hostport[colon_idx + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;
    return .{ .host = host, .port = port };
}

fn netAddressToSockAddr(addr: std.net.Address) conn_mod.SockAddr {
    var out: conn_mod.SockAddr = .{};
    const addr_len: usize = addr.getOsSockLen();
    @memcpy(
        @as([*]u8, @ptrCast(&out.storage))[0..addr_len],
        @as([*]const u8, @ptrCast(&addr.any))[0..addr_len],
    );
    out.len = @intCast(addr_len);
    return out;
}

fn lookupHosts(host: []const u8, port: u16, prefer_ipv6: bool) ?conn_mod.SockAddr {
    const hosts_file = std.fs.openFileAbsolute("/etc/hosts", .{}) catch return null;
    defer hosts_file.close();

    var buf: [8192]u8 = undefined;
    const bytes_read = hosts_file.readAll(&buf) catch return null;
    const content = buf[0..bytes_read];

    var fallback: ?conn_mod.SockAddr = null;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const ip_str = fields.next() orelse continue;

        var matched = false;
        while (fields.next()) |hostname| {
            if (std.mem.eql(u8, hostname, host)) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;

        const addr = std.net.Address.parseIp(ip_str, port) catch continue;
        const sock = netAddressToSockAddr(addr);
        const is_v6 = sock.family() == posix.AF.INET6;

        if ((prefer_ipv6 and is_v6) or (!prefer_ipv6 and !is_v6)) {
            return sock;
        }
        if (fallback == null) fallback = sock;
    }

    return fallback;
}

/// Resolve hostname:port string to socket address.
/// Handles:
/// - "localhost" -> 127.0.0.1
/// - "server4"/"server" -> resolves from /etc/hosts or defaults to test IP
/// - "server6" -> resolves from /etc/hosts or defaults to test IPv6
/// - IPv4 / IPv6 literals (IPv6 must use bracket form in hostport)
pub fn resolveAny(hostport: []const u8, proto: enum { udp }) !conn_mod.SockAddr {
    _ = proto;
    const hp = try splitHostPort(hostport);
    const host = hp.host;
    const port = hp.port;

    // Numeric literal fast path.
    if (std.net.Address.parseIp(host, port)) |addr| {
        return netAddressToSockAddr(addr);
    } else |_| {}

    if (std.mem.eql(u8, host, "localhost")) {
        return conn_mod.SockAddr.ipv4(127, 0, 0, 1, port);
    }

    if (std.mem.eql(u8, host, "server6")) {
        if (lookupHosts(host, port, true)) |resolved| return resolved;
        if (lookupHosts("server", port, true)) |resolved| return resolved;
        const fallback = std.net.Address.parseIp("fd00:cafe:cafe:100::100", port) catch return error.InvalidAddress;
        return netAddressToSockAddr(fallback);
    }

    if (std.mem.eql(u8, host, "server4") or std.mem.eql(u8, host, "server")) {
        if (lookupHosts(host, port, false)) |resolved| return resolved;
        if (!std.mem.eql(u8, host, "server")) {
            if (lookupHosts("server", port, false)) |resolved| return resolved;
        }
        return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
    }

    // Generic /etc/hosts lookup for other hostnames.
    if (lookupHosts(host, port, false)) |resolved| return resolved;
    if (lookupHosts(host, port, true)) |resolved| return resolved;

    // Final fallback: resolver-backed lookup.
    const resolved = std.net.Address.resolveIp(host, port) catch return error.InvalidAddress;
    return netAddressToSockAddr(resolved);
}
