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
    }
    // Return as-is if not IPv4-mapped
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

/// Resolve hostname:port string to socket address.
/// Handles:
/// - "localhost" -> 127.0.0.1
/// - "server4"/"server" -> resolves from /etc/hosts or defaults to test IP
/// - IPv4 dotted-quad addresses
pub fn resolveAny(hostport: []const u8, proto: enum { udp }) !conn_mod.SockAddr {
    _ = proto;
    var parts = std.mem.splitScalar(u8, hostport, ':');
    const host = parts.next() orelse return error.InvalidAddress;
    const port_s = parts.next() orelse return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidAddress;

    // Handle common hostnames used in tests
    if (std.mem.eql(u8, host, "localhost")) {
        return conn_mod.SockAddr.ipv4(127, 0, 0, 1, port);
    }
    if (std.mem.eql(u8, host, "server4") or std.mem.eql(u8, host, "server")) {
        // In Docker, server4 should resolve to the server container
        // Try to use the IP from /etc/hosts if available
        const hosts_file = std.fs.openFileAbsolute("/etc/hosts", .{}) catch {
            // Fallback to a default IP used in tests
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        defer hosts_file.close();

        var buf: [4096]u8 = undefined;
        const bytes_read = hosts_file.readAll(&buf) catch {
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        const content = buf[0..bytes_read];

        // Parse /etc/hosts for server4
        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            var parts_line = std.mem.tokenizeAny(u8, line, " \t");
            const ip_str = parts_line.next() orelse continue;
            while (parts_line.next()) |hostname| {
                if (std.mem.eql(u8, hostname, "server4") or std.mem.eql(u8, hostname, "server")) {
                    // Parse the IP address
                    var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
                    var octets: [4]u8 = .{0} ** 4;
                    var i: usize = 0;
                    while (i < 4) : (i += 1) {
                        const octet_str = ip_parts.next() orelse break;
                        octets[i] = std.fmt.parseInt(u8, octet_str, 10) catch break;
                    }
                    if (i == 4) {
                        return conn_mod.SockAddr.ipv4(octets[0], octets[1], octets[2], octets[3], port);
                    }
                }
            }
        }
        // Default fallback
        return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
    }

    // Try dotted-quad IPv4 parse
    var it = std.mem.splitScalar(u8, host, '.');
    var oct: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const seg = it.next() orelse break;
        oct[i] = std.fmt.parseInt(u8, seg, 10) catch break;
    }
    if (i == 4 and it.next() == null) {
        return conn_mod.SockAddr.ipv4(oct[0], oct[1], oct[2], oct[3], port);
    }

    // Fallback: Check /etc/hosts for ANY hostname
    // In Docker, containers are in /etc/hosts
    if (std.fs.openFileAbsolute("/etc/hosts", .{})) |hosts_file| {
        defer hosts_file.close();

        var buf: [4096]u8 = undefined;
        if (hosts_file.readAll(&buf)) |bytes_read| {
            const content = buf[0..bytes_read];
            var lines = std.mem.tokenizeScalar(u8, content, '\n');
            while (lines.next()) |line| {
                var parts_line = std.mem.tokenizeAny(u8, line, " \t");
                const ip_str = parts_line.next() orelse continue;
                while (parts_line.next()) |hostname| {
                    if (std.mem.eql(u8, hostname, host)) {
                        // Found match, parse IP
                        var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
                        var ip_octs: [4]u8 = .{0} ** 4;
                        var j: usize = 0;
                        while (j < 4) : (j += 1) {
                            const oct_str = ip_parts.next() orelse break;
                            ip_octs[j] = std.fmt.parseInt(u8, oct_str, 10) catch break;
                        }
                        if (j == 4) {
                            return conn_mod.SockAddr.ipv4(ip_octs[0], ip_octs[1], ip_octs[2], ip_octs[3], port);
                        }
                    }
                }
            }
        } else |_| {}
    } else |_| {}

    return error.InvalidAddress;
}
