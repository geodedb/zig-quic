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
pub fn sockToIsize(sock: posix.socket_t) isize {
    return @as(isize, @intCast(sock));
}
