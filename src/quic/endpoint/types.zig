// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic endpoint types and utilities.
//!
//! RFC 9000 §5.1: Connection Routing
//! RFC 9002 §6.2: Probe Timeout (PTO)
//! RFC 9000 §14.2: Path MTU Discovery

const std = @import("std");
const posix = std.posix;
const conn_mod = @import("quic_conn");

/// Timer structure for endpoint scheduling.
pub const Timer = struct {
    deadline_ms: i64,
    id: u64,
    kind: TimerKind = .Generic,
    conn: ?*conn_mod.Connection = null,
    // Pacing payload support (Generic kind): when paced is true and payload!=null, send on expiry
    paced: bool = false,
    payload: ?[]u8 = null,
    // Snapshot of peer at pacing enqueue time; avoids replaying old-path packets
    // to a newly migrated peer address.
    paced_peer: ?conn_mod.SockAddr = null,
};

/// Endpoint timer kinds: generic app timers plus per-PN-space PTO and PMTUD timers.
///
/// PTO timers correspond to RFC 9002 §6.2, while PMTUD follows RFC 9000 §14.2.
pub const TimerKind = enum { Generic, PtoInitial, PtoHandshake, PtoApp, Pmtud };

/// Hash key combining peer address + destination CID for connection lookup.
///
/// RFC 9000 §5.1 mandates that servers route packets using tuple + DCID. We use
/// this composite hash so multipath/path validation still find the right entry.
pub const Key = struct {
    peer_hash: u64,
    dcid_hash: u64,
};

/// Endpoint role enum (Client or Server).
pub const EndpointRole = enum {
    Client,
    Server,
};

/// Hash bytes using Wyhash.
pub fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

/// Convert network-order port to host order.
inline fn portFromNetwork(value: u16) u16 {
    return @byteSwap(value);
}

/// Normalize IPv4-mapped IPv6 address to IPv4 for consistent hashing.
/// This ensures that ::ffff:127.0.0.1 and 127.0.0.1 hash to the same value.
pub fn normalizeAddr(sa: *const posix.sockaddr.storage, len: u32) conn_mod.SockAddr {
    if (sa.family == posix.AF.INET6) {
        const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
        // Check if this is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
        // The first 10 bytes must be zero, bytes 10-11 must be 0xFF
        const addr_bytes = @as(*const [16]u8, @ptrCast(&sin6.addr)).*;
        const is_v4_mapped =
            addr_bytes[0] == 0 and addr_bytes[1] == 0 and
            addr_bytes[2] == 0 and addr_bytes[3] == 0 and
            addr_bytes[4] == 0 and addr_bytes[5] == 0 and
            addr_bytes[6] == 0 and addr_bytes[7] == 0 and
            addr_bytes[8] == 0 and addr_bytes[9] == 0 and
            addr_bytes[10] == 0xFF and addr_bytes[11] == 0xFF;

        if (is_v4_mapped) {
            // Extract the IPv4 address from bytes 12-15 and convert to IPv4 sockaddr
            const a = addr_bytes[12];
            const b = addr_bytes[13];
            const c = addr_bytes[14];
            const d = addr_bytes[15];
            const port = portFromNetwork(sin6.port);
            return conn_mod.SockAddr.ipv4(a, b, c, d, port);
        }
    }

    // Not IPv4-mapped, return as-is
    var result: conn_mod.SockAddr = .{};
    result.storage = sa.*;
    result.len = len;
    return result;
}

/// Hash a sockaddr for connection lookup.
/// RFC 9000 §5.1: Connection routing uses address + DCID.
pub fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const normalized = normalizeAddr(sa, len);
    const bytes = @as([*]const u8, @ptrCast(&normalized.storage))[0..normalized.len];
    return hashBytes(bytes);
}
