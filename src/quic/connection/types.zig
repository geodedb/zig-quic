// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic QUIC connection types and utilities.
//!
//! RFC 9000 §2-5: Connection roles, addresses, and identifiers.

const std = @import("std");
const posix = std.posix;
const byteorder = @import("byteorder");

/// Connection role: client initiates, server responds.
/// RFC 9000 §5: Connection Establishment
pub const Role = enum { Client, Server };

/// Portable socket address wrapper used by endpoint/connection.
/// Encapsulates both IPv4 and IPv6 addresses with their lengths.
pub const SockAddr = struct {
    storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage),
    len: u32 = 0,

    /// Initialize from a POSIX addrinfo entry (copies raw bytes).
    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    /// Return address family (AF.INET or AF.INET6).
    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

    /// Compare two SockAddr values for byte-wise equality.
    pub fn eq(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.len != b.len) return false;
        if (a.storage.family != b.storage.family) return false;
        const pa = @as([*]const u8, @ptrCast(&a.storage))[0..a.len];
        const pb = @as([*]const u8, @ptrCast(&b.storage))[0..b.len];
        return std.mem.eql(u8, pa, pb);
    }

    /// Build an IPv4 SockAddr from octets and host-order port (test helper).
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port_host: u16) SockAddr {
        var s: SockAddr = .{};
        s.storage = std.mem.zeroes(posix.sockaddr.storage);
        var sin: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = byteorder.toEndian(u16, .big, port_host),
            .addr = byteorder.toEndian(u32, .big, (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d)),
            .zero = .{0} ** 8,
        };
        s.len = @intCast(@sizeOf(posix.sockaddr.in));
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..s.len], @as([*]const u8, @ptrCast(&sin))[0..s.len]);
        return s;
    }

    /// Extract IP address bytes for token validation (RFC 9000 §8.1).
    /// Returns a slice pointing to the IP address portion of the sockaddr structure.
    /// For IPv4: 4 bytes, For IPv6: 16 bytes.
    pub fn getIpBytes(self: *const SockAddr) []const u8 {
        const storage_bytes = @as([*]const u8, @ptrCast(&self.storage));
        if (self.family() == posix.AF.INET) {
            // IPv4: addr is at offset 4 (after family:u16 + port:u16)
            return storage_bytes[4..8];
        } else if (self.family() == posix.AF.INET6) {
            // IPv6: addr is at offset 8 (after family:u16 + port:u16 + flowinfo:u32)
            return storage_bytes[8..24];
        }
        return &[_]u8{};
    }
};

/// Fixed-size Connection ID used in tests/internals.
/// RFC 9000 §5.1: Connection IDs are opaque identifiers chosen by endpoints.
pub const Cid = struct {
    len: u8 = 0,
    bytes: [20]u8 = [_]u8{0} ** 20,
};

/// Sender callback used by Endpoint to provide paced sending.
/// Allows endpoint to control packet transmission timing.
/// Connection parameter is passed as *anyopaque to avoid circular dependencies.
pub const SendFn = *const fn (ctx: *anyopaque, conn: *anyopaque, data: []const u8) anyerror!usize;
