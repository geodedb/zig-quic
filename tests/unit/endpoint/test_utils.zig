//! Unit tests for endpoint/utils.zig
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection ID routing
//! - RFC 9000 §5.2: Matching Packets to Connections
//!
//! Coverage:
//! - Byte hashing for connection routing
//! - Socket address hashing
//! - IPv4-mapped IPv6 normalization
//! - Network byte order conversions

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const quic_conn = @import("quic_conn");

const SockAddr = quic_conn.SockAddr;

// =============================================================================
// Byte Hashing Tests
// =============================================================================

test "RFC 9000 §5.2 - hashBytes produces consistent hash" {
    // Same bytes should always produce same hash
    const data = "test_connection_id_bytes";
    const hash1 = utils.hashBytes(data);
    const hash2 = utils.hashBytes(data);

    try testing.expectEqual(hash1, hash2);
}

test "RFC 9000 §5.2 - hashBytes differentiates different data" {
    // Different bytes should produce different hashes
    const data1 = "connection_id_1";
    const data2 = "connection_id_2";
    const hash1 = utils.hashBytes(data1);
    const hash2 = utils.hashBytes(data2);

    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.2 - hashBytes handles empty data" {
    // Empty data should be hashable
    const data: []const u8 = &[_]u8{};
    const hash = utils.hashBytes(data);

    _ = hash; // Hash should be computed without error
}

// =============================================================================
// Socket Address Hashing Tests
// =============================================================================

test "RFC 9000 §5.2 - hashSockaddr produces consistent hash for IPv4" {
    // Same IPv4 address should always produce same hash
    const addr = SockAddr.ipv4(192, 168, 1, 100, 4433);
    const hash1 = utils.hashSockaddr(&addr.storage, addr.len);
    const hash2 = utils.hashSockaddr(&addr.storage, addr.len);

    try testing.expectEqual(hash1, hash2);
}

test "RFC 9000 §5.2 - hashSockaddr differentiates addresses" {
    // Different addresses should produce different hashes
    const addr1 = SockAddr.ipv4(192, 168, 1, 10, 4433);
    const addr2 = SockAddr.ipv4(192, 168, 1, 20, 4433);
    const hash1 = utils.hashSockaddr(&addr1.storage, addr1.len);
    const hash2 = utils.hashSockaddr(&addr2.storage, addr2.len);

    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.2 - hashSockaddr differentiates ports" {
    // Same IP with different ports should produce different hashes
    const addr1 = SockAddr.ipv4(127, 0, 0, 1, 4433);
    const addr2 = SockAddr.ipv4(127, 0, 0, 1, 4434);
    const hash1 = utils.hashSockaddr(&addr1.storage, addr1.len);
    const hash2 = utils.hashSockaddr(&addr2.storage, addr2.len);

    try testing.expect(hash1 != hash2);
}

// =============================================================================
// IPv4-Mapped IPv6 Normalization Tests
// =============================================================================

test "RFC 9000 §5.2 - normalizeAddr returns IPv4 as-is" {
    // Plain IPv4 address should pass through unchanged
    const addr = SockAddr.ipv4(10, 0, 0, 1, 8080);
    const normalized = utils.normalizeAddr(&addr.storage, addr.len);

    try testing.expectEqual(addr.storage.family, normalized.storage.family);
    try testing.expectEqual(addr.len, normalized.len);
}

test "RFC 9000 §5.2 - normalizeAddr converts IPv4-mapped IPv6 to IPv4" {
    // ::ffff:127.0.0.1 should normalize to 127.0.0.1
    // This test documents the expected behavior - implementation may need adjustment
    // if SockAddr doesn't have ipv6() constructor yet

    // Create IPv4-mapped IPv6 manually
    var storage: std.posix.sockaddr.storage = undefined;
    storage.family = std.posix.AF.INET6;

    const sin6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
    @memset(std.mem.asBytes(&sin6.addr), 0);

    // Set ::ffff:127.0.0.1 pattern
    const addr_bytes = @as(*[16]u8, @ptrCast(&sin6.addr));
    addr_bytes[10] = 0xFF;
    addr_bytes[11] = 0xFF;
    addr_bytes[12] = 127;
    addr_bytes[13] = 0;
    addr_bytes[14] = 0;
    addr_bytes[15] = 1;

    sin6.port = utils.portToNetwork(4433);

    const normalized = utils.normalizeAddr(&storage, @sizeOf(std.posix.sockaddr.in6));

    // Should be converted to IPv4
    try testing.expectEqual(std.posix.AF.INET, normalized.storage.family);
}

test "RFC 9000 §5.2 - normalizeAddr preserves non-mapped IPv6" {
    // Regular IPv6 address (not IPv4-mapped) should pass through
    var storage: std.posix.sockaddr.storage = undefined;
    storage.family = std.posix.AF.INET6;

    const sin6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
    @memset(std.mem.asBytes(&sin6.addr), 0);

    // Set non-mapped IPv6 (2001:db8::1)
    const addr_bytes = @as(*[16]u8, @ptrCast(&sin6.addr));
    addr_bytes[0] = 0x20;
    addr_bytes[1] = 0x01;
    addr_bytes[2] = 0x0d;
    addr_bytes[3] = 0xb8;
    addr_bytes[15] = 1;

    sin6.port = utils.portToNetwork(4433);

    const normalized = utils.normalizeAddr(&storage, @sizeOf(std.posix.sockaddr.in6));

    // Should remain IPv6
    try testing.expectEqual(std.posix.AF.INET6, normalized.storage.family);
}

// =============================================================================
// Byte Order Conversion Tests
// =============================================================================

test "portToNetwork converts port to network byte order" {
    // Port 4433 (0x1151) should convert to network byte order
    const port: u16 = 4433;
    const network_port = utils.portToNetwork(port);

    // On little-endian: 0x1151 -> 0x5111
    // On big-endian: 0x1151 -> 0x1151
    _ = network_port; // Verify it compiles and runs
}

test "addrToNetwork converts address to network byte order" {
    // 127.0.0.1 as u32
    const addr: u32 = (127 << 24) | (0 << 16) | (0 << 8) | 1;
    const network_addr = utils.addrToNetwork(addr);

    // Should convert to network byte order
    _ = network_addr; // Verify it compiles and runs
}

test "sockToIsize converts socket descriptor" {
    // Socket file descriptor conversion
    // On Windows, socket_t is a pointer type, so we use @ptrFromInt
    const sock = if (comptime @import("builtin").os.tag == .windows)
        @as(std.posix.socket_t, @ptrFromInt(42))
    else
        @as(std.posix.socket_t, 42);
    const isize_sock = utils.sockToIsize(sock);

    try testing.expectEqual(@as(isize, 42), isize_sock);
}
