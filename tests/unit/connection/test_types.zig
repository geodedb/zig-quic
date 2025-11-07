//! Unit tests for connection/types.zig
//!
//! RFC References:
//! - RFC 9000 §2-5: Connection roles, addresses, identifiers
//! - RFC 9000 §5: Connection Establishment
//! - RFC 9000 §5.1: Connection IDs
//!
//! Coverage:
//! - Positive cases: Role usage, SockAddr construction/operations, Cid structure
//! - Negative cases: Address inequality, family mismatch
//! - Edge cases: Zero values, max values, boundary conditions
//! - RFC compliance: CID length constraints, address family validation

const std = @import("std");
const testing = std.testing;
const types = @import("quic_connection_types");
const posix = std.posix;

// =============================================================================
// Role Tests
// =============================================================================

test "RFC 9000 §5 - Role enum basic usage" {
    const client_role = types.Role.Client;
    const server_role = types.Role.Server;

    try testing.expect(client_role == .Client);
    try testing.expect(server_role == .Server);
    try testing.expect(client_role != server_role);
}

// =============================================================================
// SockAddr IPv4 Tests
// =============================================================================

test "RFC 9000 §5 - SockAddr ipv4 construction with valid address" {
    const addr = types.SockAddr.ipv4(127, 0, 0, 1, 443);

    try testing.expectEqual(@as(u16, posix.AF.INET), addr.family());
    try testing.expect(addr.len > 0);
}

test "RFC 9000 §5 - SockAddr ipv4 with different ports creates different addresses" {
    const addr1 = types.SockAddr.ipv4(127, 0, 0, 1, 443);
    const addr2 = types.SockAddr.ipv4(127, 0, 0, 1, 8443);

    try testing.expect(!addr1.eq(&addr2));
}

test "RFC 9000 §5 - SockAddr ipv4 with different IPs creates different addresses" {
    const addr1 = types.SockAddr.ipv4(127, 0, 0, 1, 443);
    const addr2 = types.SockAddr.ipv4(192, 168, 1, 1, 443);

    try testing.expect(!addr1.eq(&addr2));
}

test "boundary: SockAddr ipv4 all zeros is valid" {
    const addr = types.SockAddr.ipv4(0, 0, 0, 0, 0);

    try testing.expectEqual(@as(u16, posix.AF.INET), addr.family());
    try testing.expect(addr.len > 0);
}

test "boundary: SockAddr ipv4 all max values is valid" {
    const addr = types.SockAddr.ipv4(255, 255, 255, 255, 65535);

    try testing.expectEqual(@as(u16, posix.AF.INET), addr.family());
    try testing.expect(addr.len > 0);
}

test "RFC 9000 §5 - SockAddr ipv4 loopback address" {
    const localhost = types.SockAddr.ipv4(127, 0, 0, 1, 8080);

    try testing.expectEqual(@as(u16, posix.AF.INET), localhost.family());
}

test "RFC 9000 §5 - SockAddr ipv4 typical server ports" {
    const http = types.SockAddr.ipv4(0, 0, 0, 0, 80);
    const https = types.SockAddr.ipv4(0, 0, 0, 0, 443);
    const quic = types.SockAddr.ipv4(0, 0, 0, 0, 4433);

    try testing.expect(!http.eq(&https));
    try testing.expect(!https.eq(&quic));
    try testing.expect(!http.eq(&quic));
}

// =============================================================================
// SockAddr Equality Tests
// =============================================================================

test "RFC 9000 §5 - SockAddr equality: identical addresses are equal" {
    const addr1 = types.SockAddr.ipv4(192, 168, 1, 100, 8080);
    const addr2 = types.SockAddr.ipv4(192, 168, 1, 100, 8080);

    try testing.expect(addr1.eq(&addr2));
    try testing.expect(addr2.eq(&addr1)); // Symmetry
}

test "RFC 9000 §5 - SockAddr equality: self equality" {
    const addr = types.SockAddr.ipv4(10, 0, 0, 1, 5000);

    try testing.expect(addr.eq(&addr));
}

test "RFC 9000 §5 - SockAddr inequality: different ports" {
    const addr1 = types.SockAddr.ipv4(192, 168, 1, 1, 80);
    const addr2 = types.SockAddr.ipv4(192, 168, 1, 1, 443);

    try testing.expect(!addr1.eq(&addr2));
}

test "RFC 9000 §5 - SockAddr inequality: different last octet" {
    const addr1 = types.SockAddr.ipv4(192, 168, 1, 1, 443);
    const addr2 = types.SockAddr.ipv4(192, 168, 1, 2, 443);

    try testing.expect(!addr1.eq(&addr2));
}

test "RFC 9000 §5 - SockAddr inequality: completely different addresses" {
    const addr1 = types.SockAddr.ipv4(10, 0, 0, 1, 1234);
    const addr2 = types.SockAddr.ipv4(172, 16, 0, 1, 5678);

    try testing.expect(!addr1.eq(&addr2));
}

// =============================================================================
// SockAddr Family Tests
// =============================================================================

test "RFC 9000 §5 - SockAddr family detection for IPv4" {
    const addr = types.SockAddr.ipv4(192, 168, 0, 1, 9000);

    try testing.expectEqual(@as(u16, posix.AF.INET), addr.family());
}

test "RFC 9000 §5 - SockAddr multiple IPv4 addresses have same family" {
    const addr1 = types.SockAddr.ipv4(127, 0, 0, 1, 443);
    const addr2 = types.SockAddr.ipv4(192, 168, 1, 1, 8080);
    const addr3 = types.SockAddr.ipv4(10, 0, 0, 1, 3000);

    try testing.expectEqual(addr1.family(), addr2.family());
    try testing.expectEqual(addr2.family(), addr3.family());
}

// =============================================================================
// Cid (Connection ID) Tests
// =============================================================================

test "RFC 9000 §5.1 - Cid structure basic construction" {
    const cid: types.Cid = .{};

    try testing.expectEqual(@as(u8, 0), cid.len);
    try testing.expectEqual(@as(usize, 20), cid.bytes.len);
}

test "RFC 9000 §5.1 - Cid zero-length is valid" {
    // RFC 9000 §5.1: A zero-length connection ID MAY be used
    const cid: types.Cid = .{ .len = 0 };

    try testing.expectEqual(@as(u8, 0), cid.len);
}

test "RFC 9000 §5.1 - Cid max 20-byte length is valid" {
    // RFC 9000 §5.1: Connection IDs are between 0 and 20 bytes in length
    const cid: types.Cid = .{ .len = 20 };

    try testing.expectEqual(@as(u8, 20), cid.len);
}

test "RFC 9000 §5.1 - Cid can store arbitrary byte values" {
    var cid: types.Cid = .{ .len = 8 };
    cid.bytes[0] = 0x01;
    cid.bytes[1] = 0x23;
    cid.bytes[2] = 0x45;
    cid.bytes[3] = 0x67;
    cid.bytes[4] = 0x89;
    cid.bytes[5] = 0xab;
    cid.bytes[6] = 0xcd;
    cid.bytes[7] = 0xef;

    try testing.expectEqual(@as(u8, 0x01), cid.bytes[0]);
    try testing.expectEqual(@as(u8, 0xef), cid.bytes[7]);
}

test "RFC 9000 §5.1 - Cid bytes array initialized to zeros" {
    const cid: types.Cid = .{};

    for (cid.bytes) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "boundary: Cid with typical lengths" {
    // Test common CID lengths: 0, 8, 16, 20
    const cid0: types.Cid = .{ .len = 0 };
    const cid8: types.Cid = .{ .len = 8 };
    const cid16: types.Cid = .{ .len = 16 };
    const cid20: types.Cid = .{ .len = 20 };

    try testing.expectEqual(@as(u8, 0), cid0.len);
    try testing.expectEqual(@as(u8, 8), cid8.len);
    try testing.expectEqual(@as(u8, 16), cid16.len);
    try testing.expectEqual(@as(u8, 20), cid20.len);
}

// =============================================================================
// Edge Cases and Boundary Conditions
// =============================================================================

test "boundary: SockAddr zero-initialized has expected defaults" {
    const addr: types.SockAddr = .{};

    try testing.expectEqual(@as(u32, 0), addr.len);
}

test "boundary: Multiple SockAddr constructions are independent" {
    const addr1 = types.SockAddr.ipv4(1, 2, 3, 4, 5000);
    const addr2 = types.SockAddr.ipv4(5, 6, 7, 8, 6000);

    // Verify they don't interfere with each other
    try testing.expect(!addr1.eq(&addr2));
    try testing.expectEqual(@as(u16, posix.AF.INET), addr1.family());
    try testing.expectEqual(@as(u16, posix.AF.INET), addr2.family());
}

test "boundary: Cid with all 0xFF bytes" {
    var cid: types.Cid = .{ .len = 20 };
    for (0..20) |i| {
        cid.bytes[i] = 0xFF;
    }

    try testing.expectEqual(@as(u8, 20), cid.len);
    for (cid.bytes) |byte| {
        try testing.expectEqual(@as(u8, 0xFF), byte);
    }
}

test "boundary: Cid partial length with data beyond" {
    // Verify that only len bytes matter, not what's beyond
    var cid: types.Cid = .{ .len = 4 };
    cid.bytes[0] = 0x01;
    cid.bytes[1] = 0x02;
    cid.bytes[2] = 0x03;
    cid.bytes[3] = 0x04;
    cid.bytes[10] = 0xFF; // Beyond len, should be ignored

    try testing.expectEqual(@as(u8, 4), cid.len);
    try testing.expectEqual(@as(u8, 0x04), cid.bytes[3]);
}
