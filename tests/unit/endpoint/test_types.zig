//! Unit tests for endpoint/types.zig
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection Routing
//! - RFC 9002 §6.2: Probe Timeout (PTO)
//! - RFC 9000 §14.2: Path MTU Discovery
//!
//! Coverage:
//! - Positive cases: Timer creation, Key construction, hashing functions
//! - Negative cases: Timer comparison edge cases
//! - Edge cases: Zero deadlines, max values, hash collisions
//! - RFC compliance: Timer kinds align with RFC requirements

const std = @import("std");
const testing = std.testing;
const types = @import("quic_endpoint_types");
const posix = std.posix;
const conn_types = @import("quic_connection_types");
const conn = @import("quic_conn");

// =============================================================================
// Timer Tests
// =============================================================================

test "RFC 9002 §6.2 - Timer structure basic construction" {
    const timer: types.Timer = .{
        .deadline_ms = 1000,
        .id = 1,
    };

    try testing.expectEqual(@as(i64, 1000), timer.deadline_ms);
    try testing.expectEqual(@as(u64, 1), timer.id);
    try testing.expectEqual(types.TimerKind.Generic, timer.kind);
    try testing.expect(timer.conn == null);
    try testing.expect(!timer.paced);
    try testing.expect(timer.payload == null);
}

test "RFC 9002 §6.2 - Timer with zero deadline" {
    const timer: types.Timer = .{
        .deadline_ms = 0,
        .id = 0,
    };

    try testing.expectEqual(@as(i64, 0), timer.deadline_ms);
}

test "RFC 9002 §6.2 - Timer with negative deadline" {
    // Negative deadlines can represent past times or relative offsets
    const timer: types.Timer = .{
        .deadline_ms = -1000,
        .id = 1,
    };

    try testing.expectEqual(@as(i64, -1000), timer.deadline_ms);
}

test "RFC 9002 §6.2 - Timer with max deadline" {
    const max_deadline = std.math.maxInt(i64);
    const timer: types.Timer = .{
        .deadline_ms = max_deadline,
        .id = 1,
    };

    try testing.expectEqual(max_deadline, timer.deadline_ms);
}

test "RFC 9002 §6.2 - Timer deadline ordering" {
    const timer1: types.Timer = .{ .deadline_ms = 100, .id = 1 };
    const timer2: types.Timer = .{ .deadline_ms = 200, .id = 2 };
    const timer3: types.Timer = .{ .deadline_ms = 150, .id = 3 };

    try testing.expect(timer1.deadline_ms < timer2.deadline_ms);
    try testing.expect(timer1.deadline_ms < timer3.deadline_ms);
    try testing.expect(timer3.deadline_ms < timer2.deadline_ms);
}

test "RFC 9002 §6.2 - Timers with same deadline" {
    const timer1: types.Timer = .{ .deadline_ms = 1000, .id = 1 };
    const timer2: types.Timer = .{ .deadline_ms = 1000, .id = 2 };

    try testing.expectEqual(timer1.deadline_ms, timer2.deadline_ms);
    try testing.expect(timer1.id != timer2.id); // IDs distinguish them
}

test "RFC 9002 §6.2 - Timer with pacing enabled" {
    const timer: types.Timer = .{
        .deadline_ms = 500,
        .id = 10,
        .paced = true,
    };

    try testing.expect(timer.paced);
    try testing.expect(timer.payload == null);
}

// =============================================================================
// TimerKind Tests
// =============================================================================

test "RFC 9002 §6.2 - TimerKind all variants" {
    const generic = types.TimerKind.Generic;
    const pto_initial = types.TimerKind.PtoInitial;
    const pto_handshake = types.TimerKind.PtoHandshake;
    const pto_app = types.TimerKind.PtoApp;
    const pmtud = types.TimerKind.Pmtud;

    try testing.expect(generic == .Generic);
    try testing.expect(pto_initial == .PtoInitial);
    try testing.expect(pto_handshake == .PtoHandshake);
    try testing.expect(pto_app == .PtoApp);
    try testing.expect(pmtud == .Pmtud);
}

test "RFC 9002 §6.2 - Timer with PTO kinds" {
    const pto_initial: types.Timer = .{
        .deadline_ms = 1000,
        .id = 1,
        .kind = .PtoInitial,
    };
    const pto_handshake: types.Timer = .{
        .deadline_ms = 2000,
        .id = 2,
        .kind = .PtoHandshake,
    };
    const pto_app: types.Timer = .{
        .deadline_ms = 3000,
        .id = 3,
        .kind = .PtoApp,
    };

    try testing.expect(pto_initial.kind == .PtoInitial);
    try testing.expect(pto_handshake.kind == .PtoHandshake);
    try testing.expect(pto_app.kind == .PtoApp);
}

test "RFC 9000 §14.2 - Timer with PMTUD kind" {
    const pmtud_timer: types.Timer = .{
        .deadline_ms = 5000,
        .id = 100,
        .kind = .Pmtud,
    };

    try testing.expect(pmtud_timer.kind == .Pmtud);
}

// =============================================================================
// Key Tests
// =============================================================================

test "RFC 9000 §5.1 - Key structure basic construction" {
    const key: types.Key = .{
        .peer_hash = 0x1234567890abcdef,
        .dcid_hash = 0xfedcba0987654321,
    };

    try testing.expectEqual(@as(u64, 0x1234567890abcdef), key.peer_hash);
    try testing.expectEqual(@as(u64, 0xfedcba0987654321), key.dcid_hash);
}

test "RFC 9000 §5.1 - Key with zero hashes" {
    const key: types.Key = .{
        .peer_hash = 0,
        .dcid_hash = 0,
    };

    try testing.expectEqual(@as(u64, 0), key.peer_hash);
    try testing.expectEqual(@as(u64, 0), key.dcid_hash);
}

test "RFC 9000 §5.1 - Key with max hashes" {
    const max_hash = std.math.maxInt(u64);
    const key: types.Key = .{
        .peer_hash = max_hash,
        .dcid_hash = max_hash,
    };

    try testing.expectEqual(max_hash, key.peer_hash);
    try testing.expectEqual(max_hash, key.dcid_hash);
}

test "RFC 9000 §5.1 - Different Keys are distinguishable" {
    const key1: types.Key = .{ .peer_hash = 1, .dcid_hash = 2 };
    const key2: types.Key = .{ .peer_hash = 3, .dcid_hash = 4 };

    try testing.expect(key1.peer_hash != key2.peer_hash);
    try testing.expect(key1.dcid_hash != key2.dcid_hash);
}

// =============================================================================
// EndpointRole Tests
// =============================================================================

test "RFC 9000 §5.1 - EndpointRole basic usage" {
    const client = types.EndpointRole.Client;
    const server = types.EndpointRole.Server;

    try testing.expect(client == .Client);
    try testing.expect(server == .Server);
    try testing.expect(client != server);
}

// =============================================================================
// Hash Function Tests
// =============================================================================

test "RFC 9000 §5.1 - hashBytes with empty slice" {
    const empty: []const u8 = &[_]u8{};
    const hash = types.hashBytes(empty);

    // Hash of empty should be deterministic
    const hash2 = types.hashBytes(empty);
    try testing.expectEqual(hash, hash2);
}

test "RFC 9000 §5.1 - hashBytes with single byte" {
    const data = [_]u8{0x42};
    const hash = types.hashBytes(&data);

    // Should produce non-zero hash
    try testing.expect(hash != 0);
}

test "RFC 9000 §5.1 - hashBytes is deterministic" {
    const data = [_]u8{ 1, 2, 3, 4, 5 };
    const hash1 = types.hashBytes(&data);
    const hash2 = types.hashBytes(&data);

    try testing.expectEqual(hash1, hash2);
}

test "RFC 9000 §5.1 - hashBytes different inputs produce different hashes" {
    const data1 = [_]u8{ 1, 2, 3 };
    const data2 = [_]u8{ 4, 5, 6 };
    const hash1 = types.hashBytes(&data1);
    const hash2 = types.hashBytes(&data2);

    // Hashes should be different (with overwhelming probability)
    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.1 - hashBytes order matters" {
    const data1 = [_]u8{ 1, 2, 3 };
    const data2 = [_]u8{ 3, 2, 1 };
    const hash1 = types.hashBytes(&data1);
    const hash2 = types.hashBytes(&data2);

    // Different order should produce different hash
    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.1 - hashBytes with longer data" {
    const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const hash = types.hashBytes(&data);

    // Should handle longer data correctly
    const hash2 = types.hashBytes(&data);
    try testing.expectEqual(hash, hash2);
}

test "boundary: hashBytes with max single byte value" {
    const data = [_]u8{0xFF};
    const hash = types.hashBytes(&data);

    try testing.expect(hash != 0);
}

test "boundary: hashBytes with all zeros" {
    const data = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const hash = types.hashBytes(&data);

    // Even all zeros should produce a hash
    const hash2 = types.hashBytes(&data);
    try testing.expectEqual(hash, hash2);
}

test "boundary: hashBytes with all 0xFF" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const hash = types.hashBytes(&data);

    const hash2 = types.hashBytes(&data);
    try testing.expectEqual(hash, hash2);
}

// =============================================================================
// hashSockaddr Tests
// =============================================================================

test "RFC 9000 §5.1 - hashSockaddr with IPv4 address" {
    const addr = conn.SockAddr.ipv4(192, 168, 1, 1, 443);
    const hash = types.hashSockaddr(&addr.storage, addr.len);

    // Should produce a hash
    try testing.expect(hash != 0);

    // Should be deterministic
    const hash2 = types.hashSockaddr(&addr.storage, addr.len);
    try testing.expectEqual(hash, hash2);
}

test "RFC 9000 §5.1 - hashSockaddr different addresses produce different hashes" {
    const addr1 = conn.SockAddr.ipv4(192, 168, 1, 1, 443);
    const addr2 = conn.SockAddr.ipv4(192, 168, 1, 2, 443);

    const hash1 = types.hashSockaddr(&addr1.storage, addr1.len);
    const hash2 = types.hashSockaddr(&addr2.storage, addr2.len);

    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.1 - hashSockaddr different ports produce different hashes" {
    const addr1 = conn.SockAddr.ipv4(127, 0, 0, 1, 443);
    const addr2 = conn.SockAddr.ipv4(127, 0, 0, 1, 8443);

    const hash1 = types.hashSockaddr(&addr1.storage, addr1.len);
    const hash2 = types.hashSockaddr(&addr2.storage, addr2.len);

    try testing.expect(hash1 != hash2);
}

test "RFC 9000 §5.1 - hashSockaddr same address produces same hash" {
    const addr = conn.SockAddr.ipv4(10, 0, 0, 1, 9000);

    const hash1 = types.hashSockaddr(&addr.storage, addr.len);
    const hash2 = types.hashSockaddr(&addr.storage, addr.len);

    try testing.expectEqual(hash1, hash2);
}

// =============================================================================
// normalizeAddr Tests
// =============================================================================

test "RFC 9000 §5.1 - normalizeAddr with regular IPv4" {
    const addr = conn.SockAddr.ipv4(192, 168, 1, 100, 8080);
    const normalized = types.normalizeAddr(&addr.storage, addr.len);

    // Should be unchanged
    try testing.expectEqual(addr.family(), normalized.family());
    try testing.expect(addr.eq(&normalized));
}

test "RFC 9000 §5.1 - normalizeAddr multiple calls are consistent" {
    const addr = conn.SockAddr.ipv4(10, 0, 0, 1, 5000);
    const norm1 = types.normalizeAddr(&addr.storage, addr.len);
    const norm2 = types.normalizeAddr(&addr.storage, addr.len);

    try testing.expect(norm1.eq(&norm2));
}

// =============================================================================
// Edge Cases and Boundary Conditions
// =============================================================================

test "boundary: Timer ID uniqueness" {
    const timer1: types.Timer = .{ .deadline_ms = 1000, .id = 0 };
    const timer2: types.Timer = .{ .deadline_ms = 1000, .id = 1 };
    const timer3: types.Timer = .{ .deadline_ms = 1000, .id = std.math.maxInt(u64) };

    try testing.expect(timer1.id != timer2.id);
    try testing.expect(timer2.id != timer3.id);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), timer3.id);
}

test "boundary: Timer deadline range coverage" {
    const min_timer: types.Timer = .{ .deadline_ms = std.math.minInt(i64), .id = 1 };
    const zero_timer: types.Timer = .{ .deadline_ms = 0, .id = 2 };
    const max_timer: types.Timer = .{ .deadline_ms = std.math.maxInt(i64), .id = 3 };

    try testing.expectEqual(std.math.minInt(i64), min_timer.deadline_ms);
    try testing.expectEqual(@as(i64, 0), zero_timer.deadline_ms);
    try testing.expectEqual(std.math.maxInt(i64), max_timer.deadline_ms);
}

test "boundary: Key hash value full range" {
    const zero_key: types.Key = .{ .peer_hash = 0, .dcid_hash = 0 };
    const mid_key: types.Key = .{ .peer_hash = 0x8000000000000000, .dcid_hash = 0x8000000000000000 };
    const max_key: types.Key = .{ .peer_hash = std.math.maxInt(u64), .dcid_hash = std.math.maxInt(u64) };

    try testing.expectEqual(@as(u64, 0), zero_key.peer_hash);
    try testing.expectEqual(@as(u64, 0x8000000000000000), mid_key.peer_hash);
    try testing.expectEqual(std.math.maxInt(u64), max_key.peer_hash);
}
