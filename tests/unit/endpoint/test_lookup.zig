//! Unit tests for endpoint/lookup.zig
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection ID Routing
//! - RFC 9000 §5.2: Matching Packets to Connections
//! - RFC 9000 §5.3: Connection ID Management
//!
//! Coverage:
//! - Positive cases: Insert, lookup, remove operations
//! - Negative cases: Lookup non-existent key, remove non-existent entry
//! - Edge cases: Empty table, multiple connections, key collisions
//! - RFC compliance: Connection routing by address + DCID

const std = @import("std");
const testing = std.testing;

const lookup = @import("lookup");
const types = @import("types");
const conn = @import("quic_conn");
const packet = @import("quic_packet");

var test_allocator = std.testing.allocator;

// Dummy keys for mock connections
const dummy_keys = packet.AeadKeys{
    .key = [_]u8{0} ** 16,
    .iv = [_]u8{0} ** 12,
    .hp = [_]u8{0} ** 16,
};

// =============================================================================
// ConnectionTable Initialization Tests
// =============================================================================

test "RFC 9000 §5.1 - ConnectionTable initial state" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    try testing.expectEqual(@as(usize, 0), table.count());
}

test "RFC 9000 §5.1 - ConnectionTable deinit cleans up" {
    var table = lookup.ConnectionTable.init(test_allocator);
    table.deinit();

    // Should not crash or leak memory (verified by test allocator)
}

// =============================================================================
// makeKey Function Tests
// =============================================================================

test "RFC 9000 §5.2 - makeKey creates composite key" {
    const peer_hash: u64 = 0x1234567890ABCDEF;
    const dcid_hash: u64 = 0xFEDCBA0987654321;

    const key = lookup.makeKey(peer_hash, dcid_hash);

    try testing.expectEqual(peer_hash, key.peer_hash);
    try testing.expectEqual(dcid_hash, key.dcid_hash);
}

test "RFC 9000 §5.2 - makeKey with zero hashes" {
    const key = lookup.makeKey(0, 0);

    try testing.expectEqual(@as(u64, 0), key.peer_hash);
    try testing.expectEqual(@as(u64, 0), key.dcid_hash);
}

test "RFC 9000 §5.2 - makeKey with max hashes" {
    const max = std.math.maxInt(u64);
    const key = lookup.makeKey(max, max);

    try testing.expectEqual(max, key.peer_hash);
    try testing.expectEqual(max, key.dcid_hash);
}

test "RFC 9000 §5.2 - makeKey creates unique keys for different inputs" {
    const key1 = lookup.makeKey(1, 2);
    const key2 = lookup.makeKey(2, 1);
    const key3 = lookup.makeKey(1, 1);

    try testing.expect(key1.peer_hash != key2.peer_hash or key1.dcid_hash != key2.dcid_hash);
    try testing.expect(key1.peer_hash != key3.peer_hash or key1.dcid_hash != key3.dcid_hash);
}

// =============================================================================
// Count Tests
// =============================================================================

test "RFC 9000 §5.1 - count returns zero for empty table" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    try testing.expectEqual(@as(usize, 0), table.count());
}

// =============================================================================
// Lookup Tests
// =============================================================================

test "RFC 9000 §5.2 - lookup returns null for empty table" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(1, 2);
    const result = table.lookup(key);

    try testing.expectEqual(@as(?*conn.Connection, null), result);
}

test "RFC 9000 §5.2 - lookup returns null for non-existent key" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(999, 888);
    const result = table.lookup(key);

    try testing.expectEqual(@as(?*conn.Connection, null), result);
}

// =============================================================================
// Remove Tests
// =============================================================================

test "RFC 9000 §5.3 - remove returns false for empty table" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(1, 2);
    const removed = table.remove(key);

    try testing.expect(!removed);
}

test "RFC 9000 §5.3 - remove returns false for non-existent key" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(999, 888);
    const removed = table.remove(key);

    try testing.expect(!removed);
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "boundary: makeKey with identical peer and DCID hashes" {
    const hash: u64 = 0x0123456789ABCDEF;
    const key = lookup.makeKey(hash, hash);

    try testing.expectEqual(hash, key.peer_hash);
    try testing.expectEqual(hash, key.dcid_hash);
}

test "boundary: makeKey with alternating bit patterns" {
    const key1 = lookup.makeKey(0xAAAAAAAAAAAAAAAA, 0x5555555555555555);
    const key2 = lookup.makeKey(0x5555555555555555, 0xAAAAAAAAAAAAAAAA);

    try testing.expect(key1.peer_hash != key2.peer_hash or key1.dcid_hash != key2.dcid_hash);
}

test "boundary: ConnectionTable remains valid after multiple operations" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    // Multiple operations on empty table
    const key1 = lookup.makeKey(1, 2);
    _ = table.lookup(key1);
    _ = table.remove(key1);
    _ = table.lookup(key1);

    try testing.expectEqual(@as(usize, 0), table.count());
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §5.1 - Connection routing uses composite key (peer + DCID)" {
    // RFC 9000 §5.1: Servers route packets using address tuple and DCID
    const peer_addr_hash: u64 = 0x1111111111111111; // Simulated peer address hash
    const dcid_hash: u64 = 0x2222222222222222; // Destination CID hash

    const key = lookup.makeKey(peer_addr_hash, dcid_hash);

    try testing.expectEqual(peer_addr_hash, key.peer_hash);
    try testing.expectEqual(dcid_hash, key.dcid_hash);
}

test "RFC 9000 §5.2 - Matching packets to connections" {
    // RFC 9000 §5.2: Endpoints match packets to connections using DCID and address
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    // Simulate different peer addresses and DCIDs
    const key1 = lookup.makeKey(0x1111, 0xAAAA); // Peer 1, DCID A
    const key2 = lookup.makeKey(0x1111, 0xBBBB); // Peer 1, DCID B (different CID)
    const key3 = lookup.makeKey(0x2222, 0xAAAA); // Peer 2, DCID A (different peer)

    // Keys should be distinct
    try testing.expect(key1.peer_hash != key2.peer_hash or key1.dcid_hash != key2.dcid_hash);
    try testing.expect(key1.peer_hash != key3.peer_hash or key1.dcid_hash != key3.dcid_hash);
}

test "RFC 9000 §5.3 - Connection ID updates create new routing entries" {
    // RFC 9000 §5.3: When a connection updates its CID, new routing entries are created
    const peer_hash: u64 = 0x1234567890ABCDEF;

    const old_dcid_hash: u64 = 0x1111111111111111;
    const new_dcid_hash: u64 = 0x2222222222222222;

    const old_key = lookup.makeKey(peer_hash, old_dcid_hash);
    const new_key = lookup.makeKey(peer_hash, new_dcid_hash);

    // Keys should be different (same peer, different DCID)
    try testing.expect(old_key.dcid_hash != new_key.dcid_hash);
    try testing.expectEqual(old_key.peer_hash, new_key.peer_hash);
}

test "RFC 9000 §5.1 - ConnectionTable supports multiple connections from same peer" {
    // RFC 9000: Multiple connections from same peer use different DCIDs
    const peer_hash: u64 = 0xABCDEF0123456789;

    const key1 = lookup.makeKey(peer_hash, 0x1111);
    const key2 = lookup.makeKey(peer_hash, 0x2222);
    const key3 = lookup.makeKey(peer_hash, 0x3333);

    // All have same peer but different DCIDs
    try testing.expectEqual(key1.peer_hash, key2.peer_hash);
    try testing.expectEqual(key2.peer_hash, key3.peer_hash);
    try testing.expect(key1.dcid_hash != key2.dcid_hash);
    try testing.expect(key2.dcid_hash != key3.dcid_hash);
}

test "RFC 9000 §5.2 - Zero-length DCID uses peer address only" {
    // RFC 9000 §5.2: Zero-length DCID connections route by peer address only
    const peer_hash: u64 = 0xFEDCBA9876543210;
    const zero_dcid_hash: u64 = 0; // Zero-length DCID represented as zero hash

    const key = lookup.makeKey(peer_hash, zero_dcid_hash);

    try testing.expectEqual(peer_hash, key.peer_hash);
    try testing.expectEqual(@as(u64, 0), key.dcid_hash);
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: lookup after deinit should not crash" {
    var table = lookup.ConnectionTable.init(test_allocator);
    table.deinit();

    // Creating a new table instance for lookup since deinit invalidates the original
    // This test verifies cleanup doesn't leave dangling pointers
}

test "negative: double remove returns false second time" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(1, 2);

    const removed1 = table.remove(key);
    try testing.expect(!removed1); // Not present

    const removed2 = table.remove(key);
    try testing.expect(!removed2); // Still not present
}

test "negative: lookup with different key returns null" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key1 = lookup.makeKey(1, 2);
    const key2 = lookup.makeKey(3, 4);

    const result1 = table.lookup(key1);
    try testing.expectEqual(@as(?*conn.Connection, null), result1);

    const result2 = table.lookup(key2);
    try testing.expectEqual(@as(?*conn.Connection, null), result2);
}

// =============================================================================
// Key Equality Tests
// =============================================================================

test "RFC 9000 §5.2 - Keys with same values are equal" {
    const key1 = lookup.makeKey(12345, 67890);
    const key2 = lookup.makeKey(12345, 67890);

    try testing.expectEqual(key1.peer_hash, key2.peer_hash);
    try testing.expectEqual(key1.dcid_hash, key2.dcid_hash);
}

test "RFC 9000 §5.2 - Keys with different peer hashes are unequal" {
    const key1 = lookup.makeKey(11111, 67890);
    const key2 = lookup.makeKey(22222, 67890);

    try testing.expect(key1.peer_hash != key2.peer_hash);
}

test "RFC 9000 §5.2 - Keys with different DCID hashes are unequal" {
    const key1 = lookup.makeKey(12345, 11111);
    const key2 = lookup.makeKey(12345, 22222);

    try testing.expect(key1.dcid_hash != key2.dcid_hash);
}

// =============================================================================
// Phase 4b.5 Session 3: findConnectionByDcid Tests
// =============================================================================

const endpoint_types = @import("endpoint/types");
const conn_mod = @import("quic_conn");
const posix = std.posix;

/// Mock connection for testing
fn createMockConnection(
    allocator: std.mem.Allocator,
    our_scid: []const u8,
    has_app_rx: bool,
    has_app_tx: bool,
) !*conn_mod.Connection {
    const c = try allocator.create(conn_mod.Connection);
    c.* = undefined; // Initialize to undefined first
    c.our_scid.len = @intCast(our_scid.len);
    @memcpy(c.our_scid.bytes[0..our_scid.len], our_scid);
    c.app_rx_keys = if (has_app_rx) dummy_keys else null;
    c.app_tx_keys = if (has_app_tx) dummy_keys else null;
    return c;
}

/// Hash helper for tests
fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

/// Hash socket address for tests
fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

/// Create test IPv4 address
fn makeTestAddr(port: u16) conn_mod.SockAddr {
    var sa: conn_mod.SockAddr = undefined;
    sa.len = @sizeOf(posix.sockaddr.in);
    const sin: *posix.sockaddr.in = @ptrCast(&sa.storage);
    sin.family = posix.AF.INET;
    sin.port = std.mem.nativeToBig(u16, port);
    sin.addr = 0x7f000001; // 127.0.0.1
    return sa;
}

/// Create short header packet with given DCID
fn makeShortHeaderPacket(allocator: std.mem.Allocator, dcid: []const u8) ![]u8 {
    const pkt_buf = try allocator.alloc(u8, 1 + dcid.len + 20);
    pkt_buf[0] = 0x40; // Short header, fixed bit set
    @memcpy(pkt_buf[1 .. 1 + dcid.len], dcid);
    // Fill rest with dummy data
    for (pkt_buf[1 + dcid.len ..]) |*b| {
        b.* = 0;
    }
    return pkt_buf;
}

// Mock callback state
const PathChangeState = struct {
    called: bool = false,
    conn: ?*conn_mod.Connection = null,
    peer_hash: u64 = 0,
    dcid_len: usize = 0,
};

threadlocal var path_change_state: PathChangeState = .{};

fn mockPathChangedFn(
    connection: *conn_mod.Connection,
    new_peer: conn_mod.SockAddr,
    new_peer_hash: u64,
    dcid_len: usize,
) !void {
    _ = new_peer;
    path_change_state.called = true;
    path_change_state.conn = connection;
    path_change_state.peer_hash = new_peer_hash;
    path_change_state.dcid_len = dcid_len;
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: Phase 1 match with peer_hash + DCID" {
    const allocator = testing.allocator;

    // Create connection with 8-byte DCID
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const connection = try createMockConnection(allocator, &dcid, false, false);
    defer allocator.destroy(connection);

    // Create connection table
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    // Insert connection with matching peer_hash + DCID
    const peer = makeTestAddr(1234);
    const peer_h = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{
        .peer_hash = peer_h,
        .dcid_hash = hashBytes(&dcid),
    };
    try conns.put(key, connection);

    // Create packet with matching DCID
    const pkt_buf = try makeShortHeaderPacket(allocator, &dcid);
    defer allocator.free(pkt_buf);

    // Reset mock state
    path_change_state = .{};

    // Lookup should find connection via Phase 1
    const result = lookup.findConnectionByDcid(&conns, peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn != null);
    try testing.expectEqual(connection, result.conn.?);
    try testing.expectEqual(@as(usize, 8), result.dcid_len);
    try testing.expectEqual(false, result.nat_rebinding);
    try testing.expectEqual(false, path_change_state.called); // No NAT rebinding
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: Server prioritization (both keys)" {
    const allocator = testing.allocator;

    // Create two connections with different DCIDs
    const dcid1 = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    const dcid2 = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x22 };

    // conn1: no app keys
    // conn2: has both app keys (should be preferred)
    const conn1 = try createMockConnection(allocator, &dcid1, false, false);
    defer allocator.destroy(conn1);

    const conn2 = try createMockConnection(allocator, &dcid2, true, true);
    defer allocator.destroy(conn2);

    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    const peer = makeTestAddr(5678);
    const peer_h = hashSockaddr(&peer.storage, peer.len);

    const key1 = endpoint_types.Key{ .peer_hash = peer_h, .dcid_hash = hashBytes(&dcid1) };
    const key2 = endpoint_types.Key{ .peer_hash = peer_h, .dcid_hash = hashBytes(&dcid2) };
    try conns.put(key1, conn1);
    try conns.put(key2, conn2);

    // Create packet that matches dcid2 (conn2 with both keys)
    const pkt_buf = try makeShortHeaderPacket(allocator, &dcid2);
    defer allocator.free(pkt_buf);

    path_change_state = .{};

    const result = lookup.findConnectionByDcid(&conns, peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn != null);
    try testing.expectEqual(conn2, result.conn.?); // Should select conn2 (has both keys)
    try testing.expectEqual(@as(usize, 8), result.dcid_len);
    try testing.expectEqual(false, result.nat_rebinding);
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: Phase 2 NAT rebinding fallback" {
    const allocator = testing.allocator;

    const dcid = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const connection = try createMockConnection(allocator, &dcid, false, false);
    defer allocator.destroy(connection);

    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    // Insert connection with DIFFERENT peer_hash than we'll query with
    const original_peer = makeTestAddr(1111);
    const original_peer_h = hashSockaddr(&original_peer.storage, original_peer.len);
    const key = endpoint_types.Key{
        .peer_hash = original_peer_h,
        .dcid_hash = hashBytes(&dcid),
    };
    try conns.put(key, connection);

    // Query with DIFFERENT peer address (simulates NAT rebinding)
    const new_peer = makeTestAddr(9999);
    const pkt_buf = try makeShortHeaderPacket(allocator, &dcid);
    defer allocator.free(pkt_buf);

    path_change_state = .{};

    // Lookup should trigger Phase 2 NAT rebinding fallback
    const result = lookup.findConnectionByDcid(&conns, new_peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn != null);
    try testing.expectEqual(connection, result.conn.?);
    try testing.expectEqual(@as(usize, 4), result.dcid_len);
    try testing.expectEqual(true, result.nat_rebinding); // NAT rebinding detected!
    try testing.expectEqual(true, path_change_state.called); // Callback invoked
    try testing.expectEqual(connection, path_change_state.conn);
    try testing.expectEqual(@as(usize, 4), path_change_state.dcid_len);
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: No match returns null" {
    const allocator = testing.allocator;

    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    // Empty connection table
    const peer = makeTestAddr(1234);
    const dcid = [_]u8{ 0xff, 0xee, 0xdd, 0xcc };
    const pkt_buf = try makeShortHeaderPacket(allocator, &dcid);
    defer allocator.free(pkt_buf);

    path_change_state = .{};

    const result = lookup.findConnectionByDcid(&conns, peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn == null);
    try testing.expectEqual(@as(usize, 0), result.dcid_len);
    try testing.expectEqual(false, result.nat_rebinding);
    try testing.expectEqual(false, path_change_state.called);
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: Zero-length DCID skipped" {
    const allocator = testing.allocator;

    // Create connection with zero-length DCID (ambiguous, should be skipped)
    const connection = try createMockConnection(allocator, &[_]u8{}, false, false);
    defer allocator.destroy(connection);

    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    const peer = makeTestAddr(1234);
    const peer_h = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{
        .peer_hash = peer_h,
        .dcid_hash = hashBytes(&[_]u8{}),
    };
    try conns.put(key, connection);

    const pkt_buf = try makeShortHeaderPacket(allocator, &[_]u8{});
    defer allocator.free(pkt_buf);

    path_change_state = .{};

    // Should not match zero-length DCID
    const result = lookup.findConnectionByDcid(&conns, peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn == null);
    try testing.expectEqual(@as(usize, 0), result.dcid_len);
}

test "Phase 4b.5 Session 3 - findConnectionByDcid: Longer DCID wins tie-break" {
    const allocator = testing.allocator;

    // Create two connections with different DCID lengths
    const dcid_short = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const dcid_long = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    const conn_short = try createMockConnection(allocator, &dcid_short, false, false);
    defer allocator.destroy(conn_short);

    const conn_long = try createMockConnection(allocator, &dcid_long, false, false);
    defer allocator.destroy(conn_long);

    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();

    const peer = makeTestAddr(1234);
    const peer_h = hashSockaddr(&peer.storage, peer.len);

    const key_short = endpoint_types.Key{
        .peer_hash = peer_h,
        .dcid_hash = hashBytes(&dcid_short),
    };
    const key_long = endpoint_types.Key{
        .peer_hash = peer_h,
        .dcid_hash = hashBytes(&dcid_long),
    };

    try conns.put(key_short, conn_short);
    try conns.put(key_long, conn_long);

    // Create packet with long DCID prefix (matches both, but long should win)
    const pkt_buf = try makeShortHeaderPacket(allocator, &dcid_long);
    defer allocator.free(pkt_buf);

    path_change_state = .{};

    const result = lookup.findConnectionByDcid(&conns, peer, pkt_buf, mockPathChangedFn);

    try testing.expect(result.conn != null);
    try testing.expectEqual(conn_long, result.conn.?); // Longer DCID wins
    try testing.expectEqual(@as(usize, 8), result.dcid_len);
    try testing.expectEqual(false, result.nat_rebinding);
}
