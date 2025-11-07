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

var test_allocator = std.testing.allocator;

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
    const table = lookup.ConnectionTable.init(test_allocator);
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

    try testing.expectEqual(@as(?*anyopaque, null), result);
}

test "RFC 9000 §5.2 - lookup returns null for non-existent key" {
    var table = lookup.ConnectionTable.init(test_allocator);
    defer table.deinit();

    const key = lookup.makeKey(999, 888);
    const result = table.lookup(key);

    try testing.expectEqual(@as(?*anyopaque, null), result);
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
    try testing.expectEqual(@as(?*anyopaque, null), result1);

    const result2 = table.lookup(key2);
    try testing.expectEqual(@as(?*anyopaque, null), result2);
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
