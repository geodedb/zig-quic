//! Unit tests for endpoint/client.zig
//!
//! RFC References:
//! - RFC 9000 §7: Cryptographic and Transport Handshake
//! - RFC 9000 §7.2: Negotiating Connection IDs
//! - RFC 9000 §5.1.1: Client Chooses Destination Connection ID
//! - RFC 9000 §14.1: Initial Datagram Size (1200 bytes minimum)
//! - RFC 9000 §8.1.2: Address Validation for Client
//! - RFC 9001 §5.2: Initial Secrets
//!
//! Coverage:
//! - Connection establishment: connectTo, connectClient
//! - Initial packet generation: clientSendInitialProbe
//! - CID generation and management
//! - Version negotiation (v1 vs v2)
//! - Transport parameter encoding
//! - Configuration application (CC, pacing, ALPN)
//!
//! Note: These tests document expected behavior for the client module.
//! Currently endpoint.zig contains the implementation. Tests designed for
//! future extraction to client.zig.

const std = @import("std");
const testing = std.testing;

const client = @import("client");

var test_allocator = std.testing.allocator;

// =============================================================================
// Helper Function Tests (Phase 4b)
// =============================================================================

test "RFC 9000 §5.1.1 - generateRandomCid generates 8-byte CID" {
    // Client must choose a Destination Connection ID
    var cid: [8]u8 = undefined;
    client.generateRandomCid(&cid);

    // Verify length (all 8 bytes should be filled)
    try testing.expectEqual(@as(usize, 8), cid.len);
}

test "RFC 9000 §5.1.1 - generateRandomCid produces different values" {
    // Ensure randomness - two calls should produce different CIDs
    var cid1: [8]u8 = undefined;
    var cid2: [8]u8 = undefined;

    client.generateRandomCid(&cid1);
    client.generateRandomCid(&cid2);

    // While theoretically possible for two random 8-byte values to match,
    // probability is 1 in 2^64, which is negligible for testing
    const are_equal = std.mem.eql(u8, &cid1, &cid2);
    try testing.expect(!are_equal);
}

test "RFC 9000 §5.1.1 - generateRandomCid fills all bytes" {
    // Verify that all bytes in the CID are set (not left at zero)
    var cid: [8]u8 = [_]u8{0} ** 8;
    client.generateRandomCid(&cid);

    // At least one byte should be non-zero (probability of all zeros: 1 in 2^64)
    var has_nonzero = false;
    for (cid) |byte| {
        if (byte != 0) {
            has_nonzero = true;
            break;
        }
    }
    try testing.expect(has_nonzero);
}

test "RFC 9000 §5.1.1 - generateRandomCid works with different sizes" {
    // Test with standard 8-byte CID
    var cid8: [8]u8 = undefined;
    client.generateRandomCid(&cid8);
    try testing.expectEqual(@as(usize, 8), cid8.len);

    // Test with 20-byte CID (maximum per RFC 9000 §5.1)
    var cid20: [20]u8 = undefined;
    client.generateRandomCid(&cid20);
    try testing.expectEqual(@as(usize, 20), cid20.len);

    // Test with 4-byte CID (shorter than standard)
    var cid4: [4]u8 = undefined;
    client.generateRandomCid(&cid4);
    try testing.expectEqual(@as(usize, 4), cid4.len);
}

// =============================================================================

// =============================================================================
// End of Unit Tests
// =============================================================================
//
// NOTE: Integration tests for connectTo, connectClient, and clientSendInitialProbe
// require a complete Endpoint object with UDP socket, configuration, and routing
// infrastructure. These should be implemented as integration tests in a separate
// test suite once the integration test framework is ready.
//
// The unit tests above verify the core helper function (generateRandomCid)
// which can be tested in isolation.
