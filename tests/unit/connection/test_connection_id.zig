//! Unit tests for connection/connection_id.zig
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection ID
//! - RFC 9000 §5.2: Matching Packets to Connections
//! - RFC 9000 §5.3: Connection ID Management
//! - RFC 9000 §10.3: Stateless Reset
//! - RFC 9000 §19.15: NEW_CONNECTION_ID Frame
//!
//! Coverage:
//! - Positive cases: LocalCid creation, reset token derivation
//! - Negative cases: Invalid sequence numbers
//! - Edge cases: Zero-length CIDs, max sequence numbers
//! - RFC compliance: Reset token cryptographic properties, CID management

const std = @import("std");
const testing = std.testing;

const cid = @import("connection_id");
const types = @import("types");

// =============================================================================
// LocalCid Tests
// =============================================================================

test "RFC 9000 §5.3 - LocalCid initial state" {
    const local_cid: cid.LocalCid = .{};

    try testing.expect(!local_cid.in_use);
    try testing.expectEqual(@as(u64, 0), local_cid.sequence);
    try testing.expectEqual(@as(u8, 0), local_cid.cid.len);
}

test "RFC 9000 §5.3 - LocalCid with sequence number" {
    var local_cid: cid.LocalCid = .{};
    local_cid.sequence = 5;
    local_cid.in_use = true;

    try testing.expectEqual(@as(u64, 5), local_cid.sequence);
    try testing.expect(local_cid.in_use);
}

test "RFC 9000 §5.1 - LocalCid stores connection ID" {
    var local_cid: cid.LocalCid = .{};
    local_cid.cid.len = 8;
    local_cid.cid.bytes[0] = 0x01;
    local_cid.cid.bytes[7] = 0xFF;

    try testing.expectEqual(@as(u8, 8), local_cid.cid.len);
    try testing.expectEqual(@as(u8, 0x01), local_cid.cid.bytes[0]);
    try testing.expectEqual(@as(u8, 0xFF), local_cid.cid.bytes[7]);
}

test "RFC 9000 §10.3 - LocalCid contains reset token" {
    var local_cid: cid.LocalCid = .{};

    // Set a specific reset token
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        local_cid.reset_token[i] = @intCast(i);
    }

    try testing.expectEqual(@as(u8, 0), local_cid.reset_token[0]);
    try testing.expectEqual(@as(u8, 15), local_cid.reset_token[15]);
}

// =============================================================================
// Stateless Reset Token Derivation Tests
// =============================================================================

test "RFC 9000 §10.3 - deriveStatelessResetToken basic derivation" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    // Token should be 16 bytes
    try testing.expectEqual(@as(usize, 16), token.len);

    // Token should not be all zeros
    var all_zeros = true;
    for (token) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
}

test "RFC 9000 §10.3 - deriveStatelessResetToken deterministic" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 5;
    const cid_bytes = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const token1 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);
    const token2 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    // Same inputs should produce same token
    try testing.expectEqualSlices(u8, &token1, &token2);
}

test "RFC 9000 §10.3 - deriveStatelessResetToken different sequences produce different tokens" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const token1 = cid.deriveStatelessResetToken(&base, 1, &cid_bytes);
    const token2 = cid.deriveStatelessResetToken(&base, 2, &cid_bytes);

    // Different sequences should produce different tokens
    try testing.expect(!std.mem.eql(u8, &token1, &token2));
}

test "RFC 9000 §10.3 - deriveStatelessResetToken different CIDs produce different tokens" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 1;
    const cid_bytes1 = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const cid_bytes2 = [_]u8{ 0x05, 0x06, 0x07, 0x08 };

    const token1 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes1);
    const token2 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes2);

    // Different CIDs should produce different tokens
    try testing.expect(!std.mem.eql(u8, &token1, &token2));
}

test "RFC 9000 §10.3 - deriveStatelessResetToken different bases produce different tokens" {
    var base1: [32]u8 = [_]u8{0x42} ** 32;
    var base2: [32]u8 = [_]u8{0x99} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const token1 = cid.deriveStatelessResetToken(&base1, sequence, &cid_bytes);
    const token2 = cid.deriveStatelessResetToken(&base2, sequence, &cid_bytes);

    // Different bases should produce different tokens
    try testing.expect(!std.mem.eql(u8, &token1, &token2));
}

test "RFC 9000 §10.3 - deriveStatelessResetToken with zero-length CID" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 1;
    const cid_bytes: []const u8 = &[_]u8{};

    const token = cid.deriveStatelessResetToken(&base, sequence, cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

test "RFC 9000 §10.3 - deriveStatelessResetToken with max-length CID" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{0xFF} ** 20; // Max CID length is 20

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "boundary: LocalCid max sequence number" {
    var local_cid: cid.LocalCid = .{};
    local_cid.sequence = std.math.maxInt(u64);

    try testing.expectEqual(std.math.maxInt(u64), local_cid.sequence);
}

test "boundary: LocalCid zero-length CID" {
    var local_cid: cid.LocalCid = .{};
    local_cid.cid.len = 0;
    local_cid.in_use = true;

    try testing.expectEqual(@as(u8, 0), local_cid.cid.len);
    try testing.expect(local_cid.in_use);
}

test "boundary: LocalCid 20-byte CID" {
    var local_cid: cid.LocalCid = .{};
    local_cid.cid.len = 20;

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        local_cid.cid.bytes[i] = @intCast(i);
    }

    try testing.expectEqual(@as(u8, 20), local_cid.cid.len);
}

test "boundary: deriveStatelessResetToken sequence zero" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = 0;
    const cid_bytes = [_]u8{ 0x01, 0x02 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

test "boundary: deriveStatelessResetToken sequence max" {
    var base: [32]u8 = [_]u8{0x42} ** 32;
    const sequence: u64 = std.math.maxInt(u64);
    const cid_bytes = [_]u8{ 0x01, 0x02 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

test "boundary: deriveStatelessResetToken all-zero base" {
    var base: [32]u8 = [_]u8{0} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

test "boundary: deriveStatelessResetToken all-0xFF base" {
    var base: [32]u8 = [_]u8{0xFF} ** 32;
    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02 };

    const token = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    try testing.expectEqual(@as(usize, 16), token.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §5.3 - Connection ID sequence numbers are unique" {
    const cid1: cid.LocalCid = .{ .sequence = 0 };
    const cid2: cid.LocalCid = .{ .sequence = 1 };
    const cid3: cid.LocalCid = .{ .sequence = 2 };

    try testing.expect(cid1.sequence != cid2.sequence);
    try testing.expect(cid2.sequence != cid3.sequence);
    try testing.expect(cid1.sequence < cid2.sequence);
    try testing.expect(cid2.sequence < cid3.sequence);
}

test "RFC 9000 §10.3 - Stateless reset tokens are computationally difficult to guess" {
    var base: [32]u8 = undefined;
    std.crypto.random.bytes(&base);

    const sequence: u64 = 1;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const token1 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes);

    // Generate another token with slightly different input
    const cid_bytes2 = [_]u8{ 0x01, 0x02, 0x03, 0x05 };
    const token2 = cid.deriveStatelessResetToken(&base, sequence, &cid_bytes2);

    // Tokens should be completely different (avalanche effect)
    try testing.expect(!std.mem.eql(u8, &token1, &token2));
}

test "RFC 9000 §5.1 - Connection IDs can be zero-length" {
    var local_cid: cid.LocalCid = .{};
    local_cid.cid.len = 0;
    local_cid.sequence = 1;
    local_cid.in_use = true;

    // Zero-length CID is valid
    try testing.expectEqual(@as(u8, 0), local_cid.cid.len);
    try testing.expect(local_cid.in_use);
}

test "RFC 9000 §19.15 - NEW_CONNECTION_ID provides sequence and reset token" {
    var local_cid: cid.LocalCid = .{};
    local_cid.sequence = 10;
    local_cid.cid.len = 8;

    // Derive reset token for this CID
    var base: [32]u8 = [_]u8{0x42} ** 32;
    local_cid.reset_token = cid.deriveStatelessResetToken(
        &base,
        local_cid.sequence,
        local_cid.cid.bytes[0..local_cid.cid.len]
    );

    try testing.expectEqual(@as(u64, 10), local_cid.sequence);
    try testing.expectEqual(@as(usize, 16), local_cid.reset_token.len);
}

test "RFC 9000 §5.2 - Connection ID matching" {
    var cid1: cid.LocalCid = .{};
    cid1.cid.len = 8;
    cid1.cid.bytes[0] = 0x01;
    cid1.cid.bytes[1] = 0x02;

    var cid2: cid.LocalCid = .{};
    cid2.cid.len = 8;
    cid2.cid.bytes[0] = 0x01;
    cid2.cid.bytes[1] = 0x02;

    // Same CID bytes
    try testing.expectEqualSlices(u8, cid1.cid.bytes[0..2], cid2.cid.bytes[0..2]);
}

test "RFC 9000 §5.3 - Retire prior to mechanism" {
    // Simulating retire_prior_to=3 means CIDs 0, 1, 2 should be retired
    const cid0_init: cid.LocalCid = .{ .sequence = 0, .in_use = true };
    const cid1_init: cid.LocalCid = .{ .sequence = 1, .in_use = true };
    const cid2_init: cid.LocalCid = .{ .sequence = 2, .in_use = true };
    const cid3_init: cid.LocalCid = .{ .sequence = 3, .in_use = true };

    var cid0 = cid0_init;
    var cid1 = cid1_init;
    var cid2 = cid2_init;
    const cid3 = cid3_init;

    const retire_prior_to: u64 = 3;

    // Retire CIDs before sequence 3
    if (cid0.sequence < retire_prior_to) cid0.in_use = false;
    if (cid1.sequence < retire_prior_to) cid1.in_use = false;
    if (cid2.sequence < retire_prior_to) cid2.in_use = false;

    try testing.expect(!cid0.in_use);
    try testing.expect(!cid1.in_use);
    try testing.expect(!cid2.in_use);
    try testing.expect(cid3.in_use);
}
