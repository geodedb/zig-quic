//! Unit tests for version.zig
//!
//! RFC References:
//! - RFC 9000 §6: Version Negotiation
//! - RFC 9000 §6.1: Sending Version Negotiation Packets
//! - RFC 9000 §6.2: Handling Version Negotiation Packets
//! - RFC 9000 §15: QUIC Version 1
//! - RFC 9000 §17.2: Long Header Packets
//! - RFC 9000 §17.2.1: Version Negotiation Packet
//! - RFC 9369: QUIC Version 2
//!
//! Coverage:
//! - Positive cases: Version parsing/encoding, VN packet encode/decode, version selection
//! - Negative cases: Truncated data, invalid versions, downgrade attacks
//! - Boundary cases: Zero-length CIDs, empty version lists, all supported versions
//! - RFC compliance: Version constants, VN packet format, downgrade protection

const std = @import("std");
const testing = std.testing;

const version = @import("version");

var test_allocator = std.testing.allocator;

// =============================================================================
// Version Constants Tests (RFC 9000 §15, RFC 9369)
// =============================================================================

test "RFC 9000 §15 - QUIC_V1 constant is 0x00000001" {
    try testing.expectEqual(@as(u32, 0x00000001), version.QUIC_V1);
}

test "RFC 9369 - QUIC_V2 constant is 0x709a50c4" {
    try testing.expectEqual(@as(u32, 0x709a50c4), version.QUIC_V2);
}

test "QUIC_V1 and QUIC_V2 are different" {
    try testing.expect(version.QUIC_V1 != version.QUIC_V2);
}

test "SUPPORTED_VERSIONS contains both v1 and v2" {
    try testing.expectEqual(@as(usize, 2), version.SUPPORTED_VERSIONS.len);
    try testing.expectEqual(version.QUIC_V1, version.SUPPORTED_VERSIONS[0]);
    try testing.expectEqual(version.QUIC_V2, version.SUPPORTED_VERSIONS[1]);
}

test "SUPPORTED_VERSIONS array length matches expected" {
    try testing.expect(version.SUPPORTED_VERSIONS.len >= 1);
}

// =============================================================================
// Version Support Checks (RFC 9000 §6.1)
// =============================================================================

test "RFC 9000 §6.1 - isSupported returns true for QUIC v1" {
    try testing.expect(version.isSupported(version.QUIC_V1));
}

test "RFC 9000 §6.1 - isSupported returns true for QUIC v2" {
    try testing.expect(version.isSupported(version.QUIC_V2));
}

test "isSupported returns false for unsupported version" {
    try testing.expect(!version.isSupported(0x12345678));
}

test "isSupported returns false for version zero" {
    try testing.expect(!version.isSupported(0x00000000));
}

test "isSupported returns false for all-ones version" {
    try testing.expect(!version.isSupported(0xFFFFFFFF));
}

test "isV1 returns true for QUIC_V1" {
    try testing.expect(version.isV1(version.QUIC_V1));
}

test "isV1 returns false for QUIC_V2" {
    try testing.expect(!version.isV1(version.QUIC_V2));
}

test "isV1 returns false for other versions" {
    try testing.expect(!version.isV1(0x12345678));
}

test "isV2 returns true for QUIC_V2" {
    try testing.expect(version.isV2(version.QUIC_V2));
}

test "isV2 returns false for QUIC_V1" {
    try testing.expect(!version.isV2(version.QUIC_V1));
}

test "isV2 returns false for other versions" {
    try testing.expect(!version.isV2(0xABCDEF00));
}

// =============================================================================
// Version Parsing Tests (RFC 9000 §17.2)
// =============================================================================

test "RFC 9000 §17.2 - parseVersion decodes QUIC v1" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(version.QUIC_V1, v);
}

test "RFC 9000 §17.2 - parseVersion decodes QUIC v2" {
    const bytes = [_]u8{ 0x70, 0x9a, 0x50, 0xc4 };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(version.QUIC_V2, v);
}

test "parseVersion decodes version zero" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(@as(u32, 0x00000000), v);
}

test "parseVersion decodes all-ones version" {
    const bytes = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), v);
}

test "parseVersion handles big-endian correctly" {
    const bytes = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(@as(u32, 0x12345678), v);
}

test "parseVersion ignores extra bytes" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(version.QUIC_V1, v);
}

test "negative: parseVersion fails on truncated input (3 bytes)" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00 };
    try testing.expectError(error.Truncated, version.parseVersion(&bytes));
}

test "negative: parseVersion fails on truncated input (2 bytes)" {
    const bytes = [_]u8{ 0x00, 0x00 };
    try testing.expectError(error.Truncated, version.parseVersion(&bytes));
}

test "negative: parseVersion fails on empty input" {
    const bytes = [_]u8{};
    try testing.expectError(error.Truncated, version.parseVersion(&bytes));
}

// =============================================================================
// Version Encoding Tests (RFC 9000 §17.2)
// =============================================================================

test "RFC 9000 §17.2 - encodeVersion encodes QUIC v1" {
    const bytes = version.encodeVersion(version.QUIC_V1);
    try testing.expectEqual(@as(u8, 0x00), bytes[0]);
    try testing.expectEqual(@as(u8, 0x00), bytes[1]);
    try testing.expectEqual(@as(u8, 0x00), bytes[2]);
    try testing.expectEqual(@as(u8, 0x01), bytes[3]);
}

test "RFC 9000 §17.2 - encodeVersion encodes QUIC v2" {
    const bytes = version.encodeVersion(version.QUIC_V2);
    try testing.expectEqual(@as(u8, 0x70), bytes[0]);
    try testing.expectEqual(@as(u8, 0x9a), bytes[1]);
    try testing.expectEqual(@as(u8, 0x50), bytes[2]);
    try testing.expectEqual(@as(u8, 0xc4), bytes[3]);
}

test "encodeVersion encodes version zero" {
    const bytes = version.encodeVersion(0x00000000);
    try testing.expectEqual(@as(u8, 0x00), bytes[0]);
    try testing.expectEqual(@as(u8, 0x00), bytes[1]);
    try testing.expectEqual(@as(u8, 0x00), bytes[2]);
    try testing.expectEqual(@as(u8, 0x00), bytes[3]);
}

test "encodeVersion encodes all-ones version" {
    const bytes = version.encodeVersion(0xFFFFFFFF);
    try testing.expectEqual(@as(u8, 0xFF), bytes[0]);
    try testing.expectEqual(@as(u8, 0xFF), bytes[1]);
    try testing.expectEqual(@as(u8, 0xFF), bytes[2]);
    try testing.expectEqual(@as(u8, 0xFF), bytes[3]);
}

test "encodeVersion uses big-endian byte order" {
    const bytes = version.encodeVersion(0x12345678);
    try testing.expectEqual(@as(u8, 0x12), bytes[0]);
    try testing.expectEqual(@as(u8, 0x34), bytes[1]);
    try testing.expectEqual(@as(u8, 0x56), bytes[2]);
    try testing.expectEqual(@as(u8, 0x78), bytes[3]);
}

test "encodeVersion returns exactly 4 bytes" {
    const bytes = version.encodeVersion(0xABCDEF00);
    try testing.expectEqual(@as(usize, 4), bytes.len);
}

// =============================================================================
// Round-trip Encoding Tests
// =============================================================================

test "parseVersion and encodeVersion are inverse operations for v1" {
    const original = version.QUIC_V1;
    const encoded = version.encodeVersion(original);
    const decoded = try version.parseVersion(&encoded);
    try testing.expectEqual(original, decoded);
}

test "parseVersion and encodeVersion are inverse operations for v2" {
    const original = version.QUIC_V2;
    const encoded = version.encodeVersion(original);
    const decoded = try version.parseVersion(&encoded);
    try testing.expectEqual(original, decoded);
}

test "parseVersion and encodeVersion round-trip arbitrary version" {
    const original: u32 = 0xDEADBEEF;
    const encoded = version.encodeVersion(original);
    const decoded = try version.parseVersion(&encoded);
    try testing.expectEqual(original, decoded);
}

// =============================================================================
// Version Negotiation Encoding Tests (RFC 9000 §17.2.1)
// =============================================================================

test "RFC 9000 §17.2.1 - encodeVersionNegotiation basic packet" {
    const dcid = [_]u8{ 0x01, 0x02 };
    const scid = [_]u8{ 0x03, 0x04 };
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    try testing.expect(packet.len > 0);
    // First byte should be 0x80 (long header bit + fixed bit)
    try testing.expectEqual(@as(u8, 0x80), packet[0]);
}

test "encodeVersionNegotiation has version zero" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // Version field at bytes 1-4 should be 0
    try testing.expectEqual(@as(u8, 0x00), packet[1]);
    try testing.expectEqual(@as(u8, 0x00), packet[2]);
    try testing.expectEqual(@as(u8, 0x00), packet[3]);
    try testing.expectEqual(@as(u8, 0x00), packet[4]);
}

test "encodeVersionNegotiation includes DCID length and bytes" {
    const dcid = [_]u8{ 0xAA, 0xBB };
    const scid = [_]u8{0x00};
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // After first byte(1) + version(4), DCID length at offset 5
    try testing.expectEqual(@as(u8, 2), packet[5]);
    try testing.expectEqual(@as(u8, 0xAA), packet[6]);
    try testing.expectEqual(@as(u8, 0xBB), packet[7]);
}

test "encodeVersionNegotiation includes SCID length and bytes" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{ 0xCC, 0xDD, 0xEE };
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // After first(1) + version(4) + dcid_len(1) + dcid(1) = 7, SCID length at offset 7
    try testing.expectEqual(@as(u8, 3), packet[7]);
    try testing.expectEqual(@as(u8, 0xCC), packet[8]);
    try testing.expectEqual(@as(u8, 0xDD), packet[9]);
    try testing.expectEqual(@as(u8, 0xEE), packet[10]);
}

test "encodeVersionNegotiation includes all versions" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // Each version is 4 bytes, should have both in packet
    try testing.expect(packet.len >= 1 + 4 + 1 + 0 + 1 + 0 + 8); // header + 2 versions
}

test "encodeVersionNegotiation with empty DCID and SCID" {
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &[_]u8{}, &[_]u8{}, &versions);
    defer test_allocator.free(packet);

    try testing.expect(packet.len > 0);
    // DCID length should be 0 at offset 5
    try testing.expectEqual(@as(u8, 0), packet[5]);
    // SCID length should be 0 at offset 6
    try testing.expectEqual(@as(u8, 0), packet[6]);
}

test "encodeVersionNegotiation with single version" {
    const dcid = [_]u8{0x01};
    const scid = [_]u8{0x02};
    const versions = [_]u32{version.QUIC_V2};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // Should have exactly: 1 + 4 + 1 + 1 + 1 + 1 + 4 = 13 bytes
    try testing.expectEqual(@as(usize, 13), packet.len);
}

test "encodeVersionNegotiation with multiple versions" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2, 0x1a2a3a4a };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // Should have 3 versions * 4 bytes = 12 bytes for versions
    try testing.expect(packet.len >= 12);
}

// =============================================================================
// Version Negotiation Decoding Tests (RFC 9000 §17.2.1)
// =============================================================================

test "RFC 9000 §17.2.1 - decodeVersionNegotiation basic packet" {
    const dcid = [_]u8{ 0x01, 0x02 };
    const scid = [_]u8{ 0x03, 0x04 };
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqualSlices(u8, &dcid, decoded.dcid);
    try testing.expectEqualSlices(u8, &scid, decoded.scid);
    try testing.expectEqual(@as(usize, 2), decoded.versions.len);
}

test "decodeVersionNegotiation extracts DCID correctly" {
    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC };
    const scid = [_]u8{0x00};
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqualSlices(u8, &dcid, decoded.dcid);
}

test "decodeVersionNegotiation extracts SCID correctly" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const versions = [_]u32{version.QUIC_V2};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqualSlices(u8, &scid, decoded.scid);
}

test "decodeVersionNegotiation extracts all versions" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2, 0x12345678 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqual(@as(usize, 3), decoded.versions.len);
    try testing.expectEqual(version.QUIC_V1, decoded.versions[0]);
    try testing.expectEqual(version.QUIC_V2, decoded.versions[1]);
    try testing.expectEqual(@as(u32, 0x12345678), decoded.versions[2]);
}

test "decodeVersionNegotiation with empty CIDs" {
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &[_]u8{}, &[_]u8{}, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqual(@as(usize, 0), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 0), decoded.scid.len);
}

test "negative: decodeVersionNegotiation fails on truncated packet" {
    const short_packet = [_]u8{ 0x80, 0x00, 0x00 };
    try testing.expectError(error.Truncated, version.decodeVersionNegotiation(test_allocator, &short_packet));
}

test "negative: decodeVersionNegotiation fails on non-long header" {
    const packet = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x03 };
    try testing.expectError(error.InvalidHeader, version.decodeVersionNegotiation(test_allocator, &packet));
}

test "negative: decodeVersionNegotiation fails on non-zero version" {
    const packet = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try testing.expectError(error.NotVersionNegotiation, version.decodeVersionNegotiation(test_allocator, &packet));
}

test "negative: decodeVersionNegotiation fails on malformed versions" {
    // Packet with 1 extra byte after CIDs (not multiple of 4)
    const packet = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };
    try testing.expectError(error.MalformedVersions, version.decodeVersionNegotiation(test_allocator, &packet));
}

// =============================================================================
// Round-trip VN Packet Tests
// =============================================================================

test "VN packet encode/decode round-trip" {
    const dcid = [_]u8{ 0x11, 0x22 };
    const scid = [_]u8{ 0x33, 0x44 };
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqualSlices(u8, &dcid, decoded.dcid);
    try testing.expectEqualSlices(u8, &scid, decoded.scid);
    try testing.expectEqualSlices(u32, &versions, decoded.versions);
}

// =============================================================================
// Downgrade Protection Tests (RFC 9000 §6.2)
// =============================================================================

test "RFC 9000 §6.2 - shouldAcceptVersionNegotiation rejects if original in list" {
    const original = version.QUIC_V1;
    const vn_versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    try testing.expect(!version.shouldAcceptVersionNegotiation(original, &vn_versions));
}

test "RFC 9000 §6.2 - shouldAcceptVersionNegotiation accepts if original not in list" {
    const original: u32 = 0x0a0a0a0a; // Some unsupported version
    const vn_versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    try testing.expect(version.shouldAcceptVersionNegotiation(original, &vn_versions));
}

test "shouldAcceptVersionNegotiation with single version in list" {
    const original = version.QUIC_V1;
    const vn_versions = [_]u32{version.QUIC_V2};

    try testing.expect(version.shouldAcceptVersionNegotiation(original, &vn_versions));
}

test "shouldAcceptVersionNegotiation with empty list" {
    const original = version.QUIC_V1;
    const vn_versions = [_]u32{};

    try testing.expect(version.shouldAcceptVersionNegotiation(original, &vn_versions));
}

test "shouldAcceptVersionNegotiation detects downgrade attack" {
    const original = version.QUIC_V2;
    const vn_versions = [_]u32{ version.QUIC_V2, 0x12345678 };

    // Should reject because original version is in the list
    try testing.expect(!version.shouldAcceptVersionNegotiation(original, &vn_versions));
}

// =============================================================================
// Version Negotiation Validation Tests (RFC 9000 §6.2)
// =============================================================================

test "RFC 9000 §6.2 - validateVersionNegotiation accepts valid VN" {
    const original_version = 0x0a0a0a0a; // Unsupported version
    const original_dcid = [_]u8{ 0x01, 0x02 };
    const original_scid = [_]u8{ 0x03, 0x04 };
    const vn_dcid = [_]u8{ 0x03, 0x04 }; // Swapped
    const vn_scid = [_]u8{ 0x01, 0x02 }; // Swapped
    const vn_versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 };

    const valid = version.validateVersionNegotiation(
        original_version,
        &original_dcid,
        &original_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(valid);
}

test "validateVersionNegotiation rejects downgrade attack" {
    const original_version = version.QUIC_V1;
    const original_dcid = [_]u8{0x01};
    const original_scid = [_]u8{0x02};
    const vn_dcid = [_]u8{0x02};
    const vn_scid = [_]u8{0x01};
    const vn_versions = [_]u32{ version.QUIC_V1, version.QUIC_V2 }; // Contains original

    const valid = version.validateVersionNegotiation(
        original_version,
        &original_dcid,
        &original_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(!valid);
}

test "validateVersionNegotiation rejects mismatched DCID" {
    const original_version: u32 = 0x0a0a0a0a;
    const original_dcid = [_]u8{ 0x01, 0x02 };
    const original_scid = [_]u8{ 0x03, 0x04 };
    const vn_dcid = [_]u8{ 0xFF, 0xFF }; // Wrong DCID
    const vn_scid = [_]u8{ 0x01, 0x02 };
    const vn_versions = [_]u32{version.QUIC_V1};

    const valid = version.validateVersionNegotiation(
        original_version,
        &original_dcid,
        &original_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(!valid);
}

test "validateVersionNegotiation rejects mismatched SCID" {
    const original_version: u32 = 0x0a0a0a0a;
    const original_dcid = [_]u8{ 0x01, 0x02 };
    const original_scid = [_]u8{ 0x03, 0x04 };
    const vn_dcid = [_]u8{ 0x03, 0x04 };
    const vn_scid = [_]u8{ 0xFF, 0xFF }; // Wrong SCID
    const vn_versions = [_]u32{version.QUIC_V1};

    const valid = version.validateVersionNegotiation(
        original_version,
        &original_dcid,
        &original_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(!valid);
}

test "validateVersionNegotiation rejects if no supported version offered" {
    const original_version: u32 = 0x0a0a0a0a;
    const original_dcid = [_]u8{0x01};
    const original_scid = [_]u8{0x02};
    const vn_dcid = [_]u8{0x02};
    const vn_scid = [_]u8{0x01};
    const vn_versions = [_]u32{ 0x11111111, 0x22222222 }; // No supported versions

    const valid = version.validateVersionNegotiation(
        original_version,
        &original_dcid,
        &original_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(!valid);
}

test "validateVersionNegotiation checks CID swap correctly" {
    // RFC 9000 §6.2: DCID from client becomes SCID in VN, and vice versa
    const original_version: u32 = 0x0a0a0a0a;
    const client_dcid = [_]u8{0xAA};
    const client_scid = [_]u8{0xBB};
    const vn_dcid = [_]u8{0xBB}; // Should equal client's SCID
    const vn_scid = [_]u8{0xAA}; // Should equal client's DCID
    const vn_versions = [_]u32{version.QUIC_V1};

    const valid = version.validateVersionNegotiation(
        original_version,
        &client_dcid,
        &client_scid,
        &vn_dcid,
        &vn_scid,
        &vn_versions,
    );

    try testing.expect(valid);
}

// =============================================================================
// Version Selection Tests (RFC 9000 §6.2)
// =============================================================================

test "RFC 9000 §6.2 - selectVersion chooses first supported in preference order" {
    const offered = [_]u32{ version.QUIC_V2, version.QUIC_V1, 0x12345678 };

    const selected = version.selectVersion(&offered);

    // Should choose QUIC_V1 as it appears first in SUPPORTED_VERSIONS
    try testing.expectEqual(version.QUIC_V1, selected.?);
}

test "selectVersion returns QUIC v1 when only v1 offered" {
    const offered = [_]u32{version.QUIC_V1};

    const selected = version.selectVersion(&offered);

    try testing.expectEqual(version.QUIC_V1, selected.?);
}

test "selectVersion returns QUIC v2 when only v2 offered" {
    const offered = [_]u32{version.QUIC_V2};

    const selected = version.selectVersion(&offered);

    try testing.expectEqual(version.QUIC_V2, selected.?);
}

test "selectVersion returns null when no supported version offered" {
    const offered = [_]u32{ 0x11111111, 0x22222222, 0x33333333 };

    const selected = version.selectVersion(&offered);

    try testing.expect(selected == null);
}

test "selectVersion returns null for empty list" {
    const offered = [_]u32{};

    const selected = version.selectVersion(&offered);

    try testing.expect(selected == null);
}

test "selectVersion prefers v1 over v2" {
    const offered = [_]u32{ version.QUIC_V2, version.QUIC_V1 };

    const selected = version.selectVersion(&offered);

    // Should prefer v1 as it's first in SUPPORTED_VERSIONS
    try testing.expectEqual(version.QUIC_V1, selected.?);
}

test "selectVersion ignores unsupported versions" {
    const offered = [_]u32{ 0xAAAAAAAA, version.QUIC_V2, 0xBBBBBBBB };

    const selected = version.selectVersion(&offered);

    try testing.expectEqual(version.QUIC_V2, selected.?);
}

// =============================================================================
// Boundary and Edge Cases
// =============================================================================

test "boundary: parseVersion with exact 4 bytes" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 };
    const v = try version.parseVersion(&bytes);
    try testing.expectEqual(version.QUIC_V1, v);
}

test "boundary: encodeVersionNegotiation with maximum CID lengths" {
    const dcid = [_]u8{0xAA} ** 20;
    const scid = [_]u8{0xBB} ** 20;
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    try testing.expect(packet.len > 40);
}

test "boundary: decodeVersionNegotiation with many versions" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{ version.QUIC_V1, version.QUIC_V2, 0x11111111, 0x22222222, 0x33333333 };

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    const decoded = try version.decodeVersionNegotiation(test_allocator, packet);
    defer test_allocator.free(decoded.versions);

    try testing.expectEqual(@as(usize, 5), decoded.versions.len);
}

test "boundary: validateVersionNegotiation with zero-length CIDs" {
    const original_version: u32 = 0x0a0a0a0a;
    const vn_versions = [_]u32{version.QUIC_V1};

    const valid = version.validateVersionNegotiation(
        original_version,
        &[_]u8{},
        &[_]u8{},
        &[_]u8{},
        &[_]u8{},
        &vn_versions,
    );

    try testing.expect(valid);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §6 - version negotiation provides both v1 and v2" {
    try testing.expect(version.isSupported(version.QUIC_V1));
    try testing.expect(version.isSupported(version.QUIC_V2));
}

test "RFC 9000 §17.2.1 - VN packet has version field set to zero" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const versions = [_]u32{version.QUIC_V1};

    const packet = try version.encodeVersionNegotiation(test_allocator, &dcid, &scid, &versions);
    defer test_allocator.free(packet);

    // Verify version is 0 at bytes 1-4
    const ver = try version.parseVersion(packet[1..5]);
    try testing.expectEqual(@as(u32, 0), ver);
}

test "RFC 9000 §6.2 - downgrade protection implemented" {
    const original = version.QUIC_V1;
    const vn_with_original = [_]u32{ version.QUIC_V1, version.QUIC_V2 };
    const vn_without_original = [_]u32{version.QUIC_V2};

    // Should reject if original is present
    try testing.expect(!version.shouldAcceptVersionNegotiation(original, &vn_with_original));

    // Should accept if original is absent
    try testing.expect(version.shouldAcceptVersionNegotiation(original, &vn_without_original));
}

test "RFC 9000 §6.2 - VN validation checks CID swap" {
    const original_version: u32 = 0x0a0a0a0a;
    const client_dcid = [_]u8{0x01};
    const client_scid = [_]u8{0x02};
    const vn_versions = [_]u32{version.QUIC_V1};

    // Correct swap: client DCID becomes server SCID
    const valid_swap = version.validateVersionNegotiation(
        original_version,
        &client_dcid,
        &client_scid,
        &client_scid, // VN DCID = client SCID
        &client_dcid, // VN SCID = client DCID
        &vn_versions,
    );
    try testing.expect(valid_swap);

    // Incorrect swap
    const invalid_swap = version.validateVersionNegotiation(
        original_version,
        &client_dcid,
        &client_scid,
        &client_dcid, // VN DCID = client DCID (wrong!)
        &client_scid, // VN SCID = client SCID (wrong!)
        &vn_versions,
    );
    try testing.expect(!invalid_swap);
}

test "RFC 9000 §6.2 - version selection uses preference order" {
    // SUPPORTED_VERSIONS = [QUIC_V1, QUIC_V2]
    // Should prefer v1 over v2
    const offered = [_]u32{ version.QUIC_V2, version.QUIC_V1 };
    const selected = version.selectVersion(&offered);
    try testing.expectEqual(version.QUIC_V1, selected.?);
}

test "RFC 9000 §17.2 - version encoding is big-endian" {
    const test_version: u32 = 0x12345678;
    const encoded = version.encodeVersion(test_version);

    // Big-endian: most significant byte first
    try testing.expectEqual(@as(u8, 0x12), encoded[0]);
    try testing.expectEqual(@as(u8, 0x34), encoded[1]);
    try testing.expectEqual(@as(u8, 0x56), encoded[2]);
    try testing.expectEqual(@as(u8, 0x78), encoded[3]);
}

test "RFC 9000 §15 - QUIC v1 uses correct constant value" {
    try testing.expectEqual(@as(u32, 0x00000001), version.QUIC_V1);
    try testing.expect(version.isV1(0x00000001));
}

test "RFC 9369 - QUIC v2 uses correct constant value" {
    try testing.expectEqual(@as(u32, 0x709a50c4), version.QUIC_V2);
    try testing.expect(version.isV2(0x709a50c4));
}
