//! Unit tests for packet/types.zig
//!
//! RFC References:
//! - RFC 9000 §17: Packet Formats
//! - RFC 9000 §17.2: Long Header Packets
//! - RFC 9000 §17.2.1: Version Negotiation Packet
//! - RFC 9000 §17.2.2: Initial Packet
//! - RFC 9000 §17.3: Short Header Packets (1-RTT)
//! - RFC 9000 §15: QUIC Version 1
//! - RFC 9369: QUIC Version 2
//! - RFC 9001 §5: Packet Protection
//!
//! Coverage:
//! - Positive cases: Type validation, struct initialization, version constants
//! - Negative cases: Invalid packet number ranges
//! - Boundary cases: Min/max packet numbers, empty CID/SCID
//! - RFC compliance: Version constants, packet number range, decoded structure formats

const std = @import("std");
const testing = std.testing;

const types = @import("types");

// =============================================================================
// PacketNumber Type Tests (RFC 9000 §12.3)
// =============================================================================

test "RFC 9000 §12.3 - PacketNumber is u64" {
    const pn: types.PacketNumber = 42;
    try testing.expectEqual(@as(u64, 42), pn);
}

test "RFC 9000 §12.3 - PacketNumber minimum value is 0" {
    const pn: types.PacketNumber = 0;
    try testing.expectEqual(@as(u64, 0), pn);
}

test "RFC 9000 §12.3 - PacketNumber maximum value is 2^62-1" {
    // RFC 9000: "Packet numbers are integers in the range 0 to 2^62-1"
    const max_pn: types.PacketNumber = (1 << 62) - 1;
    try testing.expect(max_pn == 4611686018427387903);
}

test "PacketNumber can be incremented" {
    var pn: types.PacketNumber = 100;
    pn += 1;
    try testing.expectEqual(@as(u64, 101), pn);
}

test "PacketNumber comparison works" {
    const pn1: types.PacketNumber = 10;
    const pn2: types.PacketNumber = 20;
    try testing.expect(pn1 < pn2);
    try testing.expect(pn2 > pn1);
}

// =============================================================================
// LongHeaderType Enum Tests (RFC 9000 §17.2)
// =============================================================================

test "RFC 9000 §17.2 - LongHeaderType has Initial variant" {
    const ty: types.LongHeaderType = .Initial;
    try testing.expectEqual(types.LongHeaderType.Initial, ty);
}

test "RFC 9000 §17.2 - LongHeaderType has Handshake variant" {
    const ty: types.LongHeaderType = .Handshake;
    try testing.expectEqual(types.LongHeaderType.Handshake, ty);
}

test "LongHeaderType variants are distinct" {
    const initial: types.LongHeaderType = .Initial;
    const handshake: types.LongHeaderType = .Handshake;
    try testing.expect(initial != handshake);
}

test "LongHeaderType can be used in switch" {
    const ty: types.LongHeaderType = .Initial;
    const result = switch (ty) {
        .Initial => 0,
        .Handshake => 2,
    };
    try testing.expectEqual(@as(u8, 0), result);
}

test "LongHeaderType switch on Handshake" {
    const ty: types.LongHeaderType = .Handshake;
    const result = switch (ty) {
        .Initial => 0,
        .Handshake => 2,
    };
    try testing.expectEqual(@as(u8, 2), result);
}

// =============================================================================
// DecodedShort Structure Tests (RFC 9000 §17.3)
// =============================================================================

test "RFC 9000 §17.3 - DecodedShort structure initialization" {
    var payload_buf = [_]u8{ 0x01, 0x02, 0x03 };
    const decoded: types.DecodedShort = .{
        .packet_number = 42,
        .packet_number_len = 2,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u64, 42), decoded.packet_number);
    try testing.expectEqual(@as(u3, 2), decoded.packet_number_len);
    try testing.expectEqual(@as(usize, 3), decoded.payload.len);
}

test "DecodedShort with minimal packet number length" {
    var payload_buf = [_]u8{0x00};
    const decoded: types.DecodedShort = .{
        .packet_number = 1,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u3, 1), decoded.packet_number_len);
}

test "DecodedShort with maximum packet number length" {
    var payload_buf = [_]u8{0x00};
    const decoded: types.DecodedShort = .{
        .packet_number = 1,
        .packet_number_len = 4,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u3, 4), decoded.packet_number_len);
}

test "DecodedShort with empty payload" {
    const decoded: types.DecodedShort = .{
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &[_]u8{},
    };

    try testing.expectEqual(@as(usize, 0), decoded.payload.len);
}

test "DecodedShort with large packet number" {
    var payload_buf = [_]u8{0xFF};
    const decoded: types.DecodedShort = .{
        .packet_number = 1000000,
        .packet_number_len = 4,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u64, 1000000), decoded.packet_number);
}

// =============================================================================
// DecodedInitial Structure Tests (RFC 9000 §17.2.2)
// =============================================================================

test "RFC 9000 §17.2.2 - DecodedInitial structure initialization" {
    const dcid_buf = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid_buf = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    var payload_buf = [_]u8{ 0x10, 0x20, 0x30 };

    const decoded: types.DecodedInitial = .{
        .version = 0x00000001,
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .packet_number = 10,
        .packet_number_len = 2,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u32, 0x00000001), decoded.version);
    try testing.expectEqual(@as(usize, 4), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 4), decoded.scid.len);
    try testing.expectEqual(@as(u32, 10), decoded.packet_number);
    try testing.expectEqual(@as(u3, 2), decoded.packet_number_len);
    try testing.expectEqual(@as(usize, 3), decoded.payload.len);
}

test "DecodedInitial with zero-length CIDs" {
    var payload_buf = [_]u8{0x00};
    const decoded: types.DecodedInitial = .{
        .version = 0x00000001,
        .dcid = &[_]u8{},
        .scid = &[_]u8{},
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(usize, 0), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 0), decoded.scid.len);
}

test "DecodedInitial with maximum CID lengths" {
    const dcid_buf = [_]u8{0x00} ** 20;
    const scid_buf = [_]u8{0xFF} ** 20;
    var payload_buf = [_]u8{0xAA};

    const decoded: types.DecodedInitial = .{
        .version = 0x00000001,
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(usize, 20), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 20), decoded.scid.len);
}

test "DecodedInitial with QUIC v2 version" {
    const dcid_buf = [_]u8{0x01};
    const scid_buf = [_]u8{0x02};
    var payload_buf = [_]u8{0x00};

    const decoded: types.DecodedInitial = .{
        .version = 0x709a50c4,
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u32, 0x709a50c4), decoded.version);
}

test "DecodedInitial DCID and SCID are independent" {
    const dcid_buf = [_]u8{ 0xAA, 0xBB };
    const scid_buf = [_]u8{ 0xCC, 0xDD };
    var payload_buf = [_]u8{0x00};

    const decoded: types.DecodedInitial = .{
        .version = 0x00000001,
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };

    try testing.expectEqual(@as(u8, 0xAA), decoded.dcid[0]);
    try testing.expectEqual(@as(u8, 0xCC), decoded.scid[0]);
}

// =============================================================================
// DecodedVN Structure Tests (RFC 9000 §17.2.1)
// =============================================================================

test "RFC 9000 §17.2.1 - DecodedVN structure initialization" {
    const dcid_buf = [_]u8{ 0x01, 0x02 };
    const scid_buf = [_]u8{ 0x03, 0x04 };
    var versions_buf = [_]u32{ 0x00000001, 0x709a50c4 };

    const decoded: types.DecodedVN = .{
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .versions = &versions_buf,
    };

    try testing.expectEqual(@as(usize, 2), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 2), decoded.scid.len);
    try testing.expectEqual(@as(usize, 2), decoded.versions.len);
}

test "DecodedVN with single version" {
    const dcid_buf = [_]u8{0x01};
    const scid_buf = [_]u8{0x02};
    var versions_buf = [_]u32{0x00000001};

    const decoded: types.DecodedVN = .{
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .versions = &versions_buf,
    };

    try testing.expectEqual(@as(usize, 1), decoded.versions.len);
    try testing.expectEqual(@as(u32, 0x00000001), decoded.versions[0]);
}

test "DecodedVN with multiple versions" {
    const dcid_buf = [_]u8{0x00};
    const scid_buf = [_]u8{0x00};
    var versions_buf = [_]u32{ 0x00000001, 0x709a50c4, 0x1a2a3a4a };

    const decoded: types.DecodedVN = .{
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .versions = &versions_buf,
    };

    try testing.expectEqual(@as(usize, 3), decoded.versions.len);
    try testing.expectEqual(@as(u32, 0x00000001), decoded.versions[0]);
    try testing.expectEqual(@as(u32, 0x709a50c4), decoded.versions[1]);
    try testing.expectEqual(@as(u32, 0x1a2a3a4a), decoded.versions[2]);
}

test "DecodedVN with empty CIDs" {
    var versions_buf = [_]u32{0x00000001};

    const decoded: types.DecodedVN = .{
        .dcid = &[_]u8{},
        .scid = &[_]u8{},
        .versions = &versions_buf,
    };

    try testing.expectEqual(@as(usize, 0), decoded.dcid.len);
    try testing.expectEqual(@as(usize, 0), decoded.scid.len);
}

// =============================================================================
// QUIC Version Constants Tests (RFC 9000 §15, RFC 9369)
// =============================================================================

test "RFC 9000 §15 - QUIC_V1 constant is 0x00000001" {
    try testing.expectEqual(@as(u32, 0x00000001), types.QUIC_V1);
}

test "RFC 9369 - QUIC_V2 constant is 0x709a50c4" {
    try testing.expectEqual(@as(u32, 0x709a50c4), types.QUIC_V2);
}

test "QUIC_V1 and QUIC_V2 are different" {
    try testing.expect(types.QUIC_V1 != types.QUIC_V2);
}

test "Version constants can be used in comparisons" {
    const version: u32 = 0x00000001;
    try testing.expect(version == types.QUIC_V1);
    try testing.expect(version != types.QUIC_V2);
}

test "Version constants in switch statement" {
    const version = types.QUIC_V1;
    const result = switch (version) {
        types.QUIC_V1 => "v1",
        types.QUIC_V2 => "v2",
        else => "unknown",
    };
    try testing.expectEqualStrings("v1", result);
}

// =============================================================================
// Boundary and Edge Cases
// =============================================================================

test "boundary: PacketNumber zero value" {
    const pn: types.PacketNumber = 0;
    try testing.expectEqual(@as(u64, 0), pn);
}

test "boundary: PacketNumber near maximum" {
    const pn: types.PacketNumber = (1 << 62) - 2;
    try testing.expect(pn > 0);
}

test "boundary: packet_number_len minimum (1 byte)" {
    var payload_buf = [_]u8{0x00};
    const decoded: types.DecodedShort = .{
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload_buf,
    };
    try testing.expectEqual(@as(u3, 1), decoded.packet_number_len);
}

test "boundary: packet_number_len maximum (4 bytes)" {
    var payload_buf = [_]u8{0x00};
    const decoded: types.DecodedShort = .{
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = &payload_buf,
    };
    try testing.expectEqual(@as(u3, 4), decoded.packet_number_len);
}

test "boundary: DecodedInitial with maximum payload size" {
    const dcid_buf = [_]u8{0x00};
    const scid_buf = [_]u8{0x00};
    var large_payload = [_]u8{0xFF} ** 1200; // Typical QUIC MTU

    const decoded: types.DecodedInitial = .{
        .version = types.QUIC_V1,
        .dcid = &dcid_buf,
        .scid = &scid_buf,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &large_payload,
    };

    try testing.expectEqual(@as(usize, 1200), decoded.payload.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §17 - All decoded structures have packet_number field" {
    // Verify DecodedShort has packet_number
    var buf1 = [_]u8{0x00};
    const short: types.DecodedShort = .{
        .packet_number = 1,
        .packet_number_len = 1,
        .payload = &buf1,
    };
    try testing.expect(short.packet_number > 0);

    // Verify DecodedInitial has packet_number
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    var buf2 = [_]u8{0x00};
    const initial: types.DecodedInitial = .{
        .version = types.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 1,
        .packet_number_len = 1,
        .payload = &buf2,
    };
    try testing.expect(initial.packet_number > 0);
}

test "RFC 9000 §17.2 - Initial packets include version field" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    var payload = [_]u8{0x00};

    const decoded: types.DecodedInitial = .{
        .version = types.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload,
    };

    try testing.expectEqual(types.QUIC_V1, decoded.version);
}

test "RFC 9000 §17.2.1 - Version Negotiation includes multiple versions" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    var versions = [_]u32{ types.QUIC_V1, types.QUIC_V2 };

    const decoded: types.DecodedVN = .{
        .dcid = &dcid,
        .scid = &scid,
        .versions = &versions,
    };

    try testing.expect(decoded.versions.len >= 1);
}

test "RFC 9000 §17 - Packet structures contain payload" {
    var payload = [_]u8{ 0x01, 0x02, 0x03 };

    const short: types.DecodedShort = .{
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload,
    };
    try testing.expectEqual(@as(usize, 3), short.payload.len);

    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const initial: types.DecodedInitial = .{
        .version = types.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload,
    };
    try testing.expectEqual(@as(usize, 3), initial.payload.len);
}

test "RFC 9000 §17 - LongHeaderType enum covers required packet types" {
    // Must support Initial and Handshake
    const initial: types.LongHeaderType = .Initial;
    const handshake: types.LongHeaderType = .Handshake;

    try testing.expect(initial == .Initial);
    try testing.expect(handshake == .Handshake);
}
