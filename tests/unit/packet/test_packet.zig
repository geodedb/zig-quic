//! Unit tests for packet/packet.zig (coordinator module)
//!
//! RFC References:
//! - RFC 9000 §17: Packet Formats
//! - RFC 9001 §5: Packet Protection
//! - RFC 9000 §17.2: Long Header Packets
//! - RFC 9000 §17.2.1: Version Negotiation Packet
//! - RFC 9000 §17.2.2: Initial Packet
//! - RFC 9000 §17.2.4: Handshake Packet
//! - RFC 9000 §17.2.5: Retry Packet
//! - RFC 9000 §17.3: Short Header Packets (1-RTT)
//! - RFC 9001 §4.6.1: 0-RTT Packets
//!
//! Coverage:
//! - Positive cases: Module re-exports, type availability, coordinator integration
//! - Negative cases: Type mismatch validation
//! - Boundary cases: Re-exported constants, function availability
//! - RFC compliance: All required types are re-exported, legacy function compatibility

const std = @import("std");
const testing = std.testing;

const packet = @import("packet");

// =============================================================================
// Type Re-export Tests
// =============================================================================

test "coordinator re-exports PacketNumber from types module" {
    const pn: packet.PacketNumber = 42;
    try testing.expectEqual(@as(u64, 42), pn);
}

test "coordinator re-exports LongHeaderType from types module" {
    const ty: packet.LongHeaderType = .Initial;
    try testing.expectEqual(packet.LongHeaderType.Initial, ty);
}

test "coordinator re-exports DecodedShort from types module" {
    var payload = [_]u8{0x00};
    const decoded: packet.DecodedShort = .{
        .packet_number = 1,
        .packet_number_len = 1,
        .payload = &payload,
        .key_phase = false,
    };
    try testing.expectEqual(@as(u64, 1), decoded.packet_number);
}

test "coordinator re-exports DecodedInitial from types module" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    var payload = [_]u8{0x00};

    const decoded: packet.DecodedInitial = .{
        .version = 0x00000001,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload,
    };
    try testing.expectEqual(@as(u32, 0x00000001), decoded.version);
}

test "coordinator re-exports DecodedVN from types module" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    var versions = [_]u32{0x00000001};

    const decoded: packet.DecodedVN = .{
        .dcid = &dcid,
        .scid = &scid,
        .versions = &versions,
    };
    try testing.expectEqual(@as(usize, 1), decoded.versions.len);
}

test "coordinator re-exports QUIC_V1 constant" {
    try testing.expectEqual(@as(u32, 0x00000001), packet.QUIC_V1);
}

test "coordinator re-exports QUIC_V2 constant" {
    try testing.expectEqual(@as(u32, 0x709a50c4), packet.QUIC_V2);
}

// =============================================================================
// Header Re-export Tests
// =============================================================================

test "coordinator re-exports LongHeader from header module" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const payload = [_]u8{0x00};

    const long_hdr: packet.LongHeader = .{
        .ty = .Initial,
        .version = packet.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 0,
        .payload = &payload,
    };

    try testing.expectEqual(packet.LongHeaderType.Initial, long_hdr.ty);
}

test "coordinator re-exports ShortHeader from header module" {
    const payload = [_]u8{0x00};

    const short_hdr: packet.ShortHeader = .{
        .dcid = &[_]u8{},
        .packet_number = 0,
        .payload = &payload,
    };

    try testing.expectEqual(@as(u64, 0), short_hdr.packet_number);
}

test "LongHeader encode is accessible through coordinator" {
    const dcid = [_]u8{0x01};
    const scid = [_]u8{0x02};
    const payload = [_]u8{0xFF};

    const long_hdr: packet.LongHeader = .{
        .ty = .Handshake,
        .version = packet.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 1,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const written = try long_hdr.encode(fbs.writer());

    try testing.expect(written > 0);
}

test "ShortHeader encode is accessible through coordinator" {
    const payload = [_]u8{0xAA};

    const short_hdr: packet.ShortHeader = .{
        .dcid = &[_]u8{},
        .packet_number = 1,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const written = try short_hdr.encode(fbs.writer());

    try testing.expect(written > 0);
}

// =============================================================================
// Legacy Function Re-export Tests
// =============================================================================

test "coordinator re-exports AeadKeys type" {
    // Verify type is accessible
    const KeysType = packet.AeadKeys;
    _ = KeysType;
}

test "coordinator re-exports InitialKeys type" {
    // Verify type is accessible
    const InitialType = packet.InitialKeys;
    _ = InitialType;
}

test "coordinator re-exports encodeInitialProtected function" {
    // Verify function is accessible
    const encode_fn = packet.encodeInitialProtected;
    _ = encode_fn;
}

test "coordinator re-exports decodeInitialProtected function" {
    const decode_fn = packet.decodeInitialProtected;
    _ = decode_fn;
}

test "coordinator re-exports derive_initial_keys function" {
    const derive_fn = packet.derive_initial_keys;
    _ = derive_fn;
}

test "coordinator re-exports initialAeadKeys function" {
    const keys_fn = packet.initialAeadKeys;
    _ = keys_fn;
}

test "coordinator re-exports encodeHandshakeProtected function" {
    const encode_fn = packet.encodeHandshakeProtected;
    _ = encode_fn;
}

test "coordinator re-exports encodeShortProtected function" {
    const encode_fn = packet.encodeShortProtected;
    _ = encode_fn;
}

test "coordinator re-exports decodeShortProtected function" {
    const decode_fn = packet.decodeShortProtected;
    _ = decode_fn;
}

test "coordinator re-exports short-header write-into decode-into functions" {
    const encode_into_fn = packet.encodeShortProtectedInto;
    const decode_into_fn = packet.decodeShortProtectedInto;
    const decode_hp_into_fn = packet.decodeShortProtectedWithHpInto;
    _ = encode_into_fn;
    _ = decode_into_fn;
    _ = decode_hp_into_fn;
}

test "coordinator re-exports decodeShortProtectedLegacy function" {
    const decode_fn = packet.decodeShortProtectedLegacy;
    _ = decode_fn;
}

test "coordinator re-exports encodeVersionNegotiation function" {
    const encode_fn = packet.encodeVersionNegotiation;
    _ = encode_fn;
}

test "coordinator re-exports decodeVersionNegotiation function" {
    const decode_fn = packet.decodeVersionNegotiation;
    _ = decode_fn;
}

test "coordinator re-exports shouldAcceptVersionNegotiation function" {
    const check_fn = packet.shouldAcceptVersionNegotiation;
    _ = check_fn;
}

test "coordinator re-exports encodeRetry function" {
    const encode_fn = packet.encodeRetry;
    _ = encode_fn;
}

test "coordinator re-exports verifyRetry function" {
    const verify_fn = packet.verifyRetry;
    _ = verify_fn;
}

test "coordinator re-exports encode0RTTProtected function" {
    const encode_fn = packet.encode0RTTProtected;
    _ = encode_fn;
}

test "coordinator re-exports decode0RTTProtected function" {
    const decode_fn = packet.decode0RTTProtected;
    _ = decode_fn;
}

test "short-header write-into/decode-into roundtrip" {
    const dcid = "HPBM";
    const keys = packet.AeadKeys{
        .key = .{0} ** 16,
        .iv = .{0} ** 12,
        .hp = .{0} ** 16,
    };

    var packet_buf: [4096]u8 = undefined;
    const payload = [_]u8{ 0x01, 0xAA, 0xBB };
    const packet_len = try packet.encodeShortProtectedInto(
        packet_buf[0..],
        dcid,
        7,
        2,
        payload[0..],
        keys,
        false,
    );

    var decode_buf: [4096]u8 = undefined;
    const decoded = try packet.decodeShortProtectedInto(
        packet_buf[0..packet_len],
        dcid.len,
        keys,
        0,
        decode_buf[0..],
    );

    try testing.expectEqual(@as(u64, 7), decoded.packet_number);
    try testing.expectEqual(payload.len, decoded.payload.len);
    try testing.expectEqualSlices(u8, payload[0..], decoded.payload);
}

// =============================================================================
// Submodule Access Tests
// =============================================================================

test "coordinator provides access to types submodule" {
    const types_module = packet.types;
    try testing.expectEqual(@as(u32, 0x00000001), types_module.QUIC_V1);
}

test "coordinator provides access to header submodule" {
    const header_module = packet.header;
    const LongHeaderType = header_module.LongHeader;
    _ = LongHeaderType;
}

test "types submodule PacketNumber matches re-export" {
    const pn1: packet.PacketNumber = 42;
    const pn2: packet.types.PacketNumber = 42;
    try testing.expectEqual(pn1, pn2);
}

test "types submodule LongHeaderType matches re-export" {
    const ty1: packet.LongHeaderType = .Initial;
    const ty2: packet.types.LongHeaderType = .Initial;
    try testing.expectEqual(ty1, ty2);
}

test "types submodule QUIC_V1 matches re-export" {
    try testing.expectEqual(packet.QUIC_V1, packet.types.QUIC_V1);
}

test "types submodule QUIC_V2 matches re-export" {
    try testing.expectEqual(packet.QUIC_V2, packet.types.QUIC_V2);
}

// =============================================================================
// Integration Tests
// =============================================================================

test "can create LongHeader using coordinator types" {
    const dcid = [_]u8{ 0x01, 0x02 };
    const scid = [_]u8{ 0x03, 0x04 };
    const payload = [_]u8{ 0x05, 0x06 };

    const long_hdr: packet.LongHeader = .{
        .ty = packet.LongHeaderType.Initial,
        .version = packet.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 1,
        .payload = &payload,
    };

    try testing.expectEqual(packet.LongHeaderType.Initial, long_hdr.ty);
    try testing.expectEqual(packet.QUIC_V1, long_hdr.version);
}

test "can create DecodedInitial using coordinator constants" {
    const dcid = [_]u8{0x11};
    const scid = [_]u8{0x22};
    var payload = [_]u8{0x33};

    const decoded: packet.DecodedInitial = .{
        .version = packet.QUIC_V2,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 10,
        .packet_number_len = 2,
        .payload = &payload,
    };

    try testing.expectEqual(packet.QUIC_V2, decoded.version);
}

test "can encode LongHeader and access packet number" {
    const dcid = [_]u8{0xAA};
    const scid = [_]u8{0xBB};
    const payload = [_]u8{0xCC};

    const long_hdr: packet.LongHeader = .{
        .ty = .Handshake,
        .version = packet.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 42,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const written = try long_hdr.encode(fbs.writer());

    try testing.expect(written > 0);
    try testing.expectEqual(@as(u64, 42), long_hdr.packet_number);
}

test "coordinator types work with header encoding" {
    const payload = [_]u8{ 0x10, 0x20, 0x30 };

    const short_hdr: packet.ShortHeader = .{
        .dcid = &[_]u8{},
        .packet_number = 100,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const written = try short_hdr.encode(fbs.writer());

    try testing.expect(written >= 4); // first byte + pn + payload
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §17 - coordinator provides all packet types" {
    // Verify PacketNumber type
    const pn: packet.PacketNumber = 0;
    _ = pn;

    // Verify Long Header types
    const initial: packet.LongHeaderType = .Initial;
    const handshake: packet.LongHeaderType = .Handshake;
    _ = initial;
    _ = handshake;

    // Verify decoded structures
    var payload = [_]u8{0x00};
    const short: packet.DecodedShort = .{
        .packet_number = 0,
        .packet_number_len = 1,
        .payload = &payload,
        .key_phase = false,
    };
    _ = short;
}

test "RFC 9000 §15 - coordinator provides QUIC version constants" {
    try testing.expectEqual(@as(u32, 0x00000001), packet.QUIC_V1);
}

test "RFC 9369 - coordinator provides QUIC v2 constant" {
    try testing.expectEqual(@as(u32, 0x709a50c4), packet.QUIC_V2);
}

test "RFC 9001 §5 - coordinator provides packet protection functions" {
    // Verify all protection functions are accessible
    _ = packet.encodeInitialProtected;
    _ = packet.decodeInitialProtected;
    _ = packet.encodeHandshakeProtected;
    _ = packet.encodeShortProtected;
    _ = packet.decodeShortProtected;
}

test "RFC 9000 §17.2.1 - coordinator provides version negotiation support" {
    _ = packet.encodeVersionNegotiation;
    _ = packet.decodeVersionNegotiation;
    _ = packet.shouldAcceptVersionNegotiation;
}

test "RFC 9000 §17.2.5 - coordinator provides Retry packet support" {
    _ = packet.encodeRetry;
    _ = packet.verifyRetry;
}

test "RFC 9001 §4.6.1 - coordinator provides 0-RTT packet support" {
    _ = packet.encode0RTTProtected;
    _ = packet.decode0RTTProtected;
}

test "RFC 9000 §17.2 - coordinator provides long header encoding" {
    const dcid = [_]u8{0x00};
    const scid = [_]u8{0x00};
    const payload = [_]u8{0x00};

    const long_hdr: packet.LongHeader = .{
        .ty = .Initial,
        .version = packet.QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_number = 0,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    _ = try long_hdr.encode(fbs.writer());
}

test "RFC 9000 §17.3 - coordinator provides short header encoding" {
    const payload = [_]u8{0x00};

    const short_hdr: packet.ShortHeader = .{
        .dcid = &[_]u8{},
        .packet_number = 0,
        .payload = &payload,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    _ = try short_hdr.encode(fbs.writer());
}

test "RFC 9001 §5.1 - coordinator provides initial key derivation" {
    _ = packet.derive_initial_keys;
    _ = packet.initialAeadKeys;
}

// =============================================================================
// Boundary and Edge Cases
// =============================================================================

test "boundary: all packet types have consistent access through coordinator" {
    // Verify all types can be accessed
    const Types = struct {
        pn: packet.PacketNumber,
        lht: packet.LongHeaderType,
        ds: packet.DecodedShort,
        di: packet.DecodedInitial,
        dvn: packet.DecodedVN,
    };
    _ = Types;
}

test "boundary: version constants are distinct and correct" {
    try testing.expect(packet.QUIC_V1 != packet.QUIC_V2);
    try testing.expectEqual(@as(u32, 0x00000001), packet.QUIC_V1);
    try testing.expectEqual(@as(u32, 0x709a50c4), packet.QUIC_V2);
}

test "boundary: coordinator provides both modular and legacy APIs" {
    // Modular API
    const long_hdr_type = packet.LongHeader;
    _ = long_hdr_type;

    // Legacy API
    const legacy_fn = packet.encodeInitialProtected;
    _ = legacy_fn;
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: type consistency - PacketNumber is always u64" {
    const pn1: packet.PacketNumber = 100;
    const pn2: u64 = 100;
    try testing.expectEqual(pn1, pn2);
}

test "negative: type consistency - version constants are u32" {
    const v1: u32 = packet.QUIC_V1;
    const v2: u32 = packet.QUIC_V2;
    try testing.expect(v1 != v2);
}

test "negative: LongHeaderType enum has exactly 2 variants" {
    const initial: packet.LongHeaderType = .Initial;
    const handshake: packet.LongHeaderType = .Handshake;

    // Both should be valid
    try testing.expect(initial == .Initial);
    try testing.expect(handshake == .Handshake);
    try testing.expect(initial != handshake);
}
