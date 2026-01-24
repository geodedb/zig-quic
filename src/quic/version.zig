// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC version negotiation and version-specific constants.
//!
//! RFC 9000 §6: Version Negotiation
//! RFC 9369: QUIC Version 2

const std = @import("std");

/// QUIC version 1 constant.
/// RFC 9000 §15: QUIC Version 1
pub const QUIC_V1: u32 = 0x00000001;

/// QUIC version 2 constant.
/// RFC 9369: QUIC Version 2
pub const QUIC_V2: u32 = 0x709a50c4;

/// List of supported QUIC versions in preference order.
pub const SUPPORTED_VERSIONS = [_]u32{ QUIC_V1, QUIC_V2 };

/// Check if a version is supported by this implementation.
/// RFC 9000 §6.1: Sending Version Negotiation Packets
pub fn isSupported(version: u32) bool {
    for (SUPPORTED_VERSIONS) |v| {
        if (v == version) return true;
    }
    return false;
}

/// Check if a version is QUIC v1.
pub fn isV1(version: u32) bool {
    return version == QUIC_V1;
}

/// Check if a version is QUIC v2.
pub fn isV2(version: u32) bool {
    return version == QUIC_V2;
}

/// Parse version from 4-byte big-endian representation.
/// RFC 9000 §17.2: Long Header Packets
pub fn parseVersion(bytes: []const u8) !u32 {
    if (bytes.len < 4) return error.Truncated;
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

/// Encode version to 4-byte big-endian representation.
/// RFC 9000 §17.2: Long Header Packets
pub fn encodeVersion(version: u32) [4]u8 {
    return .{
        @as(u8, @intCast((version >> 24) & 0xff)),
        @as(u8, @intCast((version >> 16) & 0xff)),
        @as(u8, @intCast((version >> 8) & 0xff)),
        @as(u8, @intCast(version & 0xff)),
    };
}

/// Decoded representation of a Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet
pub const DecodedVN = struct {
    dcid: []const u8,
    scid: []const u8,
    versions: []const u32,
};

/// Encode a Version Negotiation (VN) packet with Version=0 and provided version list.
/// RFC 9000 §6.2: Handling Version Negotiation Packets
/// RFC 9000 §17.2.1: Version Negotiation Packet Format
/// Returned slice is owned by alloc.
pub fn encodeVersionNegotiation(alloc: std.mem.Allocator, dcid: []const u8, scid: []const u8, versions: []const u32) ![]u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    // Long Header bit set + fixed bit set (0x80)
    try w.writeByte(0x80);

    // Version = 0x00000000 for Version Negotiation
    try w.writeAll(&[_]u8{ 0, 0, 0, 0 });

    // DCID Len + DCID
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);

    // SCID Len + SCID
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);

    // Supported versions (4-byte big-endian each)
    for (versions) |v| {
        const be = encodeVersion(v);
        try w.writeAll(&be);
    }

    return buf.toOwnedSlice(alloc);
}

/// Decode a Version Negotiation (VN) packet (Version=0x00000000).
/// RFC 9000 §17.2.1: Version Negotiation Packet
/// Returns slices into the original packet_bytes; caller must keep it alive.
pub fn decodeVersionNegotiation(alloc: std.mem.Allocator, packet_bytes: []const u8) !DecodedVN {
    if (packet_bytes.len < 7) return error.Truncated;

    var i: usize = 0;
    const first = packet_bytes[i];
    i += 1;

    // Must be long form
    if ((first & 0x80) == 0) return error.InvalidHeader;

    // Version must be 0
    if (i + 4 > packet_bytes.len) return error.Truncated;
    const ver = try parseVersion(packet_bytes[i..]);
    i += 4;
    if (ver != 0) return error.NotVersionNegotiation;

    // DCID
    if (i >= packet_bytes.len) return error.Truncated;
    const dcid_len: usize = packet_bytes[i];
    i += 1;
    if (i + dcid_len > packet_bytes.len) return error.Truncated;
    const dcid = packet_bytes[i .. i + dcid_len];
    i += dcid_len;

    // SCID
    if (i >= packet_bytes.len) return error.Truncated;
    const scid_len: usize = packet_bytes[i];
    i += 1;
    if (i + scid_len > packet_bytes.len) return error.Truncated;
    const scid = packet_bytes[i .. i + scid_len];
    i += scid_len;

    // Versions: 4-byte big-endian values till end
    if ((packet_bytes.len - i) % 4 != 0) return error.MalformedVersions;
    const count = (packet_bytes.len - i) / 4;

    var vers = try alloc.alloc(u32, count);
    errdefer alloc.free(vers);

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const o = i + idx * 4;
        vers[idx] = try parseVersion(packet_bytes[o..]);
    }

    return .{ .dcid = dcid, .scid = scid, .versions = vers };
}

/// Basic downgrade protection per RFC 9000 §6.1: ignore VN if it lists the
/// version originally attempted by the client.
/// RFC 9000 §6.2: Handling Version Negotiation Packets
/// Returns true if the VN packet should be accepted (original version not in list).
pub fn shouldAcceptVersionNegotiation(original_version: u32, vn_versions: []const u32) bool {
    for (vn_versions) |v| {
        if (v == original_version) return false;
    }
    return true;
}

/// Validate a Version Negotiation packet.
/// RFC 9000 §6.2: Handling Version Negotiation Packets
/// Returns true if valid and should be processed.
pub fn validateVersionNegotiation(
    original_version: u32,
    original_dcid: []const u8,
    original_scid: []const u8,
    vn_dcid: []const u8,
    vn_scid: []const u8,
    vn_versions: []const u32,
) bool {
    // Check downgrade protection
    if (!shouldAcceptVersionNegotiation(original_version, vn_versions)) {
        return false;
    }

    // Verify DCID and SCID match (RFC 9000 §6.2)
    if (!std.mem.eql(u8, original_dcid, vn_scid)) return false;
    if (!std.mem.eql(u8, original_scid, vn_dcid)) return false;

    // Check if any supported version is offered
    for (vn_versions) |v| {
        if (isSupported(v)) return true;
    }

    return false;
}

/// Select best supported version from a list of offered versions.
/// RFC 9000 §6.2: Handling Version Negotiation Packets
/// Returns the first supported version in preference order, or null if none supported.
pub fn selectVersion(offered_versions: []const u32) ?u32 {
    for (SUPPORTED_VERSIONS) |supported| {
        for (offered_versions) |offered| {
            if (supported == offered) return supported;
        }
    }
    return null;
}
