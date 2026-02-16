// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Common QUIC packet types and constants.
//!
//! RFC 9000 §17: Packet Formats
//! RFC 9001 §5: Packet Protection

const std = @import("std");

/// Packet number type alias.
/// RFC 9000 §12.3: Packet numbers are integers in the range 0 to 2^62-1.
pub const PacketNumber = u64;

/// Long header type discriminator used when encoding/decoding.
/// RFC 9000 §17.2: Long Header Packet Types
pub const LongHeaderType = enum {
    Initial, // 0x00 - RFC 9000 §17.2.2
    Handshake, // 0x02 - RFC 9000 §17.2.4
};

// NOTE: AeadKeys and InitialKeys are defined in legacy packet.zig
// and re-exported by the coordinator module to maintain compatibility

/// Result of decoding a protected short header packet.
/// RFC 9000 §17.3: Short Header Packets (1-RTT)
pub const DecodedShort = struct {
    packet_number: u64, // Expanded packet number
    packet_number_len: u3, // Original encoded length (1-4 bytes)
    payload: []u8, // Decrypted payload
};

/// Result of decoding an Initial packet.
/// RFC 9000 §17.2.2: Initial Packet
pub const DecodedInitial = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u32,
    packet_number_len: u3,
    payload: []u8, // Decrypted payload
};

/// Result of decoding a Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet
pub const DecodedVN = struct {
    dcid: []const u8,
    scid: []const u8,
    versions: []u32,
};

/// QUIC version 1 constant.
/// RFC 9000 §15: QUIC Version 1
pub const QUIC_V1: u32 = 0x00000001;

/// QUIC version 2 constant.
/// RFC 9369: QUIC Version 2
pub const QUIC_V2: u32 = 0x709a50c4;
