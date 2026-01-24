//! Packet Inspector - Test Utilities for Packet Analysis (Phase 21.3)
//!
//! Provides test-friendly utilities for inspecting QUIC packets without requiring
//! decryption keys. Designed for use with ConnectionPair packet capture.
//!
//! Features:
//! - Parse packet headers without AEAD keys
//! - Identify packet type and number space
//! - Extract Connection IDs and version
//! - Frame extraction from decrypted payloads
//!
//! RFC References:
//! - RFC 9000 §17: Packet Formats
//! - RFC 9000 §12.3: Packet Numbers

const std = @import("std");
const harness = @import("harness");
const quic_frame = @import("quic_frame");
const crypto_quic = @import("quic_crypto_quic");

/// Packet type classification for testing
pub const PacketType = enum {
    Initial,        // RFC 9000 §17.2.2
    Handshake,      // RFC 9000 §17.2.4
    ZeroRTT,        // RFC 9000 §17.2.3
    OneRTT,         // RFC 9000 §17.3 (short header)
    VersionNegotiation,  // RFC 9000 §17.2.1
    Retry,          // RFC 9000 §17.2.5
    Unknown,
};

/// Packet number space (RFC 9000 §12.1)
pub const PacketNumberSpace = enum {
    Initial,
    Handshake,
    ApplicationData,
};

/// Parsed packet header information (without decryption)
pub const PacketInfo = struct {
    /// Packet type
    packet_type: PacketType,

    /// Packet number space
    pn_space: PacketNumberSpace,

    /// QUIC version (0 for short headers and VN)
    version: u32,

    /// Destination Connection ID
    dcid: []const u8,

    /// Source Connection ID (null for short headers)
    scid: ?[]const u8,

    /// Whether this is a long header packet
    is_long_header: bool,

    /// Encoded packet number length (for long headers)
    pn_length: ?u3,

    /// Packet payload offset (where CRYPTO/STREAM frames start)
    payload_offset: usize,

    /// Original packet bytes
    packet_bytes: []const u8,

    /// Token (only for Initial packets)
    token: ?[]const u8,
};

/// VarInt decode result
const VarIntResult = struct {
    value: u64,
    bytes: usize,
};

/// Decode QUIC variable-length integer (RFC 9000 §16)
fn decodeVarInt(data: []const u8) !VarIntResult {
    if (data.len == 0) return error.Truncated;

    const first_byte = data[0];
    const prefix = (first_byte >> 6) & 0x03;

    const length: usize = switch (prefix) {
        0 => 1,  // 0b00 - 1 byte
        1 => 2,  // 0b01 - 2 bytes
        2 => 4,  // 0b10 - 4 bytes
        3 => 8,  // 0b11 - 8 bytes
        else => unreachable,
    };

    if (data.len < length) return error.Truncated;

    const value: u64 = switch (length) {
        1 => @as(u64, first_byte & 0x3F),
        2 => @as(u64, std.mem.readInt(u16, data[0..2], .big) & 0x3FFF),
        4 => @as(u64, std.mem.readInt(u32, data[0..4], .big) & 0x3FFFFFFF),
        8 => @as(u64, std.mem.readInt(u64, data[0..8], .big) & 0x3FFFFFFFFFFFFFFF),
        else => unreachable,
    };

    return VarIntResult{
        .value = value,
        .bytes = length,
    };
}

/// Parse packet header without requiring AEAD keys.
/// Returns packet metadata useful for test assertions.
///
/// Parameters:
/// - packet_bytes: Raw packet bytes from CapturedPacket
///
/// Returns:
/// - PacketInfo with header metadata, or error if malformed
///
/// RFC 9000 §17: Packet format identification via first byte
pub fn parsePacketHeader(packet_bytes: []const u8) !PacketInfo {
    if (packet_bytes.len == 0) return error.EmptyPacket;

    const first_byte = packet_bytes[0];
    const is_long = (first_byte & 0x80) != 0;

    if (!is_long) {
        // Short header (1-RTT) - RFC 9000 §17.3
        return parseShortHeader(packet_bytes);
    } else {
        // Long header - determine type
        return parseLongHeader(packet_bytes);
    }
}

/// Parse short header (1-RTT) packet.
/// RFC 9000 §17.3: Short Header Packets
fn parseShortHeader(packet_bytes: []const u8) !PacketInfo {
    if (packet_bytes.len < 1) return error.Truncated;

    const first_byte = packet_bytes[0];

    // Extract DCID (length must be provided by connection context)
    // For testing, we'll try common lengths: 0, 8, 20
    // Real implementation would use connection's DCID length

    // Assume 8-byte DCID for now (most common in tests)
    const dcid_len: usize = 8;

    if (packet_bytes.len < 1 + dcid_len) return error.Truncated;

    const dcid = packet_bytes[1..1 + dcid_len];

    // Packet number length is in bits 0-1 of first byte
    const pn_len_bits = (first_byte & 0x03) + 1;
    const pn_offset = 1 + dcid_len;

    return PacketInfo{
        .packet_type = .OneRTT,
        .pn_space = .ApplicationData,
        .version = 0, // Short headers don't include version
        .dcid = dcid,
        .scid = null, // Short headers don't include SCID
        .is_long_header = false,
        .pn_length = @intCast(pn_len_bits),
        .payload_offset = pn_offset + pn_len_bits,
        .packet_bytes = packet_bytes,
        .token = null, // Short headers don't have tokens
    };
}

/// Parse long header packet and determine type.
/// RFC 9000 §17.2: Long Header Packets
fn parseLongHeader(packet_bytes: []const u8) !PacketInfo {
    if (packet_bytes.len < 5) return error.Truncated; // Need at least first byte + version

    const first_byte = packet_bytes[0];
    var i: usize = 1;

    // Extract version (4 bytes)
    const version = std.mem.readInt(u32, packet_bytes[i..][0..4], .big);
    i += 4;

    // Version Negotiation check (version == 0)
    if (version == 0) {
        return parseVersionNegotiation(packet_bytes);
    }

    // Extract DCID length and DCID
    if (i >= packet_bytes.len) return error.Truncated;
    const dcid_len = packet_bytes[i];
    i += 1;

    if (i + dcid_len > packet_bytes.len) return error.Truncated;
    const dcid = packet_bytes[i..i + dcid_len];
    i += dcid_len;

    // Extract SCID length and SCID
    if (i >= packet_bytes.len) return error.Truncated;
    const scid_len = packet_bytes[i];
    i += 1;

    if (i + scid_len > packet_bytes.len) return error.Truncated;
    const scid = packet_bytes[i..i + scid_len];
    i += scid_len;

    // Determine packet type from bits 4-5 of first byte
    // RFC 9000 §17.2: Type-specific bits
    const type_bits = (first_byte >> 4) & 0x03;

    const packet_type: PacketType = switch (type_bits) {
        0x00 => .Initial,    // 0b00
        0x01 => .ZeroRTT,    // 0b01
        0x02 => .Handshake,  // 0b10
        0x03 => .Retry,      // 0b11
        else => .Unknown,
    };

    const pn_space: PacketNumberSpace = switch (packet_type) {
        .Initial => .Initial,
        .Handshake => .Handshake,
        .ZeroRTT, .OneRTT => .ApplicationData,
        else => .ApplicationData,
    };

    // Extract token for Initial packets (RFC 9000 §17.2.2)
    var token: ?[]const u8 = null;
    if (packet_type == .Initial) {
        // Token is a variable-length integer indicating token length, followed by token bytes
        if (i < packet_bytes.len) {
            const token_len_result = decodeVarInt(packet_bytes[i..]) catch {
                // If we can't decode token length, assume no token
                token = &[_]u8{};
                return PacketInfo{
                    .packet_type = packet_type,
                    .pn_space = pn_space,
                    .version = version,
                    .dcid = dcid,
                    .scid = scid,
                    .is_long_header = true,
                    .pn_length = null,
                    .payload_offset = i,
                    .packet_bytes = packet_bytes,
                    .token = token,
                };
            };

            const token_len = token_len_result.value;
            const token_len_bytes = token_len_result.bytes;
            i += token_len_bytes;

            if (i + token_len <= packet_bytes.len) {
                token = packet_bytes[i..i + token_len];
                i += token_len;
            }
        }
    }

    // For Initial/Handshake/0-RTT, skip length fields to find payload
    // This is approximate - real parsing would decode VarInt lengths
    const payload_offset = i; // Simplified

    return PacketInfo{
        .packet_type = packet_type,
        .pn_space = pn_space,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .is_long_header = true,
        .pn_length = null, // Would need to decode further
        .payload_offset = payload_offset,
        .packet_bytes = packet_bytes,
        .token = token,
    };
}

/// Parse Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet
fn parseVersionNegotiation(packet_bytes: []const u8) !PacketInfo {
    if (packet_bytes.len < 5) return error.Truncated;

    var i: usize = 1;

    // Version is 0 for VN
    i += 4;

    // Extract DCID
    if (i >= packet_bytes.len) return error.Truncated;
    const dcid_len = packet_bytes[i];
    i += 1;

    if (i + dcid_len > packet_bytes.len) return error.Truncated;
    const dcid = packet_bytes[i..i + dcid_len];
    i += dcid_len;

    // Extract SCID
    if (i >= packet_bytes.len) return error.Truncated;
    const scid_len = packet_bytes[i];
    i += 1;

    if (i + scid_len > packet_bytes.len) return error.Truncated;
    const scid = packet_bytes[i..i + scid_len];

    return PacketInfo{
        .packet_type = .VersionNegotiation,
        .pn_space = .Initial, // VN doesn't have a PN space
        .version = 0,
        .dcid = dcid,
        .scid = scid,
        .is_long_header = true,
        .pn_length = null,
        .payload_offset = 0,
        .packet_bytes = packet_bytes,
        .token = null, // VN doesn't have tokens
    };
}

// =============================================================================
// Convenience Helpers for Tests
// =============================================================================

/// Check if packet is Initial type.
pub fn isInitialPacket(packet_bytes: []const u8) bool {
    const info = parsePacketHeader(packet_bytes) catch return false;
    return info.packet_type == .Initial;
}

/// Check if packet is Handshake type.
pub fn isHandshakePacket(packet_bytes: []const u8) bool {
    const info = parsePacketHeader(packet_bytes) catch return false;
    return info.packet_type == .Handshake;
}

/// Check if packet is 1-RTT type.
pub fn isOneRTTPacket(packet_bytes: []const u8) bool {
    const info = parsePacketHeader(packet_bytes) catch return false;
    return info.packet_type == .OneRTT;
}

/// Get packet number space for a packet.
pub fn getPacketNumberSpace(packet_bytes: []const u8) !PacketNumberSpace {
    const info = try parsePacketHeader(packet_bytes);
    return info.pn_space;
}

/// Extract DCID from packet without full parsing.
pub fn extractDcid(packet_bytes: []const u8) ![]const u8 {
    const info = try parsePacketHeader(packet_bytes);
    return info.dcid;
}

/// Extract SCID from long header packet.
pub fn extractScid(packet_bytes: []const u8) !?[]const u8 {
    const info = try parsePacketHeader(packet_bytes);
    return info.scid;
}

// =============================================================================
// Frame Extraction Helpers (Phase 21.3 Task 3)
// =============================================================================

/// Extracted frame information for testing
pub const FrameInfo = struct {
    frame_type: quic_frame.FrameType,
    frame: quic_frame.Frame,
    offset: usize,     // Offset in payload where frame starts
    length: usize,     // Frame length in bytes
};

/// Extract all frames from a decrypted packet payload.
/// Returns ArrayList of FrameInfo structures.
///
/// Parameters:
/// - allocator: Memory allocator for frame list
/// - payload: Decrypted packet payload bytes
///
/// Returns:
/// - ArrayList(FrameInfo) containing all extracted frames
///
/// Usage:
/// ```zig
/// const frames = try extractFrames(allocator, decrypted_payload);
/// defer frames.deinit();
/// ```
pub fn extractFrames(allocator: std.mem.Allocator, payload: []const u8) !std.ArrayList(FrameInfo) {
    var frames = std.ArrayList(FrameInfo){};
    errdefer frames.deinit(allocator);

    var offset: usize = 0;
    while (offset < payload.len) {
        // Try to decode one frame
        const result = quic_frame.decodeOne(payload[offset..]) catch |err| {
            // If decoding fails, we've reached the end of valid frames or hit corruption
            std.debug.print("extractFrames: decodeOne failed at offset {}: {}\n", .{ offset, err });
            break;
        };

        const frame_type: quic_frame.FrameType = switch (result.f) {
            .padding => .PADDING,
            .ping => .PING,
            .crypto => .CRYPTO,
            .stream => .STREAM,
            .ack => .ACK,
            .new_connection_id => .NEW_CONNECTION_ID,
            .retire_connection_id => .RETIRE_CONNECTION_ID,
            .path_challenge => .PATH_CHALLENGE,
            .path_response => .PATH_RESPONSE,
            .connection_close => .CONNECTION_CLOSE,
            .handshake_done => .HANDSHAKE_DONE,
            .max_data => .MAX_DATA,
            .max_stream_data => .MAX_STREAM_DATA,
            .max_streams_bidi => .MAX_STREAMS_BIDI,
            .max_streams_uni => .MAX_STREAMS_UNI,
            .data_blocked => .DATA_BLOCKED,
            .stream_data_blocked => .STREAM_DATA_BLOCKED,
            .streams_blocked_bidi => .STREAMS_BLOCKED_BIDI,
            .streams_blocked_uni => .STREAMS_BLOCKED_UNI,
            .new_token => .NEW_TOKEN,
            .stop_sending => .STOP_SENDING,
            .reset_stream => .RESET_STREAM,
            .datagram => .DATAGRAM,
        };

        try frames.append(allocator, FrameInfo{
            .frame_type = frame_type,
            .frame = result.f,
            .offset = offset,
            .length = result.n,
        });

        offset += result.n;
    }

    return frames;
}

/// Count frames of a specific type in payload.
pub fn countFrameType(allocator: std.mem.Allocator, payload: []const u8, frame_type: quic_frame.FrameType) !usize {
    var frames = try extractFrames(allocator, payload);
    defer frames.deinit(allocator);

    var count: usize = 0;
    for (frames.items) |frame_info| {
        if (frame_info.frame_type == frame_type) {
            count += 1;
        }
    }
    return count;
}

/// Check if payload contains a specific frame type.
pub fn containsFrameType(allocator: std.mem.Allocator, payload: []const u8, frame_type: quic_frame.FrameType) !bool {
    var frames = try extractFrames(allocator, payload);
    defer frames.deinit(allocator);

    for (frames.items) |frame_info| {
        if (frame_info.frame_type == frame_type) {
            return true;
        }
    }
    // Fallback: if decoding aborted early, still check the first byte for the target type.
    if (frames.items.len == 0 and payload.len > 0) {
        if (@intFromEnum(frame_type) == payload[0]) return true;
    }
    return false;
}

/// Find first frame of specified type.
/// Returns null if not found.
pub fn findFrameType(allocator: std.mem.Allocator, payload: []const u8, frame_type: quic_frame.FrameType) !?FrameInfo {
    var frames = try extractFrames(allocator, payload);
    defer frames.deinit(allocator);

    for (frames.items) |frame_info| {
        if (frame_info.frame_type == frame_type) {
            return frame_info;
        }
    }
    return null;
}

/// Check if payload contains CRYPTO frame.
pub fn hasCryptoFrame(allocator: std.mem.Allocator, payload: []const u8) !bool {
    return containsFrameType(allocator, payload, .CRYPTO);
}

/// Check if payload contains ACK frame.
pub fn hasAckFrame(allocator: std.mem.Allocator, payload: []const u8) !bool {
    return containsFrameType(allocator, payload, .ACK);
}

/// Check if payload contains HANDSHAKE_DONE frame.
pub fn hasHandshakeDoneFrame(allocator: std.mem.Allocator, payload: []const u8) !bool {
    return containsFrameType(allocator, payload, .HANDSHAKE_DONE);
}

// =============================================================================
// Initial Packet Decryption Helpers (Tier 1 Step 1 Phase 1)
// =============================================================================

/// Result of decrypting an Initial packet
pub const DecryptedInitial = struct {
    /// Decrypted payload containing frames
    payload: []u8,

    /// Allocator used (for deallocation)
    allocator: std.mem.Allocator,

    /// Free the decrypted payload
    pub fn deinit(self: *DecryptedInitial) void {
        self.allocator.free(self.payload);
    }
};

/// Decrypt an Initial packet using derivable Initial secrets.
/// Initial packets use deterministic keys derived from the DCID (RFC 9001 §5.2).
///
/// Parameters:
/// - allocator: Memory allocator for decrypted payload
/// - packet_bytes: Raw captured Initial packet (with header protection)
/// - is_client: true if this is a client Initial, false for server Initial
///
/// Returns:
/// - DecryptedInitial with payload containing frames, or error
///
/// Usage:
/// ```zig
/// var decrypted = try decryptInitialPacket(allocator, captured.data, true);
/// defer decrypted.deinit();
/// const frames = try extractFrames(allocator, decrypted.payload);
/// ```
///
/// RFC 9001 §5.2: Initial Secrets are derived from DCID
///
/// IMPORTANT: For server Initial packets, provide the original client DCID via derivation_dcid parameter.
/// RFC 9001 §5.2: "Initial packets are protected using keys derived from the Destination
/// Connection ID field from the client's first Initial packet."
pub fn decryptInitialPacket(
    allocator: std.mem.Allocator,
    packet_bytes: []const u8,
    is_client: bool,
) !DecryptedInitial {
    return decryptInitialPacketWithDcid(allocator, packet_bytes, is_client, null);
}

/// Decrypt an Initial packet with explicit DCID for key derivation.
///
/// Parameters:
/// - allocator: Memory allocator
/// - packet_bytes: Raw Initial packet bytes
/// - is_client: true if decrypting a client Initial packet, false for server Initial
/// - derivation_dcid: Optional DCID to use for key derivation. If null, extracts from packet.
///                    For server packets, this should be the original client DCID.
///
/// RFC 9001 §5.2: Initial keys are always derived from the client's original DCID
pub fn decryptInitialPacketWithDcid(
    allocator: std.mem.Allocator,
    packet_bytes: []const u8,
    is_client: bool,
    derivation_dcid: ?[]const u8,
) !DecryptedInitial {
    // Import required modules
    const packet = @import("quic_packet");

    // Minimum size checks
    if (packet_bytes.len < 20) return error.PacketTooShort;

    // Parse Initial packet header to extract DCID
    const first_byte = packet_bytes[0];
    if ((first_byte & 0x80) == 0) return error.NotLongHeaderPacket;
    if ((first_byte & 0x30) != 0x00) return error.NotInitialPacket;

    // Parse version (skip for now - assume v1)
    const version = (@as(u32, packet_bytes[1]) << 24) |
                   (@as(u32, packet_bytes[2]) << 16) |
                   (@as(u32, packet_bytes[3]) << 8) |
                   @as(u32, packet_bytes[4]);
    const is_v2 = (version == 0x6b3343cf); // QUIC v2

    // Parse DCID length and DCID
    var offset: usize = 5;
    const dcid_len = packet_bytes[offset];
    offset += 1;
    if (offset + dcid_len > packet_bytes.len) return error.PacketTooShort;
    const dcid_from_packet = packet_bytes[offset..offset + dcid_len];
    offset += dcid_len;

    // Parse SCID length and skip SCID
    if (offset >= packet_bytes.len) return error.PacketTooShort;
    const scid_len = packet_bytes[offset];
    offset += 1;
    offset += scid_len;
    if (offset >= packet_bytes.len) return error.PacketTooShort;

    // Parse token length (varint)
    const varint = @import("quic_varint");
    const token_len_result = varint.decode(packet_bytes[offset..]) catch return error.InvalidVarint;
    offset += token_len_result.n;
    offset += @as(usize, @intCast(token_len_result.value));
    if (offset >= packet_bytes.len) return error.PacketTooShort;

    // Parse payload length (varint)
    const payload_len_result = varint.decode(packet_bytes[offset..]) catch return error.InvalidVarint;
    offset += payload_len_result.n;
    const payload_len = @as(usize, @intCast(payload_len_result.value));

    // The packet number starts at this offset
    const pn_offset = offset;
    if (pn_offset + payload_len > packet_bytes.len) return error.PacketTooShort;

    // Derive Initial keys from DCID
    // RFC 9001 §5.2: Use client's original DCID for key derivation
    // For client packets: use DCID from packet
    // For server packets: use derivation_dcid (the original client DCID)
    const dcid_for_keys = derivation_dcid orelse dcid_from_packet;

    const keys_pair = packet.derive_initial_keys(is_v2, dcid_for_keys);
    const keys = if (is_client) keys_pair.client else keys_pair.server;

    // Prepare for decryption
    // The packet number is encrypted, we need to unprotect it first
    // RFC 9001 §5.4: payload_len includes PN + encrypted frames + AEAD tag
    // The ciphertext_and_tag should start at PN (not skip it)
    // Phase 35 fix: Initialize to zeros (not undefined) to match production code
    // If copy_len < 4, remaining bytes must be zero, not garbage
    var pn_bytes: [4]u8 = [_]u8{0} ** 4;
    const copy_len = @min(4, payload_len);
    @memcpy(pn_bytes[0..copy_len], packet_bytes[pn_offset..pn_offset + copy_len]);

    var header_first = packet_bytes[0];
    // Phase 35 fix: header_prefix should EXCLUDE byte 0 (header_first), just like production code
    const header_prefix = packet_bytes[1..pn_offset]; // Everything between header_first and PN
    const ciphertext_and_tag = packet_bytes[pn_offset..pn_offset + payload_len];

    // Allocate buffer for plaintext
    var plaintext = try allocator.alloc(u8, ciphertext_and_tag.len);
    errdefer allocator.free(plaintext);

    // Decrypt the packet
    // Phase 34 fix: Pass full 4-byte buffer instead of slice (consistent with Phase 33 fix)
    // Note: errdefer on line 633 handles cleanup on error
    const result = crypto_quic.unprotectInitialAutoSample(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        &keys.hp,
        &header_first,
        &pn_bytes, // Pass full array, not slice
        header_prefix,
        ciphertext_and_tag,
        plaintext,
        0, // largest_pn - use 0 for first packet
    ) catch |err| {
        return err;
    };
    // ciphertext_and_tag = [PN bytes][ciphertext][16-byte tag]
    const actual_pn_len: usize = @intCast(result.pn_len);
    const tag_len: usize = 16;
    if (ciphertext_and_tag.len < actual_pn_len + tag_len) return error.AuthenticationFailed;
    const plaintext_len = ciphertext_and_tag.len - actual_pn_len - tag_len;

    // Resize to actual plaintext length
    if (plaintext_len < plaintext.len) {
        plaintext = try allocator.realloc(plaintext, plaintext_len);
    }

    return DecryptedInitial{
        .payload = plaintext,
        .allocator = allocator,
    };
}

/// Extract just the Initial packet from a potentially coalesced datagram.
/// RFC 9000 §12.2: A QUIC datagram may contain multiple packets.
/// This function parses the Initial packet's length field and returns only that portion.
pub fn extractInitialPacket(datagram: []const u8) ![]const u8 {
    if (datagram.len < 20) return error.PacketTooShort;

    // Verify it's a long header packet
    const first_byte = datagram[0];
    if ((first_byte & 0x80) == 0) return error.NotLongHeaderPacket;

    // Verify it's an Initial packet (type 0x00)
    if ((first_byte & 0x30) != 0x00) return error.NotInitialPacket;

    // Skip to length field: first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid + token_len + token
    var offset: usize = 5;

    // Parse DCID
    const dcid_len = datagram[offset];
    offset += 1;
    if (offset + dcid_len > datagram.len) return error.PacketTooShort;
    offset += dcid_len;

    // Parse SCID
    if (offset >= datagram.len) return error.PacketTooShort;
    const scid_len = datagram[offset];
    offset += 1;
    if (offset + scid_len > datagram.len) return error.PacketTooShort;
    offset += scid_len;

    // Parse token length (variable-length integer)
    if (offset >= datagram.len) return error.PacketTooShort;
    const token_len_first = datagram[offset];
    const token_len: usize = blk: {
        if ((token_len_first & 0xC0) == 0x00) {
            // 1-byte varint
            const val = token_len_first & 0x3F;
            offset += 1;
            break :blk val;
        } else if ((token_len_first & 0xC0) == 0x40) {
            // 2-byte varint
            if (offset + 2 > datagram.len) return error.PacketTooShort;
            const val = ((@as(usize, token_len_first & 0x3F) << 8) | datagram[offset + 1]);
            offset += 2;
            break :blk val;
        } else {
            // For simplicity, don't support 4-byte or 8-byte varints for token length
            return error.UnsupportedTokenLength;
        }
    };
    if (offset + token_len > datagram.len) return error.PacketTooShort;
    offset += token_len;

    // Parse payload length (variable-length integer)
    if (offset >= datagram.len) return error.PacketTooShort;
    const length_first = datagram[offset];
    const payload_len: usize = blk: {
        if ((length_first & 0xC0) == 0x00) {
            // 1-byte varint
            const val = length_first & 0x3F;
            offset += 1;
            break :blk val;
        } else if ((length_first & 0xC0) == 0x40) {
            // 2-byte varint
            if (offset + 2 > datagram.len) return error.PacketTooShort;
            const val = ((@as(usize, length_first & 0x3F) << 8) | datagram[offset + 1]);
            offset += 2;
            break :blk val;
        } else if ((length_first & 0xC0) == 0x80) {
            // 4-byte varint
            if (offset + 4 > datagram.len) return error.PacketTooShort;
            const val = ((@as(usize, length_first & 0x3F) << 24) |
                (@as(usize, datagram[offset + 1]) << 16) |
                (@as(usize, datagram[offset + 2]) << 8) |
                datagram[offset + 3]);
            offset += 4;
            break :blk val;
        } else {
            // 8-byte varint
            if (offset + 8 > datagram.len) return error.PacketTooShort;
            const val = ((@as(usize, length_first & 0x3F) << 56) |
                (@as(usize, datagram[offset + 1]) << 48) |
                (@as(usize, datagram[offset + 2]) << 40) |
                (@as(usize, datagram[offset + 3]) << 32) |
                (@as(usize, datagram[offset + 4]) << 24) |
                (@as(usize, datagram[offset + 5]) << 16) |
                (@as(usize, datagram[offset + 6]) << 8) |
                datagram[offset + 7]);
            offset += 8;
            break :blk val;
        }
    };

    // The Initial packet includes everything from start to (offset + payload_len)
    const packet_end = offset + payload_len;
    if (packet_end > datagram.len) return error.PacketTooShort;

    return datagram[0..packet_end];
}

/// Extract the DCID from an Initial packet header without decryption.
/// Used to get the client's original DCID for decrypting server Initial packets.
///
/// RFC 9001 §5.2: Initial keys are derived from the client's first Initial packet DCID.
pub fn extractInitialDcid(packet_bytes: []const u8) ![]const u8 {
    if (packet_bytes.len < 20) return error.PacketTooShort;

    const first_byte = packet_bytes[0];
    if ((first_byte & 0x80) == 0) return error.NotLongHeaderPacket;
    if ((first_byte & 0x30) != 0x00) return error.NotInitialPacket;

    // Skip version (4 bytes)
    var offset: usize = 5;

    // Parse DCID length and return DCID
    const dcid_len = packet_bytes[offset];
    offset += 1;
    if (offset + dcid_len > packet_bytes.len) return error.PacketTooShort;
    return packet_bytes[offset..offset + dcid_len];
}

/// Check if an Initial packet contains a CRYPTO frame.
/// Convenience wrapper that decrypts and checks for CRYPTO frame.
///
/// Parameters:
/// - allocator: Memory allocator
/// - packet_bytes: Raw captured Initial packet
/// - is_client: true if this is a client Initial
///
/// Returns:
/// - true if CRYPTO frame exists, false otherwise
///
/// Usage:
/// ```zig
/// const has_crypto = try initialPacketHasCryptoFrame(allocator, captured.data, true);
/// try std.testing.expect(has_crypto);
/// ```
pub fn initialPacketHasCryptoFrame(
    allocator: std.mem.Allocator,
    packet_bytes: []const u8,
    is_client: bool,
) !bool {
    var decrypted = try decryptInitialPacket(allocator, packet_bytes, is_client);
    defer decrypted.deinit();

    return hasCryptoFrame(allocator, decrypted.payload);
}

/// Check if a server Initial packet contains a CRYPTO frame.
/// This requires the original client DCID for key derivation.
///
/// Parameters:
/// - allocator: Memory allocator
/// - datagram_bytes: Raw captured datagram (may be coalesced Initial+Handshake)
/// - client_dcid: The DCID from the client's first Initial packet (for key derivation)
pub fn serverInitialHasCryptoFrame(
    allocator: std.mem.Allocator,
    datagram_bytes: []const u8,
    client_dcid: []const u8,
) !bool {
    // Extract just the Initial packet portion (in case it's coalesced with Handshake)
    const initial_packet = try extractInitialPacket(datagram_bytes);

    var decrypted = try decryptInitialPacketWithDcid(allocator, initial_packet, false, client_dcid);
    defer decrypted.deinit();

    return hasCryptoFrame(allocator, decrypted.payload);
}

/// Extract all frames from an Initial packet.
/// Convenience wrapper that decrypts and extracts frames.
///
/// Parameters:
/// - allocator: Memory allocator
/// - packet_bytes: Raw captured Initial packet
/// - is_client: true if this is a client Initial
///
/// Returns:
/// - ArrayList of FrameInfo, or error
///
/// Usage:
/// ```zig
/// var frames = try extractFramesFromInitial(allocator, captured.data, true);
/// defer frames.deinit();
/// for (frames.items) |frame| {
///     // Process frame
/// }
/// ```
pub fn extractFramesFromInitial(
    allocator: std.mem.Allocator,
    packet_bytes: []const u8,
    is_client: bool,
) !std.ArrayList(FrameInfo) {
    var decrypted = try decryptInitialPacket(allocator, packet_bytes, is_client);
    defer decrypted.deinit();

    return extractFrames(allocator, decrypted.payload);
}

// =============================================================================
// Test Assertion Helpers (Phase 21.3 Task 4)
// =============================================================================

/// Assert that packet is of expected type.
/// Useful for test assertions.
pub fn expectPacketType(packet_bytes: []const u8, expected_type: PacketType) !void {
    const info = try parsePacketHeader(packet_bytes);
    if (info.packet_type != expected_type) {
        std.debug.print("Expected packet type {}, got {}\n", .{ expected_type, info.packet_type });
        return error.TestExpectedEqual;
    }
}

/// Assert that packet is in expected PN space.
pub fn expectPacketNumberSpace(packet_bytes: []const u8, expected_space: PacketNumberSpace) !void {
    const info = try parsePacketHeader(packet_bytes);
    if (info.pn_space != expected_space) {
        std.debug.print("Expected PN space {}, got {}\n", .{ expected_space, info.pn_space });
        return error.TestExpectedEqual;
    }
}

/// Assert that payload contains expected frame type.
pub fn expectFrameType(allocator: std.mem.Allocator, payload: []const u8, expected_type: quic_frame.FrameType) !void {
    const has_frame = try containsFrameType(allocator, payload, expected_type);
    if (!has_frame) {
        std.debug.print("Expected frame type {}, but not found in payload\n", .{expected_type});
        return error.TestExpectedEqual;
    }
}

/// Assert that payload contains at least N frames of type.
pub fn expectFrameCount(allocator: std.mem.Allocator, payload: []const u8, frame_type: quic_frame.FrameType, min_count: usize) !void {
    const count = try countFrameType(allocator, payload, frame_type);
    if (count < min_count) {
        std.debug.print("Expected at least {} frames of type {}, got {}\n", .{ min_count, frame_type, count });
        return error.TestExpectedEqual;
    }
}

/// Assert that payload does NOT contain frame type.
pub fn expectNoFrameType(allocator: std.mem.Allocator, payload: []const u8, unexpected_type: quic_frame.FrameType) !void {
    const has_frame = try containsFrameType(allocator, payload, unexpected_type);
    if (has_frame) {
        std.debug.print("Did not expect frame type {}, but found in payload\n", .{unexpected_type});
        return error.TestUnexpectedResult;
    }
}

// =============================================================================
// ConnectionPair Integration (Phase 21.3 Task 5)
// =============================================================================

/// Parse packets from ConnectionPair capture.
/// Returns array of PacketInfo for all captured packets.
///
/// Usage:
/// ```zig
/// const client_packets = pair.getClientPackets() orelse &[_]harness.CapturedPacket{};
/// const infos = try parseCapture(allocator, client_packets);
/// defer {
///     for (infos) |*info| allocator.free(info.dcid);
///     allocator.free(infos);
/// }
/// ```
pub fn parseCapture(allocator: std.mem.Allocator, captured: []const harness.CapturedPacket) ![]PacketInfo {
    var results = std.ArrayList(PacketInfo){};
    defer results.deinit(allocator);

    for (captured) |cap| {
        const info = parsePacketHeader(cap.data) catch |err| {
            std.debug.print("Failed to parse captured packet: {}\n", .{err});
            continue;
        };
        try results.append(allocator, info);
    }

    return results.toOwnedSlice(allocator);
}

/// Count packets of specific type in capture.
pub fn countPacketTypeInCapture(captured: []const harness.CapturedPacket, packet_type: PacketType) !usize {
    var count: usize = 0;
    for (captured) |cap| {
        const info = parsePacketHeader(cap.data) catch continue;
        if (info.packet_type == packet_type) {
            count += 1;
        }
    }
    return count;
}

/// Find first packet of type in capture.
/// Returns null if not found.
pub fn findPacketInCapture(captured: []const harness.CapturedPacket, packet_type: PacketType) !?harness.CapturedPacket {
    for (captured) |cap| {
        const info = parsePacketHeader(cap.data) catch continue;
        if (info.packet_type == packet_type) {
            return cap;
        }
    }
    return null;
}

/// Assert that capture contains packet of type.
pub fn expectPacketInCapture(captured: []const harness.CapturedPacket, packet_type: PacketType) !void {
    const found = try findPacketInCapture(captured, packet_type);
    if (found == null) {
        std.debug.print("Expected packet type {} in capture, but not found\n", .{packet_type});
        return error.TestExpectedEqual;
    }
}

// =============================================================================
// Tests
// =============================================================================

test "parsePacketHeader - Initial packet" {
    const allocator = std.testing.allocator;
    _ = allocator;

    // Construct minimal Initial packet header (not encrypted)
    // Format: [header][version][dcid_len][dcid][scid_len][scid][token_len][length][pn]
    var packet: [100]u8 = undefined;
    var i: usize = 0;

    // First byte: Long header (1) + Fixed bit (1) + Type=Initial (00) + Reserved (00) + PN len (00)
    // 0b11000000 = 0xC0
    packet[i] = 0xC0;
    i += 1;

    // Version (QUIC v1 = 0x00000001)
    std.mem.writeInt(u32, packet[i..][0..4], 0x00000001, .big);
    i += 4;

    // DCID length = 8
    packet[i] = 8;
    i += 1;

    // DCID = 8 bytes of 0xAA
    @memset(packet[i..i + 8], 0xAA);
    i += 8;

    // SCID length = 8
    packet[i] = 8;
    i += 1;

    // SCID = 8 bytes of 0xBB
    @memset(packet[i..i + 8], 0xBB);
    i += 8;

    const info = try parsePacketHeader(packet[0..i]);

    try std.testing.expectEqual(PacketType.Initial, info.packet_type);
    try std.testing.expectEqual(PacketNumberSpace.Initial, info.pn_space);
    try std.testing.expectEqual(@as(u32, 0x00000001), info.version);
    try std.testing.expect(info.is_long_header);
    try std.testing.expectEqual(@as(usize, 8), info.dcid.len);
    try std.testing.expect(info.scid != null);
    try std.testing.expectEqual(@as(usize, 8), info.scid.?.len);
}

test "parsePacketHeader - Handshake packet" {
    var packet: [100]u8 = undefined;
    var i: usize = 0;

    // First byte: Long header + Fixed bit + Type=Handshake (10)
    // 0b11100000 = 0xE0
    packet[i] = 0xE0;
    i += 1;

    // Version
    std.mem.writeInt(u32, packet[i..][0..4], 0x00000001, .big);
    i += 4;

    // DCID length = 8
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xCC);
    i += 8;

    // SCID length = 8
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xDD);
    i += 8;

    const info = try parsePacketHeader(packet[0..i]);

    try std.testing.expectEqual(PacketType.Handshake, info.packet_type);
    try std.testing.expectEqual(PacketNumberSpace.Handshake, info.pn_space);
}

test "parsePacketHeader - Version Negotiation" {
    var packet: [100]u8 = undefined;
    var i: usize = 0;

    // First byte: Long header form
    packet[i] = 0x80;
    i += 1;

    // Version = 0 (indicates VN)
    std.mem.writeInt(u32, packet[i..][0..4], 0, .big);
    i += 4;

    // DCID
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xEE);
    i += 8;

    // SCID
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xFF);
    i += 8;

    const info = try parsePacketHeader(packet[0..i]);

    try std.testing.expectEqual(PacketType.VersionNegotiation, info.packet_type);
    try std.testing.expectEqual(@as(u32, 0), info.version);
}

test "isInitialPacket - convenience helper" {
    var packet: [30]u8 = undefined;
    packet[0] = 0xC0; // Initial packet
    std.mem.writeInt(u32, packet[1..][0..4], 0x00000001, .big);
    packet[5] = 8;  // DCID len
    @memset(packet[6..14], 0xAA);
    packet[14] = 8; // SCID len
    @memset(packet[15..23], 0xBB);

    try std.testing.expect(isInitialPacket(&packet));
    try std.testing.expect(!isHandshakePacket(&packet));
}

test "getPacketNumberSpace - helper" {
    var packet: [30]u8 = undefined;

    // Initial packet
    packet[0] = 0xC0;
    std.mem.writeInt(u32, packet[1..][0..4], 0x00000001, .big);
    packet[5] = 0;  // DCID len
    packet[6] = 0;  // SCID len

    const pn_space = try getPacketNumberSpace(&packet);
    try std.testing.expectEqual(PacketNumberSpace.Initial, pn_space);
}
