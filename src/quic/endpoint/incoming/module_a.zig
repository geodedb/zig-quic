const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const key_schedule = @import("vendor_ztls_key_schedule");
const crypto = @import("crypto_quic");
const frame = @import("frame");
const frame_handler = @import("frame_handler");
const handshake_integration = @import("handshake_integration");
const lookup = @import("lookup");
const varint = @import("varint");

fn addDcidCandidate(len: u8, list: []u8, count: *usize, max_len: u8) void {
    if (len > max_len) return;
    var idx: usize = 0;
    while (idx < count.*) : (idx += 1) {
        if (list[idx] == len) return;
    }
    list[count.*] = len;
    count.* += 1;
}

pub const DcidLengthResult = struct {
    /// Successfully decoded packet, or null if all lengths failed
    decoded: ?packet.DecodedShort,
    /// DCID length that succeeded, or 0 if all failed
    dcid_len: u8,
    /// Whether connection appears to be stateless reset
    is_stateless_reset: bool,
};

/// Enumerate DCID lengths to decrypt short header packet (Bug #6 fix).
/// Extracted from endpoint.zig lines 1236-1264 (Phase 4b.5 Session 3).
///
/// RFC 9000 §17.2-17.3: Short headers omit DCID length field.
/// The length must be discovered via matching heuristics or enumeration.
///
/// Strategy:
/// 1. Try the provided `initial_dcid_len` first (cached or connection-matched)
/// 2. Check for stateless reset token if initial decryption fails
/// 3. Systematically enumerate all DCID lengths 0-20 until one succeeds
/// 4. Return successful decode result and discovered length
///
/// This fixes Bug #6 where incorrect DCID length assumptions caused packet drops.
///
/// Parameters:
/// - allocator: Allocator for packet decoding
/// - packet_bytes: Raw short header packet bytes
/// - initial_dcid_len: Initial DCID length to try (from cache or connection match)
/// - app_rx_keys: Application-level RX keys for decryption
/// - largest_pn: Largest packet number seen (for PN reconstruction)
/// - conn: Connection pointer (for stateless reset check only)
///
/// Returns: DcidLengthResult with decoded packet, dcid_len, and stateless reset flag
pub fn enumerateDcidLength(
    allocator: std.mem.Allocator,
    packet_bytes: []const u8,
    initial_dcid_len: usize,
    app_rx_keys: packet.AeadKeys,
    largest_pn: u64,
    conn: ?*conn_mod.Connection,
) DcidLengthResult {
    logger.debugPrint("[ENUM-SHORT] Start enumerateDcidLength initial_len={} bytes_len={} largest_pn={}\n", .{ initial_dcid_len, packet_bytes.len, largest_pn });
    var payload_scratch: [4096]u8 = undefined;

    // Try initial length first
    if (packet.decodeShortProtectedInto(
        packet_bytes,
        initial_dcid_len,
        .{ .key = app_rx_keys.key, .iv = app_rx_keys.iv, .hp = app_rx_keys.hp },
        largest_pn,
        payload_scratch[0..],
    )) |result| {
        const owned_payload = allocator.alloc(u8, result.payload.len) catch return .{
            .decoded = null,
            .dcid_len = 0,
            .is_stateless_reset = false,
        };
        @memcpy(owned_payload, result.payload);
        return .{
            .decoded = .{
                .packet_number = result.packet_number,
                .packet_number_len = result.packet_number_len,
                .payload = owned_payload,
                .key_phase = result.key_phase,
            },
            .dcid_len = @intCast(initial_dcid_len),
            .is_stateless_reset = false,
        };
    } else |_| {
        // Check for stateless reset token to fail fast
        if (conn) |c| {
            if (c.looksLikeStatelessReset(packet_bytes)) {
                return .{
                    .decoded = null,
                    .dcid_len = 0,
                    .is_stateless_reset = true,
                };
            }
        }

        // Bug #6 fix: Enumerate all DCID lengths 0-20 systematically
        var test_len: u8 = 0;
        while (test_len <= 20) : (test_len += 1) {
            if (test_len == initial_dcid_len) {
                // Already tried this length above
                continue;
            }

            if (packet.decodeShortProtectedInto(
                packet_bytes,
                test_len,
                .{ .key = app_rx_keys.key, .iv = app_rx_keys.iv, .hp = app_rx_keys.hp },
                largest_pn,
                payload_scratch[0..],
            )) |result| {
                const owned_payload = allocator.alloc(u8, result.payload.len) catch return .{
                    .decoded = null,
                    .dcid_len = 0,
                    .is_stateless_reset = false,
                };
                @memcpy(owned_payload, result.payload);
                // SUCCESS! Return discovered length
                return .{
                    .decoded = .{
                        .packet_number = result.packet_number,
                        .packet_number_len = result.packet_number_len,
                        .payload = owned_payload,
                        .key_phase = result.key_phase,
                    },
                    .dcid_len = test_len,
                    .is_stateless_reset = false,
                };
            } else |_| {
                // This length didn't work, continue trying
            }
        }

        // All lengths 0-20 failed
        return .{
            .decoded = null,
            .dcid_len = 0,
            .is_stateless_reset = false,
        };
    }
}

// =============================================================================
// Phase 4b.5 Session 5: Initial Packet Header Parsing
// =============================================================================

/// Result of parsing an Initial packet header.
/// Contains the extracted DCID and SCID along with the offset after header parsing.
pub const InitialHeader = struct {
    /// Destination Connection ID bytes
    dcid: []const u8,
    /// Source Connection ID bytes
    scid: []const u8,
    /// Offset in the packet after SCID (points to token length varint)
    offset: usize,
};

/// Parse Initial packet header to extract DCID and SCID.
/// Extracted from endpoint.zig lines 1682-1694 (Phase 4b.5 Session 5).
///
/// RFC 9000 §17.2.2: Initial Packet Format
/// ```
/// Initial Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2) = 0,
///   Reserved Bits (2),
///   Packet Number Length (2),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Token Length (i),
///   Token (..),
///   Length (i),
///   Packet Number (8..32),
///   Packet Payload (..),
/// }
/// ```
///
/// Parameters:
/// - bytes: Raw packet bytes (must be at least 6 bytes: 1 header + 4 version + 1 dcid_len)
///
/// Returns:
/// - InitialHeader with DCID, SCID, and offset after SCID
/// - error.InvalidPacket if packet is malformed or too short
///
/// RFC 9000 §17.2.2: "The Destination Connection ID field is preceded by a
/// one-byte length field that encodes the length of the Connection ID."
pub fn parseInitialHeader(bytes: []const u8) !InitialHeader {
    // Offset starts after: 1 byte header + 4 bytes version = 5
    var i: usize = 5;

    // Parse DCID length (1 byte)
    if (i >= bytes.len) return error.InvalidPacket;
    const dcid_len = bytes[i];
    i += 1;

    // RFC 9000 §17.2: CID length MUST NOT exceed 20 bytes (SF-022)
    if (dcid_len > 20) return error.ProtocolViolation;

    // Parse DCID bytes (0-20 bytes per RFC 9000 §17.2)
    if (i + dcid_len > bytes.len) return error.InvalidPacket;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length (1 byte)
    if (i >= bytes.len) return error.InvalidPacket;
    const scid_len = bytes[i];
    i += 1;

    // RFC 9000 §17.2: CID length MUST NOT exceed 20 bytes (SF-022)
    if (scid_len > 20) return error.ProtocolViolation;

    // Parse SCID bytes (0-20 bytes per RFC 9000 §17.2)
    if (i + scid_len > bytes.len) return error.InvalidPacket;
    const scid = bytes[i .. i + scid_len];
    i += scid_len;

    return InitialHeader{
        .dcid = dcid,
        .scid = scid,
        .offset = i,
    };
}

// =============================================================================
// Phase 4b.5 Session 6: Initial Key Derivation and Packet Decryption
// =============================================================================

/// Result of Initial key derivation.
/// Contains RX and TX keys for role-oriented encryption.
pub const InitialKeys = struct {
    /// RX keys (for decrypting received packets)
    rx_keys: packet.AeadKeys,
    /// TX keys (for encrypting sent packets)
    tx_keys: packet.AeadKeys,
};

/// Derive Initial packet protection keys from the active Initial key epoch DCID.
/// Extracted from endpoint.zig lines 1886-1938 (Phase 4b.5 Session 6).
///
/// RFC 9001 §5.2: Initial keys are derived from the Destination Connection ID in
/// the Initial packet sent by the client. If Retry is used, this changes to the
/// server-selected connection ID carried in the client's post-Retry Initial.
///
/// This function handles role-oriented key derivation:
/// - Server: Derives client keys for RX, server keys for TX
/// - Client: Derives server keys for RX, client keys for TX
///
/// Parameters:
/// - conn: Connection with role and ODCID information
/// - dcid: Current packet DCID (used for post-Retry re-keying on server)
/// - version: QUIC version (v1 or v2)
///
/// Returns:
/// - InitialKeys with rx_keys and tx_keys
///
/// RFC 9001 §5.2: "Initial packets use AEAD_AES_128_GCM with keys derived
/// from the Destination Connection ID field."
pub fn deriveInitialKeys(
    conn: *conn_mod.Connection,
    dcid: []const u8,
    version: u32,
) InitialKeys {
    // RFC 9001 §5.2 keys are bound to the client's Initial key epoch DCID.
    // In non-Retry handshakes this stays the first client Initial DCID even if
    // subsequent packets change destination CID for routing. After a successful
    // Retry token validation, the server re-keys to the post-Retry DCID.
    const derive_dcid = blk: {
        if (conn.role == .Server) {
            if (conn.retry_sent and conn.address_validated) break :blk dcid;
            if (conn.peer_initial_dcid.len > 0) {
                break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
            }
            break :blk dcid;
        }
        if (conn.peer_initial_dcid.len > 0) {
            break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
        }
        break :blk dcid;
    };

    // Check for QUIC v2
    const is_v2 = (version == packet.QUIC_V2);

    // Derive Initial keys based on role
    const keys = packet.initialAeadKeys(is_v2, conn.role == .Server, derive_dcid);

    return InitialKeys{
        .rx_keys = packet.AeadKeys{ .key = keys.rx.key, .iv = keys.rx.iv, .hp = keys.rx.hp },
        .tx_keys = packet.AeadKeys{ .key = keys.tx.key, .iv = keys.tx.iv, .hp = keys.tx.hp },
    };
}

/// Result of Initial packet decryption.
pub const DecryptedInitial = struct {
    /// Decrypted payload (frames)
    payload: []const u8,
    /// Packet number (reconstructed from truncated PN)
    packet_number: u64,
    /// Packet number length (1-4 bytes)
    pn_len: u3,
};

/// Decrypt Initial packet using Initial keys.
/// Extracted from endpoint.zig lines 1940-2089 (Phase 4b.5 Session 6).
///
/// RFC 9001 §5.4: "Packet protection applies confidentiality protection to the
/// contents of the packet. This includes the packet number and the payload."
///
/// This function:
/// 1. Parses token length and token bytes
/// 2. Parses payload length varint
/// 3. Extracts ciphertext (PN + payload + 16-byte AEAD tag)
/// 4. Enumerates PN lengths 1-4 using header protection removal
/// 5. Attempts AEAD decryption for each PN length until success
/// 6. Returns decrypted payload and reconstructed packet number
///
/// Parameters:
/// - allocator: Memory allocator for decrypted payload
/// - bytes: Raw Initial packet bytes
/// - header_offset: Offset after SCID (points to token length varint)
/// - keys: Initial AEAD keys for decryption
/// - largest_pn: Largest packet number seen (for PN reconstruction)
///
/// Returns:
/// - DecryptedInitial with payload, packet_number, pn_len
/// - error.DecryptionFailed if all PN lengths fail
///
/// RFC 9000 §17.2: "The Length field is protected by using the same header
/// protection process as the packet number."
pub fn decryptInitialPacket(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    header_offset: usize,
    keys: packet.AeadKeys,
    largest_pn: u64,
) !DecryptedInitial {
    // Parse token length varint
    var i = header_offset;
    const tok_dec = try varint.decode(bytes[i..]);
    i += tok_dec.n;

    // Skip token bytes
    const tok_len: usize = @intCast(@min(tok_dec.value, bytes.len - i));
    if (i + tok_len > bytes.len) return error.InvalidPacket;
    i += tok_len;

    // Parse payload length varint
    const len_dec = try varint.decode(bytes[i..]);
    i += len_dec.n;

    // Validate payload length
    if (len_dec.value > bytes.len - i) return error.InvalidPacket;
    const end_total = i + @as(usize, @intCast(len_dec.value));

    // Header protection and PN decryption state
    const first_byte = bytes[0];
    const header_prefix = bytes[1..i]; // Everything before PN
    const pn_start = i;
    const ciphertext = bytes[pn_start..end_total];

    // Minimum ciphertext must be: 1 byte PN + 16 byte tag = 17 bytes
    if (ciphertext.len < 17) return error.PacketTooShort;

    // Enumerate PN lengths 1-4 until decryption succeeds
    var pn_len_try: u3 = 1;
    while (pn_len_try <= 4) : (pn_len_try += 1) {
        if (pn_start + pn_len_try > end_total) break;

        // Allocate payload buffer (ciphertext - 16 byte tag)
        const payload = try allocator.alloc(u8, ciphertext.len - 16);
        errdefer allocator.free(payload);

        // Copy masked header and PN bytes
        var header_first = first_byte;
        var pn_masked: [4]u8 = [_]u8{0} ** 4;
        @memcpy(pn_masked[0..@min(4, ciphertext.len)], ciphertext[0..@min(4, ciphertext.len)]);

        // Phase 33 fix: Always pass full 4-byte buffer to allow function to extract actual PN length
        // The function will use actual_pn_len from unmasked header, not buffer size
        const result = crypto.unprotectInitialAutoSample(
            .aes_128_gcm,
            &keys.key,
            &keys.iv,
            &keys.hp,
            &header_first,
            &pn_masked, // Pass full buffer, not slice
            header_prefix,
            ciphertext,
            payload,
            largest_pn,
        ) catch {
            // This PN length didn't work, try next
            allocator.free(payload);
            continue;
        };

        // Calculate correct payload size: ciphertext - pn_len - 16 byte tag
        // The allocated buffer is ciphertext.len - 16, but actual data is smaller
        const actual_pn_len: usize = @intCast(result.pn_len);
        const actual_payload_len = ciphertext.len - actual_pn_len - 16;

        // Resize the buffer to match actual payload length
        // This ensures free() works correctly with the returned slice
        const resized_payload = allocator.realloc(payload, actual_payload_len) catch {
            // Realloc failed - free original and return error
            allocator.free(payload);
            return error.OutOfMemory;
        };

        // Success! Return decrypted packet with correctly-sized payload
        return DecryptedInitial{
            .payload = resized_payload,
            .packet_number = result.packet_number,
            .pn_len = result.pn_len,
        };
    }

    // All PN lengths failed
    return error.DecryptionFailed;
}
