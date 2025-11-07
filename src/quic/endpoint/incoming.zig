//! Incoming packet processing pipeline (RFC 9000 §12-17).
//!
//! This module handles the complete packet ingress path including:
//! - UDP datagram reception (poll loop)
//! - Version negotiation (RFC 9000 §6)
//! - Long header packet processing (Initial, Handshake, 0-RTT)
//! - Short header packet processing (1-RTT Application Data)
//! - Frame dispatching
//! - ECN processing (RFC 3168)
//! - ICMP error handling (PMTUD)
//! - Connection routing and lookup
//! - Coalesced packet handling (RFC 9000 §12.2)
//!
//! RFC References:
//! - RFC 9000 §6: Version Negotiation
//! - RFC 9000 §12: Packets and Frames
//! - RFC 9000 §12.2: Coalescing Packets
//! - RFC 9000 §13: Packetization and Reliability
//! - RFC 9000 §17: Packet Formats
//! - RFC 9001 §5: Packet Protection
//! - RFC 3168: Explicit Congestion Notification (ECN)

const std = @import("std");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const posix = std.posix;

// Phase 4b.5: Modular extraction using focused context structs.
// Functions below use RxContext instead of full Endpoint pointer.

// Inline hash helpers (avoid module dependency on utils.zig)
inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

inline fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    // Hash the raw bytes of the address
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

/// Incoming packet processing functions are currently implemented in endpoint.zig
/// due to extensive dependencies on Endpoint state (socket, connections, config, etc.).
///
/// Usage from tests:
///   const incoming = @import("endpoint/incoming.zig");
///   // Then call via endpoint instance:
///   try endpoint.poll(timeout_ms);
///   endpoint.testInject(peer, packet_bytes);
///
/// The following functions are available via Endpoint methods:
///
/// **poll**(timeout_ms: i32) -> void
///   Main event loop that:
///   - Processes expired timers (PTO, PMTUD, generic)
///   - Waits for socket readability (epoll/kqueue/IOCP)
///   - Drains incoming packets from UDP socket
///   - Processes ICMP error queue (Linux only)
///   - Prunes closed connections
///   RFC 9000 §13: Endpoint drives packet I/O and timer processing.
///
/// **processIncomingDatagram**(peer: SockAddr, bytes: []const u8, ecn_bits: ?u8) -> void
///   Main packet dispatcher that:
///   1. Classifies packet as long/short header
///   2. Routes to appropriate handler:
///      - Version Negotiation (version == 0)
///      - Initial packets (server acceptance or client handshake)
///      - Handshake packets
///      - 0-RTT packets
///      - 1-RTT packets (short header)
///   3. Looks up connection by peer + DCID
///   4. Handles NAT rebinding / connection migration (RFC 9000 §9.3)
///   5. Processes ECN bits if provided
///   RFC 9000 §17: Packet format determines processing path.
///
/// **drainReadable**() -> void
///   Reads all available packets from UDP socket:
///   - Non-blocking recvfrom loop
///   - Extracts ECN bits (Linux recvmsg only)
///   - Calls processIncomingDatagram for each packet
///   - Handles WouldBlock gracefully
///
/// **drainErrorQueue**() -> void (Linux only)
///   Processes ICMP error messages from MSG_ERRQUEUE:
///   - ICMP Packet Too Big (PTB) for PMTUD
///   - Matches quoted packet to connection by DCID
///   - Calls connection's onIcmpPacketTooBig handler
///   RFC 8899 (DPLPMTUD): Path MTU discovery via ICMP feedback.
///
/// **handleIcmpPtb**(peer: SockAddr, quoted_payload: []const u8, reported_mtu: u16) -> void
///   Matches ICMP PTB message to connection:
///   - Scans quoted UDP payload for DCID match
///   - Verifies peer address matches
///   - Updates connection's PMTUD state with new MTU
///   Prevents ICMP spoofing by requiring DCID match.
///
/// **poll_epoll_backend**(timeout_ms: i32) -> void (Linux)
///   Linux-specific event loop using epoll:
///   - epoll_wait for socket readability
///   - Handles EPOLLIN and EPOLLERR events
///   - Falls back to sleep+drain on non-Linux
///
/// **poll_kqueue_backend**(timeout_ms: i32) -> void (BSD/macOS)
///   BSD-specific event loop using kqueue:
///   - kevent for socket readability
///   - Falls back to sleep+drain on non-BSD
///
/// **poll_iocp_backend**(timeout_ms: i32) -> void (Windows)
///   Windows-specific event loop using IOCP:
///   - GetQueuedCompletionStatus for I/O completion
///   - Falls back to sleep+drain on non-Windows
///
/// Version Negotiation (RFC 9000 §6):
///   When a packet arrives with version == 0, it's a Version Negotiation
///   packet from the server. The client:
///   1. Validates the packet is acceptable (shouldAcceptVersionNegotiation)
///   2. Selects a compatible version (v1 or v2)
///   3. Updates connection's version field
///   4. Retransmits Initial packet with new version
///
/// Connection Routing:
///   Short header packets are routed by:
///   1. Peer address hash + DCID hash (normal case)
///   2. Fallback to DCID-only match (NAT rebinding / migration)
///   3. Prefer connections with both RX and TX app keys installed
///   4. Tie-break on longer DCID length
///   RFC 9000 §5.2: "Servers route packets to connections using the DCID."
///
/// Coalesced Packets (RFC 9000 §12.2):
///   Multiple QUIC packets may be coalesced in a single UDP datagram.
///   processIncomingDatagram handles one packet; endpoint must loop
///   to process remaining bytes if datagram contains multiple packets.
///
/// ECN Processing (RFC 3168):
///   If ECN bits are available (via recvmsg on Linux):
///   - Extract 2-bit ECN field from IP TOS/Traffic Class
///   - 0b00: Non-ECT (not capable)
///   - 0b01: ECT(1)
///   - 0b10: ECT(0)
///   - 0b11: CE (Congestion Experienced)
///   Pass to connection for congestion control response.
///
/// Test Helpers:
///   - **testInject**(peer, bytes): Inject packet without ECN
///   - **testInjectWithEcn**(peer, bytes, ecn_bits): Inject with ECN
///   - **testInjectIcmpPtb**(peer, quoted_payload, mtu): Inject ICMP PTB
///
/// Example usage:
/// ```zig
/// var endpoint = Endpoint.init(allocator, config);
/// defer endpoint.deinit();
///
/// // Main event loop
/// while (!shutdown) {
///     try endpoint.poll(100); // Wait up to 100ms
///     // Process accepted connections
///     while (endpoint.popAccepted()) |conn| {
///         handleNewConnection(conn);
///     }
/// }
/// ```

/// Module marker for Phase 4a modular structure.
/// Full implementation extraction is Phase 4b (future work).
pub const extracted = false; // Set to true when implementations are fully extracted

/// For documentation and test organization, these function signatures represent
/// the interface that will eventually be extracted. Currently implemented in endpoint.zig.
pub const Interface = struct {
    /// Main event loop
    pub const PollSignature = fn (timeout_ms: i32) anyerror!void;

    /// Process single incoming datagram
    pub const ProcessIncomingDatagramSignature = fn (peer: @import("quic_conn").SockAddr, bytes: []const u8, ecn_bits: ?u8) void;

    /// Drain all readable packets from socket
    pub const DrainReadableSignature = fn () void;

    /// Process ICMP error queue (Linux only)
    pub const DrainErrorQueueSignature = fn () void;

    /// Handle ICMP Packet Too Big
    pub const HandleIcmpPtbSignature = fn (peer: conn_mod.SockAddr, quoted_payload: []const u8, reported_mtu: u16) void;
};

/// Helper: Check if a packet byte indicates a long header.
/// RFC 9000 §17: "The Header Form bit (0x80) is set to 1 for long headers."
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & 0x80) != 0;
}

/// Helper: Extract ECN bits from IP TOS/Traffic Class byte.
/// RFC 3168: ECN bits are the low 2 bits of the TOS/TC field.
pub fn extractEcnBits(tos_byte: u8) u8 {
    return tos_byte & 0x03;
}

/// Helper: ECN codepoint names for debugging.
pub const EcnCodepoint = enum(u8) {
    NotEct = 0b00, // Not ECN-Capable Transport
    Ect1 = 0b01, // ECN-Capable Transport (1)
    Ect0 = 0b10, // ECN-Capable Transport (0)
    Ce = 0b11, // Congestion Experienced
};

// =============================================================================
// Phase 4b.5: Modular RX Context and Extracted Functions
// =============================================================================

/// Function signature for sending UDP datagrams
pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;

/// Function signature for scheduling timers
pub const ScheduleTimerFn = *const fn (conn: *conn_mod.Connection, kind: endpoint_types.TimerKind, delay_ms: u32) anyerror!u64;

/// Function signature for sending Initial probe (after VN, path migration, etc.)
pub const SendInitialProbeFn = *const fn (conn: *conn_mod.Connection) anyerror!void;

/// Context for RX packet processing - contains only what's needed
/// This focused context replaces passing full Endpoint pointer, enabling
/// better testability and clearer dependency tracking.
pub const RxContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection),
    accepted: *std.ArrayList(*conn_mod.Connection),
    cfg: *const cfg.QuicConfig,
    send_fn: SendFn,
    schedule_timer_fn: ScheduleTimerFn,
    send_initial_probe_fn: SendInitialProbeFn,
    test_capture_enabled: bool,
    endpoint_role: endpoint_types.EndpointRole,
};

/// Helper: Placeholder for IncomingProcessor when needed
pub const IncomingProcessor = struct {
    pub fn init() IncomingProcessor {
        return .{};
    }
};

// =============================================================================
// Extracted RX Pipeline Functions (Phase 4b.5 Session 2 POC)
// =============================================================================

/// Process Version Negotiation packet (RFC 9000 §6).
/// Extracted from endpoint.zig lines 1062-1090 as proof-of-concept.
///
/// Client-side version negotiation:
/// 1. Decode VN packet to get list of supported versions
/// 2. Look up connection by peer hash + DCID/SCID
/// 3. Check if VN should be accepted (RFC 9000 §6.2.1)
/// 4. Select compatible version (v1 or v2)
/// 5. Update connection version and send new Initial probe
///
/// RFC 9000 §6.2: Client receiving VN MUST select a compatible version
/// RFC 9369: QUIC v2 version negotiation
pub fn processVersionNegotiation(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
) void {
    // Arena allocator for temporary VN packet decoding
    var arena = std.heap.ArenaAllocator.init(ctx.allocator.*);
    defer arena.deinit();
    const aa = arena.allocator();

    // Decode Version Negotiation packet
    const vn = packet.decodeVersionNegotiation(aa, bytes) catch return;

    // Look up connection by peer + DCID or SCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    var found: ?*conn_mod.Connection = null;
    const k1 = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.dcid) };
    const k2 = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.scid) };

    if (ctx.conns.getPtr(k1)) |e| {
        found = e.*;
    } else if (ctx.conns.getPtr(k2)) |e2| {
        found = e2.*;
    }

    const c = found orelse return;

    // Check if VN is enabled in config
    if (!ctx.cfg.compatible_vn) return; // Ignore VN when disabled

    // Validate VN packet per RFC 9000 §6.2.1
    if (!packet.shouldAcceptVersionNegotiation(c.initial_version, vn.versions)) return;

    // Select compatible version (prefer v2 over v1 if both offered)
    var chosen: u32 = 0;
    var i_sel: usize = 0;
    while (i_sel < vn.versions.len) : (i_sel += 1) {
        const v = vn.versions[i_sel];
        if (v == packet.QUIC_V1 or v == packet.QUIC_V2) {
            chosen = v;
            break;
        }
    }

    if (chosen == 0) return; // No compatible version found

    // Update connection to use chosen version
    c.version = chosen;
    c.version_v2 = (chosen == packet.QUIC_V2);

    // Send new Initial packet with chosen version
    ctx.send_initial_probe_fn(c) catch {};
}

/// DCID length enumeration result
pub const DcidLengthResult = struct {
    /// Successfully decoded packet, or null if all lengths failed
    decoded: ?packet.DecodedShortProtected,
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
    app_rx_keys: struct { key: []const u8, iv: []const u8, hp: []const u8 },
    largest_pn: u64,
    conn: ?*conn_mod.Connection,
) DcidLengthResult {
    // Try initial length first
    if (packet.decodeShortProtected(
        allocator,
        packet_bytes,
        initial_dcid_len,
        .{ .key = app_rx_keys.key, .iv = app_rx_keys.iv, .hp = app_rx_keys.hp },
        largest_pn,
    )) |result| {
        return .{
            .decoded = result,
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

            if (packet.decodeShortProtected(
                allocator,
                packet_bytes,
                test_len,
                .{ .key = app_rx_keys.key, .iv = app_rx_keys.iv, .hp = app_rx_keys.hp },
                largest_pn,
            )) |result| {
                // SUCCESS! Return discovered length
                return .{
                    .decoded = result,
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

    // Parse DCID bytes (0-20 bytes per RFC 9000 §17.2)
    if (i + dcid_len > bytes.len) return error.InvalidPacket;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length (1 byte)
    if (i >= bytes.len) return error.InvalidPacket;
    const scid_len = bytes[i];
    i += 1;

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

/// Derive Initial packet protection keys from connection ID.
/// Extracted from endpoint.zig lines 1886-1938 (Phase 4b.5 Session 6).
///
/// RFC 9001 §5.2: "The keys used for Initial packets are calculated using the
/// Destination Connection ID field from the client's first Initial packet."
///
/// RFC 9000 §5.2: "After a Retry, the client changes the DCID but MUST continue
/// to use the original DCID (ODCID) for key derivation."
///
/// This function handles role-oriented key derivation:
/// - Server: Derives client keys for RX, server keys for TX
/// - Client: Derives server keys for RX, client keys for TX
///
/// Parameters:
/// - conn: Connection with role and ODCID information
/// - dcid: Destination Connection ID from packet (used if ODCID not yet set)
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
    // Determine which DCID to use for key derivation (ODCID per RFC 9000 §5.2)
    const derive_dcid = blk: {
        if (conn.role == .Server) {
            // Server: Use packet's DCID (client's original DCID)
            // For first packet, original_dcid not yet set
            if (conn.original_dcid.len > 0 and
                conn.original_dcid.len <= conn.original_dcid.bytes.len)
            {
                break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
            }
            // First Initial packet from client - use packet's DCID
            break :blk dcid;
        } else {
            // Client: Must use its own original DCID (never server's)
            if (conn.original_dcid.len > 0 and
                conn.original_dcid.len <= conn.original_dcid.bytes.len)
            {
                break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
            }
            // Error: Client without original_dcid is not properly initialized
            // Return empty keys (caller should handle error)
            break :blk dcid[0..0];
        }
    };

    // Check for QUIC v2
    const is_v2 = (version == packet.QUIC_V2);

    // Derive Initial keys based on role
    const keys = packet.initialAeadKeys(is_v2, conn.role == .Server, derive_dcid);

    return InitialKeys{
        .rx_keys = keys.rx,
        .tx_keys = keys.tx,
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
    const varint = @import("varint");

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
        var payload = try allocator.alloc(u8, ciphertext.len - 16);
        errdefer allocator.free(payload);

        // Copy masked header and PN bytes
        var header_first = first_byte;
        var pn_masked: [4]u8 = [_]u8{0} ** 4;
        @memcpy(pn_masked[0..@min(4, ciphertext.len)], ciphertext[0..@min(4, ciphertext.len)]);

        // Attempt header protection removal and AEAD decryption
        const result = crypto.unprotectInitialAutoSample(
            .aes_128_gcm,
            &keys.key,
            &keys.iv,
            &keys.hp,
            &header_first,
            pn_masked[0..pn_len_try],
            header_prefix,
            ciphertext,
            payload,
            largest_pn,
        ) catch {
            // This PN length didn't work, try next
            allocator.free(payload);
            continue;
        };

        // Success! Return decrypted packet
        return DecryptedInitial{
            .payload = payload,
            .packet_number = result.pn,
            .pn_len = pn_len_try,
        };
    }

    // All PN lengths failed
    return error.DecryptionFailed;
}

/// Process Initial packet with key derivation and decryption.
/// Extracted from endpoint.zig lines 1672-2900 (Phase 4b.5 Sessions 5-6).
///
/// This function handles:
/// 1. Parsing Initial packet header (DCID, SCID) - Session 5
/// 2. Connection lookup or creation - Session 5
/// 3. Token validation for address verification - Session 5
/// 4. Retry packet generation (if configured and address not validated) - Session 5
/// 5. Initial key derivation from ODCID - Session 6
/// 6. Initial packet decryption with PN enumeration - Session 6
/// 7. Frame parsing from decrypted payload - Future session
/// 8. CRYPTO frame processing via handshake_integration - Future session
///
/// RFC 9000 §17.2.2: Initial Packet Format
/// RFC 9000 §8.1: Address Validation
/// RFC 9000 §8.1.1: Address Validation Using Retry Packets
/// RFC 9001 §5.2: Initial Key Derivation
///
/// Parameters:
/// - ctx: RxContext with allocator, connections, config, etc.
/// - peer: Socket address of the client
/// - bytes: Raw Initial packet bytes
/// - version: QUIC version from packet header
///
/// Returns: void (errors are logged but not propagated)
pub fn processInitial(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    version: u32,
) void {
    // Parse Initial header to extract DCID and SCID
    const header = parseInitialHeader(bytes) catch return;

    // Look up connection by peer hash + client DCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(header.dcid) };

    var conn: *conn_mod.Connection = blk: {
        // Check if connection already exists
        if (ctx.conns.getPtr(key)) |p| {
            // Found existing connection
            if (p.*.role == .Server) {
                // Server connection exists, reuse it
                break :blk p.*;
            }
            // Client connection exists - check if we need server twin
            const dcid_is_client_initial = p.*.peer_initial_dcid.len > 0 and
                std.mem.eql(u8, header.dcid, p.*.peer_initial_dcid.bytes[0..p.*.peer_initial_dcid.len]);
            const dcid_is_our_scid = p.*.our_scid.len > 0 and
                std.mem.eql(u8, header.dcid, p.*.our_scid.bytes[0..p.*.our_scid.len]);

            if (dcid_is_client_initial and !dcid_is_our_scid) {
                // Need to create server twin for single-endpoint test scenario
                // Fall through to connection creation
            } else {
                // Reuse existing client connection
                break :blk p.*;
            }
        }

        // No suitable connection exists - create new server connection
        // Only server endpoints should create server connections
        if (ctx.endpoint_role == .Client) {
            return; // Client endpoints don't create server connections
        }

        // Create ServerContext
        const server_mod = @import("server.zig");
        var server_ctx = server_mod.ServerContext{
            .allocator = ctx.allocator,
            .conns = ctx.conns,
            .cfg = ctx.cfg,
            .sock_fd = @intCast(0), // Will be set by endpoint
            .endpoint_ptr = undefined, // Will be set by endpoint
            .sender_fn = undefined, // Will be set by endpoint
        };

        // Create and initialize server connection
        const c_new = server_mod.createServerConnection(
            &server_ctx,
            peer,
            version,
            header.dcid,
            header.scid,
        ) catch return;

        break :blk c_new;
    };

    // Parse token from packet (offset points to token length varint)
    const varint = @import("varint");
    var i = header.offset;
    const tok_len_dec = varint.decode(bytes[i..]) catch return;
    i += tok_len_dec.n;
    const tok_len_usize = @as(usize, @intCast(@min(tok_len_dec.value, bytes.len - i)));
    if (i + tok_len_usize > bytes.len) return;
    const token_bytes = bytes[i .. i + tok_len_usize];

    // Address validation via token (RFC 9000 §8.1.4)
    if (conn.role == .Server and !conn.address_validated and token_bytes.len > 0) {
        const token_mod = @import("token.zig");
        const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
        const secret = ctx.cfg.token_secret orelse "default-retry-secret-16";
        const now_ns: i128 = std.time.nanoTimestamp();
        const now_ms: u64 = @intCast(if (now_ns > 0) @as(u128, @intCast(now_ns)) / std.time.ns_per_ms else 0);

        if (token_mod.verify(token_bytes, client_ip_bytes, secret, now_ms)) {
            conn.address_validated = true;
            conn.new_token_pending = true;
        }
    }

    // If address still not validated, consider issuing Retry (RFC 9000 §8.1.1)
    if (conn.role == .Server and !conn.address_validated and ctx.cfg.enable_retry) {
        const token_mod = @import("token.zig");
        const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
        const secret = ctx.cfg.token_secret orelse "default-retry-secret-16";

        // Generate Retry token bound to client IP and ODCID
        const retry_tok = token_mod.encode(
            ctx.allocator.*,
            client_ip_bytes,
            header.dcid,
            secret,
            ctx.cfg.token_expiry_ms,
        ) catch return;
        defer ctx.allocator.free(retry_tok);

        // Encode and send Retry packet
        const retry_bytes = packet.encodeRetry(
            ctx.allocator.*,
            version,
            header.scid, // Retry DCID = client's SCID
            conn.our_scid.bytes[0..conn.our_scid.len], // Retry SCID = server's SCID
            header.dcid, // ODCID for integrity tag
            retry_tok,
        ) catch return;
        defer ctx.allocator.free(retry_bytes);

        // Send Retry packet
        _ = ctx.send_fn(peer, retry_bytes) catch {};

        // Don't continue processing this Initial
        return;
    }

    // ==========================================================================
    // Phase 4b.5 Session 6: Key Derivation and Packet Decryption
    // ==========================================================================

    // Derive Initial keys for this connection
    const keys_result = deriveInitialKeys(conn, header.dcid, version);

    // Decrypt Initial packet
    const decrypted = decryptInitialPacket(
        ctx.allocator.*,
        bytes,
        header.offset,
        keys_result.rx_keys,
        if (conn.pn_initial.have_any) conn.pn_initial.max else 0,
    ) catch |err| {
        // Decryption failed - log and return
        _ = err; // Suppress unused variable
        return;
    };
    defer ctx.allocator.free(decrypted.payload);

    // Update packet number tracking
    conn.pn_initial.max = decrypted.packet_number;
    conn.pn_initial.have_any = true;

    // Track bytes received from unvalidated address (anti-amplification)
    if (conn.role == .Server and !conn.address_validated) {
        conn.addRxUnvalidated(bytes.len);
    }

    // Parse frames from decrypted payload
    // NOTE: Frame parsing and CRYPTO processing will be fully implemented
    // when handshake_integration module is complete

    // For Session 6, we document the expected flow:
    // 1. Parse frames from decrypted.payload using frame.decodeOne()
    // 2. For each CRYPTO frame:
    //    - Extract crypto_data and offset
    //    - Create HandshakeContext
    //    - Call handshake_integration.processCryptoFrame()
    // 3. Handle other frames (ACK, PADDING, PING, etc.)
    // 4. Generate ACK for this packet if needed
    // 5. Send response packets (ServerHello, CRYPTO, etc.)

    _ = decrypted.payload; // Suppress unused variable for now

    // Mark that Initial packet was successfully processed
    // (Full frame processing will be added in future sessions)
}
