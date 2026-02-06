// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const endpoint_types = @import("types");
const posix = std.posix;

// Import TLS key schedule for key rotation
const key_schedule = @import("vendor_ztls_key_schedule");
const crypto = @import("crypto_quic");

// Import frame processing modules
const frame = @import("frame");
const frame_handler = @import("frame_handler");
const handshake_integration = @import("handshake_integration");

// Import connection lookup module (Phase 4b.5 Session 3)
const lookup = @import("lookup");

// Import varint for varint decoding (Phase 4b.5 Session 5)
const varint = @import("varint");

// Phase 4b.5: Modular extraction using focused context structs.
// Functions below use RxContext instead of full Endpoint pointer.

// Inline hash helpers (avoid module dependency on utils.zig)

/// Cross-platform invalid socket value (inline to avoid module dependency).
/// On POSIX systems, this is -1.
/// On Windows, this is INVALID_SOCKET (null pointer).
fn invalidSocket() posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) {
        // Windows INVALID_SOCKET is ~0 cast to SOCKET (pointer type)
        return @ptrFromInt(~@as(usize, 0));
    } else {
        return -1;
    }
}
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

fn addDcidCandidate(len: u8, list: []u8, count: *usize, max_len: u8) void {
    if (len > max_len) return;
    var idx: usize = 0;
    while (idx < count.*) : (idx += 1) {
        if (list[idx] == len) return;
    }
    list[count.*] = len;
    count.* += 1;
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

/// Function signature for setting up connection sender callback
pub const SetupSenderFn = *const fn (conn: *conn_mod.Connection) void;

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
    setup_sender_fn: SetupSenderFn,
    test_capture_enabled: bool,
    endpoint_role: endpoint_types.EndpointRole,
    /// Optional opaque endpoint pointer for send_fn context (Phase 4b.5 Session 3)
    /// When non-null, send_fn can use this to access endpoint state
    endpoint_ctx: ?*anyopaque = null,
    /// Generated token secret for Retry/NEW_TOKEN when cfg.token_secret is null.
    /// This is a pointer to the endpoint's generated 32-byte cryptographic secret,
    /// replacing the hardcoded fallback that was predictable and insecure.
    generated_token_secret: *const [32]u8 = undefined,
    /// Maximum concurrent connections (CWE-400 mitigation).
    /// Enforces RFC 9000 §8.1 rate-limiting recommendation.
    /// New connections are rejected when active count >= max_connections.
    /// Set to 0 for unlimited (not recommended for production).
    max_connections: usize = 10000,
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
    // First check if v2 is available
    while (i_sel < vn.versions.len) : (i_sel += 1) {
        if (vn.versions[i_sel] == packet.QUIC_V2) {
            chosen = packet.QUIC_V2;
            break;
        }
    }
    // If v2 not found, check for v1
    if (chosen == 0) {
        i_sel = 0;
        while (i_sel < vn.versions.len) : (i_sel += 1) {
            if (vn.versions[i_sel] == packet.QUIC_V1) {
                chosen = packet.QUIC_V1;
                break;
            }
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
    logger.debugPrint("[ENUM-SHORT] Start enumerateDcidLength initial_len={} bytes_len={} largest_pn={}\n", .{initial_dcid_len, packet_bytes.len, largest_pn});
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
    const header = parseInitialHeader(bytes) catch {
        return;
    };



    // Look up connection by peer hash + client DCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(header.dcid) };

    var conn: *conn_mod.Connection = blk: {
        // Special case: Zero-length DCID requires peer-only lookup
        // RFC 9000 §5.2: Server may use zero-length CIDs
        if (header.dcid.len == 0) {
            // Find any server connection from this peer
            var it = ctx.conns.iterator();
            while (it.next()) |entry| {
                const c = entry.value_ptr.*;
                if (c.role == .Server) {
                    // Check if peer matches
                    const c_peer_hash = hashSockaddr(&c.peer.storage, c.peer.len);
                    if (c_peer_hash == ph) {
                        break :blk c;
                    }
                }
            }
        }

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

        // CWE-400 mitigation: Enforce connection limit before creating new connections.
        // RFC 9000 §8.1 recommends servers implement rate-limiting to prevent DoS.
        // When at capacity, silently drop the Initial packet (do not send error to avoid amplification).
        if (ctx.max_connections > 0 and ctx.conns.count() >= ctx.max_connections) {
            logger.debugPrint("processInitial: Connection limit reached ({}/{}), dropping Initial packet\n", .{
                ctx.conns.count(), ctx.max_connections
            });
            return; // Drop packet - do not create connection
        }

        // Create server connection using Session 5 API
        const server_mod = @import("server.zig");

        // Debug: Log client SCID from header
        logger.debugPrint("processInitial: Parsed Initial header - client_scid.len={}\n", .{header.scid.len});
        if (header.scid.len >= 4) {
            logger.debugPrint("  client_scid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
                header.scid[0], header.scid[1], header.scid[2], header.scid[3]
            });
        }

        const config = server_mod.ServerConnectionConfig{
            .version = version,
            .client_dcid = header.dcid,
            .client_scid = header.scid,
            .server_cert_der = ctx.cfg.inline_server_cert_der,
            .server_priv_key_der = ctx.cfg.inline_server_priv_p256,
            .transport_params = null, // Will be set by setupServerTransportParams
            .use_cubic = (ctx.cfg.cc == .cubic),
            .allow_insecure = ctx.cfg.allow_insecure,
            .allowed_alpns = ctx.cfg.alpn,
            .enable_pacing = ctx.cfg.enable_pacing,
            .max_datagram_size = ctx.cfg.max_datagram_size,
            .aead_confidentiality_limit = ctx.cfg.aead_confidentiality_limit_override orelse 0,
            .aead_integrity_limit = ctx.cfg.aead_integrity_limit_override orelse 0,
            .require_client_cert = ctx.cfg.require_client_cert,
        };

        // Create and initialize server connection
        const c_new = server_mod.createServerConnection(
            ctx.allocator,
            invalidSocket(), // sock_fd will be set by endpoint
            peer,
            config,
        ) catch return;

        // Debug: Check peer_initial_dcid after server connection creation
        logger.debugPrint("processInitial: Server conn created, peer_initial_dcid len={}\n", .{
            c_new.peer_initial_dcid.len
        });
        if (c_new.peer_initial_dcid.len > 0) {
            logger.debugPrint("  peer_initial_dcid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
                c_new.peer_initial_dcid.bytes[0], c_new.peer_initial_dcid.bytes[1],
                c_new.peer_initial_dcid.bytes[2], c_new.peer_initial_dcid.bytes[3]
            });
        }

        // Set up transport parameters for server (RFC 9000 §18.2)
        // IMPORTANT: Must be done AFTER connection creation but BEFORE TLS processing
        handshake_integration.setupServerTransportParams(c_new, ctx.cfg, ctx.allocator.*) catch {};

        // Set up sender callback so connection can send packets
        ctx.setup_sender_fn(c_new);

        // Register connection in map by peer + client DCID (reusing ph and key from outer scope)
        _ = ctx.conns.put(key, c_new) catch {
            c_new.deinit();
            ctx.allocator.destroy(c_new);
            return;
        };

        // Also register by peer + server SCID for Handshake packet lookup
        const our_key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len]) };
        _ = ctx.conns.put(our_key, c_new) catch {};

        logger.debugPrint("processInitial: Registered new server conn={*}\n", .{c_new});
        logger.debugPrint("  By client DCID hash={X:0>16}\n", .{hashBytes(header.dcid)});
        logger.debugPrint("  By server SCID hash={X:0>16}\n", .{hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len])});

        // Add newly created server connection to accepted list for accept() API
        _ = ctx.accepted.append(ctx.allocator.*, c_new) catch {};

        break :blk c_new;
    };

    // For client connections, capture the peer's Initial DCID/SCID so short-header
    // packets use the server-chosen SCID as the destination connection ID.
    if (conn.role == .Client) {
        conn.setPeerInitialCids(header.dcid, header.scid);
    }

    // Parse token from packet (offset points to token length varint)
    var i = header.offset;
    const tok_len_dec = varint.decode(bytes[i..]) catch return;
    i += tok_len_dec.n;
    const tok_len_usize = @as(usize, @intCast(@min(tok_len_dec.value, bytes.len - i)));
    if (i + tok_len_usize > bytes.len) return;
    const token_bytes = bytes[i .. i + tok_len_usize];

    // Address validation via token (RFC 9000 §8.1.4)
    if (conn.role == .Server and !conn.address_validated and token_bytes.len > 0) {
        const token_mod = @import("token");
        const client_ip_bytes = peer.getIpBytes();
        // Use user-provided secret if available, otherwise use the cryptographically
        // random secret generated at endpoint init (never use a hardcoded fallback)
        const secret = ctx.cfg.token_secret orelse ctx.generated_token_secret;
        const now_ns: i128 = std.time.nanoTimestamp();
        const now_ms: u64 = @intCast(if (now_ns > 0) @as(u128, @intCast(now_ns)) / std.time.ns_per_ms else 0);

        if (token_mod.verify(token_bytes, client_ip_bytes, secret, now_ms)) {
            conn.address_validated = true;
            conn.new_token_pending = true;
        }
    }

    // PHASE 42 PART 7 FIX: Auto-validate localhost addresses to avoid unnecessary amplification limits
    // RFC 9000 §8.1 allows servers to skip address validation for trusted addresses
    const is_localhost = conn.isLocalhost();
    logger.debugPrint("[PHASE42] processInitial: role={s} address_validated={} isLocalhost={} enable_retry={}\n", .{
        if (conn.role == .Server) "Server" else "Client",
        conn.address_validated,
        is_localhost,
        ctx.cfg.enable_retry,
    });
    // Skip localhost auto-validation if retry is explicitly enabled (allows testing retry mechanism)
    if (conn.role == .Server and !conn.address_validated and is_localhost and !ctx.cfg.enable_retry) {
        logger.debugPrint("[LOCALHOST] Auto-validating localhost address - bypassing amplification limits\n", .{});
        conn.address_validated = true;
        conn.bytes_rx_unvalidated = 0;
        conn.bytes_tx_unvalidated = 0;
    }

    // If address still not validated, consider issuing Retry (RFC 9000 §8.1.1)
    if (conn.role == .Server and !conn.address_validated and ctx.cfg.enable_retry) {
        const token_mod = @import("token");
        const client_ip_bytes = peer.getIpBytes();
        // Use user-provided secret if available, otherwise use the cryptographically
        // random secret generated at endpoint init (never use a hardcoded fallback)
        const secret = ctx.cfg.token_secret orelse ctx.generated_token_secret;

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

    // Store Initial keys in connection if not already set
    if (conn.initial_rx_keys == null) {
        conn.initial_rx_keys = packet.InitialKeys{
            .key = keys_result.rx_keys.key,
            .iv = keys_result.rx_keys.iv,
            .hp = keys_result.rx_keys.hp,
        };

        logger.debugPrint("[Server RX] Initial key[0..4]: ", .{});
        for (keys_result.rx_keys.key[0..4]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint(" (dcid len={})\n", .{header.dcid.len});
    }
    if (conn.initial_tx_keys == null) {
        conn.initial_tx_keys = packet.InitialKeys{
            .key = keys_result.tx_keys.key,
            .iv = keys_result.tx_keys.iv,
            .hp = keys_result.tx_keys.hp,
        };
    }

    // Decrypt Initial packet
    const largest_pn = if (conn.pn_initial.have_any) conn.pn_initial.max else 0;
    logger.debugPrint("[processInitial] Before decrypt: largest_pn_for_expansion={}\n", .{largest_pn});
    const decrypted = decryptInitialPacket(
        ctx.allocator.*,
        bytes,
        header.offset,
        keys_result.rx_keys,
        largest_pn,
    ) catch |err| {
        // Decryption failed - return
        logger.debugPrint("[Server] Initial decrypt failed: {} (dcid len={})\n", .{ err, header.dcid.len });
        return;
    };
    defer ctx.allocator.free(decrypted.payload);
    logger.debugPrint("[processInitial] After decrypt: expanded packet_number={}\n", .{decrypted.packet_number});

    // Set connection context for TLS Context callbacks (Phase 21.2)
    handshake_integration.setCurrentConnection(if (@TypeOf(conn) == **conn_mod.Connection) conn.* else conn);
    defer handshake_integration.clearCurrentConnection();

    // Update packet number tracking (RFC 9000 §13.2)
    // MUST use trackRecvPnInitial() to properly update the bitmap window
    logger.debugPrint("[processInitial] Tracking received packet number: {}\n", .{decrypted.packet_number});
    conn.trackRecvPnInitial(decrypted.packet_number);
    logger.debugPrint("[processInitial] After tracking - pn_initial.max={}, have_any={}\n", .{
        conn.pn_initial.max,
        conn.pn_initial.have_any,
    });

    // Track bytes received from unvalidated address (anti-amplification)
    if (conn.role == .Server and !conn.address_validated) {
        conn.addRxUnvalidated(bytes.len);
    }

    // Parse frames from decrypted payload
    var offset: usize = 0;
    var saw_crypto: bool = false;
    var saw_ack_eliciting: bool = false;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    logger.debugPrint("[processInitial] Decrypted payload length: {} bytes\n", .{decrypted.payload.len});

    while (offset < decrypted.payload.len) {
        logger.debugPrint("[processInitial] Decoding frame at offset {}/{}\n", .{offset, decrypted.payload.len});
        const fr = frame.decodeOne(decrypted.payload[offset..]) catch |err| {
            const first_byte = if (offset < decrypted.payload.len) decrypted.payload[offset] else 0;
            // RFC 9000 §12.4: Endpoints MUST ignore unknown frame types
            if (err == error.Unsupported) {
                logger.debugPrint("[processInitial] Ignoring unknown frame type 0x{X:0>2} at offset {} (RFC 9000 §12.4)\n", .{ first_byte, offset });
                break; // Can't continue without knowing frame length
            }
            logger.debugPrint("[processInitial] Frame decode error at offset {}: {} (first_byte=0x{X:0>2})\n", .{ offset, err, first_byte });
            break;
        };
        logger.debugPrint("[processInitial] Decoded frame type: {}\n", .{std.meta.activeTag(fr.f)});
        offset += fr.n;

        switch (fr.f) {
            .crypto => |cr| {
                // Process CRYPTO frame to advance TLS handshake
                logger.debugPrint("{s}: Received Initial CRYPTO frame with {} bytes at offset {} (expected {})\n", .{
                    if (conn.role == .Server) "Server" else "Client",
                    cr.data.len,
                    cr.offset,
                    conn.crypto_rx_off_initial,
                });

                const ack_needed = conn.handleInitialCrypto(
                    ctx.allocator,
                    cr.offset,
                    cr.data,
                ) catch |err| blk: {
                    logger.debugPrint("processInitial: handleInitialCrypto error: {}\n", .{err});

                    // BUGFIX: Handle DuplicateClientHello gracefully
                    // This happens when the client retransmits an Initial packet we already processed.
                    // The TLS context rejects it as duplicate, but this is normal QUIC behavior.
                    // We should NOT destroy the TLS context - just ignore the duplicate and continue.
                    if (err == error.DuplicateClientHello) {
                        logger.debugPrint("processInitial: Ignoring duplicate ClientHello (likely retransmission)\n", .{});
                        // Continue processing - the TLS state machine is still valid
                        // We may have already sent ServerHello, or we're about to
                        break :blk true; // Treat as if we saw crypto data
                    }

                    // For other errors, log and skip this frame
                    break :blk false;
                };

                if (ack_needed) {
                    saw_crypto = true;
                    saw_ack_eliciting = true;

                    // Check if app keys are now ready (handshake complete)
                    if (conn.app_rx_keys != null and conn.app_tx_keys != null) {
                        logger.debugPrint("processInitial: App keys ready - handshake complete\n", .{});
                        // Endpoint will handle closeStaleConnectionsForPeer via callback
                    }
                }
            },
            .ack => |a| {
                // Process ACK frame for PTO cancellation
                conn.onAckReceivedSpace(.Initial, a.largest, a.first_range, a.ranges, a.ecn);

                // Cancel Initial PTO timer
                conn.pto_initial_count = 0;
                // Note: Actual timer cancellation requires endpoint access - handled by caller
            },
            .padding => {},
            .ping => {
                // PING frames are ack-eliciting
                saw_ack_eliciting = true;
            },
            else => {
                // Other frames are unexpected in Initial packets but ignored per RFC 9000 §12.4
                logger.debugPrint("processInitial: Unexpected frame type in Initial packet\n", .{});
            },
        }
    }

    // Record ack-eliciting reception for ACK generation
    if (saw_ack_eliciting) {
        conn.recordAckElicitingRx(.Initial, now_ns);
    }

    // Send ServerHello if we're a server and TLS has responses
    // Try after each CRYPTO frame in case ClientHello is fragmented
    logger.debugPrint("[processInitial] Checking ServerHello condition: role={s}, saw_crypto={}\n", .{
        if (conn.role == .Server) "Server" else "Client",
        saw_crypto,
    });
    if (conn.role == .Server and saw_crypto) {
        logger.debugPrint("[processInitial] Attempting to send ServerHello...\n", .{});
        // ServerHello must be sent in Initial packet (RFC 9001 §4.1.1)
        var hs_ctx = handshake_integration.HandshakeContext{
            .conn = conn,
            .peer = peer,
            .allocator = ctx.allocator,
            .send_fn = ctx.send_fn,
            .cfg = ctx.cfg,
        };
        handshake_integration.sendServerHello(&hs_ctx) catch {
            // ServerHello sending failed - continue processing
        };

        // Send Handshake packets if Handshake keys are available
        // RFC 9001 §4.1: "A server sends the first Handshake packet as soon as it has Handshake keys"
        handshake_integration.sendHandshakePackets(&hs_ctx) catch {
            // Handshake packet sending failed - continue processing
        };
    }

    // Send ACK for received Initial packet
    if (saw_crypto) {
        if (conn.initial_tx_keys) |tx_keys| {
            // Build ACK frame
            var frames_buf: [4096]u8 = undefined;
            var frames_stream = std.io.fixedBufferStream(&frames_buf);
            const w = frames_stream.writer();

            const ack_desc = conn.buildAckInitial();
            logger.debugPrint("[processInitial] Building ACK: largest={}, first_range={}, ranges_len={}\n", .{
                ack_desc.largest,
                ack_desc.first_range,
                ack_desc.ranges.len,
            });
            logger.debugPrint("[processInitial] pn_initial: max={}, have_any={}\n", .{
                conn.pn_initial.max,
                conn.pn_initial.have_any,
            });
            const ack_frame = frame.Frame{ .ack = .{
                .largest = ack_desc.largest,
                .ack_delay = 0,
                .first_range = ack_desc.first_range,
                .ranges = ack_desc.ranges,
            } };
            _ = ack_frame.write(w) catch 0;
            const frames_data = frames_stream.getWritten();

            // Debug: Print ACK frame bytes
            logger.debugPrint("[processInitial] ACK frame bytes ({} bytes): ", .{frames_data.len});
            for (frames_data) |b| {
                logger.debugPrint("{X:0>2} ", .{b});
            }
            logger.debugPrint("\n", .{});

            // Use peer's SCID as DCID
            const initial_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

            // Encode and send Initial ACK packet
            const pkt = packet.encodeInitialProtected(
                ctx.allocator.*,
                version,
                initial_dcid,
                conn.our_scid.bytes[0..conn.our_scid.len],
                &[_]u8{}, // No token in ACK packet
                @as(u32, @truncate(conn.pn_initial_tx)),
                2,
                frames_data,
                tx_keys,
            ) catch null;

            if (pkt) |bytes_out| {
                defer ctx.allocator.free(bytes_out);
                _ = ctx.send_fn(peer, bytes_out) catch {};
                conn.onPacketSent(.Initial, conn.pn_initial_tx, bytes_out.len, false);
                conn.pn_initial_tx +%= 1;
            }
        }
    }
}

// =============================================================================
// Phase 4b.5 Session 8: RX Handshake Packet Processing
// =============================================================================

/// Process Handshake packet (RFC 9000 §17.2.2, RFC 9001 §5.2).
/// Extracted from endpoint.zig lines 2900-3296 (Phase 4b.5 Session 8).
///
/// RFC 9001 §5.2: "Handshake packets are used to carry cryptographic handshake
/// messages and acknowledgments for handshake packets. They are encrypted using
/// the Handshake packet protection keys."
///
/// This function:
/// 1. Looks up existing connection by peer + DCID
/// 2. Decrypts using Handshake keys (hs_rx_keys)
/// 3. Processes CRYPTO frames to advance TLS state machine
/// 4. Processes ACK frames to cancel PTO timers
/// 5. Validates client address (server-side only)
/// 6. Sends CRYPTO and ACK responses
///
/// Parameters:
/// - ctx: RxContext with endpoint state, allocator, send_fn
/// - peer: Peer socket address
/// - bytes: Raw UDP datagram bytes
/// - version: QUIC version
/// - ecn_bits: Optional ECN bits from IP header
/// - send_fn: Function to send UDP datagrams
///
/// RFC 9000 §8.1: "Successfully processing any message encrypted with Handshake
/// keys confirms that the peer successfully processed an Initial packet."
pub fn processHandshake(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    version: u32,
    ecn_bits: ?u8,
    send_fn: SendFn,
) void {
    _ = version; // Currently unused, but reserved for version negotiation

    // Parse Handshake header to extract DCID and SCID
    const header = parseHandshakeHeader(bytes) catch return;

    // Look up connection by peer hash + DCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(header.dcid) };

    logger.debugPrint("processHandshake: Looking up conn with peer_hash={X:0>16}, DCID len={}, DCID hash={X:0>16}\n", .{
        ph, header.dcid.len, hashBytes(header.dcid)
    });

    var c_ptr = ctx.conns.getPtr(key);

    // Debug: Print all registered connections if lookup fails
    if (c_ptr == null) {
        logger.debugPrint("processHandshake: Connection not found. Registered connections:\n", .{});
        var iter = ctx.conns.iterator();
        while (iter.next()) |entry| {
            logger.debugPrint("  Key: peer_hash={X:0>16}, dcid_hash={X:0>16}, conn={*}\n", .{
                entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash, entry.value_ptr.*
            });
        }
    }

    // Fallback: If lookup failed and DCID is empty, find connection by peer address alone
    // This handles the case where client sends empty DCID in Handshake packets
    if (c_ptr == null and header.dcid.len == 0) {
        var iter = ctx.conns.iterator();
        while (iter.next()) |entry| {
            if (entry.key_ptr.peer_hash == ph) {
                c_ptr = entry.value_ptr;
                break;
            }
        }
    }

    const conn = (if (c_ptr) |p| p.* else null) orelse {
        // No connection found - ignore packet
        logger.debugPrint("processHandshake: Connection not found for Handshake packet\n", .{});
        return;
    };

    // Record ECN marking if present
    if (ecn_bits) |e| conn.*.onEcnMark(.Handshake, e);

    // Check if we have Handshake RX keys
    const rx_keys = conn.*.hs_rx_keys orelse {
        logger.debugPrint("processHandshake: No Handshake RX keys available for conn={*} role={s}\n", .{
            conn, if (conn.*.role == .Client) "Client" else "Server"
        });
        return;
    };

    // Debug: Show packet info and keys being used
    logger.debugPrint("processHandshake: Packet len={}, header offset={}, role={s}, conn_ptr={*}\n", .{
        bytes.len,
        header.offset,
        if (conn.*.role == .Client) "Client" else "Server",
        conn
    });
    logger.debugPrint("  RX keys - key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}, hp[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
        rx_keys.key[0], rx_keys.key[1], rx_keys.key[2], rx_keys.key[3],
        rx_keys.hp[0], rx_keys.hp[1], rx_keys.hp[2], rx_keys.hp[3]
    });
    if (conn.*.hs_tx_keys) |tx_keys| {
        logger.debugPrint("  TX keys - key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}, hp[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
            tx_keys.key[0], tx_keys.key[1], tx_keys.key[2], tx_keys.key[3],
            tx_keys.hp[0], tx_keys.hp[1], tx_keys.hp[2], tx_keys.hp[3]
        });
    }

    // Decrypt Handshake packet
    const decrypted = decryptHandshakePacket(
        ctx.allocator.*,
        bytes,
        header.offset,
        rx_keys,
        if (conn.*.pn_handshake.have_any) conn.*.pn_handshake.max else 0,
    ) catch |err| {
        logger.debugPrint("processHandshake: Decryption failed: {}\n", .{err});
        conn.*.onAeadAuthFailure();
        return;
    };
    defer ctx.allocator.free(decrypted.payload);

    // Set connection context for TLS Context callbacks (Phase 21.2)
    handshake_integration.setCurrentConnection(if (@TypeOf(conn) == **conn_mod.Connection) conn.* else conn);
    defer handshake_integration.clearCurrentConnection();

    // Update packet number tracking
    conn.*.trackRecvPnHandshake(decrypted.packet_number);

    // RFC 9000 §8.1: Successfully authenticating a packet at the Handshake level
    // proves the client received the server's Initial (which provided handshake keys).
    // This validates the client's address for anti-amplification purposes.
    if (conn.*.role == .Server and !conn.*.address_validated) {
        logger.debugPrint("processHandshake: Validating client address after Handshake packet\n", .{});
        conn.*.address_validated = true;
        conn.*.bytes_rx_unvalidated = 0;
        conn.*.bytes_tx_unvalidated = 0;
    }

    // Process frames from decrypted payload
    var offset: usize = 0;
    var saw_crypto: bool = false;
    var saw_ack_eliciting: bool = false;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    while (offset < decrypted.payload.len) {
        const fr = frame.decodeOne(decrypted.payload[offset..]) catch |err| {
            logger.debugPrint("processHandshake: Frame decode error at offset {}: {}\n", .{ offset, err });
            break;
        };
        offset += fr.n;

        switch (fr.f) {
            .crypto => |cr| {
                // Process CRYPTO frame to advance TLS handshake
                logger.debugPrint("{s}: Received Handshake CRYPTO frame with {} bytes at offset {} (expected {})\n", .{
                    if (conn.*.role == .Server) "Server" else "Client",
                    cr.data.len,
                    cr.offset,
                    conn.*.crypto_rx_off_handshake,
                });

                const ack_needed = conn.*.handleHandshakeCrypto(
                    ctx.allocator,
                    cr.offset,
                    cr.data,
                ) catch |err| blk: {
                    logger.debugPrint("processHandshake: Failed to process CRYPTO: {}\n", .{err});
                    break :blk false;
                };

                if (ack_needed) {
                    saw_crypto = true;
                    saw_ack_eliciting = true;

                    // Check if app keys are now ready (handshake complete)
                    if (conn.*.app_rx_keys != null and conn.*.app_tx_keys != null) {
                        logger.debugPrint("processHandshake: App keys ready - handshake complete\n", .{});
                        // Endpoint will handle closeStaleConnectionsForPeer via callback
                    }
                }
            },
            .ack => |a| {
                // Process ACK frame for PTO cancellation
                conn.*.onAckReceivedSpace(.Handshake, a.largest, a.first_range, a.ranges, a.ecn);

                // Cancel Handshake PTO timer
                conn.*.pto_handshake_count = 0;
                // Note: Actual timer cancellation requires endpoint access - handled by caller
            },
            .padding => {},
            .ping => {
                // PING frames are allowed in Handshake packets (RFC 9000 §19.2)
                // They're used for keepalive and connection validation
                // No action needed - the packet itself will trigger ACK generation
            },
            else => {
                // Other frames are unexpected in Handshake packets
                logger.debugPrint("processHandshake: Unexpected frame type in Handshake packet: {}\n", .{fr.f});
            },
        }
    }

    // Record ack-eliciting reception for ACK generation
    if (saw_ack_eliciting) {
        conn.*.recordAckElicitingRx(.Handshake, now_ns);
    }

    // Send pending Handshake CRYPTO data (e.g., server Finished, client Finished)
    if (conn.*.hs_tx_keys) |tx_keys| {
        // Poll TLS Context for Handshake-level CRYPTO data
        var crypto_data: ?[]const u8 = null;
        var owns_data = false;

        // Set connection context for callbacks
        handshake_integration.setCurrentConnection(conn);
        defer handshake_integration.clearCurrentConnection();

        // Poll for Handshake-level CRYPTO data
        const tls_ctx = conn.tls_context orelse return; // No TLS Context, skip processing
        const hs_data = tls_ctx.pollCrypto(ctx.allocator.*, .Handshake) catch |err| blk: {
            // Unimplemented means no data available (expected)
            if (err != error.Unimplemented) {
                logger.debugPrint("processHandshake: Context pollCrypto error: {}\n", .{err});
            }
            break :blk null;
        };
        if (hs_data) |data| {
            crypto_data = data;
            owns_data = true;
        }

        if (crypto_data) |data| {
            defer if (owns_data) ctx.allocator.free(data);
            const n = data.len;
            // Fragment CRYPTO data across multiple packets if needed
            const max_crypto_per_packet: usize = 1100;
            var crypto_offset: usize = 0;
            const base_off = conn.*.crypto_tx_off_handshake;

            while (crypto_offset < n) {
                const chunk_size = @min(max_crypto_per_packet, n - crypto_offset);
                const chunk = data[crypto_offset .. crypto_offset + chunk_size];

                var frames_buf = std.ArrayList(u8){};
                defer frames_buf.deinit(ctx.allocator.*);
                const w = frames_buf.writer(ctx.allocator.*);

                // Add CRYPTO frame
                const crypto_frame_offset = base_off + crypto_offset;
                _ = (frame.Frame{ .crypto = .{ .offset = crypto_frame_offset, .data = chunk } }).write(w) catch 0;

                // Use peer's SCID as DCID
                const hs_dcid = conn.*.peer_initial_scid.bytes[0..conn.*.peer_initial_scid.len];

                // Encode and send Handshake packet
                const pkt = packet.encodeHandshakeProtected(
                    ctx.allocator.*,
                    0x00000001, // QUIC v1
                    hs_dcid,
                    conn.*.our_scid.bytes[0..conn.*.our_scid.len],
                    @as(u32, @truncate(conn.*.pn_handshake_tx)),
                    2,
                    frames_buf.items,
                    tx_keys,
                ) catch null;

                if (pkt) |bytes_out| {
                    defer ctx.allocator.free(bytes_out);
                    _ = send_fn(peer, bytes_out) catch {};
                    conn.*.onPacketSent(.Handshake, conn.*.pn_handshake_tx, bytes_out.len, true);
                    conn.*.pn_handshake_tx +%= 1;
                }

                crypto_offset += chunk_size;
            }

            // Save retransmit buffer
            if (conn.*.crypto_retx_handshake) |old_buf| ctx.allocator.free(old_buf);
            const owned = ctx.allocator.alloc(u8, n) catch {
                conn.*.crypto_tx_off_handshake += n;
                return;
            };
            @memcpy(owned[0..n], data[0..n]);
            conn.*.crypto_retx_handshake = owned;
            conn.*.crypto_retx_handshake_off = base_off;
            conn.*.crypto_tx_off_handshake += n;

            // Attempt delayed 1-RTT key derivation after flushing TLS outbox
            conn.*.maybeDeriveAppKeysAfterFlush();
        }
    }

    // Send ACK for received Handshake packet
    if (saw_crypto) {
        if (conn.*.hs_tx_keys) |tx_keys| {
            var frames_buf = std.ArrayList(u8){};
            defer frames_buf.deinit(ctx.allocator.*);
            const w = frames_buf.writer(ctx.allocator.*);

            const ack_desc = conn.*.buildAckHandshake();
            const ack_ecn = conn.*.getAckEcn(.Handshake);
            const ack_delay = conn.*.getAckDelayEncoded(.Handshake, now_ns);

            if (ack_desc.largest != 0xFFFFFFFFFFFFFFFF) {
                const ack_frame = frame.Frame{ .ack = .{
                    .largest = ack_desc.largest,
                    .ack_delay = ack_delay,
                    .first_range = ack_desc.first_range,
                    .ranges = ack_desc.ranges,
                    .ecn = ack_ecn,
                } };
                _ = ack_frame.write(w) catch 0;
            }

            // Use peer's SCID as DCID
            const hs_dcid = conn.*.peer_initial_scid.bytes[0..conn.*.peer_initial_scid.len];

            // Encode and send ACK packet
            const pkt = packet.encodeHandshakeProtected(
                ctx.allocator.*,
                0x00000001, // QUIC v1
                hs_dcid,
                conn.*.our_scid.bytes[0..conn.*.our_scid.len],
                @as(u32, @truncate(conn.*.pn_handshake_tx)),
                2,
                frames_buf.items,
                tx_keys,
            ) catch null;

            if (pkt) |bytes_out| {
                defer ctx.allocator.free(bytes_out);
                _ = send_fn(peer, bytes_out) catch {};
                // ACK-only packet is not ack-eliciting
                conn.*.pn_handshake_tx +%= 1;
            }
        }
    }
}

/// Parse Handshake packet header.
/// Returns structure with DCID, SCID, and offset to payload+PN.
fn parseHandshakeHeader(bytes: []const u8) !struct { dcid: []const u8, scid: []const u8, offset: usize } {
    if (bytes.len < 5) return error.PacketTooShort;

    const first = bytes[0];
    const is_long = (first & 0x80) != 0;
    if (!is_long) return error.NotLongHeader;

    const pkt_type = (first & 0x30) >> 4;
    if (pkt_type != 2) return error.NotHandshakePacket; // Handshake = 2

    var i: usize = 5; // Skip first byte + 4-byte version

    // Parse DCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const dcid_len = bytes[i];
    i += 1;
    if (i + dcid_len > bytes.len) return error.PacketTooShort;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const scid_len = bytes[i];
    i += 1;
    if (i + scid_len > bytes.len) return error.PacketTooShort;
    const scid = bytes[i .. i + scid_len];
    i += scid_len;

    // Return offset pointing to length field (before PN + payload)
    return .{ .dcid = dcid, .scid = scid, .offset = i };
}

/// Decrypt Handshake packet using Handshake protection keys.
/// Similar to decryptInitialPacket but uses Handshake keys.
fn decryptHandshakePacket(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    length_offset: usize,
    rx_keys: packet.InitialKeys,
    largest_pn: u64,
) !struct { payload: []u8, packet_number: u64 } {
    // Parse length field
    var i = length_offset;
    const len_dec = varint.decode(bytes[i..]) catch return error.InvalidLength;
    i += len_dec.n;

    const end_total = i + @as(usize, @intCast(len_dec.value));

    logger.debugPrint("decryptHandshakePacket: bytes.len={}, length_offset={}, payload_len={}, end_total={}\n", .{
        bytes.len, length_offset, len_dec.value, end_total,
    });

    if (end_total > bytes.len) return error.PacketTooShort;

    const first = bytes[0];
    const header_prefix = bytes[1..i];
    const full_pn_and_payload = bytes[i..end_total];

    if (full_pn_and_payload.len < 20) return error.PayloadTooShort;

    // Step 1: Extract HP sample and unmask header byte to get PN length
    // RFC 9001 §5.4.2: Sample always starts at offset 4 from PN field start
    var sample16: [16]u8 = undefined;
    @memcpy(&sample16, full_pn_and_payload[4..20]);

    // Manually generate HP mask using AES-ECB
    const Aes128 = std.crypto.core.aes.Aes128;
    const aes = Aes128.initEnc(rx_keys.hp[0..16].*);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, &sample16);

    // Create a copy of first byte and unmask it to get PN length
    var header_peek = first;
    // For long header (Handshake), mask only lower 4 bits
    const mask_bits = mask[0] & 0x0f;
    header_peek ^= mask_bits;

    logger.debugPrint("decryptHandshakePacket: PN length detection - original=0x{X:0>2}, mask=0x{X:0>2}, unmasked=0x{X:0>2}\n", .{
        first, mask_bits, header_peek
    });

    const actual_pn_len: u3 = @intCast((header_peek & 0x03) + 1);
    logger.debugPrint("  Detected PN length: {} (from bits 0x{X:0>2})\n", .{
        actual_pn_len, header_peek & 0x03
    });

    // Step 2: Allocate plaintext buffer
    const expected_pt_len = if (full_pn_and_payload.len > 16 + @as(usize, actual_pn_len))
        full_pn_and_payload.len - 16 - @as(usize, actual_pn_len)
    else
        0;

    const pt_slice = try allocator.alloc(u8, if (expected_pt_len > 0) expected_pt_len else 1);
    errdefer allocator.free(pt_slice);

    // Step 3: Unmask header and PN bytes using the already-generated mask
    // We already have the mask from step 1, so we can just apply it directly
    var unmasked_header = first;  // Fresh copy of the original masked first byte
    var unmasked_pn_bytes: [4]u8 = undefined;
    // The packet number bytes are at the start of full_pn_and_payload
    @memcpy(unmasked_pn_bytes[0..actual_pn_len], full_pn_and_payload[0..actual_pn_len]);

    logger.debugPrint("decryptHandshakePacket: Attempting decrypt with pn_len={}, header_prefix.len={}, ciphertext.len={}\n", .{
        actual_pn_len, header_prefix.len, full_pn_and_payload.len,
    });

    // Apply the mask we already generated
    // For long header, mask only lower 4 bits of first byte
    unmasked_header ^= mask[0] & 0x0f;

    // Apply mask to packet number bytes
    logger.debugPrint("decryptHandshakePacket: Unmasking PN bytes:\n", .{});
    for (unmasked_pn_bytes[0..actual_pn_len], 0..) |*b, idx| {
        const orig = b.*;
        const mask_byte = mask[1 + idx];
        b.* ^= mask_byte;
        logger.debugPrint("  PN[{}]: 0x{X:0>2} XOR 0x{X:0>2} = 0x{X:0>2}\n", .{
            idx, orig, mask_byte, b.*
        });
    }

    // Validate that the unmasked header has the correct format for a Handshake packet
    const expected_first = 0xE0 | @as(u8, actual_pn_len - 1);
    logger.debugPrint("decryptHandshakePacket: After HP removal: first=0x{X:0>2}, expected=0x{X:0>2}\n", .{
        unmasked_header, expected_first
    });

    // Check if the header byte looks correct (should match expected for Handshake packet)
    if ((unmasked_header & 0xF0) != 0xE0) {
        logger.debugPrint("decryptHandshakePacket: WARNING - First byte doesn't look like Handshake packet after HP removal\n", .{});
    }

    // Step 4: Build AAD with unmasked header
    var aad_buf: [256]u8 = undefined;
    aad_buf[0] = unmasked_header; // Now unmasked
    @memcpy(aad_buf[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_buf[1 + header_prefix.len .. 1 + header_prefix.len + actual_pn_len], unmasked_pn_bytes[0..actual_pn_len]);
    const aad = aad_buf[0 .. 1 + header_prefix.len + actual_pn_len];

    // Debug: Print AAD components
    logger.debugPrint("decryptHandshakePacket AAD: first_byte=0x{X:0>2} (should be ~0xE2-E3 for Handshake), header_prefix.len={}, pn_len={}\n", .{
        aad[0], header_prefix.len, actual_pn_len
    });
    logger.debugPrint("  AAD bytes: ", .{});
    for (aad[0..@min(aad.len, 32)]) |b| {
        logger.debugPrint("{X:0>2} ", .{b});
    }
    logger.debugPrint("\n", .{});

    // Step 5: Expand packet number
    var pn_trunc: u64 = 0;
    var j: usize = 0;
    while (j < actual_pn_len) : (j += 1) {
        pn_trunc = (pn_trunc << 8) | unmasked_pn_bytes[j];
    }
    const full_pn = crypto.expandPacketNumber(pn_trunc, actual_pn_len, largest_pn);

    logger.debugPrint("decryptHandshakePacket: PN expansion: truncated={}, pn_len={}, largest_pn={}, expanded={}\n", .{
        pn_trunc, actual_pn_len, largest_pn, full_pn
    });
    logger.debugPrint("  PN bytes (unmasked): ", .{});
    for (unmasked_pn_bytes[0..actual_pn_len]) |b| {
        logger.debugPrint("{X:0>2} ", .{b});
    }
    logger.debugPrint("\n", .{});

    // Step 4: AEAD decrypt
    const actual_ciphertext = full_pn_and_payload[actual_pn_len..];

    logger.debugPrint("decryptHandshakePacket: Using keys for AEAD decrypt:\n", .{});
    logger.debugPrint("  key[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
        rx_keys.key[0], rx_keys.key[1], rx_keys.key[2], rx_keys.key[3]
    });
    logger.debugPrint("  iv[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
        rx_keys.iv[0], rx_keys.iv[1], rx_keys.iv[2], rx_keys.iv[3]
    });
    logger.debugPrint("  ciphertext_len={}\n", .{actual_ciphertext.len});

    const dec = crypto.aeadDecrypt(
        .aes_128_gcm,
        &rx_keys.key,
        &rx_keys.iv,
        full_pn,
        aad,
        actual_ciphertext,
        pt_slice,
    ) catch |err| {
        logger.debugPrint("decryptHandshakePacket: AEAD decrypt failed: {}\n", .{err});
        logger.debugPrint("  Error details: pn={}, aad_len={}, ct_len={}\n", .{
            full_pn, aad.len, actual_ciphertext.len
        });
        return error.AeadDecryptFailed;
    };

    // Return decrypted payload and packet number
    return .{
        .payload = pt_slice[0..dec],
        .packet_number = full_pn,
    };
}

// =============================================================================
// Phase 4b.5 Session 3: RX Short Header (1-RTT) Processing
// =============================================================================

/// Result of short header decryption with key rotation.
pub const ShortDecryptResult = struct {
    /// Decrypted payload and packet number
    decoded: packet.DecodedShort,
    /// Whether NEXT keys were used (requires key promotion)
    used_next: bool,
    /// Whether previous keys were used (requires allowance decrement)
    used_prev: bool,
    /// Actual DCID length discovered (may differ from input)
    dcid_len: u8,
};

/// Decrypt short header packet with systematic DCID enumeration and key rotation.
/// Extracted from endpoint.zig lines 1198-1318 (Phase 4b.5 Session 3).
///
/// RFC 9000 §17.3: "Short headers do not include a length, so the DCID length
/// must be known through other means."
///
/// This function implements Bug #6 fix: systematic DCID length enumeration 0-20
/// to discover the actual DCID length when cached value fails.
///
/// RFC 9001 §6: "Endpoints can use multiple packets to send data and can update
/// keys to improve forward secrecy and confidentiality. Packets protected with
/// updated keys are sent with a different packet number space."
///
/// Key rotation strategy:
/// 1. Try current app_rx_keys with cached/heuristic DCID length
/// 2. On auth failure, try all DCID lengths 0-20 systematically
/// 3. On auth failure, derive NEXT keys and retry
/// 4. On auth failure, try previous keys (rx_prev_keys)
/// 5. Cache successful DCID length for future packets
/// 6. Promote to NEXT keys if decryption succeeded with them
///
/// Parameters:
/// - allocator: Memory allocator for decrypted payload
/// - conn: Connection with app_rx_keys, app_rx_secret, rx_prev_keys
/// - bytes: Raw 1-RTT packet bytes (short header)
/// - try_dcid_len: Initial DCID length to try (from cache or connection match)
///
/// Returns:
/// - ShortDecryptResult with decoded payload, key rotation flags, actual dcid_len
/// - error.AuthenticationFailed if all key attempts fail
/// - error.StatelessReset if packet matches stateless reset token
pub fn decryptShortHeaderWithKeyRotation(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    try_dcid_len: u8,
) !ShortDecryptResult {
    return decryptShortHeaderWithKeyRotationInternal(allocator, conn, bytes, try_dcid_len, false);
}

fn decryptShortHeaderWithKeyRotationInternal(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    try_dcid_len: u8,
    forced_attempted: bool,
) !ShortDecryptResult {
    const rx_keys = conn.app_rx_keys orelse return error.NoApplicationKeys;

    // RFC 9000 Appendix A.3: Pass largest received PN for expansion
    const largest_pn: u64 = if (conn.pn_app.have_any) conn.pn_app.max else 0;
    const should_log_attempts = largest_pn >= 80;

    // Ensure NEXT keys are always pre-derived so we can decode peer-initiated key updates
    if (conn.app_rx_next_keys == null and conn.app_rx_secret != null) {
        const cur_secret = conn.app_rx_secret.?;
        const next_secret = key_schedule.updateQuicSecret(cur_secret);
        const next_mat = if (conn.version_v2)
            key_schedule.deriveKeyIvHpV2(next_secret)
        else
            key_schedule.deriveKeyIvHp(next_secret);
        conn.app_rx_next_secret = next_secret;
        conn.app_rx_next_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = next_mat.hp };
    }

    var used_next = false;
    var used_prev = false;
    var actual_dcid_len = try_dcid_len;

    // PHASE 57 PART 4 FIX: DCID×KeySet enumeration
    // RFC 9000 §17.2/§17.3: Short headers omit DCID length; RFC 9001 §6: KEY_PHASE toggles key generation
    // CRITICAL: Cannot trust KEY_PHASE bit until we find correct DCID length!
    // When DCID length is wrong, HP removal produces garbage, including garbage KEY_PHASE.
    // Solution: Try ALL key sets (CURRENT, NEXT, PREV) for EACH DCID length (0-20)

    // PHASE 57 Part 5: Use pre-derived NEXT keys (installed at handshake completion)
    // This avoids per-packet derivation and maintains one-generation-ahead invariant
    const next_keys_opt = conn.app_rx_next_keys;

    const decoded = blk_dec: {
        // Check for stateless reset before enumeration
        if (conn.looksLikeStatelessReset(bytes)) {
            return error.StatelessReset;
        }

        // PHASE 57 Part 7: DCID enumeration optimized per msquic reference
        // msquic uses a fixed, cached DCID length (forks/msquic/src/core/packet.c:146)
        // Strategy: Try cached length FIRST with all key sets, then enumerate as fallback

    const max_dcid_len: u8 = 20;
    var candidates: [max_dcid_len + 2]u8 = undefined;
    var cand_count: usize = 0;

    // PRIORITY 1: Cached DCID length (from previous successful decrypt)
    if (conn.expected_rx_dcid_len) |cached_len| {
        addDcidCandidate(cached_len, candidates[0..], &cand_count, max_dcid_len);
    }

    // PRIORITY 2: Observed DCID length (from packet structure)
    addDcidCandidate(try_dcid_len, candidates[0..], &cand_count, max_dcid_len);

    // PRIORITY 3: Enumerate all other lengths (fallback for edge cases)
    var len_iter: u8 = 0;
    while (len_iter <= max_dcid_len) : (len_iter += 1) {
        addDcidCandidate(len_iter, candidates[0..], &cand_count, max_dcid_len);
    }

    logger.debugPrint("[APP-PATH] Enter enumerateDcidLength (short header) bytes_len={} try_dcid_len={} largest_pn={} conn_set={}\n", .{bytes.len, try_dcid_len, largest_pn, true});
    var cand_index: usize = 0;
    while (cand_index < cand_count) : (cand_index += 1) {
        const test_len = candidates[cand_index];

        if (should_log_attempts) {
            logger.debugPrint("[PHASE57-TRY] key_set=CURRENT dcid_len={} rx_phase={} largest={} forced={}\n", .{
                test_len,
                conn.rx_key_phase,
                largest_pn,
                forced_attempted,
            });
        }

        packet.phase57SetAttemptLabel("CURRENT");
        logger.debugPrint("[APP-DECODE] TRY CURRENT dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{test_len, largest_pn, conn.rx_key_phase, bytes.len});
        if (packet.decodeShortProtected(allocator, bytes, test_len, .{
            .key = rx_keys.key,
            .iv = rx_keys.iv,
            .hp = rx_keys.hp,
        }, largest_pn)) |result| {
            if (result.payload.len > 0) {
                _ = frame.decodeOne(result.payload) catch {
                    allocator.free(result.payload);
                    continue;
                };
            }
            logger.debugPrint("[PHASE57] ✅ Decrypted with CURRENT keys: dcid_len={} pn={}\n", .{ test_len, result.packet_number });
            actual_dcid_len = test_len;
            break :blk_dec result;
        } else |_| {
            if (next_keys_opt) |next_mat| {
                packet.phase57SetAttemptLabel("HYBRID_CURRENT_NEXT");
                if (packet.decodeShortProtectedWithHp(allocator, bytes, test_len, rx_keys.hp, .{
                    .key = next_mat.key,
                    .iv = next_mat.iv,
                    .hp = next_mat.hp,
                }, largest_pn)) |hybrid| {
                    logger.debugPrint("[PHASE57-HYBRID] CURRENT hp + NEXT AEAD succeeded (dcid_len={})\n", .{test_len});
                    if (hybrid.payload.len > 0) {
                        _ = frame.decodeOne(hybrid.payload) catch {
                            allocator.free(hybrid.payload);
                            continue;
                        };
                    }
                    used_next = true;
                    actual_dcid_len = test_len;
                    break :blk_dec hybrid;
                } else |_| {}
            }
        }

        if (next_keys_opt) |next_mat| {
            if (should_log_attempts) {
                logger.debugPrint("[PHASE57-TRY] key_set=NEXT dcid_len={} rx_phase={} largest={} forced={}\n", .{
                    test_len,
                    conn.rx_key_phase,
                    largest_pn,
                    forced_attempted,
                });
            }
            packet.phase57SetAttemptLabel("NEXT");
            logger.debugPrint("[APP-DECODE] TRY NEXT dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{test_len, largest_pn, conn.rx_key_phase, bytes.len});
            if (packet.decodeShortProtected(allocator, bytes, test_len, .{
                .key = next_mat.key,
                .iv = next_mat.iv,
                .hp = next_mat.hp,
            }, largest_pn)) |result| {
                if (result.payload.len > 0) {
                    _ = frame.decodeOne(result.payload) catch {
                        allocator.free(result.payload);
                        continue;
                    };
                }
                logger.debugPrint("[PHASE57] ✅ Decrypted with NEXT keys: dcid_len={} pn={} - will promote\n", .{ test_len, result.packet_number });
                used_next = true;
                actual_dcid_len = test_len;
                break :blk_dec result;
            } else |_| {}
        }

        if (conn.rx_prev_keys) |kp| {
            if (should_log_attempts) {
                logger.debugPrint("[PHASE57-TRY] key_set=PREV dcid_len={} rx_phase={} largest={} forced={}\n", .{
                    test_len,
                    conn.rx_key_phase,
                    largest_pn,
                    forced_attempted,
                });
            }
            packet.phase57SetAttemptLabel("PREV");
            logger.debugPrint("[APP-DECODE] TRY PREV dcid_len={} largest_pn={} rx_phase={} bytes={}\n", .{test_len, largest_pn, conn.rx_key_phase, bytes.len});
            if (packet.decodeShortProtected(allocator, bytes, test_len, .{
                .key = kp.key,
                .iv = kp.iv,
                .hp = kp.hp,
            }, largest_pn)) |result| {
                if (result.payload.len > 0) {
                    _ = frame.decodeOne(result.payload) catch {
                        allocator.free(result.payload);
                        continue;
                    };
                }
                logger.debugPrint("[PHASE57] ✅ Decrypted with PREV keys: dcid_len={} pn={}\n", .{ test_len, result.packet_number });
                used_prev = true;
                actual_dcid_len = test_len;
                break :blk_dec result;
            } else |_| {}
        }
    }

        // All combinations exhausted - attempt forced key update before giving up
        if (tryForceKeyUpdateAndDecrypt(allocator, conn, bytes, largest_pn)) |forced| {
            logger.debugPrint("[PHASE57] ⚠️ Forced key update derived from current secret (dcid_len={}, pn={})\n", .{
                forced.dcid_len,
                forced.decoded.packet_number,
            });
            used_next = true;
            actual_dcid_len = forced.dcid_len;
            break :blk_dec forced.decoded;
        }

        logger.debugPrint("[PHASE57] ❌ All DCID×KeySet combinations failed (0-20 × [CURRENT,NEXT,PREV])\n", .{});
        // PHASE 57 PART 9: Removed buggy force promotion that was flipping rx_key_phase prematurely.
        // Force promotion was promoting keys BEFORE successfully decrypting with NEXT keys,
        // causing rx_key_phase to match incoming key_phase and selecting wrong key generation.
        // The server should ONLY promote after successfully decrypting with NEXT keys.
        // See: PHASE57_PART8_SUMMARY.md - ACK decryption failures due to premature key promotion.
        //
        // if (!forced_attempted and conn.app_rx_next_secret != null and conn.app_rx_next_keys != null) {
        //     logger.debugPrint("[PHASE57] ⚠️ Forcing promotion to NEXT keys after repeated auth failures\n", .{});
        //     promoteToNextKeys(conn, conn.app_rx_next_secret.?, conn.app_rx_next_keys.?);
        //     return decryptShortHeaderWithKeyRotationInternal(allocator, conn, bytes, try_dcid_len, true);
        // }
        conn.onAeadAuthFailure();
        return error.AuthenticationFailed;
    };

    // Cache the successful DCID length for future packets (DCIDs may change post-handshake)
    conn.expected_rx_dcid_len = actual_dcid_len;

    // PHASE 57 PART 2: Check if packet KEY_PHASE differs from connection RX key phase
    // RFC 9001 §6: "Each packet contains a key phase bit that indicates which packet
    // protection keys are used to protect the packet."
    // If key_phase != rx_key_phase, peer has initiated key update (even if we successfully
    // decrypted with current keys, which shouldn't happen but handle defensively)
    if (!used_next and !used_prev and decoded.key_phase != conn.rx_key_phase) {
        logger.debugPrint("[PHASE57-KEY-UPDATE] 🔑 KEY_PHASE mismatch detected! packet_kp={} conn_rx_kp={} pn={}\n", .{
            decoded.key_phase,
            conn.rx_key_phase,
            decoded.packet_number,
        });
        logger.debugPrint("[PHASE57-KEY-UPDATE] Peer initiated key update - will promote to NEXT keys\n", .{});
        used_next = true; // Trigger key promotion in caller
    }

    // PHASE 57: Enhanced logging for key phase tracking
    if (used_next) {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with NEXT keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    } else if (used_prev) {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with PREV keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    } else {
        logger.debugPrint("[PHASE57-DECRYPT] ✅ Decrypted with CURRENT keys: pn={} key_phase={} conn_rx_kp={}\n", .{
            decoded.packet_number,
            decoded.key_phase,
            conn.rx_key_phase,
        });
    }

    return ShortDecryptResult{
        .decoded = decoded,
        .used_next = used_next,
        .used_prev = used_prev,
        .dcid_len = actual_dcid_len,
    };
}

fn tryForceKeyUpdateAndDecrypt(
    allocator: std.mem.Allocator,
    conn: *conn_mod.Connection,
    bytes: []const u8,
    largest_pn: u64,
) ?ShortDecryptResult {
    const current_secret = conn.app_rx_secret orelse return null;
    const current_keys = conn.app_rx_keys orelse return null;

    const next_keys_present = conn.app_rx_next_keys != null;
    const next_secret_present = conn.app_rx_next_secret != null;
    logger.debugPrint("[PHASE57] fallback invoked: rx_key_phase={} next_keys_present={} next_secret_present={} largest_pn={}\n", .{
        conn.rx_key_phase,
        next_keys_present,
        next_secret_present,
        largest_pn,
    });
    const current_key_hex = std.fmt.bytesToHex(&current_keys.key, .lower);
    var next_key_hex_storage: [32]u8 = undefined;
    const next_key_hex: []const u8 = if (conn.app_rx_next_keys) |nk| blk: {
        next_key_hex_storage = std.fmt.bytesToHex(&nk.key, .lower);
        break :blk next_key_hex_storage[0..];
    } else "null";
    logger.debugPrint("[PHASE57] current_key={s} next_key={s}\n", .{
        current_key_hex[0..],
        next_key_hex,
    });

    const forced_secret = key_schedule.updateQuicSecret(current_secret);
    const forced_mat = if (conn.version_v2)
        key_schedule.deriveKeyIvHpV2(forced_secret)
    else
        key_schedule.deriveKeyIvHp(forced_secret);

    logger.debugPrint("[PHASE57] Forced key derivation: base_secret={s} next_secret={s} key={s} iv={s} hp={s}\n", .{
        std.fmt.bytesToHex(current_secret, .lower),
        std.fmt.bytesToHex(&forced_secret, .lower),
        std.fmt.bytesToHex(&forced_mat.key, .lower),
        std.fmt.bytesToHex(&forced_mat.iv, .lower),
        std.fmt.bytesToHex(&forced_mat.hp, .lower),
    });

    var test_len: u8 = 0;
    while (test_len <= 20) : (test_len += 1) {
        packet.phase57SetAttemptLabel("FORCED");
        logger.debugPrint("[APP-DECODE] TRY FORCED dcid_len={} largest_pn={} bytes={}\n", .{test_len, largest_pn, bytes.len});
        if (packet.decodeShortProtected(allocator, bytes, test_len, .{
            .key = forced_mat.key,
            .iv = forced_mat.iv,
            .hp = forced_mat.hp,
        }, largest_pn)) |result| {
            if (result.payload.len > 0) {
                _ = frame.decodeOne(result.payload) catch {
                    allocator.free(result.payload);
                    continue;
                };
            }

            conn.app_rx_next_secret = forced_secret;
            conn.app_rx_next_keys = .{
                .key = forced_mat.key,
                .iv = forced_mat.iv,
                .hp = forced_mat.hp,
            };

            return ShortDecryptResult{
                .decoded = result,
                .used_next = true,
                .used_prev = false,
                .dcid_len = test_len,
            };
        } else |_| {}
    }

    return null;
}

/// Promote connection to NEXT application keys after successful decryption.
/// Extracted from endpoint.zig lines 1289-1302 (Phase 4b.5 Session 3).
///
/// RFC 9001 §6: "Endpoints can use multiple packets to send data and can update
/// keys to improve forward secrecy and confidentiality."
///
/// When a packet is successfully decrypted with derived NEXT keys:
/// 1. Preserve current keys as previous (zeroize any older prev first)
/// 2. Install NEXT keys as current app_rx_keys
/// 3. Update app_rx_secret to NEXT secret
/// 4. Toggle rx_key_phase bit
/// 5. Set rx_prev_allow window to 16 packets
///
/// Parameters:
/// - conn: Connection to promote keys on
/// - next_secret: NEXT RX traffic secret (32 bytes)
/// - next_keys: NEXT RX AEAD keys (key, iv, hp)
pub fn promoteToNextKeys(
    conn: *conn_mod.Connection,
    next_secret: [32]u8,
    next_keys: packet.AeadKeys,
) void {
    // PHASE 57: Log key promotion
    const old_key_phase = conn.rx_key_phase;
    const new_key_phase = !old_key_phase;
    logger.debugPrint("[PHASE57-KEY-PROMOTE] 🔑 Promoting to NEXT RX keys: rx_key_phase {} → {}\n", .{
        old_key_phase,
        new_key_phase,
    });

    // PHASE 57 Part 5: Re-derive NEXT keys from the current NEXT secret BEFORE promotion
    // This maintains the one-generation-ahead invariant (quic-go updatable_aead.go:120-123)
    // Derive NEXT from the NEXT secret (the one we're about to promote)
    const new_next_secret = key_schedule.updateQuicSecret(next_secret);
    const new_next_mat = if (conn.version_v2)
        key_schedule.deriveKeyIvHpV2(new_next_secret)
    else
        key_schedule.deriveKeyIvHp(new_next_secret);
    logger.debugPrint("[PHASE57-KEY-PROMOTE] 🔄 Pre-derived new NEXT keys before promotion\n", .{});

    // Preserve current keys as previous (zeroize any older prev first)
    if (conn.rx_prev_keys) |*old_prev| {
        @memset(&old_prev.key, 0);
        @memset(&old_prev.iv, 0);
        @memset(&old_prev.hp, 0);
    }
    conn.rx_prev_keys = conn.app_rx_keys;
    conn.rx_prev_allow = 16; // bounded window for reordering

    // PHASE 57 PART 10: Preserve CURRENT HP key - RFC 9001 §6 and quic-go confirm HP is NOT rotated
    // Evidence: quic-go's rollKeys() only updates rcvAEAD/sendAEAD, NOT headerDecrypter/headerEncrypter
    const preserved_hp = conn.app_rx_keys.?.hp;

    // Install NEXT keys/secret as current (AEAD only, HP preserved)
    conn.app_rx_keys = .{ .key = next_keys.key, .iv = next_keys.iv, .hp = preserved_hp };
    conn.app_rx_secret = next_secret;
    conn.rx_key_phase = !conn.rx_key_phase;

    logger.debugPrint("[PHASE57-HP-PRESERVE] HP key preserved during promotion (not rotated per RFC 9001 §6)\n", .{});

    // Install the pre-derived NEXT keys/secret
    conn.app_rx_next_secret = new_next_secret;
    conn.app_rx_next_keys = .{ .key = new_next_mat.key, .iv = new_next_mat.iv, .hp = new_next_mat.hp };

    logger.debugPrint("[PHASE57-KEY-PROMOTE] ✅ Key promotion complete - ready for next packet\n", .{});
}

/// Decrement previous key allowance after using rx_prev_keys.
/// Extracted from endpoint.zig lines 1326-1346 (Phase 4b.5 Session 3).
///
/// RFC 9001 §6.5: "An endpoint MAY retain old keys for a short period to allow
/// decryption of packets that are reordered in the network."
///
/// When a packet is decrypted with previous keys:
/// 1. Decrement rx_prev_allow counter
/// 2. If counter reaches zero, zeroize and drop rx_prev_keys
/// 3. This prevents unbounded key retention
///
/// Parameters:
/// - conn: Connection with rx_prev_keys and rx_prev_allow
pub fn decrementPrevKeyAllowance(conn: *conn_mod.Connection) void {
    if (conn.rx_prev_allow > 0) {
        conn.rx_prev_allow -= 1;
        if (conn.rx_prev_allow == 0) {
            if (conn.rx_prev_keys) |*to_zero| {
                @memset(&to_zero.key, 0);
                @memset(&to_zero.iv, 0);
                @memset(&to_zero.hp, 0);
            }
            conn.rx_prev_keys = null;
        }
    } else {
        // Safety: if allowance already zero, drop prev immediately
        if (conn.rx_prev_keys) |*to_zero2| {
            @memset(&to_zero2.key, 0);
            @memset(&to_zero2.iv, 0);
            @memset(&to_zero2.hp, 0);
        }
        conn.rx_prev_keys = null;
    }
}

// =============================================================================
// Phase 4b.5 Session 3: Frame Processing and ACK Generation
// =============================================================================

/// Result of frame processing.
/// Tracks flags that affect ACK generation and connection state.
pub const FrameProcessResult = struct {
    /// Whether any ack-eliciting frames were seen (RFC 9000 §13.2.1)
    saw_ack_eliciting: bool = false,
    /// Whether HANDSHAKE_DONE was received (triggers key drop)
    saw_handshake_done: bool = false,
    /// Whether CONNECTION_CLOSE was received (terminates processing)
    saw_close: bool = false,
};

/// Parse and process frames from decrypted 1-RTT payload.
/// Extracted from endpoint.zig lines 1347-1492 (Phase 4b.5 Session 3).
///
/// RFC 9000 §12: "After removing packet protection, the unprotected payload
/// includes frames."
///
/// This function:
/// 1. Parses frames one by one using frame.decodeOne()
/// 2. Dispatches each frame to frame_handler.processFrame()
/// 3. Tracks ack-eliciting status, HANDSHAKE_DONE, CONNECTION_CLOSE
/// 4. Handles post-frame-processing logic (key drops, connection closure)
///
/// Parameters:
/// - ctx: RxContext with allocator, config, connections
/// - conn: Connection receiving the frames
/// - peer: Socket address of the peer
/// - payload: Decrypted frame payload
/// - send_fn: Function to send UDP datagrams
///
/// Returns:
/// - FrameProcessResult with saw_ack_eliciting, saw_handshake_done, saw_close flags
///
/// RFC 9000 §13.2.1: "Packets that are ack-eliciting MUST be acknowledged
/// within the maximum ack delay."
pub fn processFrames(
    ctx: *RxContext,
    conn: *conn_mod.Connection,
    peer: conn_mod.SockAddr,
    payload: []const u8,
    send_fn: SendFn,
) !FrameProcessResult {
    // RFC 9000 §10.2: Discard frames for connections in the closing/draining state.
    // After sendConnectionClose() sets closed=true, no further frame processing
    // should occur to prevent accessing inconsistent connection state.
    if (conn.closed) return FrameProcessResult{};

    var result = FrameProcessResult{};
    var offset: usize = 0;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    logger.debugPrint("Parsing frames from payload, total_len={}, role={s}\n", .{
        payload.len,
        if (conn.role == .Server) "Server" else "Client",
    });

    // Parse frames from payload
    while (offset < payload.len) {
        const first_byte = if (payload[offset..].len > 0) payload[offset] else 0;
        const fr = frame.decodeOne(payload[offset..]) catch |err| {
            logger.debugPrint("Frame decode error at offset {}: {} (first_byte=0x{X:0>2})\n", .{ offset, err, first_byte });
            break;
        };
        logger.debugPrint("Decoded frame at offset {}: type={s}\n", .{ offset, @tagName(fr.f) });
        if (fr.f == .stream) {
            const s = fr.f.stream;
            logger.debugPrint("[STREAM-FRAME] id={} off={} len={} fin={}\n", .{ s.stream_id, s.offset orelse 0, s.data.len, s.fin });
        }
        offset += fr.n;

        // Create frame handler context
        var frame_ctx = frame_handler.FrameContext{
            .conn = conn,
            .allocator = ctx.allocator,
            .send_fn = send_fn,
            .peer = peer,
            .space = .Application,
            .cfg = ctx.cfg,
            .endpoint = null, // Will be set by caller if needed
        };

        // Process frame through handler
        const frame_result = try frame_handler.processFrame(&frame_ctx, fr.f);

        logger.debugPrint("[processFrames] Frame processed: saw_handshake_done={}\n", .{frame_result.saw_handshake_done});

        // Accumulate flags
        result.saw_ack_eliciting = result.saw_ack_eliciting or frame_result.saw_ack_eliciting;
        result.saw_handshake_done = result.saw_handshake_done or frame_result.saw_handshake_done;
        result.saw_close = result.saw_close or frame_result.saw_close;
    }

    logger.debugPrint("[processFrames] Returning result: saw_ack_eliciting={}, saw_handshake_done={}, saw_close={}\n", .{
        result.saw_ack_eliciting,
        result.saw_handshake_done,
        result.saw_close,
    });

    // Record ack-eliciting reception if applicable
    if (result.saw_ack_eliciting) {
        conn.recordAckElicitingRx(.Application, now_ns);
        if (conn.app_tx_keys) |tx_keys| {
            var fb: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&fb);
            const w = fbs.writer();
            const ack_desc = conn.buildAckApp();
            const ack_frame = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = 0, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges } };
            _ = ack_frame.write(w) catch 0;
            const frames_data = fbs.getWritten();
            const dcid_sh = conn.shortHeaderDcid();
            if (packet.encodeShortProtected(ctx.allocator.*, dcid_sh, @as(u32, @truncate(conn.pn_app_tx)), 2, frames_data, tx_keys, conn.tx_key_phase)) |pkt_bytes| {
                defer ctx.allocator.free(pkt_bytes);
                _ = ctx.send_fn(peer, pkt_bytes) catch {};
                conn.onShortHeaderPacketSent(pkt_bytes.len, false);
                logger.debugPrint("[APP-ACK] immediate ack largest={} pn={} bytes={}\n", .{ack_desc.largest, conn.pn_app_tx, pkt_bytes.len});
                conn.pn_app_tx +%= 1;
            } else |_| {}
        }
    }

    // Handle HANDSHAKE_DONE: drop Handshake keys (with conditions)
    if (result.saw_handshake_done) {
        logger.debugPrint("[processApplicationFrames] Setting handshake_done_seen=true for {s}\n", .{
            if (conn.role == .Server) "Server" else "Client",
        });
        conn.handshake_done_seen = true;

        // RFC 9001 §4.1.2: Only drop Handshake keys if safe to do so
        // Client (which receives HANDSHAKE_DONE): drop after first Handshake packet sent
        const can_drop_hs_keys = if (conn.role == .Client) conn.handshake_packet_sent else false;

        if (can_drop_hs_keys) {
            logger.debugPrint("[processApplicationFrames] {s}: Dropping Handshake keys after HANDSHAKE_DONE\n", .{
                if (conn.role == .Server) "Server" else "Client",
            });
            conn.hs_rx_keys = null;
            conn.hs_tx_keys = null;
        } else {
            logger.debugPrint("[processApplicationFrames] {s}: Deferring Handshake key drop (handshake_packet_sent={})\n", .{
                if (conn.role == .Server) "Server" else "Client",
                conn.handshake_packet_sent,
            });
        }
    }

    // Handle CONNECTION_CLOSE: mark connection as closed
    if (result.saw_close) {
        logger.debugPrint("DEBUG: Received CONNECTION_CLOSE frame, closing connection\n", .{});
        conn.closed = true;
    }

    return result;
}

/// Context for ACK generation and transmission.
/// Contains only what's needed for generating and sending ACK responses.
pub const AckContext = struct {
    allocator: *std.mem.Allocator,
    conn: *conn_mod.Connection,
    peer: conn_mod.SockAddr,
    send_fn: SendFn,
    cfg: *const cfg.QuicConfig,
    test_capture_enabled: bool,
};

/// Generate and send ACK frame for received 1-RTT packet.
/// Extracted from endpoint.zig lines 1493-1669 (Phase 4b.5 Session 3).
///
/// RFC 9000 §13.2: "Receivers send ACK frames to inform senders of packets
/// they have received and processed."
///
/// This function handles:
/// 1. Deferred ECN ACK emission when amplification allows
/// 2. AEAD integrity limit CONNECTION_CLOSE (RFC 9000 §20, code 0x0f)
/// 3. Main ACK generation with ECN support
/// 4. Amplification limit enforcement (RFC 9000 §8.1)
/// 5. MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS piggybacking
/// 6. NEW_CONNECTION_ID frame piggybacking
/// 7. ACK-only fallback when amplification-limited
///
/// Parameters:
/// - ack_ctx: AckContext with allocator, connection, peer, send_fn, config
/// - frame_result: Result from frame processing (for ack-eliciting check)
/// - ecn_bits: ECN bits from IP header (if available)
///
/// Returns: void (errors are logged but not propagated)
///
/// RFC 9000 §8.1: "A server MAY send a single packet containing only an ACK
/// frame in response to each received datagram when under amplification limit."
pub fn generateAndSendAck(
    ack_ctx: *AckContext,
    frame_result: FrameProcessResult,
    ecn_bits: ?u8,
) !void {
    const conn = ack_ctx.conn;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    // Test-only debug logging
    if (ack_ctx.test_capture_enabled) {
        logger.debugPrint("APP saw_any={s}\n", .{if (frame_result.saw_ack_eliciting) "y" else "n"});
    }

    // Check if connection is closed (from CONNECTION_CLOSE frame)
    if (conn.closed) {
        return; // Stop processing
    }

    // If deferred ECN ACK is pending and amplification allows, emit it now
    if (conn.ecn_app_ack_pending and conn.app_tx_keys != null and conn.canSendUnderAmplification()) {
        var ack_buf = std.ArrayList(u8){};
        defer ack_buf.deinit(ack_ctx.allocator.*);
        const w = ack_buf.writer(ack_ctx.allocator.*);
        const ad = conn.buildAckApp();
        const ack_ecn_now = conn.getAckEcn(.Application);

        if (ack_ctx.test_capture_enabled and ack_ecn_now != null) {
            logger.debugPrint("APP pending ACK_ECN flush ce={d} ect0={d} ect1={d}\n", .{
                ack_ecn_now.?.ce, ack_ecn_now.?.ect0, ack_ecn_now.?.ect1
            });
        }

        const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
        const ackf = frame.Frame{ .ack = .{
            .largest = ad.largest,
            .ack_delay = ack_delay,
            .first_range = ad.first_range,
            .ranges = ad.ranges,
            .ecn = ack_ecn_now
        } };
        _ = ackf.write(w) catch 0;

        const dcid_ack = if (conn.peer_initial_scid.len > 0)
            conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)]
        else
            &[_]u8{};

        const pkt = packet.encodeShortProtected(
            ack_ctx.allocator.*,
            dcid_ack,
            @as(u32, @truncate(conn.pn_app_tx)),
            2,
            ack_buf.items,
            conn.app_tx_keys.?,
            conn.tx_key_phase
        ) catch null;

        if (pkt) |bytes_out| {
            defer ack_ctx.allocator.free(bytes_out);
            _ = ack_ctx.send_fn(ack_ctx.peer, bytes_out) catch {};
            conn.onShortHeaderPacketSent(bytes_out.len, false);
            conn.ecn_app_ack_pending = false;
            return; // Stop further processing
        }
    }

    // Enforce AEAD integrity limit: send CONNECTION_CLOSE if limit reached
    if (conn.closed) {
        if (conn.app_tx_keys) |tx_keys| {
            var fb = std.ArrayList(u8){};
            defer fb.deinit(ack_ctx.allocator.*);
            const w = fb.writer(ack_ctx.allocator.*);

            // AEAD_LIMIT_REACHED = 0x0f per RFC 9000 §20
            _ = (frame.Frame{ .connection_close = .{
                .error_code = 0x0f,
                .frame_type = 0,
                .reason = "AEAD integrity limit reached"
            } }).write(w) catch 0;

            // Amplification gating: only send if validated or within 3x limit
            const allow_send = conn.canSendUnderAmplification();
            if (allow_send) {
                const dcid_ack2 = if (conn.peer_initial_scid.len > 0)
                    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                else
                    &[_]u8{};

                const out = packet.encodeShortProtected(
                    ack_ctx.allocator.*,
                    dcid_ack2,
                    @as(u32, @truncate(conn.pn_app_tx)),
                    2,
                    fb.items,
                    tx_keys,
                    conn.tx_key_phase
                ) catch null;

                if (out) |pkt_bytes| {
                    defer ack_ctx.allocator.free(pkt_bytes);
                    _ = ack_ctx.send_fn(ack_ctx.peer, pkt_bytes) catch {};
                    conn.onShortHeaderPacketSent(pkt_bytes.len, true);
                }
            }
        }
        return;
    }

    // Generate ACK if we saw ack-eliciting frames or ECN bits
    if (frame_result.saw_ack_eliciting or (ecn_bits != null)) {
        if (ack_ctx.test_capture_enabled) {
            logger.debugPrint("APP have_tx_keys={s}\n", .{if (conn.app_tx_keys != null) "y" else "n"});
        }

        // PHASE 42 PART 21: Comprehensive ACK timing and trigger logging
        const ack_trigger_ns = now_ns;
        const last_rx_ns = conn.last_ack_eliciting_rx_app_ns;
        const delay_since_rx_us = if (last_rx_ns > 0 and ack_trigger_ns >= last_rx_ns)
            (ack_trigger_ns - last_rx_ns) / 1000
        else
            0;

        logger.debugPrint("[P42-21-ACK-TRIGGER] ⏰ ACK triggered: saw_ack_elicit={s} ecn={s} delay_since_rx={d}us\n", .{
            if (frame_result.saw_ack_eliciting) "Y" else "N",
            if (ecn_bits != null) "Y" else "N",
            delay_since_rx_us,
        });

        if (conn.app_tx_keys) |tx_keys| {
            const allow_send = conn.canSendUnderAmplification();

            // PHASE 42 PART 21: Enhanced amplification logging with timing context
            logger.debugPrint("[P42-21-ACK-AMPLIF] allow_send={s} rx_unval={d} tx_unval={d} validated={s} ratio={d:.2}\n", .{
                if (allow_send) "Y" else "N",
                conn.bytes_rx_unvalidated,
                conn.bytes_tx_unvalidated,
                if (conn.address_validated) "Y" else "N",
                if (conn.bytes_rx_unvalidated > 0)
                    @as(f64, @floatFromInt(conn.bytes_tx_unvalidated)) / @as(f64, @floatFromInt(conn.bytes_rx_unvalidated))
                else
                    0.0,
            });

            // Precompute ACK_ECN selection to keep consistent across branches
            var ack_ecn_common = conn.getAckEcn(.Application);
            if (ack_ecn_common == null) {
                if (ecn_bits) |e_cur| {
                    const bcur: u8 = e_cur & 0x03;
                    if (bcur != 0) {
                        ack_ecn_common = switch (bcur) {
                            0x01 => .{ .ect0 = 0, .ect1 = 1, .ce = 0 },
                            0x02 => .{ .ect0 = 1, .ect1 = 0, .ce = 0 },
                            0x03 => .{ .ect0 = 0, .ect1 = 0, .ce = 1 },
                            else => null,
                        };
                    }
                }
            }

            // If ECN observed and amplification blocks, mark pending
            if (ack_ecn_common != null and !allow_send) {
                conn.ecn_app_ack_pending = true;
            }

            if (allow_send) {
                // Emit immediate ACK_ECN if ECN observed
                if (ack_ecn_common != null) {
                    var ack_only = std.ArrayList(u8){};
                    defer ack_only.deinit(ack_ctx.allocator.*);
                    const wa = ack_only.writer(ack_ctx.allocator.*);
                    const ad = conn.buildAckApp();

                    if (ack_ctx.test_capture_enabled) {
                        logger.debugPrint("APP immediate ACK_ECN ce={d} ect0={d} ect1={d}\n", .{
                            ack_ecn_common.?.ce, ack_ecn_common.?.ect0, ack_ecn_common.?.ect1
                        });
                    }

                    const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
                    const ackf = frame.Frame{ .ack = .{
                        .largest = ad.largest,
                        .ack_delay = ack_delay,
                        .first_range = ad.first_range,
                        .ranges = ad.ranges,
                        .ecn = ack_ecn_common
                    } };
                    _ = ackf.write(wa) catch 0;

                    const dcid_ack3 = if (conn.peer_initial_scid.len > 0)
                        conn.peer_initial_scid.bytes[0..@min(conn.peer_initial_scid.len, 4)]
                    else
                        &[_]u8{};

                    const po = packet.encodeShortProtected(
                        ack_ctx.allocator.*,
                        dcid_ack3,
                        @as(u32, @truncate(conn.pn_app_tx)),
                        2,
                        ack_only.items,
                        tx_keys,
                        conn.tx_key_phase
                    ) catch null;

                    if (po) |bytes_out0| {
                        defer ack_ctx.allocator.free(bytes_out0);
                        const send_start_ns = std.time.nanoTimestamp();
                        _ = ack_ctx.send_fn(ack_ctx.peer, bytes_out0) catch {};
                        const send_end_ns = std.time.nanoTimestamp();
                        const send_duration_us = @as(u64, @intCast(@abs(send_end_ns - send_start_ns))) / 1000;
                        const total_delay_us = delay_since_rx_us + send_duration_us;

                        logger.debugPrint("[P42-21-ACK-SENT] ✅ ECN ACK sent: pkt_len={d}B largest={d} delay_rx_to_tx={d}us send_us={d}us total={d}us\n", .{
                            bytes_out0.len,
                            ad.largest,
                            delay_since_rx_us,
                            send_duration_us,
                            total_delay_us,
                        });
                        conn.onShortHeaderPacketSent(bytes_out0.len, false);
                    }
                    return; // Stop further processing
                } else {
                    // Build ACK with MAX_* frame piggybacking
                    var frames_buf = std.ArrayList(u8){};
                    defer frames_buf.deinit(ack_ctx.allocator.*);
                    const w = frames_buf.writer(ack_ctx.allocator.*);
                    const ack_desc = conn.buildAckApp();

                    if (ack_ctx.test_capture_enabled) {
                        logger.debugPrint("APP ACK (no ECN) allow_send\n", .{});
                    }

                    const ack_delay = conn.getAckDelayEncoded(.Application, now_ns);
                    const ack = frame.Frame{ .ack = .{
                        .largest = ack_desc.largest,
                        .ack_delay = ack_delay,
                        .first_range = ack_desc.first_range,
                        .ranges = ack_desc.ranges,
                        .ecn = null
                    } };
                    _ = ack.write(w) catch 0;

                    // PHASE 42 PART 9: Send MAX_STREAM_DATA for ALL active streams (RFC 9000 §4.2)
                    // Per-stream flow control requires tracking and updating each stream's window
                    // PHASE 42 PART 19: Enhanced debug logging to track flow control behavior
                    if (conn.streams_rx_init) {
                        var iter = conn.streams_rx.iterator();
                        var fc_frames_sent: u32 = 0;
                        while (iter.next()) |entry| {
                            const stream_id = entry.key_ptr.*;
                            const stream = entry.value_ptr;
                            if (stream.local_max_stream_data > stream.last_sent_max_stream_data) {
                        logger.debugPrint("[RX-INSTR] stream={} recv_off={} inbox_len={} local_max_stream_data={} last_sent={} fin_off={?}\n", .{stream_id, stream.recv_off, stream.inbox.items.len, stream.local_max_stream_data, stream.last_sent_max_stream_data, stream.fin_off});
                                const delta = stream.local_max_stream_data - stream.last_sent_max_stream_data;
                                logger.debugPrint("[P42-19-FC-TX] Sending MAX_STREAM_DATA(stream={}, max={}, delta=+{}, recv_off={}, inbox={})\n",
                                    .{stream_id, stream.local_max_stream_data, delta, stream.recv_off, stream.inbox.items.len});
                                _ = (frame.Frame{ .max_stream_data = .{
                                    .stream_id = stream_id,
                                    .max = stream.local_max_stream_data
                                } }).write(w) catch {};
                                stream.last_sent_max_stream_data = stream.local_max_stream_data;
                                fc_frames_sent += 1;
                            } else if (stream.recv_off > 0) {
                                // Log active streams that didn't need window update
                                logger.debugPrint("[P42-19-FC-SKIP] Stream {} no update needed (local_max={}, last_sent={}, recv_off={}, inbox={})\n",
                                    .{stream_id, stream.local_max_stream_data, stream.last_sent_max_stream_data, stream.recv_off, stream.inbox.items.len});
                            }
                        }
                        if (fc_frames_sent > 0) {
                            logger.debugPrint("[P42-19-FC-SUMMARY] Sent {} MAX_STREAM_DATA frames in this ACK packet\n", .{fc_frames_sent});
                        }
                    }

                    if (conn.local_max_data > conn.last_sent_max_data) {
                        _ = (frame.Frame{ .max_data = .{
                            .max = conn.local_max_data
                        } }).write(w) catch {};
                        conn.last_sent_max_data = conn.local_max_data;
                    }

                    if (conn.local_max_streams_bidi > conn.last_sent_max_streams_bidi) {
                        _ = (frame.Frame{ .max_streams_bidi = .{
                            .max = conn.local_max_streams_bidi
                        } }).write(w) catch {};
                        conn.last_sent_max_streams_bidi = conn.local_max_streams_bidi;
                    }

                    // Append pending NEW_CONNECTION_ID frames
                    var any_pending = false;
                    {
                        var bi: usize = 0;
                        while (bi < conn.local_cids.len) : (bi += 1) {
                            if (conn.pending_new_cid.isSet(@intCast(bi))) {
                                any_pending = true;
                                break;
                            }
                        }
                    }
                    if (any_pending) {
                        _ = conn.writePendingNewConnectionIds(w, 2) catch 0;
                    }

                    const dcid_ack4 = if (conn.peer_initial_scid.len > 0)
                        conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                    else
                        &[_]u8{};

                    const out = packet.encodeShortProtected(
                        ack_ctx.allocator.*,
                        dcid_ack4,
                        @as(u32, @truncate(conn.pn_app_tx)),
                        2,
                        frames_buf.items,
                        tx_keys,
                        conn.tx_key_phase
                    ) catch null;

                    if (out) |pkt_bytes| {
                        defer ack_ctx.allocator.free(pkt_bytes);
                        const send_start_ns = std.time.nanoTimestamp();
                        _ = ack_ctx.send_fn(ack_ctx.peer, pkt_bytes) catch {};
                        const send_end_ns = std.time.nanoTimestamp();
                        const send_duration_us = @as(u64, @intCast(@abs(send_end_ns - send_start_ns))) / 1000;
                        const total_delay_us = delay_since_rx_us + send_duration_us;

                        logger.debugPrint("[P42-21-ACK-SENT] ✅ Normal ACK sent: pkt_len={d}B largest={d} delay_rx_to_tx={d}us send_us={d}us total={d}us\n", .{
                            pkt_bytes.len,
                            ack_desc.largest,
                            delay_since_rx_us,
                            send_duration_us,
                            total_delay_us,
                        });
                        conn.onShortHeaderPacketSent(pkt_bytes.len, false);
                    }
                }
            } else {
                // RFC 9000 §8.1: Send ACK-only when under amplification limit
                logger.debugPrint("[P42-21-ACK-BLOCKED] ⚠️  ACK blocked by amplification limit\n", .{});
                var ack_only = std.ArrayList(u8){};
                defer ack_only.deinit(ack_ctx.allocator.*);
                const w2 = ack_only.writer(ack_ctx.allocator.*);
                const ack_desc2 = conn.buildAckApp();

                if (ack_ctx.test_capture_enabled) {
                    logger.debugPrint("APP ack-only branch\n", .{});
                    if (ack_ecn_common) |e2| {
                        logger.debugPrint("APP ACK_ECN ack-only ce={d} ect0={d} ect1={d}\n", .{
                            e2.ce, e2.ect0, e2.ect1
                        });
                    } else {
                        logger.debugPrint("APP ACK ack-only (no ECN)\n", .{});
                    }
                }

                const ack_delay2 = conn.getAckDelayEncoded(.Application, now_ns);
                const ack2 = frame.Frame{ .ack = .{
                    .largest = ack_desc2.largest,
                    .ack_delay = ack_delay2,
                    .first_range = ack_desc2.first_range,
                    .ranges = ack_desc2.ranges,
                    .ecn = ack_ecn_common
                } };
                _ = ack2.write(w2) catch 0;

                const dcid_ack5 = if (conn.peer_initial_scid.len > 0)
                    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                else
                    &[_]u8{};

                const out2 = packet.encodeShortProtected(
                    ack_ctx.allocator.*,
                    dcid_ack5,
                    @as(u32, @truncate(conn.pn_app_tx)),
                    2,
                    ack_only.items,
                    tx_keys,
                    conn.tx_key_phase
                ) catch null;

                if (out2) |pkt_bytes2| {
                    defer ack_ctx.allocator.free(pkt_bytes2);
                    _ = ack_ctx.send_fn(ack_ctx.peer, pkt_bytes2) catch {};
                    // ACK-only is not ack-eliciting
                    conn.onShortHeaderPacketSent(pkt_bytes2.len, false);
                }
            }
        }
    }
}

// =============================================================================
// Phase 4b.5 Session 3: Main processShortHeader() Coordinator
// =============================================================================

/// Process 1-RTT short header packet.
/// Extracted from endpoint.zig lines 1092-1671 (Phase 4b.5 Session 3).
///
/// This coordinator function integrates all extracted components:
/// 1. Connection lookup via peer address + DCID
/// 2. Decryption with DCID enumeration and key rotation
/// 3. Key promotion/demotion after successful decryption
/// 4. Packet number tracking
/// 5. Frame parsing and dispatch
/// 6. ACK generation and transmission
///
/// RFC 9000 §17.3: "Short header packets are used after the version and
/// 1-RTT keys are negotiated."
///
/// Parameters:
/// - ctx: RxContext with allocator, connections, config
/// - peer: Socket address of the peer
/// - bytes: Raw short header packet bytes
/// - ecn_bits: ECN bits from IP header (if available)
/// - send_fn: Function to send UDP datagrams
///
/// Returns: void (errors are logged but not propagated)
///
/// RFC 9000 §12: "QUIC packets are carried in UDP datagrams."
var g_app_decrypt_start: u64 = 0;
var g_app_decrypt_success: u64 = 0;

pub fn processShortHeader(
    ctx: *RxContext,
    peer: conn_mod.SockAddr,
    bytes: []const u8,
    ecn_bits: ?u8,
    send_fn: SendFn,
) void {
    // Phase 24 DEBUG: Unconditional logging to trace HANDSHAKE_DONE delivery
    logger.debugPrint("[processShortHeader] Called for {} bytes\n", .{bytes.len});

    // =============================================================================
    // STEP 1: Connection Lookup (RFC 9000 §5.2)
    // =============================================================================
    // Find connection by peer address + DCID from packet
    // Two-phase lookup: peer_hash + dcid_hash, then DCID-only for NAT rebinding

    const lookup_result = lookup.findConnectionByDcid(
        ctx.conns,
        peer,
        bytes,
        null, // No path_changed_fn callback - NAT rebinding handled by caller
    );

    const conn = lookup_result.conn orelse {
        // No connection found for this peer + DCID combination
        logger.debugPrint("[processShortHeader] No connection found for short header packet from peer\n", .{});
        if (ctx.test_capture_enabled) {
            logger.debugPrint("No connection found for short header packet from peer\n", .{});
        }
        return;
    };

    // RFC 9000 §10.2: Once a connection is closed, further packets MUST be
    // discarded. The connection will be removed from the tracking tables by
    // pruneClosed() at the end of the current poll() cycle.
    if (conn.closed) {
        logger.debugPrint("[processShortHeader] Dropping packet for closed connection\n", .{});
        return;
    }

    logger.debugPrint("[processShortHeader] Found connection, role={s}, has_app_rx_keys={}\n", .{
        if (conn.role == .Server) "Server" else "Client",
        conn.app_rx_keys != null,
    });

    const dcid_len = lookup_result.dcid_len;

    if (ctx.test_capture_enabled) {
        logger.debugPrint("=== RECEIVED 1-RTT PACKET === size={}, dcid_len={}, has_app_rx={}, has_app_tx={}\n", .{
            bytes.len,
            dcid_len,
            conn.app_rx_keys != null,
            conn.app_tx_keys != null,
        });
    }

    // =============================================================================
    // STEP 2: ECN and Anti-Amplification Tracking (RFC 3168, RFC 9000 §8.1)
    // =============================================================================

    // Process ECN bits if provided (RFC 3168)
    if (ecn_bits) |e| conn.onEcnMark(.Application, e);

    // Track bytes received from unvalidated address for anti-amplification (RFC 9000 §8.1)
    conn.addRxUnvalidated(bytes.len);

    // Test-only debug: log short-header match and ECN bits/keys state
    if (ctx.test_capture_enabled) {
        const has_rx = (conn.app_rx_keys != null);
        const has_tx = (conn.app_tx_keys != null);
        const eb: u8 = if (ecn_bits) |e| (e & 0x03) else 0xff;
        logger.debugPrint("APP short: match dcid_len={d} rx_keys={s} tx_keys={s} ecn_bits=0x{x}\n", .{
            dcid_len,
            if (has_rx) "y" else "n",
            if (has_tx) "y" else "n",
            eb,
        });
    }

    // =============================================================================
    // STEP 3: DCID Length Caching and Key Check (Bug #6 fix)
    // =============================================================================

    const observed_dcid_len = dcid_len;
    const cached_dcid_len = conn.expected_rx_dcid_len;

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Will try decryption with observed_dcid_len={} cached_dcid_len={}\n", .{
            observed_dcid_len,
            if (cached_dcid_len) |c| c else 0xff,
        });
    }

    // Check if we have application-level RX keys
    const rx_keys = conn.app_rx_keys orelse {
        logger.debugPrint("[APP-SHORT-NO-KEYS] dropping short header packet (pn tracking can't proceed)\n", .{});
        // No RX keys yet - handshake not complete
        if (ctx.test_capture_enabled) {
            logger.debugPrint("No app_rx_keys available, dropping packet\n", .{});
        }
        return;
    };

    // =============================================================================
    // STEP 4: Packet Decryption with Key Rotation (RFC 9001 §6)
    // =============================================================================

    if (ctx.test_capture_enabled) {
        logger.debugPrint("\n=== 1-RTT DECRYPT ATTEMPT ===\n", .{});
        logger.debugPrint("Packet first 32 bytes: ", .{});
        for (bytes[0..@min(32, bytes.len)]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\nUsing RX keys: key[0..8]=", .{});
        for (rx_keys.key[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint(", iv[0..8]=", .{});
        for (rx_keys.iv[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint(", hp[0..8]=", .{});
        for (rx_keys.hp[0..8]) |b| logger.debugPrint("{X:0>2} ", .{b});
        logger.debugPrint("\n", .{});
    }

    // Use extracted decryption function with key rotation
    // Tries CURRENT → NEXT → PREV keys automatically
    g_app_decrypt_start += 1;
    logger.debugPrint("[APP-DECRYPT-START] attempt={} dcid_len={} bytes={} cached={?}\n", .{g_app_decrypt_start, observed_dcid_len, bytes.len, conn.expected_rx_dcid_len});
    const decrypt_result = decryptShortHeaderWithKeyRotation(
        ctx.allocator.*,
        conn,
        bytes,
        @intCast(observed_dcid_len),
    ) catch |err| {
        if (err == error.StatelessReset) {
            if (ctx.test_capture_enabled) {
                logger.debugPrint("stateless-reset: closing connection\n", .{});
            }
            conn.closed = true;
        }
        return;
    };

    const dec_res = decrypt_result.decoded;
    g_app_decrypt_success += 1;
    logger.debugPrint("[APP-DECRYPT-SUCCESS] attempt={} pn={} payload_len={} used_next={} used_prev={} rx_phase={} success_ratio={}/{}\n", .{g_app_decrypt_start, decrypt_result.decoded.packet_number, decrypt_result.decoded.payload.len, decrypt_result.used_next, decrypt_result.used_prev, conn.rx_key_phase, g_app_decrypt_success, g_app_decrypt_start});
    // Frame parsing & ACK generation (Application)
    logger.debugPrint("[APP-DISPATCH] Parsing 1-RTT frames payload_len={} pn={}\n", .{dec_res.payload.len, dec_res.packet_number});
    if (dec_res.payload.len == 0) logger.debugPrint("[APP-DISPATCH] EMPTY-PAYLOAD pn={} suspect header protection/DCID length issue\n", .{dec_res.packet_number});
    // Fallback manual STREAM frame scan if decodeOne misses
    var scan_i: usize = 0; var stream_scan_hits: usize = 0;
    while (scan_i < dec_res.payload.len) : (scan_i += 1) {
        const b = dec_res.payload[scan_i];
        if ((b & 0xF8) == 0x08) { // STREAM frame type range
            stream_scan_hits += 1;
            logger.debugPrint("[APP-STREAM-SCAN] hit at offset={} type_byte=0x{X:0>2}\n", .{scan_i, b});
            break; // only need first indication
        }
    }
    if (stream_scan_hits == 0 and dec_res.payload.len > 0) logger.debugPrint("[APP-STREAM-SCAN] no STREAM type bytes found in first {} bytes\n", .{dec_res.payload.len});
    // Hex dump first up to 64 bytes of decrypted payload for diagnostics
    const dump_len: usize = @min(dec_res.payload.len, 64);
    if (dump_len > 0) {
        logger.debugPrint("[APP-PAYLOAD-HEX] ", .{});
        var di: usize = 0; while (di < dump_len) : (di += 1) logger.debugPrint("{X:0>2} ", .{dec_res.payload[di]});
        logger.debugPrint("\n", .{});
    }
    const frames_result = processFrames(ctx, conn, peer, dec_res.payload, send_fn) catch {
        logger.debugPrint("[APP-DISPATCH] processFrames error (payload_len={})\n", .{dec_res.payload.len});
        return;
    };
    if (frames_result.saw_ack_eliciting) logger.debugPrint("[APP-DISPATCH] ack-eliciting pn={}\n", .{dec_res.packet_number});
    const used_next = decrypt_result.used_next;
    const used_prev = decrypt_result.used_prev;
    defer ctx.allocator.free(dec_res.payload);

    if (ctx.test_capture_enabled) {
        logger.debugPrint("✅ 1-RTT AEAD SUCCESS - payload_len={}, pn={}\n", .{
            dec_res.payload.len,
            dec_res.packet_number,
        });
    }

    // =============================================================================
    // STEP 5: NEXT Key Promotion (RFC 9001 §6.1)
    // =============================================================================

    // Handle key promotion if NEXT keys were used
    // RFC 9001 §6.1: "After receiving a packet encrypted with the next keys,
    // an endpoint MUST update to the next keys."
    if (used_next) {
        // PHASE 57 Part 5: Use pre-derived NEXT keys (already used for decryption)
        logger.debugPrint("[PHASE57-STEP5] 🔄 used_next=true, promoting pre-derived NEXT keys\n", .{});
        if (conn.app_rx_next_secret) |next_secret| {
            if (conn.app_rx_next_keys) |next_keys| {
                logger.debugPrint("[PHASE57-STEP5] Calling promoteToNextKeys()...\n", .{});
                promoteToNextKeys(conn, next_secret, next_keys);
                conn.syncTxKeysAfterRxUpdate();

                if (ctx.test_capture_enabled) {
                    logger.debugPrint("🔑 Promoted to NEXT keys after successful decryption\n", .{});
                }
            } else {
                logger.debugPrint("[PHASE57-STEP5] ⚠️ WARNING: used_next=true but no app_rx_next_keys!\n", .{});
            }
        } else {
            logger.debugPrint("[PHASE57-STEP5] ⚠️ WARNING: used_next=true but no app_rx_next_secret!\n", .{});
        }
    } else {
        logger.debugPrint("[PHASE57-STEP5] ✓ used_next=false, no key promotion needed\n", .{});
    }

    // =============================================================================
    // STEP 6: Packet Number Tracking (RFC 9000 §12.3)
    // =============================================================================

    // dec_res.packet_number is already expanded by decryptShortHeaderWithKeyRotation
    const pn_full: u64 = dec_res.packet_number;

    // PHASE 42 PART 20: Capture PN state BEFORE tracking for duplicate/gap detection
    const prev_largest_pn = conn.pn_app.max;
    const had_any_before = conn.pn_app.have_any;

    conn.trackRecvPnApp(pn_full);

    // PHASE 42 PART 20: Comprehensive packet number tracking debug logging
    // This helps identify duplicate PNs (AEAD failures) and packet loss (gaps)
    const is_duplicate = (pn_full <= prev_largest_pn and had_any_before);
    const has_gap = (pn_full > prev_largest_pn + 1 and had_any_before);
    const gap_size: i64 = if (has_gap) @as(i64, @intCast(pn_full)) - @as(i64, @intCast(prev_largest_pn)) - 1 else 0;

    if (is_duplicate) {
        logger.debugPrint("[P42-20-PN-DUP] ⚠️  DUPLICATE PN! pn={}, prev_largest={}, gap_from_largest={}\n", .{
            pn_full,
            prev_largest_pn,
            @as(i64, @intCast(prev_largest_pn)) - @as(i64, @intCast(pn_full)),
        });
    } else if (has_gap) {
        logger.debugPrint("[P42-20-PN-GAP] ⚠️  GAP DETECTED! pn={}, prev_largest={}, gap_size={} packets missing\n", .{
            pn_full,
            prev_largest_pn,
            gap_size,
        });
    } else {
        logger.debugPrint("[P42-20-PN-OK] ✓ Sequential PN received: pn={}, prev_largest={}\n", .{
            pn_full,
            prev_largest_pn,
        });
    }

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Tracked packet number: {}\n", .{pn_full});
    }

    // =============================================================================
    // STEP 7: PREV Key Cleanup (RFC 9001 §6.5)
    // =============================================================================

    // Handle previous key cleanup if they were used
    // RFC 9001 §6.5: "An endpoint MAY retain old keys for a short period
    // to allow it to decrypt packets that were delayed."
    if (used_prev) {
        decrementPrevKeyAllowance(conn);

        if (ctx.test_capture_enabled) {
            logger.debugPrint("🔓 Decremented PREV key allowance\n", .{});
        }
    }

    // =============================================================================
    // STEP 8: Frame Processing Integration (RFC 9000 §12.4)
    // =============================================================================

    // Parse and process all frames from the decrypted payload
    const frame_result = processFrames(
        ctx,
        conn,
        peer,
        dec_res.payload,
        send_fn,
    ) catch {
        if (ctx.test_capture_enabled) {
            logger.debugPrint("Frame processing failed\n", .{});
        }
        return;
    };

    if (ctx.test_capture_enabled) {
        logger.debugPrint("Frame processing result: saw_ack_eliciting={}, saw_handshake_done={}, saw_close={}\n", .{
            frame_result.saw_ack_eliciting,
            frame_result.saw_handshake_done,
            frame_result.saw_close,
        });
    }

    // Handle HANDSHAKE_DONE frame (RFC 9000 §19.20)
    // Client: drop Handshake keys after HANDSHAKE_DONE (with conditions)
    if (frame_result.saw_handshake_done) {
        logger.debugPrint("[processShortHeader] CRITICAL: Setting handshake_done_seen=true for {s}\n", .{
            if (conn.role == .Server) "Server" else "Client",
        });
        conn.handshake_done_seen = true;

        // RFC 9001 §4.1.2: Only drop Handshake keys if safe to do so
        // Client (which receives HANDSHAKE_DONE): drop after first Handshake packet sent
        const can_drop_hs_keys = if (conn.role == .Client) conn.handshake_packet_sent else false;

        if (can_drop_hs_keys) {
            logger.debugPrint("[processShortHeader] {s}: Dropping Handshake keys after HANDSHAKE_DONE\n", .{
                if (conn.role == .Server) "Server" else "Client",
            });
            conn.hs_rx_keys = null;
            conn.hs_tx_keys = null;

            if (ctx.test_capture_enabled) {
                logger.debugPrint("🤝 HANDSHAKE_DONE received, dropped Handshake keys\n", .{});
            }
        } else {
            logger.debugPrint("[processShortHeader] {s}: Deferring Handshake key drop (handshake_packet_sent={})\n", .{
                if (conn.role == .Server) "Server" else "Client",
                conn.handshake_packet_sent,
            });

            if (ctx.test_capture_enabled) {
                logger.debugPrint("🤝 HANDSHAKE_DONE received, deferring Handshake key drop\n", .{});
            }
        }
    }

    // Handle CONNECTION_CLOSE frame (RFC 9000 §10.2)
    if (frame_result.saw_close) {
        conn.closed = true;

        if (ctx.test_capture_enabled) {
            logger.debugPrint("❌ CONNECTION_CLOSE received, closing connection\n", .{});
        }
        return; // Stop processing further
    }

    // =============================================================================
    // STEP 9: ACK Generation (RFC 9000 §13.2)
    // =============================================================================

    // Record ack-eliciting frame receipt for ACK generation
    if (frame_result.saw_ack_eliciting) {
        const now_ns_ack: u64 = @intCast(std.time.nanoTimestamp());
        conn.recordAckElicitingRx(.Application, now_ns_ack);

        if (ctx.test_capture_enabled) {
            logger.debugPrint("📨 Recorded ack-eliciting frame receipt\n", .{});
        }
    }

    // RFC 9000 §13.2.1: "An endpoint SHOULD send an ACK frame after receiving at least two
    // ack-eliciting packets." For simplicity and immediate flow control feedback, send ACK
    // immediately when ack-eliciting frames are received OR when ECN ACK is pending.
    //
    // CRITICAL FIX (Phase 42 Part 7): Send ACKs for ALL ack-eliciting packets, not just ECN!
    // Previous bug: ACKs were only sent when ecn_app_ack_pending==true, causing flow control
    // deadlock on large transfers where client exhausted send window waiting for ACKs.
    //
    // RFC 9000 §8.1: "A server MUST NOT send more than three times as many bytes
    // as the number of bytes it has received prior to validating the client address."
    if ((frame_result.saw_ack_eliciting or conn.ecn_app_ack_pending) and conn.app_tx_keys != null) {
        var ack_ctx = AckContext{
            .allocator = ctx.allocator,
            .conn = conn,
            .peer = peer,
            .send_fn = send_fn,
            .cfg = ctx.cfg,
            .test_capture_enabled = ctx.test_capture_enabled,
        };

        generateAndSendAck(&ack_ctx, frame_result, ecn_bits) catch {
            if (ctx.test_capture_enabled) {
                logger.debugPrint("Failed to generate/send ACK\n", .{});
            }
        };

        if (ctx.test_capture_enabled) {
            logger.debugPrint("📤 Sent ACK (ack_eliciting={}, ecn_pending={})\n", .{
                frame_result.saw_ack_eliciting,
                conn.ecn_app_ack_pending,
            });
        }
    }
}

/// Module marker for Phase 4b.5 Session 3 completion.
pub const session_3_complete = true;

/// Session 3 version for documentation
pub const session_3_version = "Phase 4b.5 Session 3 - Frame Processing and ACK Generation";

// =============================================================================
// Phase 4b.5 Session 5: Initial Packet Processing
// =============================================================================

/// Parsed Initial packet header information.
/// RFC 9000 §17.2.2: Initial Packet Format
pub const InitialHeaderInfo = struct {
    /// Destination Connection ID from packet header
    dcid: []const u8,
    /// Source Connection ID from packet header
    scid: []const u8,
    /// Token field (for address validation)
    token: []const u8,
    /// Packet number offset (protected, not yet decrypted)
    pn_offset: usize,
    /// Total length of packet from Length field
    packet_length: u64,
    /// Version field (already validated to be v1 or v2)
    version: u32,
};

/// Parse complete Initial packet header fields including Token and Length.
/// RFC 9000 §17.2.2: Initial Packet
///
/// This is a more complete version than parseInitialHeader(), which only extracts
/// DCID and SCID. This function additionally parses Token and Length fields.
///
/// Format:
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
///   Packet Payload (8..),
/// }
/// ```
///
/// Parameters:
/// - bytes: Raw packet bytes starting from first byte
/// - version: QUIC version from long header (already validated)
///
/// Returns:
/// - InitialHeaderInfo with parsed fields, or error if malformed
pub fn parseCompleteInitialHeader(bytes: []const u8, version: u32) !InitialHeaderInfo {
    // RFC 9000 §17.2.2: Initial packet structure
    //   byte 0: first byte (already validated as long header type 0)
    //   bytes 1-4: version (32-bit, already parsed)
    //   byte 5: DCID length
    //   bytes 6...: DCID, SCID, Token, Length, PN

    if (bytes.len < 6) return error.PacketTooShort;

    var i: usize = 5; // Start after version field (bytes 0-4)

    // Parse DCID length and value
    const dcid_len = bytes[i];
    i += 1;
    if (i + dcid_len > bytes.len) return error.InvalidDcidLength;
    const dcid = bytes[i .. i + dcid_len];
    i += dcid_len;

    // Parse SCID length and value
    if (i >= bytes.len) return error.PacketTooShort;
    const scid_len = bytes[i];
    i += 1;
    if (i + scid_len > bytes.len) return error.InvalidScidLength;
    const scid = bytes[i .. i + scid_len];
    i += scid_len;

    // Parse Token Length (varint) and Token
    if (i >= bytes.len) return error.PacketTooShort;
    const token_len_result = varint.decode(bytes[i..]) catch return error.InvalidTokenLength;
    const token_len = token_len_result.value;
    i += token_len_result.n;

    if (i + token_len > bytes.len) return error.InvalidTokenLength;
    const token = bytes[i .. i + token_len];
    i += token_len;

    // Parse Length field (varint)
    if (i >= bytes.len) return error.PacketTooShort;
    const length_result = varint.decode(bytes[i..]) catch return error.InvalidLengthField;
    const packet_length = length_result.value;
    i += length_result.n;

    // Packet Number starts at current offset (still protected)
    const pn_offset = i;

    return InitialHeaderInfo{
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .pn_offset = pn_offset,
        .packet_length = packet_length,
        .version = version,
    };
}

/// Module marker for Phase 4b.5 Session 5 Initial packet parsing.
pub const session_5_initial_header_parsing = true;

/// Documentation skeleton for complete Initial packet processing (Sessions 5-6).
/// RFC 9000 §17.2.2: Initial Packet Processing
///
/// NOTE: This is a documentation-only skeleton. The actual processInitial() function
/// exists at line 741 and is functional. This skeleton documents the intended modular
/// structure for Phase 4b.5 Sessions 5-6 extraction work.
///
/// Planned processing steps (RFC 9000 §7, §8.1):
/// 1. Parse Initial packet header (DCID, SCID, Token, Length) - DONE via parseCompleteInitialHeader()
/// 2. Validate token if present (RFC 9000 §8.1.4) - DONE via token.validateInitialToken()
/// 3. Decide whether to send Retry for address validation (RFC 9000 §8.1.2) - DONE via token.shouldSendRetry()
/// 4. Look up or create server connection - DONE via server.createServerConnection()
/// 5. Derive Initial keys from ODCID (RFC 9001 §5.2) - EXISTS as deriveInitialKeys()
/// 6. Decrypt Initial packet payload (PN + frames) - EXISTS as decryptInitialPacket()
/// 7. Process CRYPTO frame with TLS ClientHello - TBD Session 6
/// 8. Generate TLS ServerHello and Initial response - TBD Session 6
/// 9. Enqueue connection to accepted queue - DONE via server.pushAccepted()
///
/// Parameters (planned):
/// - allocator: Memory allocator
/// - bytes: Complete Initial packet bytes
/// - peer: Client socket address
/// - version: QUIC version
///
/// Returns:
/// - Success/failure status (specific return type TBD in Sessions 5-6)
pub fn processInitialSkeleton(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    peer: conn_mod.SockAddr,
    version: u32,
) !void {
    _ = allocator;
    _ = bytes;
    _ = peer;
    _ = version;

    // STEP 1: Parse Initial header (implemented)
    // const header = try parseCompleteInitialHeader(bytes, version);

    // STEP 2: Token validation (Session 5)
    // const token_valid = if (header.token.len > 0)
    //     token.validateInitialToken(header.token, peer, secret)
    // else
    //     false;

    // STEP 3: Retry decision (Session 5)
    // const should_retry = token.shouldSendRetry(
    //     header.token.len > 0,
    //     header.token,
    //     peer,
    //     secret,
    //     require_retry_policy
    // );
    // if (should_retry) {
    //     // Generate and send Retry packet
    //     const retry_token = try token.generateRetryToken(allocator, peer, header.dcid, secret, 120000);
    //     defer allocator.free(retry_token);
    //     // Send Retry packet via server.encodeRetryPacket()
    //     return;
    // }

    // STEP 4: Connection lookup/creation (Session 5)
    // const conn = try server.createServerConnection(allocator, sock_fd, peer, .{
    //     .version = version,
    //     .client_dcid = header.dcid,
    //     .client_scid = header.scid,
    //     ...
    // });

    // STEP 5: Key derivation (Session 6)
    // const initial_keys = deriveInitialKeys(conn, header.dcid, version);

    // STEP 6: Decrypt packet (Session 6)
    // const decrypted = try decryptInitialPacket(allocator, bytes, header.pn_offset, initial_keys, 0);

    // STEP 7: Process CRYPTO frame (Session 6)
    // Process TLS ClientHello via handshake_integration module

    // STEP 8: Generate response (Session 6)
    // Generate ServerHello, Handshake packets

    // STEP 9: Enqueue connection (Session 5)
    // server.pushAccepted(allocator, accepted_queue, conn);

    // NOTE: Full implementation will be completed in Sessions 5-6 extraction work
    return error.NotImplemented;
}

/// Module marker for Phase 4b.5 Session 5 processInitial skeleton.
pub const session_5_process_initial_skeleton = true;
