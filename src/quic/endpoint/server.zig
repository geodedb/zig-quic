// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Server connection acceptance and address validation (RFC 9000 §7, §8.1).
//!
//! This module handles server-side connection establishment including:
//! - Connection acceptance from Initial packets
//! - Address validation via Retry packets (RFC 9000 §8.1.1)
//! - Accepted connection queue management
//!
//! RFC References:
//! - RFC 9000 §7: Cryptographic and Transport Handshake
//! - RFC 9000 §8.1: Address Validation
//! - RFC 9000 §8.1.1: Address Validation Using Retry Packets
//! - RFC 9000 §10.3: Stateless Reset

const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const tp = @import("transport_params");
const packet = @import("packet");
const endpoint_types = @import("types");
const x509 = @import("x509");
const sig = @import("sig");
const posix = std.posix;
const handshake_integration = @import("handshake_integration");

/// Convert socket_t to isize for Connection struct (inline to avoid module dependency).
/// On POSIX systems, socket_t is an integer (fd).
/// On Windows, socket_t is a pointer (SOCKET handle).
fn sockToIsize(sock: posix.socket_t) isize {
    if (comptime @import("builtin").os.tag == .windows) {
        // Use bitCast to preserve bit pattern (handles invalid socket ~0 correctly)
        return @bitCast(@intFromPtr(sock));
    } else {
        return @as(isize, @intCast(sock));
    }
}

/// Accept a server connection from initial datagram's peer address.
///
/// Creates a new server-side Connection object for the peer that sent an Initial packet.
/// The connection is in initial state and needs to complete the handshake.
///
/// RFC 9000 §7: "A server that receives an Initial packet creates a new connection state."
///
/// Parameters:
///   - allocator: Memory allocator for the connection
///   - sock_fd: Socket file descriptor for sending/receiving
///   - peer: Socket address of the client that sent the Initial packet
///
/// Returns:
///   A new Connection object configured for server role
pub fn acceptFrom(allocator: *std.mem.Allocator, sock_fd: std.posix.socket_t, peer: conn_mod.SockAddr) conn_mod.Connection {
    var conn: conn_mod.Connection = undefined;
    conn.init(allocator, .Server, sockToIsize(sock_fd), peer);
    return conn;
}

/// Enqueue accepted server connection to the accepted queue.
///
/// After a server creates a connection from an Initial packet, it's added to the
/// accepted queue where the application can retrieve it via popAccepted().
///
/// Parameters:
///   - allocator: Memory allocator for the accepted queue
///   - accepted: ArrayList of accepted connections
///   - c: Connection pointer to enqueue
pub fn pushAccepted(allocator: std.mem.Allocator, accepted: *std.ArrayList(*conn_mod.Connection), c: *conn_mod.Connection) void {
    accepted.append(allocator, c) catch {};
}

/// Pop next accepted server-side connection if available.
///
/// Retrieves the next connection from the accepted queue. This is typically called
/// by application code to handle new incoming connections.
///
/// Parameters:
///   - accepted: ArrayList of accepted connections
///
/// Returns:
///   Connection pointer if queue non-empty, null otherwise
pub fn popAccepted(accepted: *std.ArrayList(*conn_mod.Connection)) ?*conn_mod.Connection {
    if (accepted.items.len == 0) return null;
    const c = accepted.items[0];
    _ = accepted.orderedRemove(0);
    return c;
}

/// Hash a socket address for connection routing.
///
/// Creates a hash value from the socket address structure that can be used
/// as part of a routing key for connection lookup.
///
/// Parameters:
///   - addr: Socket address structure
///   - len: Length of the address structure
///
/// Returns:
///   64-bit hash of the address
pub fn hashAddress(sa: *const posix.sockaddr, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

// Helper: Hash bytes using Wyhash
inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

// Retry packet generation (Phase 4b.5 Session 1)

/// Retry packet configuration.
pub const RetryConfig = struct {
    /// QUIC version
    version: u32,
    /// Destination Connection ID (client's SCID from Initial)
    dcid: []const u8,
    /// Source Connection ID (server's chosen SCID)
    scid: []const u8,
    /// Original Destination Connection ID (client's DCID from Initial)
    odcid: []const u8,
    /// Retry token to include
    token: []const u8,
};

/// Generate a Retry packet with integrity tag.
/// RFC 9000 §17.2.5: Retry Packet Format
/// RFC 9001 §5.8: Retry Integrity Tag
///
/// Parameters:
///   - config: Retry packet configuration
///   - out_buf: Output buffer (must be large enough)
///
/// Returns:
///   Slice of out_buf containing the Retry packet, or error
pub fn encodeRetryPacket(config: RetryConfig, out_buf: []u8) ![]u8 {
    // Validate buffer size (header + CIDs + token + tag)
    const min_len = 1 + 4 + 1 + config.dcid.len + 1 + config.scid.len + config.token.len + 16;
    if (out_buf.len < min_len) return error.BufferTooSmall;

    var i: usize = 0;

    // Byte 0: Long header, type=Retry (0b11xxxxxx, type bits=11)
    // RFC 9000 §17.2.5: "Fixed Bit (1) = 1, Long Packet Type (2) = 3 (Retry)"
    const first_byte: u8 = 0b11110000; // Form=1, Fixed=1, Type=3, Unused=0000
    out_buf[i] = first_byte;
    i += 1;

    // Bytes 1-4: Version (32-bit big-endian)
    std.mem.writeInt(u32, out_buf[i..][0..4], config.version, .big);
    i += 4;

    // DCID Length + DCID
    out_buf[i] = @intCast(config.dcid.len);
    i += 1;
    @memcpy(out_buf[i..][0..config.dcid.len], config.dcid);
    i += config.dcid.len;

    // SCID Length + SCID
    out_buf[i] = @intCast(config.scid.len);
    i += 1;
    @memcpy(out_buf[i..][0..config.scid.len], config.scid);
    i += config.scid.len;

    // Retry Token
    @memcpy(out_buf[i..][0..config.token.len], config.token);
    i += config.token.len;

    // Compute Retry Integrity Tag (RFC 9001 §5.8)
    // Tag = AEAD(key, nonce, AAD=Pseudo-Retry Packet)
    // Pseudo-Retry includes: ODCID length + ODCID + Retry packet (minus tag)
    const tag_offset = i;

    // Build Pseudo-Retry Packet for AAD
    var pseudo_buf: [1500]u8 = undefined;
    var p: usize = 0;

    // ODCID Length (1 byte)
    pseudo_buf[p] = @intCast(config.odcid.len);
    p += 1;

    // ODCID
    @memcpy(pseudo_buf[p..][0..config.odcid.len], config.odcid);
    p += config.odcid.len;

    // Retry packet (first_byte through token, excluding tag)
    @memcpy(pseudo_buf[p..][0..tag_offset], out_buf[0..tag_offset]);
    p += tag_offset;

    // Compute tag using crypto_quic.computeRetryIntegrityTag
    const crypto_quic = @import("crypto_quic");
    const tag = crypto_quic.computeRetryIntegrityTag(config.version, pseudo_buf[0..p]);

    // Append tag to Retry packet
    @memcpy(out_buf[tag_offset..][0..16], &tag);
    i += 16;

    return out_buf[0..i];
}

// Version Negotiation packet generation (Phase 4b.5 Session 1)

/// Version Negotiation packet configuration.
pub const VNConfig = struct {
    /// Destination Connection ID (client's SCID from Initial)
    dcid: []const u8,
    /// Source Connection ID (server's chosen SCID, or client's DCID)
    scid: []const u8,
    /// List of supported QUIC versions
    supported_versions: []const u32,
};

/// Generate a Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet Format
///
/// Parameters:
///   - config: VN packet configuration
///   - out_buf: Output buffer
///
/// Returns:
///   Slice of out_buf containing the VN packet, or error
pub fn encodeVersionNegotiation(config: VNConfig, out_buf: []u8) ![]u8 {
    const min_len = 1 + 4 + 1 + config.dcid.len + 1 + config.scid.len + (config.supported_versions.len * 4);
    if (out_buf.len < min_len) return error.BufferTooSmall;

    var i: usize = 0;

    // Byte 0: Long header form (0b10xxxxxx), unused bits set to random
    const first_byte: u8 = 0b10000000 | @as(u8, @truncate(std.crypto.random.int(u8) & 0x3F));
    out_buf[i] = first_byte;
    i += 1;

    // Version = 0 (indicates Version Negotiation)
    std.mem.writeInt(u32, out_buf[i..][0..4], 0, .big);
    i += 4;

    // DCID
    out_buf[i] = @intCast(config.dcid.len);
    i += 1;
    @memcpy(out_buf[i..][0..config.dcid.len], config.dcid);
    i += config.dcid.len;

    // SCID
    out_buf[i] = @intCast(config.scid.len);
    i += 1;
    @memcpy(out_buf[i..][0..config.scid.len], config.scid);
    i += config.scid.len;

    // Supported Versions
    for (config.supported_versions) |v| {
        std.mem.writeInt(u32, out_buf[i..][0..4], v, .big);
        i += 4;
    }

    return out_buf[0..i];
}

// =============================================================================
// Phase 4b.5 Session 5: Server Connection Creation
// =============================================================================

/// Server connection configuration for Initial packet processing.
pub const ServerConnectionConfig = struct {
    /// QUIC version from Initial packet
    version: u32,
    /// Destination Connection ID from client's Initial packet
    client_dcid: []const u8,
    /// Source Connection ID from client's Initial packet
    client_scid: []const u8,
    /// Server certificate DER (optional, for TLS)
    server_cert_der: ?[]const u8 = null,
    /// Server private key DER (optional, for TLS)
    server_priv_key_der: ?[]const u8 = null,
    /// Transport parameters configuration
    transport_params: ?*const tp.TransportParams = null,
    /// Congestion control: use CUBIC (true) or NewReno (false)
    use_cubic: bool = false,
    /// Allow insecure connections (skip certificate validation)
    allow_insecure: bool = false,
    /// Allowed ALPN protocols
    allowed_alpns: []const []const u8 = &[_][]const u8{},
    /// Enable pacing
    enable_pacing: bool = false,
    /// Maximum datagram size for congestion control
    max_datagram_size: u16 = 1200,
    /// AEAD confidentiality limit override (0 = use default)
    aead_confidentiality_limit: u64 = 0,
    /// AEAD integrity limit override (0 = use default)
    aead_integrity_limit: u64 = 0,
    /// Require client certificate authentication (mTLS)
    require_client_cert: bool = false,
};

/// Create a server-side connection from an Initial packet.
/// RFC 9000 §7: "A server that receives an Initial packet creates a new connection state."
///
/// This function extracts the core server connection setup logic from endpoint.zig
/// (lines 1217-1326). It handles:
/// - Connection initialization with server role
/// - Version field setup (RFC 9000 §5.2)
/// - Server SCID generation (RFC 9000 §5.1)
/// - Peer CID setup from client's Initial packet
/// - TLS certificate configuration
/// - Transport parameters setup
/// - Congestion control configuration
///
/// Parameters:
/// - allocator: Memory allocator
/// - sock_fd: Socket file descriptor
/// - peer: Client socket address
/// - config: Server connection configuration
///
/// Returns:
/// - Initialized server connection, or error if allocation/setup fails
pub fn createServerConnection(
    allocator: *std.mem.Allocator,
    sock_fd: std.posix.socket_t,
    peer: conn_mod.SockAddr,
    config: ServerConnectionConfig,
) !*conn_mod.Connection {
    // Allocate connection struct
    const c = try allocator.*.create(conn_mod.Connection);
    errdefer allocator.*.destroy(c);

    // Initialize connection with server role
    c.init(allocator, .Server, sockToIsize(sock_fd), peer);

    // Set version fields (RFC 9000 §5.2: Version Negotiation)
    c.version = config.version;
    c.version_v2 = (config.version == packet.QUIC_V2);
    c.initial_version = config.version;

    // Generate random SCID for server (RFC 9000 §5.1)
    c.our_scid.len = 8;
    std.crypto.random.bytes(c.our_scid.bytes[0..c.our_scid.len]);

    // Set peer CIDs from client's Initial packet
    // RFC 9000 §5.2: "The server uses the client's DCID as the ODCID"
    c.peer_initial_dcid.len = @intCast(@min(config.client_dcid.len, c.peer_initial_dcid.bytes.len));
    if (c.peer_initial_dcid.len > 0) {
        @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], config.client_dcid[0..c.peer_initial_dcid.len]);
    }

    logger.debugPrint("createServerConnection: Set peer_initial_dcid from client_dcid, len={}\n", .{c.peer_initial_dcid.len});
    if (c.peer_initial_dcid.len >= 4) {
        logger.debugPrint("  peer_initial_dcid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ c.peer_initial_dcid.bytes[0], c.peer_initial_dcid.bytes[1], c.peer_initial_dcid.bytes[2], c.peer_initial_dcid.bytes[3] });
    }

    // Set original_dcid to peer_initial_dcid (for Initial key derivation)
    c.original_dcid.len = c.peer_initial_dcid.len;
    if (c.original_dcid.len > 0) {
        @memcpy(c.original_dcid.bytes[0..c.original_dcid.len], c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    }

    // Set peer_initial_scid from client's SCID
    // RFC 9000 §7.3: "Servers populate peer_initial_scid from client's SCID"
    logger.debugPrint("createServerConnection: client_scid.len={}\n", .{config.client_scid.len});
    c.peer_initial_scid.len = @intCast(@min(config.client_scid.len, c.peer_initial_scid.bytes.len));
    if (c.peer_initial_scid.len > 0) {
        @memcpy(c.peer_initial_scid.bytes[0..c.peer_initial_scid.len], config.client_scid[0..c.peer_initial_scid.len]);
    }
    logger.debugPrint("createServerConnection: Set peer_initial_scid.len={}\n", .{c.peer_initial_scid.len});
    if (c.peer_initial_scid.len >= 4) {
        logger.debugPrint("  peer_initial_scid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ c.peer_initial_scid.bytes[0], c.peer_initial_scid.bytes[1], c.peer_initial_scid.bytes[2], c.peer_initial_scid.bytes[3] });
    }

    // Configure congestion control
    c.setUseCubic(config.use_cubic);

    // NOTE: TLS configuration (certificates, allow_insecure) now handled via TLS Context
    // Certificates are passed to createTlsContext() below

    // Encode transport parameters for both Connection and TLS Context
    // Need to keep tp_bytes alive until after Context creation
    var tp_bytes: []u8 = &[_]u8{};
    var tp_allocated = false;
    if (config.transport_params) |tpp| {
        tp_bytes = try tp.TransportParams.encode(tpp, allocator.*);
        tp_allocated = true;
        try c.setLocalTransportParameters(tp_bytes);
    }
    defer if (tp_allocated) allocator.free(tp_bytes);

    // Set ALPN
    c.allowed_alpns = config.allowed_alpns;

    // Configure pacing and congestion control max datagram size
    c.enable_pacing = config.enable_pacing;
    c.rec.cc.mds = @intCast(config.max_datagram_size);

    // Apply AEAD usage limits if specified
    if (config.aead_confidentiality_limit > 0 or config.aead_integrity_limit > 0) {
        c.setAeadUsageLimits(config.aead_confidentiality_limit, config.aead_integrity_limit);
    }

    // Initialize TLS Context for modular TLS 1.3
    // TLS Context is always created (required, not optional)
    const ctx_value = try handshake_integration.createTlsContext(
        allocator.*,
        .Server,
        config.allowed_alpns,
        tp_bytes,
        config.server_cert_der,
        config.server_priv_key_der,
        config.allow_insecure,
        config.require_client_cert,
        null, // Server doesn't need client cert/key
        null,
    );

    const tls_ctx = try allocator.create(@TypeOf(ctx_value));
    errdefer allocator.destroy(tls_ctx);
    tls_ctx.* = ctx_value;

    c.tls_context = tls_ctx;

    return c;
}

/// Module marker for Phase 4b.5 Session 5 server connection creation.
pub const session_5_server_connection = true;
