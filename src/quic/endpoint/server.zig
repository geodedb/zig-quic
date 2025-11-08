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
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const tp = @import("transport_params");
const packet = @import("packet");
const endpoint_types = @import("types");
const x509 = @import("x509");
const sig = @import("sig");
const posix = std.posix;

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
    conn.init(allocator, .Server, @as(isize, @intCast(sock_fd)), peer);
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
/// RFC 9000 §7: After receiving and processing an Initial packet, the server makes
/// the connection available to the application.
///
/// Parameters:
///   - accepted: ArrayList of accepted connections
///
/// Returns:
///   - Pointer to the next accepted Connection, or null if queue is empty
pub fn popAccepted(accepted: *std.ArrayList(*conn_mod.Connection)) ?*conn_mod.Connection {
    if (accepted.items.len == 0) return null;
    return accepted.orderedRemove(0);
}

// =============================================================================
// Phase 4b.5 Session 5: Server Connection Creation
// =============================================================================

/// Function signature for paced sender callback (re-export from conn.zig)
pub const SenderFn = conn_mod.SendFn;

/// Context for server connection creation.
/// This focused context replaces passing full Endpoint pointer.
pub const ServerContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection),
    cfg: *const cfg.QuicConfig,
    sock_fd: posix.socket_t,
    endpoint_ptr: *anyopaque,
    sender_fn: SenderFn,
};

/// Create and fully initialize a server connection from an Initial packet.
/// Extracted from endpoint.zig lines 1734-1850 (Phase 4b.5 Session 5).
///
/// This function performs the complete server connection initialization including:
/// - Allocating and initializing Connection struct
/// - Setting version and generating random SCID
/// - Copying client's DCID/SCID to peer_initial_dcid/peer_initial_scid
/// - Configuring TLS certificate (if available)
/// - Setting transport parameters
/// - Configuring congestion control and pacing
/// - Applying AEAD usage limits
/// - Registering connection in connection table
///
/// RFC 9000 §7: "A server that receives an Initial packet creates a new connection state."
/// RFC 9000 §8.1: "Servers MUST use address validation to protect against DoS attacks."
///
/// Parameters:
/// - ctx: ServerContext with allocator, config, socket, and connection table
/// - peer: Socket address of the client
/// - version: QUIC version from the Initial packet
/// - dcid: Client's Destination Connection ID (server's initial DCID)
/// - scid: Client's Source Connection ID
///
/// Returns:
/// - Pointer to newly created and initialized Connection
/// - error.OutOfMemory if allocation fails
pub fn createServerConnection(
    ctx: *ServerContext,
    peer: conn_mod.SockAddr,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
) !*conn_mod.Connection {
    // Allocate new connection
    const c_new = try ctx.allocator.create(conn_mod.Connection);
    errdefer ctx.allocator.destroy(c_new);

    // Initialize with Server role
    c_new.init(ctx.allocator, .Server, sockToIsize(ctx.sock_fd), peer);

    // Set version from packet (RFC 9000 §6)
    c_new.version = version;
    c_new.version_v2 = (version == packet.QUIC_V2);
    c_new.initial_version = version;

    // Generate random 8-byte SCID for server (RFC 9000 §5.1.1)
    c_new.our_scid.len = 8;
    std.crypto.random.bytes(c_new.our_scid.bytes[0..c_new.our_scid.len]);

    // Set peer_initial_dcid/original_dcid from client's DCID
    // This is critical for Initial key derivation (RFC 9001 §5.2)
    c_new.peer_initial_dcid.len = @intCast(@min(dcid.len, c_new.peer_initial_dcid.bytes.len));
    if (c_new.peer_initial_dcid.len > 0) {
        @memcpy(c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len], dcid[0..c_new.peer_initial_dcid.len]);
    }
    c_new.original_dcid.len = c_new.peer_initial_dcid.len;
    if (c_new.original_dcid.len > 0) {
        @memcpy(c_new.original_dcid.bytes[0..c_new.original_dcid.len], c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len]);
    }

    // Set peer_initial_scid from client's SCID (for Handshake packet DCID)
    c_new.peer_initial_scid.len = @intCast(@min(scid.len, c_new.peer_initial_scid.bytes.len));
    if (c_new.peer_initial_scid.len > 0) {
        @memcpy(c_new.peer_initial_scid.bytes[0..c_new.peer_initial_scid.len], scid[0..c_new.peer_initial_scid.len]);
    }

    // Configure congestion control (NewReno or CUBIC)
    c_new.setUseCubic(ctx.cfg.cc == .cubic);
    c_new.tls.allow_insecure = ctx.cfg.allow_insecure;

    // Configure server certificate for TLS 1.3 (RFC 9001 §4.2)
    if (ctx.cfg.inline_server_cert_der) |cert_der| {
        if (ctx.cfg.inline_server_priv_p256) |key_der| {
            // Infer signature algorithm from certificate
            const detected_alg = x509.inferSignatureAlgorithm(cert_der) catch sig.SigAlg.ecdsa_secp256r1_sha256;

            // Set certificate and private key
            c_new.tls.setServerCertificate(cert_der, key_der, detected_alg) catch {
                // Certificate setup failure is non-fatal for testing
                // but will cause handshake failure
            };
        }
    }

    // Set local transport parameters for server (RFC 9000 §18.2)
    var tpp: tp.TransportParams = .{};
    tpp.original_destination_connection_id = c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len];
    tpp.initial_source_connection_id = c_new.our_scid.bytes[0..c_new.our_scid.len];
    tpp.max_idle_timeout = ctx.cfg.max_idle_timeout_ms;
    tpp.max_udp_payload_size = ctx.cfg.max_udp_payload;
    tpp.initial_max_data = c_new.local_max_data;
    tpp.initial_max_stream_data_bidi_local = c_new.local_max_stream_data;
    tpp.initial_max_stream_data_bidi_remote = c_new.local_max_stream_data;
    tpp.initial_max_stream_data_uni = c_new.local_max_stream_data;
    tpp.initial_max_streams_bidi = c_new.local_max_streams_bidi;
    tpp.initial_max_streams_uni = c_new.local_max_streams_uni;

    // Encode and set transport parameters
    const tp_bytes = tp.TransportParams.encode(&tpp, ctx.allocator.*) catch &[_]u8{};
    defer {
        if (tp_bytes.len > 0) ctx.allocator.free(tp_bytes);
    }
    c_new.setLocalTransportParameters(if (tp_bytes.len > 0) tp_bytes else tp_bytes[0..0]) catch {};
    c_new.allowed_alpns = ctx.cfg.alpn;

    // Enable optional pacing and set CC max_datagram_size
    c_new.enable_pacing = ctx.cfg.enable_pacing;
    c_new.rec.cc.mds = @intCast(ctx.cfg.max_datagram_size);

    // Install paced sender callback
    c_new.setSender(ctx.endpoint_ptr, ctx.sender_fn);

    // Register connection in table by peer hash + client DCID
    const ph = hashSockaddr(&peer.storage, peer.len);
    const key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(dcid) };
    try ctx.conns.put(key, c_new);
    errdefer _ = ctx.conns.remove(key);

    // Apply AEAD limits overrides for server-side (RFC 9001 §6.6)
    c_new.setAeadUsageLimits(ctx.cfg.aead_confidentiality_limit_override, ctx.cfg.aead_integrity_limit_override);

    // Also register connection by server's SCID for Handshake packet routing
    const our_key = endpoint_types.Key{ .peer_hash = ph, .dcid_hash = hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len]) };
    ctx.conns.put(our_key, c_new) catch {};

    return c_new;
}

// Helper functions (inline to avoid circular dependency with utils.zig)

inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

inline fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

inline fn sockToIsize(sock: posix.socket_t) isize {
    return @as(isize, @intCast(sock));
}
