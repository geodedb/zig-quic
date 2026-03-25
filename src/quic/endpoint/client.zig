// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Client connection establishment (RFC 9000 §7).
//!
//! This module provides the client-side connection establishment interface including:
//! - Connection object creation and initialization
//! - Initial Connection ID generation (RFC 9000 §5.1.1)
//! - Initial packet generation with ClientHello
//! - Transport parameter encoding
//! - Version negotiation (RFC 9000 §6)
//!
//! RFC References:
//! - RFC 9000 §7: Cryptographic and Transport Handshake
//! - RFC 9000 §7.2: Negotiating Connection IDs
//! - RFC 9000 §5.1.1: Issuing Connection IDs (Client chooses initial DCID)
//! - RFC 9000 §14.1: Initial Datagram Size (minimum 1200 bytes)
//! - RFC 9001 §4: Carrying TLS Messages
//! - RFC 9001 §5: Packet Protection (Initial secrets)

const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const types = @import("types");
const handshake_integration = @import("handshake_integration");

/// Convert socket_t to isize for Connection struct (inline to avoid module dependency).
/// On POSIX systems, socket_t is an integer (fd).
/// On Windows, socket_t is a pointer (SOCKET handle).
fn sockToIsize(sock: std.posix.socket_t) isize {
    if (comptime @import("builtin").os.tag == .windows) {
        // Use bitCast to preserve bit pattern (handles invalid socket ~0 correctly)
        return @bitCast(@intFromPtr(sock));
    } else {
        return @as(isize, @intCast(sock));
    }
}

/// Client context for connection establishment.
/// Similar to HandshakeContext, provides focused state passing.
pub const ClientContext = struct {
    allocator: *std.mem.Allocator,
    conn: *conn_mod.Connection,
    sender_ctx: ?*anyopaque,
    send_fn: *const fn (sender_ctx: ?*anyopaque, peer: conn_mod.SockAddr, data: []const u8) anyerror!usize,
    peer: conn_mod.SockAddr,
};

/// Helper: Generate random 8-byte Connection ID.
/// RFC 9000 §5.1.1: "A client MUST choose a value for the Destination Connection ID field."
pub fn generateRandomCid(bytes: []u8) void {
    std.crypto.random.bytes(bytes);
}

/// Create basic connection struct (not fully initialized).
/// Returns a Connection value (not pointer) configured for client role.
/// RFC 9000 §7: Client initiates connection to server.
///
/// NOTE: This creates a minimal Connection struct. For fully initialized connections,
/// use createClientConnection instead.
pub fn connectTo(peer: conn_mod.SockAddr, sock_fd: std.posix.socket_t) conn_mod.Connection {
    return .{
        .id = 0,
        .role = .Client,
        .sock_fd = sockToIsize(sock_fd),
        .peer = peer,
        .tls_inbox = std.ArrayList(u8){},
    };
}

/// Create and fully initialize client Connection.
///
/// This function:
/// 1. Allocates Connection struct
/// 2. Initializes with client role
/// 3. Applies configuration (congestion control, pacing, ALPN)
/// 4. Generates random DCIDs and SCIDs (RFC 9000 §5.1.1)
/// 5. Sets up AEAD usage limits
/// 6. Registers connection in lookup tables
///
/// Parameters:
/// - allocator: Memory allocator
/// - peer: Remote endpoint address
/// - sock_fd: Socket file descriptor
/// - cfg: QUIC configuration
/// - version: QUIC version to use (v1 or v2)
/// - conns_map: Connection lookup table (will be registered with both DCID and SCID)
/// - peer_hash: Hash of peer address
///
/// Returns:
/// - Pointer to allocated and initialized Connection
///
/// RFC 9000 §5.1.1: "A client MUST choose a value for the Destination Connection ID field."
pub fn createClientConnection(
    allocator: *std.mem.Allocator,
    peer: conn_mod.SockAddr,
    sock_fd: std.posix.socket_t,
    cfg: anytype,
    version: u32,
    conns_map: anytype,
    peer_hash: u64,
) !*conn_mod.Connection {
    const c = try allocator.*.create(conn_mod.Connection);
    c.init(allocator, .Client, sockToIsize(sock_fd), peer);

    // Apply config flags
    c.setUseCubic(cfg.cc == .cubic);
    // NOTE: allow_insecure is now handled via TLS Context configuration during creation
    c.allowed_alpns = cfg.alpn;

    // Enable optional pacing, localhost exemption, and set CC max_datagram_size
    c.enable_pacing = cfg.enable_pacing;
    c.exempt_localhost = cfg.exempt_localhost;
    c.rec.cc.mds = @intCast(cfg.max_datagram_size);

    // Apply AEAD usage limit overrides
    c.setAeadUsageLimits(cfg.aead_confidentiality_limit_override, cfg.aead_integrity_limit_override);

    // Set version
    c.version = version;
    c.version_v2 = (c.version == packet.QUIC_V2);
    c.initial_version = c.version;

    // Client chooses DCID and SCID (RFC 9000 §5.1.1) prior to deriving Initial secrets.
    var dcid: [8]u8 = undefined;
    generateRandomCid(&dcid);
    c.peer_initial_dcid.len = @intCast(dcid.len);
    @memcpy(c.peer_initial_dcid.bytes[0..dcid.len], &dcid);

    // Preserve original DCID separately for Initial secret derivation (never changes).
    c.original_dcid.len = c.peer_initial_dcid.len;
    if (c.original_dcid.len > 0) {
        @memcpy(c.original_dcid.bytes[0..c.original_dcid.len], c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    }

    logger.debugPrint("[createClientConnection] Generated DCID len={} bytes: ", .{c.peer_initial_dcid.len});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        logger.debugPrint("{X:0>2} ", .{b});
    }
    logger.debugPrint("\n", .{});

    c.our_scid.len = 8;
    generateRandomCid(c.our_scid.bytes[0..c.our_scid.len]);

    // Map by both dcid and scid to find VN/HS
    const key_d = types.Key{
        .peer_hash = peer_hash,
        .dcid_hash = hashBytes(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]),
    };
    const key_s = types.Key{
        .peer_hash = peer_hash,
        .dcid_hash = hashBytes(c.our_scid.bytes[0..c.our_scid.len]),
    };
    conns_map.put(key_d, c) catch {
        c.deinit();
        allocator.*.destroy(c);
        return error.OutOfMemory;
    };
    conns_map.put(key_s, c) catch {
        _ = conns_map.remove(key_d);
        c.deinit();
        allocator.*.destroy(c);
        return error.OutOfMemory;
    };

    logger.debugPrint("Client connection registered:\n", .{});
    logger.debugPrint("  peer_hash={X:0>16}\n", .{peer_hash});
    logger.debugPrint("  By DCID hash={X:0>16} (peer_initial_dcid)\n", .{hashBytes(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len])});
    logger.debugPrint("  By SCID hash={X:0>16} (our_scid)\n", .{hashBytes(c.our_scid.bytes[0..c.our_scid.len])});

    // Initialize TLS Context for modular TLS 1.3 (Phase 21.2)
    // Client doesn't need certificates (server auth only)
    const tls13 = @import("quic_tls13");
    const ctx_value: ?tls13.Context = handshake_integration.createTlsContext(
        allocator.*,
        .Client,
        cfg.alpn,
        &[_]u8{}, // Transport params set separately before handshake
        null, // No server cert for client
        null, // No server key for client
        cfg.allow_insecure,
        false, // Client doesn't request client certs
        cfg.inline_client_cert_der,
        cfg.inline_client_priv_key,
    ) catch |err| blk: {
        logger.debugPrint("createClientConnection: Failed to create TLS Context: {}\n", .{err});
        break :blk null;
    };

    if (ctx_value) |ctx_val| {
        const tls_ctx = allocator.create(@TypeOf(ctx_val)) catch return c;
        tls_ctx.* = ctx_val;
        c.tls_context = tls_ctx;
    }

    return c;
}

/// Send Initial packet with ClientHello to start QUIC handshake.
///
/// RFC 9000 §7: "A client initiates a QUIC connection by sending an Initial packet."
///
/// This function:
/// 1. Derives Initial secrets from DCID (RFC 9001 §5.2)
/// 2. Sets up client transport parameters
/// 3. Generates ClientHello via TLS
/// 4. Builds CRYPTO frame with ClientHello
/// 5. Pads to 1200 bytes minimum (RFC 9000 §14.1)
/// 6. Protects packet with Initial keys
/// 7. Sends via UDP and arms Initial PTO timer
///
/// Parameters:
/// - ctx: ClientContext with connection, allocator, send_fn, and peer address
///
/// Returns:
/// - error.OutOfMemory if allocation fails
/// - error.* from packet encoding or sending
///
/// RFC 9000 §14.1: "A client MUST expand the payload of all UDP datagrams carrying
/// Initial packets to at least 1200 bytes."
pub fn sendInitialProbe(ctx: *ClientContext) !void {
    const c = ctx.conn;
    const v2 = (c.version == packet.QUIC_V2);

    // RFC 9001 §5.2: derive Initial secrets from the Destination Connection ID
    // in the Initial packet being sent by the client. This changes after Retry.
    const dcid_for_secret = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];

    const initial = ks.deriveInitialSecret(v2, dcid_for_secret);
    const pair = ks.deriveClientServerInitial(initial);

    logger.debugPrint("client: deriving Initial keys with dcid len={}: ", .{c.peer_initial_dcid.len});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        logger.debugPrint("{X:0>2} ", .{b});
    }
    logger.debugPrint("\n", .{});

    const tx_keys: packet.InitialKeys = if (v2) blk: {
        const t = ks.deriveKeyIvHpV2(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk: {
        const t = ks.deriveKeyIvHp(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };

    logger.debugPrint("[Client TX] Initial keys derived\n", .{});

    var frames = std.ArrayList(u8){};
    defer frames.deinit(ctx.allocator.*);

    // Build CRYPTO frame carrying ClientHello
    // Note: Transport parameters must be set up by caller before calling sendInitialProbe

    const tls_ctx = c.tls_context orelse {
        logger.debugPrint("sendInitialProbe: TLS Context not initialized\n", .{});
        return error.NoTlsContext;
    };

    // Set transport parameters on TLS Context
    if (c.local_transport_params_raw) |tp_bytes| {
        try tls_ctx.setTransportParameters(tp_bytes);
    }

    // Start client handshake (generates ClientHello)
    tls_ctx.startClientHandshake() catch |err| {
        logger.debugPrint("sendInitialProbe: Context startClientHandshake error: {}\n", .{err});
    };

    // Poll for the generated ClientHello
    const crypto_data = tls_ctx.pollCrypto(ctx.allocator.*, .Initial) catch |err| blk: {
        logger.debugPrint("sendInitialProbe: Context pollCrypto error: {}\n", .{err});
        break :blk null;
    };

    if (crypto_data) |data| {
        defer ctx.allocator.free(data);
        const base_off = c.crypto_tx_off_initial;
        _ = (frame.Frame{ .crypto = .{ .offset = base_off, .data = data } }).write(frames.writer(ctx.allocator.*)) catch 0;
        if (c.crypto_retx_initial) |prev| {
            ctx.allocator.free(prev);
            c.crypto_retx_initial = null;
        }
        c.crypto_retx_initial = ctx.allocator.dupe(u8, data) catch null;
        c.crypto_retx_initial_off = base_off;
        c.crypto_tx_off_initial += @intCast(data.len);
    } else {
        frames.append(ctx.allocator.*, @intFromEnum(frame.FrameType.PING)) catch |err| {
            logger.err("Initial PING frame append failed (OOM): {s}", .{@errorName(err)});
        };
    }

    // Use any stored Retry token if present
    const token_slice: []const u8 = c.initial_token.items;

    // RFC 9000 §14.1: Client MUST expand Initial packets to at least 1200 bytes
    // Calculate header overhead to determine required padding
    const dcid_len = c.peer_initial_dcid.len;
    const scid_len = c.our_scid.len;
    const pn_len: usize = 2; // Using 2-byte PN

    // Header: first(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
    const base_header: usize = 1 + 4 + 1 + dcid_len + 1 + scid_len;

    // Token: varint length + token bytes
    // For tokens < 64 bytes, varint is 1 byte. For < 16384, it's 2 bytes.
    const token_varint_len: usize = if (token_slice.len == 0) 1 else if (token_slice.len < 64) 1 else 2;
    const token_overhead = token_varint_len + token_slice.len;

    // Ciphertext overhead: AEAD tag
    const aead_tag_len: usize = 16;

    // Length varint: for ~1200 byte packets, this is typically 2 bytes (values < 16384)
    const length_varint_len: usize = 2;

    // Total overhead = header + token + length varint + PN + AEAD tag
    const overhead = base_header + token_overhead + length_varint_len + pn_len + aead_tag_len;

    // Minimum packet size per RFC 9000 §14.1
    const min_packet_size: usize = 1200;

    // Calculate required plaintext size
    const min_plaintext_size = if (overhead < min_packet_size) min_packet_size - overhead else 0;

    // Add PADDING frames to reach minimum size
    while (frames.items.len < min_plaintext_size) {
        frames.append(ctx.allocator.*, @intFromEnum(frame.FrameType.PADDING)) catch |err| {
            logger.err("Initial PADDING append failed (OOM): {s}", .{@errorName(err)});
        };
    }

    const pkt = try packet.encodeInitialProtected(
        ctx.allocator.*,
        c.version,
        // Client Initial: DCID = our chosen dcid; SCID = our scid
        // After a Retry, peer_initial_dcid is updated to the SCID from the Retry per RFC 9000 §17.2.5.
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
        c.our_scid.bytes[0..c.our_scid.len],
        token_slice,
        @as(u32, @truncate(c.pn_initial_tx)),
        2,
        frames.items,
        tx_keys,
    );

    logger.debugPrint("client: built Initial pn={} dcid=\n", .{c.pn_initial_tx});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        logger.debugPrint("{X:0>2}\n", .{b});
    }
    logger.debugPrint(" scid=\n", .{});
    for (c.our_scid.bytes[0..c.our_scid.len]) |b| {
        logger.debugPrint("{X:0>2}\n", .{b});
    }
    logger.debugPrint(" payload_len={}\n", .{frames.items.len});

    defer ctx.allocator.free(pkt);
    const sent = try ctx.send_fn(ctx.sender_ctx, ctx.peer, pkt);
    c.onPacketSent(.Initial, c.pn_initial_tx, sent, true);
    c.pn_initial_tx +%= 1;
}

/// Helper function to hash bytes (for connection lookup).
fn hashBytes(bytes: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(bytes);
    return h.final();
}

/// Placeholder struct for ClientHandshake (Phase 13).
/// This struct satisfies unit tests while full implementation is being developed.
pub const ClientHandshake = struct {
    pub fn init() ClientHandshake {
        return .{};
    }
};
