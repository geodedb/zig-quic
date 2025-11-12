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
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const types = @import("types");
const handshake_integration = @import("handshake_integration");

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
        .sock_fd = @as(isize, @intCast(sock_fd)),
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
    c.init(allocator, .Client, @as(isize, @intCast(sock_fd)), peer);

    // Apply config flags
    c.setUseCubic(cfg.cc == .cubic);
    c.tls.allow_insecure = cfg.allow_insecure;
    c.allowed_alpns = cfg.alpn;

    // Enable optional pacing and set CC max_datagram_size
    c.enable_pacing = cfg.enable_pacing;
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

    std.debug.print("[createClientConnection] Generated DCID len={} bytes: ", .{c.peer_initial_dcid.len});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        std.debug.print("{X:0>2} ", .{b});
    }
    std.debug.print("\n", .{});

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
    _ = conns_map.put(key_d, c) catch {};
    _ = conns_map.put(key_s, c) catch {};

    std.debug.print("Client connection registered:\n", .{});
    std.debug.print("  peer_hash={X:0>16}\n", .{peer_hash});
    std.debug.print("  By DCID hash={X:0>16} (peer_initial_dcid)\n", .{hashBytes(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len])});
    std.debug.print("  By SCID hash={X:0>16} (our_scid)\n", .{hashBytes(c.our_scid.bytes[0..c.our_scid.len])});

    // Initialize TLS Context for modular TLS 1.3 (Phase 21.2)
    // Client doesn't need certificates (server auth only)
    const tls13 = @import("quic_tls13");
    const ctx_value: ?tls13.Context = handshake_integration.createTlsContext(
        allocator.*,
        .Client,
        cfg.alpn,
        &[_]u8{}, // Transport params set separately before handshake
        null,     // No server cert for client
        null,     // No server key for client
    ) catch |err| blk: {
        std.debug.print("createClientConnection: Failed to create TLS Context: {}\n", .{err});
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

    // Initial secret derives from the immutable DCID per RFC 9001 §5.1/§5.2.
    const dcid_for_secret = if (c.original_dcid.len > 0)
        c.original_dcid.bytes[0..c.original_dcid.len]
    else
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];

    const initial = ks.deriveInitialSecret(v2, dcid_for_secret);
    const pair = ks.deriveClientServerInitial(initial);

    std.debug.print("client: deriving Initial keys with dcid (peer_initial_dcid) len={}: ", .{c.peer_initial_dcid.len});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        std.debug.print("{X:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
    std.debug.print("       original_dcid len={}: ", .{c.original_dcid.len});
    for (c.original_dcid.bytes[0..c.original_dcid.len]) |b| {
        std.debug.print("{X:0>2} ", .{b});
    }
    std.debug.print("\n", .{});

    const tx_keys: packet.InitialKeys = if (v2) blk: {
        const t = ks.deriveKeyIvHpV2(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk: {
        const t = ks.deriveKeyIvHp(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };

    std.debug.print("[Client TX] Initial key[0..4]: ", .{});
    for (tx_keys.key[0..4]) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    var frames = std.ArrayList(u8){};
    defer frames.deinit(ctx.allocator.*);

    // Build CRYPTO frame carrying ClientHello
    // Note: Transport parameters must be set up by caller before calling sendInitialProbe

    // Set transport parameters on TLS Context
    if (c.local_transport_params_raw) |tp_bytes| {
        c.tls_context.setTransportParameters(tp_bytes);
    }

    // Start client handshake (generates ClientHello)
    c.tls_context.startClientHandshake() catch |err| {
        std.debug.print("sendInitialProbe: Context startClientHandshake error: {}\n", .{err});
    };

    // Poll for the generated ClientHello
    const crypto_data = c.tls_context.pollCrypto(ctx.allocator.*, .Initial) catch |err| blk: {
        std.debug.print("sendInitialProbe: Context pollCrypto error: {}\n", .{err});
        break :blk null;
    };

    if (crypto_data) |data| {
        defer ctx.allocator.free(data);
        const base_off = c.crypto_tx_off_initial;
        _ = (frame.Frame{ .crypto = .{ .offset = base_off, .data = data } }).write(frames.writer(ctx.allocator.*)) catch 0;
        c.crypto_retx_initial_off = base_off;
        c.crypto_tx_off_initial += @intCast(data.len);
    } else {
        frames.append(ctx.allocator.*, @intFromEnum(frame.FrameType.PING)) catch {};
    }

    // Add padding to meet minimum Initial datagram size of 1200 bytes (RFC 9000 §14.1).
    while (frames.items.len < 1150) {
        frames.append(ctx.allocator.*, @intFromEnum(frame.FrameType.PADDING)) catch {};
    }

    // Use any stored Retry token if present
    const token_slice: []const u8 = c.initial_token.items;
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

    std.debug.print("client: built Initial pn={} dcid=\n", .{c.pn_initial_tx});
    for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| {
        std.debug.print("{X:0>2}\n", .{b});
    }
    std.debug.print(" scid=\n", .{});
    for (c.our_scid.bytes[0..c.our_scid.len]) |b| {
        std.debug.print("{X:0>2}\n", .{b});
    }
    std.debug.print(" payload_len={}\n", .{frames.items.len});

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
