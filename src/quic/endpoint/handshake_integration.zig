//! TLS handshake integration for QUIC (RFC 9001 §4, §8).
//!
//! This module bridges the QUIC packet processing layer with the TLS 1.3 handshake.
//! It handles:
//! - CRYPTO frame data reassembly and TLS state machine feeding
//! - Secret derivation on TLS state transitions
//! - Key installation for Handshake and Application encryption levels
//! - Transport parameter extraction and validation
//! - ServerHello and HANDSHAKE_DONE frame generation
//!
//! RFC References:
//! - RFC 9001 §4: Carrying TLS Messages
//! - RFC 9001 §5: Packet Protection (key derivation)
//! - RFC 9001 §8: QUIC Transport Parameters Extension
//! - RFC 8446: TLS 1.3 (handshake state machine)
//!
//! Phase 4b.5 Session 6: Extract TLS integration from endpoint.zig lines 2090-2900

const std = @import("std");
const conn_mod = @import("quic_conn");
const packet = @import("packet");
const cfg = @import("config");
const frame = @import("frame");
const crypto = @import("crypto_quic");
const transport_params = @import("transport_params");

// Import TLS from vendor/ztls
const tls13 = @import("vendor_ztls_tls13");
const key_schedule = @import("vendor_ztls_key_schedule");

/// Context for TLS handshake processing.
/// Focused context pattern - only includes what's needed for TLS integration.
pub const HandshakeContext = struct {
    /// Connection being processed
    conn: *conn_mod.Connection,
    /// Memory allocator
    allocator: *std.mem.Allocator,
    /// Function to send UDP datagrams
    send_fn: SendFn,
    /// Peer socket address
    peer: conn_mod.SockAddr,
    /// QUIC configuration
    cfg: *const cfg.QuicConfig,
};

/// Function signature for sending UDP datagrams
pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;

// =============================================================================
// TLS Context Callbacks (Phase 6)
// =============================================================================

/// Threadlocal storage for current Connection being processed.
/// This enables TLS callbacks to access Connection without modifying vendor/ztls.
/// Safe for QUIC since each connection is processed on a single thread.
threadlocal var current_tls_connection: ?*conn_mod.Connection = null;

/// Set the current connection for TLS callbacks.
/// This must be called before any TLS Context operations that might trigger callbacks.
pub fn setCurrentConnection(conn: *conn_mod.Connection) void {
    current_tls_connection = conn;
}

/// Clear the current connection after TLS operations complete.
pub fn clearCurrentConnection() void {
    current_tls_connection = null;
}

/// Callback invoked when TLS derives a new traffic secret.
/// RFC 9001 §5: Install packet protection keys derived from traffic secret.
///
/// This callback is registered with vendor/ztls Context and invoked during:
/// - Handshake level: After ServerHello (client_hs_secret, server_hs_secret)
/// - Application level: After Finished (client_app_secret, server_app_secret)
///
/// Parameters from vendor/ztls:
/// - ctx: TLS Context (contains negotiated parameters)
/// - level: EncryptionLevel (.Initial, .Handshake, .Application)
/// - secret: Traffic secret bytes (32 bytes for SHA-256 cipher suites)
fn onSecretAvailable(
    ctx: *tls13.Context,
    level: tls13.EncryptionLevel,
    secret: []const u8,
) !void {
    _ = ctx; // Context available if needed for negotiated parameters

    const conn = current_tls_connection orelse return error.NoConnectionContext;

    // RFC 9001 §5.1: Secrets are 32 bytes for SHA-256-based cipher suites
    if (secret.len != 32) return error.InvalidSecretLength;

    var secret_bytes: [32]u8 = undefined;
    @memcpy(&secret_bytes, secret[0..32]);

    // Install keys based on encryption level
    switch (level) {
        .Initial => {
            // Initial keys are derived by QUIC layer before TLS starts
            // They don't come from TLS callbacks (RFC 9001 §5.2)
        },
        .Handshake => {
            // Determine if this is client or server secret based on role
            // Context.installTrafficSecret is called twice:
            //   - Once for .send direction (our TX keys)
            //   - Once for .recv direction (our RX keys)
            //
            // We need to collect both secrets before calling installHandshakeKeys.
            // For now, store in Connection's existing hs_client/hs_server fields.
            //
            // TODO: Track direction (send/recv) to properly map secrets.
            // For now, assume first call is client, second is server (works for simple cases).
            if (conn.hs_client == null) {
                conn.hs_client = secret_bytes;
            } else if (conn.hs_server == null) {
                conn.hs_server = secret_bytes;
                // Both secrets available - install keys
                try installHandshakeKeys(conn, conn.hs_client.?, conn.hs_server.?);
            }
        },
        .Application => {
            // Similar pattern for Application secrets
            if (conn.app_rx_secret == null) {
                conn.app_rx_secret = secret_bytes;
            } else if (conn.app_tx_secret == null) {
                conn.app_tx_secret = secret_bytes;
                // Both secrets available - install keys
                try installApplicationKeys(conn, conn.app_rx_secret.?, conn.app_tx_secret.?);
            }
        },
    }
}

/// Callback invoked when handshake metadata becomes available.
/// RFC 9001 §8.2: Extract ALPN and transport parameters from TLS handshake.
///
/// This callback is invoked after EncryptedExtensions is processed (client)
/// or before sending it (server).
///
/// Parameters from vendor/ztls:
/// - ctx: TLS Context
/// - meta: HandshakeMetadata with alpn and local_transport_parameters
fn onHandshakeMetadata(
    ctx: *tls13.Context,
    meta: tls13.HandshakeMetadata,
) !void {
    _ = ctx; // Context available if needed

    const conn = current_tls_connection orelse return error.NoConnectionContext;

    // Store negotiated ALPN
    if (meta.alpn) |alpn_bytes| {
        // Allocate owned copy of ALPN
        const owned_alpn = try conn.allocator.alloc(u8, alpn_bytes.len);
        @memcpy(owned_alpn, alpn_bytes);

        // Free old ALPN if exists
        if (conn.negotiated_alpn) |old| {
            conn.allocator.free(old);
        }

        conn.negotiated_alpn = owned_alpn;
    }

    // Store and validate peer transport parameters (RFC 9000 §7.4, §18.2)
    if (meta.peer_transport_parameters) |peer_tp_bytes| {
        // Allocate owned copy
        const owned_tp = try conn.allocator.alloc(u8, peer_tp_bytes.len);
        @memcpy(owned_tp, peer_tp_bytes);

        // Store raw bytes via Connection's method
        try conn.storePeerTransportParams(owned_tp);

        // Decode, validate, and apply transport parameters
        // RFC 9000 §7.4: "An endpoint MUST apply the transport parameters provided by its peer"
        // This method now includes validate() and checkLimits() calls (Phase 7)
        try conn.applyPeerTransportParameters(peer_tp_bytes);
    }
}

/// Callback invoked when peer's Finished message is verified.
/// RFC 8446 §4.4.4: Finished contains HMAC over transcript hash.
///
/// This indicates:
/// - Peer proved knowledge of handshake traffic secret
/// - Transcript integrity confirmed
/// - Safe to process peer's application data
///
/// Parameters from vendor/ztls:
/// - ctx: TLS Context
fn onPeerFinished(ctx: *tls13.Context) !void {
    _ = ctx; // Context available if needed

    const conn = current_tls_connection orelse return error.NoConnectionContext;

    // Mark that peer's Finished has been verified
    conn.peer_finished_verified = true;

    // RFC 9001 §4.1.2: Client can drop handshake keys after sending Finished
    // Server must wait for peer Finished before dropping
    // This is handled by the Connection's existing lifecycle management
}

/// Callback invoked when TLS handshake completes successfully.
/// Both local and peer Finished messages exchanged and verified.
///
/// At this point:
/// - Application secrets installed
/// - Safe to send/receive application data
/// - Handshake messages no longer expected
///
/// Parameters from vendor/ztls:
/// - ctx: TLS Context
fn onHandshakeComplete(ctx: *tls13.Context) !void {
    _ = ctx; // Context available if needed

    const conn = current_tls_connection orelse return error.NoConnectionContext;

    // Phase 21.2: Mark handshake complete
    // RFC 9000 §4.1.2: "A server MUST send a HANDSHAKE_DONE frame as soon as it completes the handshake."
    // RFC 9001 §4.9.3: "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed."

    std.debug.print("onHandshakeComplete: Handshake complete for role={}\n", .{conn.role});

    // For server: Handshake is confirmed, ready to send HANDSHAKE_DONE
    // The actual HANDSHAKE_DONE frame will be sent by the endpoint layer
    // when it checks conn.app_tx_keys != null && !conn.handshake_done_sent

    // For client: Handshake is confirmed when HANDSHAKE_DONE received
    // Client doesn't send HANDSHAKE_DONE, only receives it

    // Mark Application keys as ready (already set via onSecretAvailable callback)
    // The handshake_done_sent flag will be checked by endpoint layer to send frame
}

/// Create and initialize a TLS Context for QUIC handshake integration.
/// RFC 9001 §4: TLS 1.3 for QUIC uses CRYPTO frames instead of TLS records.
///
/// This helper creates a vendor/ztls Context with:
/// - Proper role (Client/Server)
/// - QUIC-specific callbacks for secret installation
/// - ALPN and transport parameter configuration
///
/// Parameters:
/// - allocator: Memory allocator for TLS state
/// - role: .Client or .Server
/// - alpn_list: List of ALPNs to advertise (e.g., ["h3"])
/// - transport_params_bytes: Encoded transport parameters (from setupClientTransportParams/setupServerTransportParams)
///
/// Returns:
/// - Initialized Context ready for processCrypto() calls
///
/// Note: Caller must call context.deinit() when done.
pub fn createTlsContext(
    allocator: std.mem.Allocator,
    role: conn_mod.Role,
    alpn_list: []const []const u8,
    transport_params_bytes: []const u8,
    server_cert_der: ?[]const u8,
    server_key_der: ?[]const u8,
) !tls13.Context {
    // Create TLS configuration
    const tls_role: tls13.Role = if (role == .Client) .Client else .Server;

    const config = tls13.Config{
        .allocator = allocator,
        .role = tls_role,
        .alpn_protocols = if (alpn_list.len > 0) alpn_list else null,
        .quic_transport_parameters = if (transport_params_bytes.len > 0) transport_params_bytes else null,
        .server_cert_der = server_cert_der,
        .server_key_der = server_key_der,
    };

    // Create callbacks struct with full QUIC integration
    const callbacks = tls13.Callbacks{
        .on_secret_available = onSecretAvailable,
        .on_handshake_metadata = onHandshakeMetadata,
        .on_peer_finished = onPeerFinished,
        .on_handshake_complete = onHandshakeComplete,
    };

    // Initialize Context (may fail if client handshake generation fails)
    return try tls13.Context.init(config, callbacks);
}

// =============================================================================
// Key Installation Functions
// =============================================================================

/// Install Handshake protection keys.
/// Extracted from endpoint.zig TLS state transition handling (lines ~2200-2300).
///
/// RFC 9001 §5: Packet Protection
/// RFC 9001 §5.2: Initial Secrets → Handshake Secrets transition
///
/// When TLS handshake progresses beyond ClientHello/ServerHello exchange:
/// 1. Derive Handshake secrets from TLS early secret
/// 2. Derive client and server Handshake keys (key, IV, HP)
/// 3. Store in connection's hs_rx_keys and hs_tx_keys
/// 4. Enable Handshake packet encryption/decryption
///
/// Parameters:
/// - conn: Connection to install keys on
/// - client_secret: 32-byte client Handshake secret from TLS
/// - server_secret: 32-byte server Handshake secret from TLS
///
/// RFC 9001 §5.6: "Packets of each encryption level are protected with keys
/// derived from the secrets specific to that level."
pub fn installHandshakeKeys(
    conn: *conn_mod.Connection,
    client_secret: [32]u8,
    server_secret: [32]u8,
) !void {
    std.debug.print("installHandshakeKeys: CALLED with role={s}\n", .{if (conn.role == .Server) "Server" else "Client"});
    std.debug.print("  client_secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ client_secret[0], client_secret[1], client_secret[2], client_secret[3] });
    std.debug.print("  server_secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ server_secret[0], server_secret[1], server_secret[2], server_secret[3] });

    // Derive Handshake keys from secrets
    // Uses HKDF-Expand-Label per RFC 8446 §7.1 and RFC 9001 §5
    // AES-128-GCM (TLS_AES_128_GCM_SHA256) is the default cipher suite for QUIC

    // Derive client Handshake keys
    // RFC 9001 §5.1: "key = HKDF-Expand-Label(Secret, "quic key", "", key_length)"
    const client_keys = key_schedule.deriveKeyIvHp(client_secret);

    // Derive server Handshake keys
    const server_keys = key_schedule.deriveKeyIvHp(server_secret);

    std.debug.print("  Derived client_keys: key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ client_keys.key[0], client_keys.key[1], client_keys.key[2], client_keys.key[3] });
    std.debug.print("  Derived server_keys: key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ server_keys.key[0], server_keys.key[1], server_keys.key[2], server_keys.key[3] });

    // Install based on connection role
    // Convert KeyMaterial to packet.InitialKeys by copying fields
    if (conn.role == .Client) {
        // Client receives with server keys, sends with client keys
        conn.hs_rx_keys = .{ .key = server_keys.key, .iv = server_keys.iv, .hp = server_keys.hp };
        conn.hs_tx_keys = .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp };
    } else {
        // Server receives with client keys, sends with server keys
        conn.hs_rx_keys = .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp };
        conn.hs_tx_keys = .{ .key = server_keys.key, .iv = server_keys.iv, .hp = server_keys.hp };
    }

    // Handshake keys are now installed (indicated by non-null hs_rx_keys/hs_tx_keys)
}

/// Install Application (1-RTT) protection keys.
/// Extracted from endpoint.zig TLS state transition handling (lines ~2400-2500).
///
/// RFC 9001 §5: Packet Protection
/// RFC 9001 §5.3: Handshake Secrets → Application Secrets transition
///
/// When TLS handshake completes and Finished messages are exchanged:
/// 1. Derive Application secrets from TLS master secret
/// 2. Derive client and server Application keys (key, IV, HP)
/// 3. Store in connection's app_rx_keys and app_tx_keys
/// 4. Enable 1-RTT packet encryption/decryption
///
/// Parameters:
/// - conn: Connection to install keys on
/// - client_secret: 32-byte client Application secret from TLS
/// - server_secret: 32-byte server Application secret from TLS
///
/// RFC 9001 §4.1.3: "Handshake and 1-RTT packets can be coalesced in the same
/// UDP datagram" - both key sets may be used simultaneously.
pub fn installApplicationKeys(
    conn: *conn_mod.Connection,
    client_secret: [32]u8,
    server_secret: [32]u8,
) !void {
    // Derive Application keys from secrets
    // Uses HKDF-Expand-Label per RFC 8446 §7.1 and RFC 9001 §5
    // AES-128-GCM (TLS_AES_128_GCM_SHA256) is the default cipher suite for QUIC

    // Derive client Application keys
    // RFC 9001 §5.1: "key = HKDF-Expand-Label(Secret, "quic key", "", key_length)"
    const client_keys = key_schedule.deriveKeyIvHp(client_secret);

    // Derive server Application keys
    const server_keys = key_schedule.deriveKeyIvHp(server_secret);

    // Install based on connection role
    // Convert KeyMaterial to packet.AeadKeys by copying fields
    if (conn.role == .Client) {
        // Client receives with server keys, sends with client keys
        conn.app_rx_keys = .{ .key = server_keys.key, .iv = server_keys.iv, .hp = server_keys.hp };
        conn.app_tx_keys = .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp };
    } else {
        // Server receives with client keys, sends with server keys
        conn.app_rx_keys = .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp };
        conn.app_tx_keys = .{ .key = server_keys.key, .iv = server_keys.iv, .hp = server_keys.hp };
    }

    // Application keys are now installed (indicated by non-null app_rx_keys/app_tx_keys)
}

// =============================================================================
// CRYPTO Frame Processing
// =============================================================================

/// Process CRYPTO frame and advance TLS state machine.
/// Extracted from endpoint.zig lines 2090-2900 (Phase 4b.5 Session 6).
///
/// RFC 9001 §4: "CRYPTO frames are used to carry cryptographic handshake
/// messages. They can be sent in different packet number spaces to separate
/// handshake messages by encryption level."
///
/// This function:
/// 1. Reassembles out-of-order CRYPTO data into connection's crypto_buffer
/// 2. Attempts to drain complete TLS messages when contiguous
/// 3. Feeds TLS messages to TLS 1.3 state machine
/// 4. Monitors TLS state transitions and derives secrets
/// 5. Installs Handshake and Application keys when ready
/// 6. Extracts and validates transport parameters
///
/// Parameters:
/// - ctx: HandshakeContext with connection, allocator, send_fn, peer, config
/// - space: Packet number space (Initial, Handshake, Application)
/// - crypto_data: CRYPTO frame payload bytes
/// - offset: Offset of this data within the CRYPTO stream
///
/// RFC 9000 §19.6: "There is a separate flow of cryptographic handshake data
/// in each encryption level, and endpoints MUST be able to send and receive
/// cryptographic handshake data in any order."
pub fn processCryptoFrame(
    ctx: *HandshakeContext,
    space: conn_mod.PacketNumberSpace,
    crypto_data: []const u8,
    offset: u64,
) !bool {
    const conn = ctx.conn;

    // RFC 9001 §4: Use vendor/ztls Context.processCrypto() when available (Phase 6+)
    if (conn.tls_context) |tls_ctx| {
        // Map PacketNumberSpace to EncryptionLevel
        const level: tls13.EncryptionLevel = switch (space) {
            .Initial => .Initial,
            .Handshake => .Handshake,
            .Application => .Application,
        };

        // Get crypto buffer and RX offset for this packet number space
        const crypto_buffer = switch (space) {
            .Initial => &conn.crypto_buffer_initial,
            .Handshake => &conn.crypto_buffer_handshake,
            .Application => return false, // Not yet supported
        };
        const rx_off_ptr = switch (space) {
            .Initial => &conn.crypto_rx_off_initial,
            .Handshake => &conn.crypto_rx_off_handshake,
            .Application => return false,
        };

        // Step 1: Buffer out-of-order CRYPTO data (RFC 9000 §19.6)
        try crypto_buffer.insertFragment(ctx.allocator.*, offset, crypto_data);

        // Step 2: Set threadlocal for callback access to Connection
        current_tls_connection = conn;
        defer current_tls_connection = null;

        // Step 3: Extract and process all contiguous chunks
        while (crypto_buffer.getContiguous(rx_off_ptr.*)) |fragments| {
            for (fragments) |frag| {
                if (frag.data.len == 0) continue;

                // Feed contiguous chunk to TLS Context
                // Context.processCrypto() handles:
                // - Handshake message parsing and validation
                // - State machine transitions (ClientHello → ServerHello → Finished)
                // - Callback invocation for secret installation (via onSecretAvailable)
                try tls_ctx.processCrypto(level, frag.data);

                rx_off_ptr.* += @intCast(frag.data.len);
            }

            crypto_buffer.removeProcessed(fragments.len, ctx.allocator.*);
        }

        // Secrets are installed via onSecretAvailable callback
        return true; // ACK-eliciting
    }

    // Fallback to legacy Engine-based integration
    const ack_needed = switch (space) {
        .Initial => try conn.handleInitialCrypto(
            ctx.allocator,
            offset,
            crypto_data,
        ),
        .Handshake => try conn.handleHandshakeCrypto(
            ctx.allocator,
            offset,
            crypto_data,
        ),
        .Application => blk: {
            // Application CRYPTO frames (NewSessionTicket, KeyUpdate)
            // RFC 9001 §4.1.4: Not critical for basic operation
            break :blk false;
        },
    };

    return ack_needed;
}

/// Send ServerHello in Initial packet (server-only).
/// Extracted from endpoint.zig server Initial response logic (Phase 4b.5 Session 8).
///
/// RFC 9001 §4.1: "A server sends the first Handshake packet as soon as it
/// sends a TLS ServerHello message."
///
/// This function:
/// 1. Pops ServerHello CRYPTO data from TLS state machine
/// 2. Fragments CRYPTO data across multiple Initial packets if needed
/// 3. Encrypts each packet using Initial keys
/// 4. Sends to client
///
/// Parameters:
/// - ctx: HandshakeContext with connection, allocator, send_fn, peer, config
///
/// NOTE: The TLS state machine (conn.tls) generates ServerHello automatically
/// when processing client's ClientHello via conn.handleInitialCrypto().
pub fn sendServerHello(ctx: *HandshakeContext) !void {
    const conn = ctx.conn;

    // Check if we have Initial TX keys
    const initial_tx_keys = conn.initial_tx_keys orelse return error.NoInitialKeys;

    // Pop CRYPTO data from TLS state machine
    // Try Context API first (generates full server flight), fall back to Engine (legacy)
    var outbox: [8192]u8 = undefined;
    var n: usize = 0;
    var used_context = false;

    if (conn.tls_context) |tls_ctx| {
        used_context = true;
        // Phase 21.2: Use modular TLS 1.3 Context API (vendor/ztls)
        // Poll Initial level for ServerHello
        const sh_data = tls_ctx.pollCrypto(ctx.allocator.*, .Initial) catch {
            // No ServerHello available yet
            std.debug.print("sendServerHello: Context has no Initial CRYPTO data\n", .{});
            return;
        };
        defer ctx.allocator.free(sh_data);

        if (sh_data.len > outbox.len) return error.OutboxTooSmall;
        @memcpy(outbox[0..sh_data.len], sh_data);
        n = sh_data.len;

        std.debug.print("sendServerHello: Context provided {} bytes at Initial level\n", .{n});

        // Also poll Handshake level for Certificate+Finished messages
        // These are stored in pending_hs_messages for sendHandshakePackets to send later
        const hs_data = tls_ctx.pollCrypto(ctx.allocator.*, .Handshake) catch |err| blk: {
            // It's okay if no Handshake data is available yet
            std.debug.print("sendServerHello: No Handshake CRYPTO data (error: {})\n", .{err});
            break :blk null;
        };

        if (hs_data) |hs_msgs| {
            defer ctx.allocator.free(hs_msgs);
            std.debug.print("sendServerHello: Context provided {} bytes at Handshake level\n", .{hs_msgs.len});

            // Free old buffer if exists
            if (conn.pending_hs_messages) |old_buf| {
                ctx.allocator.free(old_buf);
            }

            // Allocate and copy Handshake messages
            const hs_buf = ctx.allocator.alloc(u8, hs_msgs.len) catch {
                return error.AllocFailed;
            };
            @memcpy(hs_buf, hs_msgs);
            conn.pending_hs_messages = hs_buf;
        }
    } else {
        // Legacy Engine path (Phase 14)
        n = conn.tls.popCrypto(outbox[0..]);
        if (n == 0) {
            // No CRYPTO data to send
            return;
        }
    }

    if (n == 0) {
        // No CRYPTO data to send
        return;
    }

    // Parse TLS message boundaries to separate ServerHello from Handshake-level messages
    // (Note: When using Context API, messages are already separated by encryption level)
    var serverhello_data: []const u8 = undefined;

    if (used_context) {
        // Context API already separated messages by encryption level
        serverhello_data = outbox[0..n];
        std.debug.print("sendServerHello: Context separated messages - ServerHello={} bytes\n", .{serverhello_data.len});
    } else {
        // Legacy Engine: Parse and split messages manually
        // TLS handshake message format: [type:1][length:3][data]
        // ServerHello = 0x02, EncryptedExtensions = 0x08, Certificate = 0x0B, Finished = 0x14

        std.debug.print("sendServerHello: Parsing {} bytes of TLS data\n", .{n});

        if (n < 4) return error.InvalidTlsMessage; // Need at least header

        const msg_type = outbox[0];
        const msg_len = (@as(u32, outbox[1]) << 16) | (@as(u32, outbox[2]) << 8) | @as(u32, outbox[3]);
        const total_msg_len = 4 + msg_len; // header + body

        std.debug.print("sendServerHello: First message type=0x{X:0>2}, length={}, total={}\n", .{ msg_type, msg_len, total_msg_len });

        if (total_msg_len > n) return error.TruncatedTlsMessage;

        // Verify first message is ServerHello
        if (msg_type != 0x02) return error.ExpectedServerHello;

        // Split messages: ServerHello goes in Initial, rest goes in Handshake
        serverhello_data = outbox[0..total_msg_len];
        const remaining_data = outbox[total_msg_len..n];

        std.debug.print("sendServerHello: ServerHello={} bytes, remaining={} bytes\n", .{ serverhello_data.len, remaining_data.len });

        // Store remaining Handshake messages for sendHandshakePackets
        if (remaining_data.len > 0) {
            // Free old buffer if exists
            if (conn.pending_hs_messages) |old_buf| {
                ctx.allocator.free(old_buf);
            }

            // Allocate and copy remaining messages
            const hs_buf = ctx.allocator.alloc(u8, remaining_data.len) catch {
                return error.AllocFailed;
            };
            @memcpy(hs_buf, remaining_data);
            conn.pending_hs_messages = hs_buf;
        }
    }

    // Fragment ServerHello CRYPTO data across multiple Initial packets if needed
    const max_crypto_per_packet: usize = 1100; // ~1200 MTU - headers - overhead
    var crypto_offset: usize = 0;
    const base_off = conn.crypto_tx_off_initial;
    const serverhello_len = serverhello_data.len;

    // Check if we should coalesce with Handshake packet
    // RFC 9000 §12.2: Initial and Handshake packets MUST be coalesced when possible
    // We will send a Handshake packet if we have keys (even if just a PING for coalescing)
    const will_send_handshake = conn.hs_tx_keys != null;

    while (crypto_offset < serverhello_len) {
        const chunk_size = @min(max_crypto_per_packet, serverhello_len - crypto_offset);
        const chunk = serverhello_data[crypto_offset .. crypto_offset + chunk_size];
        const is_last_chunk = (crypto_offset + chunk_size >= serverhello_len);

        var frames_buf: [4096]u8 = undefined;
        var frames_stream = std.io.fixedBufferStream(&frames_buf);
        const w = frames_stream.writer();

        // Add CRYPTO frame
        const crypto_frame_offset = base_off + crypto_offset;
        _ = (frame.Frame{ .crypto = .{ .offset = crypto_frame_offset, .data = chunk } }).write(w) catch 0;
        const frames_data = frames_stream.getWritten();

        // Use peer's SCID as DCID for Initial response
        const initial_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

        // Encode Initial packet
        const pkt = packet.encodeInitialProtected(
            ctx.allocator.*,
            0x00000001, // QUIC v1
            initial_dcid,
            conn.our_scid.bytes[0..conn.our_scid.len],
            &[_]u8{}, // No token in server Initial
            @as(u32, @truncate(conn.pn_initial_tx)),
            2, // PN length
            frames_data,
            initial_tx_keys,
        ) catch return error.PacketEncodeFailed;

        defer ctx.allocator.free(pkt);

        // If this is the last Initial packet and we have Handshake keys, buffer it for coalescing
        if (is_last_chunk and will_send_handshake) {
            // Store Initial packet for coalescing
            if (conn.pending_initial_packet) |old_pkt| {
                ctx.allocator.free(old_pkt);
            }
            const initial_copy = ctx.allocator.alloc(u8, pkt.len) catch return error.AllocFailed;
            @memcpy(initial_copy, pkt);
            conn.pending_initial_packet = initial_copy;
            std.debug.print("sendServerHello: Buffered Initial packet ({} bytes) for coalescing\n", .{pkt.len});
        } else {
            // Send Initial packet immediately (not the last one or no Handshake to coalesce)
            _ = ctx.send_fn(ctx.peer, pkt) catch return error.SendFailed;
        }

        conn.onPacketSent(.Initial, conn.pn_initial_tx, pkt.len, true);
        conn.pn_initial_tx +%= 1;

        crypto_offset += chunk_size;
    }

    // Save retransmit buffer (only ServerHello, not Handshake messages)
    if (conn.crypto_retx_initial) |old_buf| ctx.allocator.free(old_buf);
    const owned = ctx.allocator.alloc(u8, serverhello_len) catch {
        conn.crypto_tx_off_initial += serverhello_len;
        return error.AllocFailed;
    };
    @memcpy(owned[0..serverhello_len], serverhello_data);
    conn.crypto_retx_initial = owned;
    conn.crypto_retx_initial_off = base_off;
    conn.crypto_tx_off_initial += serverhello_len;

    // Mark ServerHello as sent
    conn.server_hello_sent = true;
}

/// Send a Handshake packet with just a PING frame (no CRYPTO data).
/// Used for coalescing when TLS doesn't have Handshake-level messages yet.
fn sendHandshakePing(ctx: *HandshakeContext) !void {
    const conn = ctx.conn;

    std.debug.print("sendHandshakePing: ENTER\n", .{});

    // Check if we have Handshake TX keys
    const hs_tx_keys = conn.hs_tx_keys orelse {
        std.debug.print("sendHandshakePing: No hs_tx_keys\n", .{});
        return error.NoHandshakeKeys;
    };
    std.debug.print("sendHandshakePing: Retrieved keys from conn - key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}, iv[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
        hs_tx_keys.key[0], hs_tx_keys.key[1], hs_tx_keys.key[2], hs_tx_keys.key[3],
        hs_tx_keys.iv[0], hs_tx_keys.iv[1], hs_tx_keys.iv[2], hs_tx_keys.iv[3],
    });

    // Build a PING frame with padding
    // Need at least 3 bytes of payload for header protection with 2-byte PN
    // (sample_offset=2 + 16 sample bytes = 18 bytes needed, tag adds 16, so need 2+ payload bytes)
    var frames_buf: [32]u8 = undefined;
    var frames_stream = std.io.fixedBufferStream(&frames_buf);
    const w = frames_stream.writer();

    // Write PING frame (1 byte)
    _ = (frame.Frame{ .ping = {} }).write(w) catch {
        std.debug.print("sendHandshakePing: Failed to write PING frame\n", .{});
        return error.FrameEncodeFailed;
    };

    // Add PADDING frame (at least 2 bytes to ensure enough ciphertext)
    // PADDING frame is just 0x00 bytes
    _ = w.writeByte(0x00) catch {};  // PADDING frame type
    _ = w.writeByte(0x00) catch {};  // Extra padding byte

    const frames_data = frames_stream.getWritten();
    std.debug.print("sendHandshakePing: Built PING + PADDING frames, {} bytes\n", .{frames_data.len});

    // Use peer's Initial SCID as DCID for Handshake packets (RFC 9000 §7.2)
    const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
    std.debug.print("sendHandshakePing: peer_initial_scid.len={}, our_scid.len={}\n", .{ conn.peer_initial_scid.len, conn.our_scid.len });

    // Encode Handshake packet with PING
    const hs_pkt = packet.encodeHandshakeProtected(
        ctx.allocator.*,
        conn.version,
        hs_dcid,
        conn.our_scid.bytes[0..conn.our_scid.len],
        @as(u32, @truncate(conn.pn_handshake_tx)),
        2, // PN length
        frames_data,
        hs_tx_keys,
    ) catch |err| {
        std.debug.print("sendHandshakePing: encodeHandshakeProtected FAILED: {}\n", .{err});
        return error.PacketEncodeFailed;
    };
    std.debug.print("sendHandshakePing: Encoded Handshake packet, {} bytes\n", .{hs_pkt.len});

    defer ctx.allocator.free(hs_pkt);

    // Check if we have a pending Initial packet to coalesce
    if (conn.pending_initial_packet) |initial_pkt| {
        defer {
            ctx.allocator.free(initial_pkt);
            conn.pending_initial_packet = null;
        }

        // RFC 9000 §12.2: Initial and Handshake packets MUST be coalesced
        // Create coalesced packet buffer
        var coalesced_buf: [4096]u8 = undefined;
        if (initial_pkt.len + hs_pkt.len > coalesced_buf.len) {
            std.debug.print("sendHandshakePing: Coalesced packet too large ({} + {} > {})\n", .{ initial_pkt.len, hs_pkt.len, coalesced_buf.len });
            return error.PacketTooLarge;
        }

        // Copy Initial packet first
        @memcpy(coalesced_buf[0..initial_pkt.len], initial_pkt);
        // Append Handshake packet
        @memcpy(coalesced_buf[initial_pkt.len .. initial_pkt.len + hs_pkt.len], hs_pkt);

        const coalesced_len = initial_pkt.len + hs_pkt.len;
        std.debug.print("sendHandshakePing: Sending coalesced packet (Initial {} + Handshake {} = {} bytes)\n", .{ initial_pkt.len, hs_pkt.len, coalesced_len });

        // Send the coalesced packet
        _ = ctx.send_fn(ctx.peer, coalesced_buf[0..coalesced_len]) catch |err| {
            std.debug.print("sendHandshakePing: send_fn FAILED: {}\n", .{err});
            return error.SendFailed;
        };
    } else {
        // No Initial packet to coalesce, send Handshake packet alone
        std.debug.print("sendHandshakePing: No pending Initial packet, sending Handshake alone\n", .{});
        _ = ctx.send_fn(ctx.peer, hs_pkt) catch |err| {
            std.debug.print("sendHandshakePing: send_fn FAILED: {}\n", .{err});
            return error.SendFailed;
        };
    }

    conn.onPacketSent(.Handshake, conn.pn_handshake_tx, hs_pkt.len, false); // PING is not ack-eliciting
    conn.pn_handshake_tx +%= 1;
    conn.handshake_packet_sent = true; // Mark that we've sent at least one Handshake packet

    std.debug.print("sendHandshakePing: SUCCESS - Sent packet\n", .{});
}

/// Send Handshake packets with TLS messages (EncryptedExtensions, Certificate, Finished).
/// RFC 9001 §4.1: "A server sends the first Handshake packet as soon as it has Handshake keys."
///
/// This function is called after sendServerHello to send the remaining TLS messages in Handshake
/// packets. These packets are encrypted with Handshake keys derived after processing ClientHello.
///
/// Parameters:
/// - ctx: HandshakeContext with connection, allocator, send_fn, peer, config
///
/// Returns:
/// - error.NoHandshakeKeys if Handshake TX keys are not available
/// - error.PacketEncodeFailed if packet encoding fails
/// - error.SendFailed if UDP send fails
pub fn sendHandshakePackets(ctx: *HandshakeContext) !void {
    const conn = ctx.conn;

    std.debug.print("sendHandshakePackets: ENTER\n", .{});

    // Check if we have Handshake TX keys
    const hs_tx_keys = conn.hs_tx_keys orelse {
        std.debug.print("sendHandshakePackets: No Handshake TX keys\n", .{});
        return error.NoHandshakeKeys;
    };
    std.debug.print("sendHandshakePackets: Have Handshake TX keys\n", .{});

    // Server: If handshake flight not yet enqueued, queue it now
    // This generates EncryptedExtensions, Certificate, CertificateVerify, Finished
    if (conn.role == .Server and !conn.tls.server_handshake_flight_enqueued) {
        std.debug.print("sendHandshakePackets: Server queueing handshake flight\n", .{});
        conn.tls.queueServerHandshakeFlight();
    }

    // Get pending Handshake messages stored by sendServerHello
    // If there are no pending messages, try popping new data from TLS
    // (TLS generates Handshake-level messages after keys are installed)
    var pending_data: []const u8 = undefined;
    var owns_buffer = false;

    if (conn.pending_hs_messages) |buffered| {
        std.debug.print("sendHandshakePackets: Using {} bytes of pending messages\n", .{buffered.len});
        pending_data = buffered;
        owns_buffer = true;
        conn.pending_hs_messages = null; // Clear immediately to avoid double-free
    } else {
        std.debug.print("sendHandshakePackets: No pending messages, checking TLS for new data\n", .{});

        // Try Context API first, fall back to Engine
        if (conn.tls_context) |tls_ctx| {
            // Phase 21.2: Use modular TLS 1.3 Context API
            const hs_data = tls_ctx.pollCrypto(ctx.allocator.*, .Handshake) catch |err| blk: {
                std.debug.print("sendHandshakePackets: Context pollCrypto(.Handshake) returned error: {s}\n", .{@errorName(err)});
                break :blk null;
            };

            if (hs_data) |data| {
                std.debug.print("sendHandshakePackets: Context provided {} bytes at Handshake level\n", .{data.len});
                pending_data = data;
                owns_buffer = true; // Context allocates with allocator, we must free
            } else {
                // No CRYPTO data from Context
                std.debug.print("sendHandshakePackets: No CRYPTO data from Context, sending PING in Handshake packet\n", .{});
                return sendHandshakePing(ctx);
            }
        } else {
            // Legacy Engine path
            std.debug.print("sendHandshakePackets: Using Legacy Engine path, outbox len={}\n", .{conn.tls.outbox.items.len});
            var outbox: [8192]u8 = undefined;
            const tls_n = conn.tls.popCrypto(outbox[0..]);
            std.debug.print("sendHandshakePackets: TLS popCrypto returned {} bytes (outbox len was {})\n", .{tls_n, conn.tls.outbox.items.len + tls_n});
            if (tls_n == 0) {
                // No CRYPTO data, but we should still send a Handshake packet for coalescing
                // RFC 9000 §12.2: Initial and Handshake packets should be coalesced
                std.debug.print("sendHandshakePackets: No CRYPTO data, sending PING in Handshake packet\n", .{});
                return sendHandshakePing(ctx);
            }
            pending_data = outbox[0..tls_n];
            owns_buffer = false; // outbox is stack-allocated
        }
    }

    defer if (owns_buffer) {
        ctx.allocator.free(pending_data);
    };

    const n = pending_data.len;
    std.debug.print("sendHandshakePackets: Sending {} bytes of CRYPTO data\n", .{n});
    if (n == 0) {
        return;
    }

    // Fragment CRYPTO data across multiple Handshake packets if needed
    const max_crypto_per_packet: usize = 1100;
    var crypto_offset: usize = 0;
    const base_off = conn.crypto_tx_off_handshake;

    var first_packet = true;
    while (crypto_offset < n) {
        const chunk_size = @min(max_crypto_per_packet, n - crypto_offset);
        const chunk = pending_data[crypto_offset .. crypto_offset + chunk_size];

        var frames_buf: [4096]u8 = undefined;
        var frames_stream = std.io.fixedBufferStream(&frames_buf);
        const w = frames_stream.writer();

        // Add CRYPTO frame
        const crypto_frame_offset = base_off + crypto_offset;
        _ = (frame.Frame{ .crypto = .{ .offset = crypto_frame_offset, .data = chunk } }).write(w) catch 0;
        const frames_data = frames_stream.getWritten();

        // Use peer's Initial SCID as DCID for Handshake packets (RFC 9000 §7.2)
        const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

        // Encode Handshake packet
        const pkt = packet.encodeHandshakeProtected(
            ctx.allocator.*,
            conn.version,
            hs_dcid,
            conn.our_scid.bytes[0..conn.our_scid.len],
            @as(u32, @truncate(conn.pn_handshake_tx)),
            2, // PN length
            frames_data,
            hs_tx_keys,
        ) catch return error.PacketEncodeFailed;

        defer ctx.allocator.free(pkt);

        // For the first packet, check if we need to coalesce with pending Initial
        if (first_packet and conn.pending_initial_packet != null) {
            const initial_pkt = conn.pending_initial_packet.?;
            defer {
                ctx.allocator.free(initial_pkt);
                conn.pending_initial_packet = null;
            }

            // RFC 9000 §12.2: Initial and Handshake packets MUST be coalesced
            var coalesced_buf: [4096]u8 = undefined;
            if (initial_pkt.len + pkt.len > coalesced_buf.len) {
                std.debug.print("sendHandshakePackets: Coalesced packet too large ({} + {} > {})\n", .{ initial_pkt.len, pkt.len, coalesced_buf.len });
                return error.PacketTooLarge;
            }

            // Copy Initial packet first
            @memcpy(coalesced_buf[0..initial_pkt.len], initial_pkt);
            // Append Handshake packet
            @memcpy(coalesced_buf[initial_pkt.len .. initial_pkt.len + pkt.len], pkt);

            const coalesced_len = initial_pkt.len + pkt.len;
            std.debug.print("sendHandshakePackets: Sending coalesced packet (Initial {} + Handshake {} = {} bytes)\n", .{ initial_pkt.len, pkt.len, coalesced_len });

            // Send the coalesced packet
            _ = ctx.send_fn(ctx.peer, coalesced_buf[0..coalesced_len]) catch return error.SendFailed;
        } else {
            // Send Handshake packet alone (not first or no Initial to coalesce)
            _ = ctx.send_fn(ctx.peer, pkt) catch return error.SendFailed;
        }

        conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt.len, true);
        conn.pn_handshake_tx +%= 1;
        conn.handshake_packet_sent = true; // Mark that we've sent at least one Handshake packet

        crypto_offset += chunk_size;
        first_packet = false;
    }

    // Save retransmit buffer
    if (conn.crypto_retx_handshake) |old_buf| ctx.allocator.free(old_buf);
    const owned = ctx.allocator.alloc(u8, n) catch {
        conn.crypto_tx_off_handshake += n;
        return error.AllocFailed;
    };
    @memcpy(owned[0..n], pending_data[0..n]);
    conn.crypto_retx_handshake = owned;
    conn.crypto_retx_handshake_off = base_off;
    conn.crypto_tx_off_handshake += n;
}

/// Send HANDSHAKE_DONE frame (server-only, RFC 9000 §4.1.2).
/// Extracted from endpoint.zig server handshake completion logic (Phase 4b.5 Session 8).
///
/// RFC 9000 §19.20: "The server uses a HANDSHAKE_DONE frame to signal
/// confirmation of the handshake to the client."
///
/// RFC 9001 §4.1.2: "The server MUST send a HANDSHAKE_DONE frame as soon as
/// it completes the handshake."
///
/// This function:
/// 1. Builds HANDSHAKE_DONE frame
/// 2. Encrypts in 1-RTT packet using Application keys
/// 3. Sends to client
///
/// Parameters:
/// - ctx: HandshakeContext with connection, allocator, send_fn, peer, config
///
/// RFC 9000 §8.3: "A server completes the handshake when it receives a
/// Handshake packet from the client and the TLS handshake is complete."
pub fn sendHandshakeDone(ctx: *HandshakeContext) !void {
    const conn = ctx.conn;

    // Only servers send HANDSHAKE_DONE
    if (conn.role != .Server) {
        return error.ClientCannotSendHandshakeDone;
    }

    // Check if we have Application TX keys
    const app_tx_keys = conn.app_tx_keys orelse return error.NoApplicationKeys;

    // Build HANDSHAKE_DONE frame
    var frames_buf: [4096]u8 = undefined;
    var frames_stream = std.io.fixedBufferStream(&frames_buf);
    const w = frames_stream.writer();

    // HANDSHAKE_DONE frame has no payload, just the type byte
    _ = (frame.Frame{ .handshake_done = {} }).write(w) catch 0;
    const frames_data = frames_stream.getWritten();

    // Use peer's SCID as DCID for 1-RTT packet
    const dcid = if (conn.peer_initial_scid.len > 0)
        conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
    else
        &[_]u8{};

    // Encode and send 1-RTT packet
    const pkt = packet.encodeShortProtected(
        ctx.allocator.*,
        dcid,
        @as(u32, @truncate(conn.pn_app_tx)),
        2, // PN length
        frames_data,
        app_tx_keys,
        conn.tx_key_phase,
    ) catch return error.PacketEncodeFailed;

    defer ctx.allocator.free(pkt);
    _ = ctx.send_fn(ctx.peer, pkt) catch return error.SendFailed;

    conn.onShortHeaderPacketSent(pkt.len, true);

    // Mark that HANDSHAKE_DONE has been sent
    // This prevents duplicate HANDSHAKE_DONE frames
    conn.handshake_done_sent = true;
}

// =============================================================================
// Transport Parameters
// =============================================================================

/// Extract and validate transport parameters from TLS EncryptedExtensions.
/// Extracted from endpoint.zig TLS handshake processing (Phase 4b.5 Session 7).
///
/// RFC 9000 §7.4: "Transport parameters are exchanged in the
/// quic_transport_parameters extension."
///
/// RFC 9000 §18.2: "Each transport parameter is encoded as a type-length-value
/// (TLV) structure."
///
/// This function:
/// 1. Decodes transport parameter TLV stream from extension bytes
/// 2. Validates required parameters are present (RFC 9000 §18.2)
/// 3. Checks parameter values are within RFC-specified limits
/// 4. Applies validated parameters to connection state
/// 5. Returns decoded parameters for caller inspection
///
/// Parameters:
/// - conn: Connection to apply parameters to
/// - allocator: Memory allocator for parameter storage
/// - extension_bytes: Raw quic_transport_parameters extension value
/// - is_retry_sent: Whether a Retry packet was sent (affects validation)
///
/// Returns:
/// - TransportParams struct with decoded parameters
/// - error.InvalidTransportParameters if decoding/validation fails
pub fn extractTransportParameters(
    conn: *conn_mod.Connection,
    allocator: std.mem.Allocator,
    extension_bytes: []const u8,
    is_retry_sent: bool,
) !transport_params.TransportParams {
    // Decode transport parameters from TLV encoding
    const params = try transport_params.TransportParams.decode(allocator, extension_bytes);

    // Validate required parameters per RFC 9000 §18.2
    // This checks that initial_source_connection_id is present, and
    // retry_source_connection_id/stateless_reset_token if applicable
    const is_server = (conn.role == .Server);
    try params.validate(is_server, is_retry_sent);

    // Check parameter values are within RFC-specified limits
    // This validates max_udp_payload_size >= 1200, ack_delay_exponent <= 20, etc.
    try params.checkLimits();

    // Apply validated parameters to connection state
    // This updates peer_max_data, peer_max_streams_*, ack_delay_exponent, etc.
    params.apply(conn);

    return params;
}

/// Set up client-side transport parameters for TLS handshake.
/// Extracted from endpoint.zig client connection establishment (Phase 4b.5 Session 7).
///
/// RFC 9000 §7.4: "Each endpoint includes transport parameters as a
/// quic_transport_parameters extension in the TLS handshake."
///
/// RFC 9000 §18.2: "Transport parameters are specified as follows:
/// - initial_max_data (0x04)
/// - initial_max_stream_data_bidi_local (0x05)
/// - initial_max_stream_data_bidi_remote (0x06)
/// - initial_max_streams_bidi (0x08)
/// - initial_max_streams_uni (0x09)"
///
/// This function:
/// 1. Creates TransportParams struct with client-side parameters
/// 2. Populates flow control limits from connection defaults
/// 3. Encodes parameters to TLV format
/// 4. Installs encoded parameters on connection for TLS extension
///
/// Parameters:
/// - conn: Connection to configure transport parameters for
/// - allocator: Memory allocator for encoding
///
/// Returns:
/// - error.OutOfMemory if encoding fails
///
/// Side Effects:
/// - Calls conn.setLocalTransportParameters() with encoded parameters
pub fn setupClientTransportParams(
    conn: *conn_mod.Connection,
    allocator: std.mem.Allocator,
) !void {
    var tpp: transport_params.TransportParams = .{};

    // Encode initial limits from connection local defaults (RFC 9000 §4.1, §4.6)
    tpp.initial_max_data = conn.local_max_data;
    tpp.initial_max_stream_data_bidi_local = conn.local_max_stream_data;
    tpp.initial_max_stream_data_bidi_remote = conn.local_max_stream_data;
    tpp.initial_max_streams_bidi = conn.local_max_streams_bidi;
    tpp.initial_max_streams_uni = 0;

    // Encode to TLV format for quic_transport_parameters extension
    const tp_bytes = try transport_params.TransportParams.encode(&tpp, allocator);
    defer if (tp_bytes.len > 0) allocator.free(tp_bytes);

    // Install on connection - will be sent in ClientHello
    try conn.setLocalTransportParameters(if (tp_bytes.len > 0) tp_bytes else tp_bytes[0..0]);
}

/// Set up server-side transport parameters for TLS handshake.
/// Extracted from endpoint.zig server connection establishment (Phase 4b.5 Session 7).
///
/// RFC 9000 §7.4: "Each endpoint includes transport parameters as a
/// quic_transport_parameters extension in the TLS handshake."
///
/// RFC 9000 §18.2: Server MUST include original_destination_connection_id
/// and initial_source_connection_id in transport parameters.
///
/// This function:
/// 1. Creates TransportParams struct with server-side parameters
/// 2. Sets connection IDs (original DCID, initial SCID)
/// 3. Sets timeouts and payload limits from config
/// 4. Sets flow control limits from connection defaults
/// 5. Encodes parameters to TLV format
/// 6. Installs encoded parameters on connection for TLS extension
///
/// Parameters:
/// - conn: Connection to configure transport parameters for
/// - cfg: QUIC configuration with timeout and payload settings
/// - allocator: Memory allocator for encoding
///
/// Returns:
/// - error.OutOfMemory if encoding fails
///
/// Side Effects:
/// - Calls conn.setLocalTransportParameters() with encoded parameters
pub fn setupServerTransportParams(
    conn: *conn_mod.Connection,
    quic_cfg: *const cfg.QuicConfig,
    allocator: std.mem.Allocator,
) !void {
    var tpp: transport_params.TransportParams = .{};

    // Server MUST send original_destination_connection_id (RFC 9000 §18.2)
    tpp.original_destination_connection_id = conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
    tpp.initial_source_connection_id = conn.our_scid.bytes[0..conn.our_scid.len];

    // Set timeouts and payload limits from config (RFC 9000 §10.1, §14.1)
    tpp.max_idle_timeout = quic_cfg.max_idle_timeout_ms;
    tpp.max_udp_payload_size = quic_cfg.max_udp_payload;

    // Set flow control limits from connection defaults (RFC 9000 §4.1, §4.6)
    tpp.initial_max_data = conn.local_max_data;
    tpp.initial_max_stream_data_bidi_local = conn.local_max_stream_data;
    tpp.initial_max_stream_data_bidi_remote = conn.local_max_stream_data;
    tpp.initial_max_stream_data_uni = conn.local_max_stream_data;
    tpp.initial_max_streams_bidi = conn.local_max_streams_bidi;
    tpp.initial_max_streams_uni = conn.local_max_streams_uni;

    // Encode to TLV format for quic_transport_parameters extension
    const tp_bytes = try transport_params.TransportParams.encode(&tpp, allocator);
    defer if (tp_bytes.len > 0) allocator.free(tp_bytes);

    // Install on connection - will be sent in ServerHello EncryptedExtensions
    try conn.setLocalTransportParameters(if (tp_bytes.len > 0) tp_bytes else tp_bytes[0..0]);

    // Note: If TLS context doesn't exist yet (config.transport_params was null),
    // the connection will use the legacy TLS Engine path which has the transport
    // parameters set via setLocalTransportParameters above.
    // The Context path is preferred when transport params are known upfront.
}

/// Module marker for Phase 4b.5 Session 6.
/// This module extracts TLS handshake integration from endpoint.zig.
pub const extracted = true; // Session 6 complete when tests pass

/// Module version for documentation
pub const version = "Phase 4b.5 Session 6 - TLS Integration Extraction";
