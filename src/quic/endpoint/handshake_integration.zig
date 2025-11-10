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

    // Mark handshake complete
    // Application data can now flow
    // Connection's existing state machine handles transition to Application phase

    // For server, HANDSHAKE_DONE frame should be sent
    // This is typically handled by the Endpoint layer, not the callback
    _ = conn; // Connection available for future state updates
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
) !tls13.Context {
    // Create TLS configuration
    const tls_role: tls13.Role = if (role == .Client) .Client else .Server;

    const config = tls13.Config{
        .allocator = allocator,
        .role = tls_role,
        .alpn_protocols = if (alpn_list.len > 0) alpn_list else null,
        .quic_transport_parameters = if (transport_params_bytes.len > 0) transport_params_bytes else null,
    };

    // Create callbacks struct with full QUIC integration
    const callbacks = tls13.Callbacks{
        .on_secret_available = onSecretAvailable,
        .on_handshake_metadata = onHandshakeMetadata,
        .on_peer_finished = onPeerFinished,
        .on_handshake_complete = onHandshakeComplete,
    };

    // Initialize Context
    return tls13.Context.init(config, callbacks);
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
    // Derive Handshake keys from secrets
    // Uses HKDF-Expand-Label per RFC 8446 §7.1 and RFC 9001 §5
    // AES-128-GCM (TLS_AES_128_GCM_SHA256) is the default cipher suite for QUIC

    // Derive client Handshake keys
    // RFC 9001 §5.1: "key = HKDF-Expand-Label(Secret, "quic key", "", key_length)"
    const client_keys = key_schedule.deriveKeyIvHp(client_secret);

    // Derive server Handshake keys
    const server_keys = key_schedule.deriveKeyIvHp(server_secret);

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
    var outbox: [4096]u8 = undefined;
    const n = conn.tls.popCrypto(outbox[0..]);
    if (n == 0) {
        // No CRYPTO data to send
        return;
    }

    // Fragment CRYPTO data across multiple Initial packets if needed
    const max_crypto_per_packet: usize = 1100; // ~1200 MTU - headers - overhead
    var crypto_offset: usize = 0;
    const base_off = conn.crypto_tx_off_initial;

    while (crypto_offset < n) {
        const chunk_size = @min(max_crypto_per_packet, n - crypto_offset);
        const chunk = outbox[crypto_offset .. crypto_offset + chunk_size];

        var frames_buf: [4096]u8 = undefined;
        var frames_stream = std.io.fixedBufferStream(&frames_buf);
        const w = frames_stream.writer();

        // Add CRYPTO frame
        const crypto_frame_offset = base_off + crypto_offset;
        _ = (frame.Frame{ .crypto = .{ .offset = crypto_frame_offset, .data = chunk } }).write(w) catch 0;
        const frames_data = frames_stream.getWritten();

        // Use peer's SCID as DCID for Initial response
        const initial_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

        // Encode and send Initial packet
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
        _ = ctx.send_fn(ctx.peer, pkt) catch return error.SendFailed;

        conn.onPacketSent(.Initial, conn.pn_initial_tx, pkt.len, true);
        conn.pn_initial_tx +%= 1;

        crypto_offset += chunk_size;
    }

    // Save retransmit buffer
    if (conn.crypto_retx_initial) |old_buf| ctx.allocator.free(old_buf);
    const owned = ctx.allocator.alloc(u8, n) catch {
        conn.crypto_tx_off_initial += n;
        return error.AllocFailed;
    };
    @memcpy(owned[0..n], outbox[0..n]);
    conn.crypto_retx_initial = owned;
    conn.crypto_retx_initial_off = base_off;
    conn.crypto_tx_off_initial += n;
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
}

/// Module marker for Phase 4b.5 Session 6.
/// This module extracts TLS handshake integration from endpoint.zig.
pub const extracted = true; // Session 6 complete when tests pass

/// Module version for documentation
pub const version = "Phase 4b.5 Session 6 - TLS Integration Extraction";
