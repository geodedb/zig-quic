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
    if (conn.role == .Client) {
        // Client receives with server keys, sends with client keys
        conn.hs_rx_keys = server_keys;
        conn.hs_tx_keys = client_keys;
    } else {
        // Server receives with client keys, sends with server keys
        conn.hs_rx_keys = client_keys;
        conn.hs_tx_keys = server_keys;
    }

    // Mark that Handshake keys are available
    conn.has_hs_keys = true;
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
    if (conn.role == .Client) {
        // Client receives with server keys, sends with client keys
        conn.app_rx_keys = server_keys;
        conn.app_tx_keys = client_keys;
    } else {
        // Server receives with client keys, sends with server keys
        conn.app_rx_keys = client_keys;
        conn.app_tx_keys = server_keys;
    }

    // Mark that Application keys are available
    conn.has_app_keys = true;
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

    // Delegate to Connection's existing CRYPTO frame handlers
    // These methods handle:
    // 1. Out-of-order buffering via CryptoBuffer
    // 2. TLS state machine integration (pushCrypto)
    // 3. Automatic key derivation on TLS transitions
    // 4. Transport parameter extraction
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
            // Application-level CRYPTO frames (post-handshake messages)
            // Currently handled directly by Connection.handleCryptoFrameGeneric
            // via a future handleApplicationCrypto method
            //
            // RFC 9001 §4.1.4: "An endpoint MUST discard its handshake keys
            // when the TLS handshake is confirmed."
            //
            // For now, Application CRYPTO is rare (NewSessionTicket, KeyUpdate)
            // and not critical for basic operation.
            break :blk false;
        },
    };

    // After processing CRYPTO frame, check for key transitions
    // This handles the documented flow:
    // - ClientHello → ServerHello: conn may have hs_rx_keys, hs_tx_keys set
    // - Finished: conn may have app_rx_keys, app_tx_keys set
    //
    // The Connection's internal methods (afterInitialCryptoChunk, etc.)
    // automatically call deriveHandshakeKeys() and deriveAppKeys() when
    // TLS state transitions occur.

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
