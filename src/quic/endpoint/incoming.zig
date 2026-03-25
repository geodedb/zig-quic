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
const incoming_shared = @import("incoming/shared.zig");

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

pub const SendFn = incoming_shared.SendFn;
pub const ScheduleTimerFn = incoming_shared.ScheduleTimerFn;
pub const SendInitialProbeFn = incoming_shared.SendInitialProbeFn;
pub const SetupSenderFn = incoming_shared.SetupSenderFn;
pub const RxContext = incoming_shared.RxContext;

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

    // Send new Initial packet with chosen version -- failure is non-fatal;
    // client will retransmit on PTO expiry.
    ctx.send_initial_probe_fn(c) catch |err| {
        logger.debugPrint("[INCOMING] Initial probe after VN failed: {s}\n", .{@errorName(err)});
    };
}

/// DCID length enumeration result

// Extracted module slices for staged modularization (#75)
const incoming_a = @import("incoming/module_a.zig");
const incoming_b = @import("incoming/module_b.zig");
const incoming_b2 = @import("incoming/module_b2.zig");
const incoming_c = @import("incoming/module_c.zig");

pub const DcidLengthResult = incoming_a.DcidLengthResult;
pub const enumerateDcidLength = incoming_a.enumerateDcidLength;
pub const InitialHeader = incoming_a.InitialHeader;
pub const parseInitialHeader = incoming_a.parseInitialHeader;
pub const InitialKeys = incoming_a.InitialKeys;
pub const deriveInitialKeys = incoming_a.deriveInitialKeys;
pub const DecryptedInitial = incoming_a.DecryptedInitial;
pub const decryptInitialPacket = incoming_a.decryptInitialPacket;

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
            logger.debugPrint("processInitial: Connection limit reached ({}/{}), dropping Initial packet\n", .{ ctx.conns.count(), ctx.max_connections });
            return; // Drop packet - do not create connection
        }

        // Create server connection using Session 5 API
        const server_mod = @import("server.zig");

        // Debug: Log client SCID from header
        logger.debugPrint("processInitial: Parsed Initial header - client_scid.len={}\n", .{header.scid.len});
        if (header.scid.len >= 4) {
            logger.debugPrint("  client_scid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ header.scid[0], header.scid[1], header.scid[2], header.scid[3] });
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
            .exempt_localhost = ctx.cfg.exempt_localhost,
        };

        // Create and initialize server connection
        const c_new = server_mod.createServerConnection(
            ctx.allocator,
            invalidSocket(), // sock_fd will be set by endpoint
            peer,
            config,
        ) catch return;

        // Wire the shared anti-replay cache to the new server connection
        // so that accept0RTT() can detect replayed 0-RTT data (RFC 8446 S8).
        c_new.anti_replay_cache = ctx.anti_replay_cache;

        // Debug: Check peer_initial_dcid after server connection creation
        logger.debugPrint("processInitial: Server conn created, peer_initial_dcid len={}\n", .{c_new.peer_initial_dcid.len});
        if (c_new.peer_initial_dcid.len > 0) {
            logger.debugPrint("  peer_initial_dcid[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{ c_new.peer_initial_dcid.bytes[0], c_new.peer_initial_dcid.bytes[1], c_new.peer_initial_dcid.bytes[2], c_new.peer_initial_dcid.bytes[3] });
        }

        // Set up transport parameters for server (RFC 9000 §18.2)
        // IMPORTANT: Must be done AFTER connection creation but BEFORE TLS processing
        handshake_integration.setupServerTransportParams(c_new, ctx.cfg, ctx.allocator.*) catch |err| {
            logger.debugPrint("[INCOMING] setupServerTransportParams failed: {s} -- dropping connection\n", .{@errorName(err)});
            c_new.deinit();
            ctx.allocator.destroy(c_new);
            return;
        };

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
        _ = ctx.conns.put(our_key, c_new) catch {
            // Remove the first registration so the connection is not left half-registered.
            _ = ctx.conns.remove(key);
            c_new.deinit();
            ctx.allocator.destroy(c_new);
            return;
        };

        logger.debugPrint("processInitial: Registered new server conn={*}\n", .{c_new});
        logger.debugPrint("  By client DCID hash={X:0>16}\n", .{hashBytes(header.dcid)});
        logger.debugPrint("  By server SCID hash={X:0>16}\n", .{hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len])});

        // Add newly created server connection to accepted list for accept() API
        _ = ctx.accepted.append(ctx.allocator.*, c_new) catch {
            // Remove both map registrations so the connection is not orphaned.
            _ = ctx.conns.remove(key);
            _ = ctx.conns.remove(our_key);
            c_new.deinit();
            ctx.allocator.destroy(c_new);
            return;
        };

        break :blk c_new;
    };

    // For client connections, cache the server Initial SCID for subsequent short-header
    // routing. Keep peer_initial_dcid unchanged: it tracks the client's current Initial
    // destination CID and is used for Initial key derivation (RFC 9001 §5.2).
    if (conn.role == .Client) {
        conn.peer_initial_scid.len = @intCast(@min(header.scid.len, conn.peer_initial_scid.bytes.len));
        if (conn.peer_initial_scid.len > 0) {
            @memcpy(conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len], header.scid[0..conn.peer_initial_scid.len]);
        }
        conn.expected_rx_dcid_len = null;
    }

    // RFC 9001 §4.9.1: Once Initial keys are discarded, endpoints MUST drop
    // all Initial packets. Never re-derive Initial keys after key discard.
    if (conn.initial_keys_dropped) {
        logger.debugPrint("processInitial: Initial keys already dropped for conn={*}; discarding packet\n", .{conn});
        return;
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
    // Gate behind exempt_localhost config flag (#124) so operators can enforce strict
    // RFC 9000 §8.1 amplification limits on loopback for conformance testing.
    if (conn.role == .Server and !conn.address_validated and is_localhost and !ctx.cfg.enable_retry and ctx.cfg.exempt_localhost) {
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

        // Mark Retry usage and refresh server transport parameters so the
        // eventual handshake includes retry_source_connection_id (RFC 9000 §7.4.1).
        conn.retry_sent = true;
        handshake_integration.setupServerTransportParams(conn, ctx.cfg, ctx.allocator.*) catch |err| {
            logger.debugPrint("[INCOMING] setupServerTransportParams (retry) failed: {s}\n", .{@errorName(err)});
            // Non-fatal on retry path: connection continues with previous transport params.
        };
        if (conn.tls_context) |tls_ctx| {
            if (conn.local_transport_params_raw) |tp_bytes| {
                tls_ctx.setTransportParameters(tp_bytes) catch |tp_err| {
                    logger.debugPrint("[INCOMING] setTransportParameters failed: {s}\n", .{@errorName(tp_err)});
                };
            }
        }

        // Send Retry packet -- fire-and-forget: UDP send failures are
        // non-fatal; the client will retransmit its Initial.
        _ = ctx.send_fn(peer, retry_bytes) catch |err| {
            logger.debugPrint("[INCOMING] Retry send failed: {s}\n", .{@errorName(err)});
        };

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

        logger.debugPrint("[Server RX] Initial keys derived (dcid len={})\n", .{header.dcid.len});
    }
    if (conn.initial_tx_keys == null) {
        conn.initial_tx_keys = packet.InitialKeys{
            .key = keys_result.tx_keys.key,
            .iv = keys_result.tx_keys.iv,
            .hp = keys_result.tx_keys.hp,
        };
    }

    // Decrypt Initial packet
    // RFC 9000 §12.3: expected_pn is largest received in this packet number
    // space plus one (or zero when no packet was received yet).
    const largest_pn = if (conn.pn_initial.have_any) conn.pn_initial.max + 1 else 0;
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
        logger.debugPrint("[processInitial] Decoding frame at offset {}/{}\n", .{ offset, decrypted.payload.len });
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

            // RFC 9000 §14.1: client Initial datagrams MUST be at least 1200 bytes.
            // RFC 9000 §8.1.2: client must echo Retry token on subsequent Initial packets.
            const token = if (conn.role == .Client) conn.initial_token.items else &[_]u8{};
            var ack_payload = std.ArrayList(u8){};
            defer ack_payload.deinit(ctx.allocator.*);
            ack_payload.appendSlice(ctx.allocator.*, frames_data) catch |err| {
                logger.debugPrint("[INCOMING] ACK payload append failed: {s}\n", .{@errorName(err)});
                return;
            };

            var pkt = packet.encodeInitialProtected(
                ctx.allocator.*,
                version,
                initial_dcid,
                conn.our_scid.bytes[0..conn.our_scid.len],
                token,
                @as(u32, @truncate(conn.pn_initial_tx)),
                2,
                ack_payload.items,
                tx_keys,
            ) catch null;

            if (pkt) |bytes_out_initial| {
                var bytes_out = bytes_out_initial;
                if (conn.role == .Client and bytes_out.len < 1200) {
                    const pad_needed = 1200 - bytes_out.len;
                    ctx.allocator.free(bytes_out);
                    ack_payload.appendNTimes(ctx.allocator.*, @intFromEnum(frame.FrameType.PADDING), pad_needed) catch |err| {
                        logger.debugPrint("[INCOMING] PADDING append failed: {s}\n", .{@errorName(err)});
                        return;
                    };
                    pkt = packet.encodeInitialProtected(
                        ctx.allocator.*,
                        version,
                        initial_dcid,
                        conn.our_scid.bytes[0..conn.our_scid.len],
                        token,
                        @as(u32, @truncate(conn.pn_initial_tx)),
                        2,
                        ack_payload.items,
                        tx_keys,
                    ) catch null;
                    if (pkt) |retry_out| {
                        bytes_out = retry_out;
                    } else {
                        return;
                    }
                }
                defer ctx.allocator.free(bytes_out);
                // Fire-and-forget: UDP send may fail transiently; loss recovery retransmits.
                _ = ctx.send_fn(peer, bytes_out) catch |err| {
                    logger.debugPrint("[INCOMING] ACK send failed: {s}\n", .{@errorName(err)});
                };
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
pub const processHandshake = incoming_b.processHandshake;
const parseHandshakeHeader = incoming_b.parseHandshakeHeader;
const decryptHandshakePacket = incoming_b.decryptHandshakePacket;
pub const ShortDecryptResult = incoming_b.ShortDecryptResult;
pub const decryptShortHeaderWithKeyRotation = incoming_b.decryptShortHeaderWithKeyRotation;
const decryptShortHeaderWithKeyRotationInternal = incoming_b.decryptShortHeaderWithKeyRotationInternal;
const tryForceKeyUpdateAndDecrypt = incoming_b.tryForceKeyUpdateAndDecrypt;
pub const promoteToNextKeys = incoming_b.promoteToNextKeys;
pub const decrementPrevKeyAllowance = incoming_b.decrementPrevKeyAllowance;
pub const FrameProcessResult = incoming_b2.FrameProcessResult;
pub const processFrames = incoming_b2.processFrames;
pub const AckContext = incoming_b2.AckContext;
pub const generateAndSendAck = incoming_b2.generateAndSendAck;

pub const processShortHeader = incoming_c.processShortHeader;
pub const session_3_complete = incoming_c.session_3_complete;
pub const session_3_version = incoming_c.session_3_version;
pub const InitialHeaderInfo = incoming_c.InitialHeaderInfo;
pub const parseCompleteInitialHeader = incoming_c.parseCompleteInitialHeader;
pub const session_5_initial_header_parsing = incoming_c.session_5_initial_header_parsing;
pub const processInitialSkeleton = incoming_c.processInitialSkeleton;
pub const session_5_process_initial_skeleton = incoming_c.session_5_process_initial_skeleton;
