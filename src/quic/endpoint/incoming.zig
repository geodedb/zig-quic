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

// Note: Incoming packet processing functions require deep access to Endpoint state.
// For Phase 4a, these functions remain in endpoint.zig.
// Full extraction to standalone functions is Phase 4b (future work).

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
    pub const ProcessIncomingDatagramSignature = fn (peer: @import("../conn.zig").SockAddr, bytes: []const u8, ecn_bits: ?u8) void;

    /// Drain all readable packets from socket
    pub const DrainReadableSignature = fn () void;

    /// Process ICMP error queue (Linux only)
    pub const DrainErrorQueueSignature = fn () void;

    /// Handle ICMP Packet Too Big
    pub const HandleIcmpPtbSignature = fn (peer: @import("../conn.zig").SockAddr, quoted_payload: []const u8, reported_mtu: u16) void;
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
