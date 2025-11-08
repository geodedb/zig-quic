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

// Note: These functions currently require access to the full Endpoint structure.
// For Phase 4a, tests and external code should call these via the Endpoint instance.
// Full extraction to standalone functions is Phase 4b (future work).

/// Client connection establishment functions are currently implemented in endpoint.zig
/// due to deep dependencies on Endpoint state (allocator, config, connection table, etc.).
///
/// Usage from tests:
///   const client = @import("endpoint/client.zig");
///   // Then call via endpoint instance:
///   const conn = try endpoint.connectClient("localhost:4433");
///   try endpoint.clientSendInitialProbe(conn);
///
/// The following functions are available via Endpoint methods:
///
/// **connectTo**(hostport: []const u8) -> Connection
///   Creates a basic Connection struct for the specified host:port.
///   Returns a Connection value (not pointer) configured for client role.
///   RFC 9000 §7: Client initiates connection to server.
///
/// **connectClient**(hostport: []const u8) -> *Connection
///   Creates a fully initialized client Connection with:
///   - Random 8-byte DCID generation (RFC 9000 §5.1.1)
///   - Random 8-byte SCID generation
///   - Configuration application (congestion control, pacing, ALPN)
///   - AEAD usage limit setup
///   - Connection table registration
///   - Version selection (v1 or v2 based on config)
///   Returns pointer to allocated Connection in endpoint's connection table.
///
/// **clientSendInitialProbe**(conn: *Connection) -> void
///   Sends Initial packet with ClientHello:
///   - Derives Initial secrets from original DCID (RFC 9001 §5.2)
///   - Builds CRYPTO frame with ClientHello and transport parameters
///   - Pads to 1200 bytes minimum (RFC 9000 §14.1)
///   - Protects packet with Initial keys
///   - Sends via UDP and arms Initial PTO timer
///
/// Example usage:
/// ```zig
/// var endpoint = Endpoint.init(allocator, config);
/// const conn = try endpoint.connectClient("server.example.com:443");
/// try endpoint.clientSendInitialProbe(conn);
/// // Connection is now in Handshake state, waiting for ServerHello
/// ```

/// Module marker for Phase 4a modular structure.
/// Full implementation extraction is Phase 4b (future work).
pub const extracted = false; // Set to true when implementations are fully extracted

/// For documentation and test organization, these function signatures represent
/// the interface that will eventually be extracted. Currently implemented in endpoint.zig.
pub const Interface = struct {
    /// Create basic connection struct (not fully initialized)
    pub const ConnectToSignature = fn (hostport: []const u8) anyerror!@import("quic_conn").Connection;

    /// Create and fully initialize client connection
    pub const ConnectClientSignature = fn (hostport: []const u8) anyerror!*@import("quic_conn").Connection;

    /// Send Initial packet with ClientHello
    pub const ClientSendInitialProbeSignature = fn (conn: *@import("quic_conn").Connection) anyerror!void;
};

/// Helper: Generate random 8-byte Connection ID.
/// RFC 9000 §5.1.1: "A client MUST choose a value for the Destination Connection ID field."
pub fn generateRandomCid(bytes: []u8) void {
    std.crypto.random.bytes(bytes);
}

/// Placeholder ClientHandshake struct for test compatibility.
/// Full implementation will be extracted in Phase 4b.
pub const ClientHandshake = struct {
    pub fn init() ClientHandshake {
        return .{};
    }
};
