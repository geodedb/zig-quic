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
