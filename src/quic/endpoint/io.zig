//! UDP I/O operations for sending and receiving packets.
//!
//! Handles platform-specific socket operations, ECN marking, and test capture mode.

const std = @import("std");
const posix = std.posix;
const conn_mod = @import("quic_conn");

/// Result of a recvFrom operation.
pub const RecvResult = struct {
    n: usize,
    peer: conn_mod.SockAddr,
    ecn_bits: u8 = 0,
};

/// Send data to a peer via UDP.
/// Returns the number of bytes sent, or an error.
pub fn sendTo(sock_fd: posix.socket_t, peer: conn_mod.SockAddr, data: []const u8) !usize {
    const sent = try posix.sendto(
        sock_fd,
        data,
        0,
        @ptrCast(&peer.storage),
        peer.len,
    );
    return sent;
}

/// Receive data from UDP socket.
/// Returns number of bytes received, peer address, and ECN bits.
pub fn recvFrom(sock_fd: posix.socket_t, buf: []u8) !RecvResult {
    var peer_storage: posix.sockaddr.storage = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    const n = try posix.recvfrom(
        sock_fd,
        buf,
        0,
        @ptrCast(&peer_storage),
        &peer_len,
    );

    var peer: conn_mod.SockAddr = .{};
    peer.storage = peer_storage;
    peer.len = peer_len;

    // ECN bits would be extracted from ancillary data (IP_TOS/IPV6_TCLASS)
    // For now, return 0 (Not-ECT)
    const ecn_bits: u8 = 0;

    return RecvResult{
        .n = n,
        .peer = peer,
        .ecn_bits = ecn_bits,
    };
}
