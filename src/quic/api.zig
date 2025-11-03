const std = @import("std");

/// Re-export the PEM helpers used for TLS certificate handling.
pub const pem = @import("pem.zig");

const config = @import("config.zig");
const endpoint = @import("quic_endpoint");
const loop_backend = @import("loop_backend.zig");
const conn_mod = @import("quic_conn");
const crypto_mod = @import("quic_crypto");

const posix = std.posix;

/// High-level QUIC configuration options, re-exported for convenience.
pub const QuicConfig = config.QuicConfig;
/// QUIC endpoint that owns sockets and connection state.
pub const QuicEndpoint = endpoint.Endpoint;
/// Event loop backend abstraction for timer/poll integration.
pub const LoopBackend = loop_backend.LoopBackend;
/// Alias for the QUIC connection type exposed to API consumers.
pub const Connection = conn_mod.Connection;
/// Backwards-compatible name for `Connection`.
pub const QuicConnection = conn_mod.Connection;
/// Stream identifier type emitted by stream helpers.
pub const QuicStreamId = u64;

/// Supported QUIC protocol versions for this implementation.
pub const QuicVersion = enum { v1, v2 };
/// Connection role used when creating endpoints or connections.
pub const Role = enum { Client, Server };

/// Sentinel error when `accept` would block because no connections are queued.
pub const AcceptError = error{WouldBlock};

/// Create and initialize a QUIC endpoint bound to `bind_addr`.
pub fn endpointInit(alloc: *std.mem.Allocator, bind_addr: []const u8, cfg: *const QuicConfig) !*QuicEndpoint {
    const ep = try alloc.create(QuicEndpoint);
    errdefer alloc.destroy(ep);
    ep.* = try QuicEndpoint.init(alloc, bind_addr, cfg);
    return ep;
}

/// Tear down an endpoint created via `endpointInit`.
pub fn endpointDeinit(ep: *QuicEndpoint) void {
    const allocator = ep.allocator;
    ep.deinit();
    allocator.destroy(ep);
}

/// Initiate a client-side connection to `server_addr` and optional `server_name` SNI.
pub fn connect(ep: *QuicEndpoint, server_addr: []const u8, server_name: []const u8) !*Connection {
    const conn = try ep.connectClient(server_addr);
    errdefer {
        conn.deinit();
        ep.allocator.destroy(conn);
    }
    if (server_name.len != 0) {
        try conn.tls.setServerName(server_name);
    }
    try ep.clientSendInitialProbe(conn);
    return conn;
}

/// Pop the next accepted connection or return `error.WouldBlock` when none are queued.
pub fn accept(ep: *QuicEndpoint) AcceptError!*Connection {
    return ep.popAccepted() orelse error.WouldBlock;
}

/// Attempt to fetch an accepted connection without surfacing an error.
pub fn tryAccept(ep: *QuicEndpoint) ?*Connection {
    return ep.popAccepted();
}

/// Schedule a QUIC timer relative to now, returning the timer handle.
pub fn scheduleTimer(ep: *QuicEndpoint, delay_ms: u32) !u64 {
    return ep.scheduleTimer(delay_ms);
}

/// Cancel the timer identified by `id`, returning true if it was removed.
pub fn cancelTimer(ep: *QuicEndpoint, id: u64) bool {
    return ep.cancelTimer(id);
}

/// Drive network IO and timers for up to `timeout_ms` milliseconds.
pub fn poll(ep: *QuicEndpoint, timeout_ms: i32) !void {
    return ep.poll(timeout_ms);
}

/// Poll repeatedly with zero timeout to advance outstanding work.
pub fn flush(ep: *QuicEndpoint, iterations: usize) void {
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        ep.flushTimers();
        ep.poll(0) catch {};
    }
}

/// Return the platform default loop backend for new endpoints.
pub fn defaultLoopBackend() LoopBackend {
    return loop_backend.defaultLoopBackend();
}

/// Derive Initial secrets for a given destination connection ID and version.
pub fn deriveInitialSecretsForConfig(dst_conn_id: []const u8, quic_version: u32, is_server: bool) crypto_mod.InitialSecrets {
    return crypto_mod.deriveInitialSecretsForConfig(dst_conn_id, quic_version, is_server);
}

/// Send an APPLICATION_CLOSE frame with an explanatory string.
pub fn close(conn: *Connection, app_error_code: u64, reason: []const u8) !void {
    return conn.sendConnectionClose(app_error_code, reason);
}

/// Close a connection with an error code but empty reason phrase.
pub fn closeConnection(conn: *Connection, app_error_code: u64) !void {
    return conn.sendConnectionClose(app_error_code, "");
}

/// Check if a peer has acknowledged the handshake via HANDSHAKE_DONE.
pub fn handshakeDoneSeen(conn: *Connection) bool {
    return conn.handshake_done_seen;
}

/// Return true once the TLS handshake has fully completed.
pub fn handshakeComplete(conn: *Connection) bool {
    return conn.tls.handshakeComplete();
}

/// Determine if 1-RTT keys are confirmed per QUIC handshake rules.
pub fn isHandshakeConfirmed(conn: *Connection) bool {
    return conn.hasConfirmedAppTxKeys();
}

/// Indicate whether the connection has entered the draining state.
pub fn isDrained(conn: *Connection) bool {
    return conn.closed;
}

/// Retrieve the negotiated ALPN protocol string, if any.
pub fn getNegotiatedAlpn(conn: *Connection) ?[]const u8 {
    return conn.getNegotiatedAlpn();
}

/// Return a view of the peer's QUIC transport parameters.
pub fn getPeerTransportParams(conn: *Connection) ?[]const u8 {
    return conn.getPeerTransportParams();
}

/// Transmit a QUIC DATAGRAM frame carrying `data`.
pub fn sendDatagram(conn: *Connection, data: []const u8) !usize {
    try conn.sendDatagram(data);
    return data.len;
}

/// Receive a pending DATAGRAM frame into `buf`, returning the payload length.
pub fn recvDatagram(conn: *Connection, buf: []u8) !usize {
    return conn.popDatagram(buf);
}

/// Allocate a new stream, optionally bidirectional.
pub fn openStream(conn: *Connection, bidirectional: bool) !QuicStreamId {
    return conn.openStream(bidirectional);
}

/// Convenience helper for opening a unidirectional stream.
pub fn openUni(conn: *Connection) !QuicStreamId {
    return conn.openStream(false);
}

/// Accept the next remotely initiated stream.
pub fn acceptStream(conn: *Connection) !QuicStreamId {
    return conn.acceptStream();
}

/// Report whether any streams are waiting to be accepted.
pub fn hasIncomingStreams(conn: *const Connection) bool {
    return conn.hasIncomingStreams();
}

/// Return the lowest numbered stream still open on the connection.
pub fn getFirstStream(conn: *Connection) ?QuicStreamId {
    return conn.getFirstStream();
}

/// Write application data to a stream, returning bytes accepted.
pub fn writeStream(conn: *Connection, stream_id: QuicStreamId, data: []const u8) !usize {
    return conn.writeStream(stream_id, data);
}

/// Read stream data into `buffer`, yielding the number of bytes copied.
pub fn readStream(conn: *Connection, stream_id: QuicStreamId, buffer: []u8) !usize {
    return conn.readStream(stream_id, buffer);
}

/// Test if the identified stream has received FIN in both directions.
pub fn isStreamFinished(conn: *Connection, stream_id: QuicStreamId) bool {
    return conn.isStreamFinished(stream_id);
}

/// Force close the stream with an application error code.
pub fn closeStream(conn: *Connection, stream_id: QuicStreamId, app_error_code: u64) !void {
    return conn.closeStream(stream_id, app_error_code);
}

/// Remove a connection from all endpoint bookkeeping and free it.
pub fn destroy(ep: *QuicEndpoint, conn: *Connection) void {
    var i: usize = 0;
    while (i < ep.accepted.items.len) : (i += 1) {
        if (ep.accepted.items[i] == conn) {
            _ = ep.accepted.orderedRemove(i);
            break;
        }
    }
    i = 0;
    while (i < ep.retired.items.len) {
        if (ep.retired.items[i] == conn) {
            _ = ep.retired.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    while (true) {
        var it = ep.conns.iterator();
        var removed = false;
        while (it.next()) |entry| {
            if (entry.value_ptr.* == conn) {
                const key = entry.key_ptr.*;
                _ = ep.conns.remove(key);
                removed = true;
                break;
            }
        }
        if (!removed) break;
    }
    i = 0;
    while (i < ep.timers.items.len) {
        const timer = ep.timers.items[i];
        if (timer.conn) |tc| {
            if (tc == conn) {
                if (timer.paced) if (timer.payload) |p| ep.allocator.free(p);
                _ = ep.timers.orderedRemove(i);
                continue;
            }
        }
        i += 1;
    }
    conn.deinit();
    ep.allocator.destroy(conn);
}

/// Inspect the bound UDP socket and return its port number.
pub fn getPort(ep: *QuicEndpoint) u16 {
    var addr = conn_mod.SockAddr{};
    addr.len = @intCast(@sizeOf(posix.sockaddr.storage));
    const sa_ptr: *posix.sockaddr = @ptrCast(@alignCast(&addr.storage));
    posix.getsockname(ep.sock_fd, sa_ptr, &addr.len) catch return 0;
    return switch (addr.storage.family) {
        posix.AF.INET => blk: {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&addr.storage));
            break :blk std.mem.byteSwap(u16, sin.port);
        },
        posix.AF.INET6 => blk: {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&addr.storage));
            break :blk std.mem.byteSwap(u16, sin6.port);
        },
        else => 0,
    };
}
