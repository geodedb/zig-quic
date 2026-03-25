// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Public QUIC convenience API bridging applications with the transport core.
//!
//! The helpers in this module wrap primitives whose normative behaviour comes
//! from RFC 9000 (transport), RFC 9001 (handshake/TLS), and RFC 9221 (DATAGRAM
//! extension). Inline comments reference the sections that motivated the
//! implementation so consumers can trace behaviour back to the specification.
const std = @import("std");
const logger = @import("quic_logger");

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
/// Metadata about a poll iteration (number of datagrams processed).
pub const PollStats = endpoint.PollStats;
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
    ep.* = try QuicEndpoint.init(alloc.*, bind_addr, cfg);
    return ep;
}

/// Tear down an endpoint created via `endpointInit`.
pub fn endpointDeinit(ep: *QuicEndpoint) void {
    const allocator = ep.allocator;
    ep.deinit();
    allocator.destroy(ep);
}

/// Initiate a client-side connection to `server_addr` and optional `server_name` SNI.
///
/// RFC 9000 §7.2 requires clients to send an Initial probe sized to the path MTU.
/// We satisfy this by immediately calling `clientSendInitialProbe`, which pads to
/// 1200 bytes per §14.1 before any handshake data is exchanged.
pub fn connect(ep: *QuicEndpoint, server_addr: []const u8, server_name: []const u8) !*Connection {
    const conn = try ep.connectClient(server_addr);
    errdefer {
        conn.deinit();
        ep.allocator.destroy(conn);
    }
    if (server_name.len != 0) {
        try conn.setServerName(server_name);
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

/// Drive IO like `poll` but report how many datagrams were drained.
pub fn pollStats(ep: *QuicEndpoint, timeout_ms: i32) !PollStats {
    return ep.pollWithStats(timeout_ms);
}

/// Poll repeatedly with zero timeout to advance outstanding work.
pub fn flush(ep: *QuicEndpoint, iterations: usize) void {
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        ep.flushTimers();
        ep.poll(0) catch |err| {
            logger.warn("flush poll iteration failed: {s}", .{@errorName(err)});
        };
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
///
/// RFC 9000 §19.19 defines CONNECTION_CLOSE/Application. The connection helper
/// exposes that behaviour verbatim so API users can surface application errors.
pub fn close(conn: *Connection, app_error_code: u64, reason: []const u8) !void {
    return conn.sendConnectionClose(app_error_code, reason);
}

/// Deprecated: Use `close(conn, error_code, "")` instead.
///
/// Close a connection with an error code and empty reason phrase.
pub fn closeConnection(conn: *Connection, app_error_code: u64) !void {
    return conn.sendConnectionClose(app_error_code, "");
}

/// Check if a peer has acknowledged the handshake via HANDSHAKE_DONE.
///
/// RFC 9000 §7.4 outlines the HANDSHAKE_DONE signal a server sends once TLS
/// authentication is complete. Applications can use this flag to delay 1-RTT
/// data until the peer confirms the handshake state.
pub fn handshakeDoneSeen(conn: *Connection) bool {
    return conn.handshake_done_seen;
}

/// Return true once the TLS handshake has fully completed.
///
/// RFC 9000 §4.1.1: The handshake is complete when the endpoint has received
/// and verified the peer's Finished message. This is distinct from handshake
/// confirmation (§4.1.2) which additionally requires key confirmation.
pub fn handshakeComplete(conn: *Connection) bool {
    return conn.peer_finished_verified;
}

/// Determine if 1-RTT keys are confirmed per QUIC handshake rules.
///
/// RFC 9000 §4.1 describes key confirmation: endpoints must not send 1-RTT data
/// until they installed confirmed keys. This helper relays that state to callers.
pub fn isHandshakeConfirmed(conn: *Connection) bool {
    return conn.hasConfirmedAppTxKeys();
}

/// Indicate whether the connection has entered the draining state.
pub fn isDrained(conn: *Connection) bool {
    return conn.closed;
}

/// Retrieve the negotiated ALPN protocol string, if any.
///
/// RFC 9001 §4.6 negotiates application protocols via TLS ALPN. QUIC exposes
/// the negotiated value to applications for post-handshake dispatch decisions.
pub fn getNegotiatedAlpn(conn: *Connection) ?[]const u8 {
    return conn.getNegotiatedAlpn();
}

/// Return a view of the peer's QUIC transport parameters.
///
/// RFC 9000 §7.4.1 transports parameters in the handshake. We provide access to
/// the encoded blob so advanced consumers can inspect extension values directly.
pub fn getPeerTransportParams(conn: *Connection) ?[]const u8 {
    return conn.getPeerTransportParams();
}

/// Transmit a QUIC DATAGRAM frame carrying `data`.
///
/// RFC 9221 §4 defines the DATAGRAM frame semantics. We propagate zig errors on
/// size violations so applications honour the `max_datagram_frame_size` transport
/// parameter negotiated in §4.1 of that document.
pub fn sendDatagram(conn: *Connection, data: []const u8) !usize {
    try conn.sendDatagram(data);
    return data.len;
}

/// Receive a pending DATAGRAM frame into `buf`, returning the payload length.
///
/// Per RFC 9221 §5, DATAGRAM reception is unreliable and unordered. The helper
/// exposes this by returning the raw payload length without imposing ordering.
pub fn recvDatagram(conn: *Connection, buf: []u8) !usize {
    return conn.popDatagram(buf);
}

/// Check whether any unreceived DATAGRAM frames are queued.
///
/// QUIC-H3-002: Allows HTTP/3 adapters to poll for datagram availability
/// without blocking.
pub fn hasDatagram(conn: *const Connection) bool {
    return conn.dgram_inbox.items.len > 0;
}

/// Per-connection readiness flags for event-driven dispatch.
///
/// QUIC-H3-003: Replaces busy-poll loops in HTTP/3 client/server with a
/// single readiness query returning all actionable state at once.
pub const ReadinessFlags = struct {
    /// True when at least one remotely-initiated stream is waiting to be accepted.
    has_incoming_streams: bool = false,
    /// True when at least one unreceived DATAGRAM is queued.
    has_datagram: bool = false,
    /// True once the TLS handshake is fully confirmed and 1-RTT keys are ready.
    handshake_complete: bool = false,
    /// True when the connection has entered the draining/closed state.
    connection_closed: bool = false,
    /// True when at least one stream became writable after flow-control unblock.
    has_writable_streams: bool = false,
};

/// Query per-connection readiness flags without blocking.
///
/// QUIC-H3-003: Returns a snapshot of connection state that HTTP/3 adapters
/// can use to drive event loops without busy-polling. Callers should still
/// call `poll` to advance IO; this helper only inspects cached state.
pub fn pollReady(conn: *const Connection) ReadinessFlags {
    return .{
        .has_incoming_streams = conn.hasIncomingStreams(),
        .has_datagram = conn.dgram_inbox.items.len > 0,
        .handshake_complete = conn.hasConfirmedAppTxKeys(),
        .connection_closed = conn.closed,
        .has_writable_streams = conn.writable_streams.items.len > 0,
    };
}

/// Check whether any streams became writable after flow-control unblock.
///
/// QUIC-H3-004: MAX_STREAM_DATA / MAX_DATA receipt may unblock previously
/// stalled streams. This helper lets callers detect that without scanning
/// the full stream map.
pub fn hasWritableStreams(conn: *const Connection) bool {
    return conn.writable_streams.items.len > 0;
}

/// Pop the next stream that became writable after flow-control unblock.
///
/// QUIC-H3-004: Returns `null` when no streams are pending. Each stream ID
/// appears at most once per unblock event, but callers should re-check
/// actual flow-control headroom before writing.
/// Uses swapRemove for O(1) dequeue — writable stream notification order is not guaranteed.
pub fn popWritableStream(conn: *Connection) ?QuicStreamId {
    if (conn.writable_streams.items.len == 0) return null;
    return conn.writable_streams.swapRemove(0);
}

/// Allocate a new stream, optionally bidirectional.
///
/// RFC 9000 §2.1 permits endpoints to create bidirectional and unidirectional
/// streams. The boolean mirrors the transport parameter `initial_max_streams_*`.
pub fn openStream(conn: *Connection, bidirectional: bool) !QuicStreamId {
    return conn.openStream(bidirectional);
}

/// Convenience helper for opening a unidirectional stream.
pub fn openUni(conn: *Connection) !QuicStreamId {
    return conn.openStream(false);
}

/// Accept the next remotely initiated stream.
///
/// Stream acceptance honours the MAX_STREAMS flow control described in RFC 9000
/// §4.7; if the peer exhausts credit the underlying connection will block.
pub fn acceptStream(conn: *Connection) !QuicStreamId {
    return conn.acceptStream();
}

/// Report whether any streams are waiting to be accepted.
///
/// This mirrors the MAX_STREAMS semantics in RFC 9000 §4.6: if the peer opened
/// streams beyond credit, this returns false until more arrive.
pub fn hasIncomingStreams(conn: *const Connection) bool {
    return conn.hasIncomingStreams();
}

/// Return the lowest numbered stream still open on the connection.
pub fn getFirstStream(conn: *Connection) ?QuicStreamId {
    return conn.getFirstStream();
}

/// Write application data to a stream, returning bytes accepted.
///
/// RFC 9000 §4.1/§4.4 specify per-stream flow control. Short writes indicate the
/// connection cannot exceed the peer's advertised credit.
pub fn writeStream(conn: *Connection, stream_id: QuicStreamId, data: []const u8, fin: bool) !usize {
    return conn.writeStream(stream_id, data, fin);
}

/// Read stream data into `buffer`, yielding the number of bytes copied.
///
/// Data arrives in-order within a stream per RFC 9000 §2.2. Partial reads follow
/// from the fragmentation rules and receiver flow control in §4.1.
pub fn readStream(conn: *Connection, stream_id: QuicStreamId, buffer: []u8) !usize {
    return conn.readStream(stream_id, buffer);
}

/// Test if the identified stream has received FIN from the peer (RX side only).
///
/// RFC 9000 §3.1 defines half-close semantics using FIN bits. This checks
/// whether the peer's FIN has been received, not whether we have sent ours.
pub fn isStreamFinished(conn: *Connection, stream_id: QuicStreamId) bool {
    return conn.isStreamFinished(stream_id);
}

/// Gracefully close a stream by sending a STREAM frame with FIN.
///
/// RFC 9000 §3.3: FIN signals the end of stream data. The peer can still read
/// any data sent before FIN. For abrupt stream termination, use `resetStream`.
pub fn closeStream(conn: *Connection, stream_id: QuicStreamId, app_error_code: u64) !void {
    return conn.closeStream(stream_id, app_error_code);
}

/// Abort a stream by sending RESET_STREAM with an application error code.
///
/// RFC 9000 §19.4: RESET_STREAM terminates sending on a stream and signals the
/// peer that any data beyond final_size will never arrive. Unlike `closeStream`
/// (graceful FIN), this immediately marks the stream as aborted.
///
/// QUIC-H3-001: Public API for HTTP/3 adapters to reset streams on error.
pub fn resetStream(conn: *Connection, stream_id: QuicStreamId, app_error_code: u64) !void {
    return conn.resetStream(stream_id, app_error_code);
}

/// Remove a connection from all endpoint bookkeeping and free it.
pub fn destroy(ep: *QuicEndpoint, conn: *Connection) void {
    var i: usize = 0;
    while (i < ep.accepted.items.len) : (i += 1) {
        if (ep.accepted.items[i] == conn) {
            // PERF-P2b: O(1) removal — accepted list order is not significant.
            _ = ep.accepted.swapRemove(i);
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

/// Inspect the bound UDP socket and return its port number in host byte order.
///
/// RFC 9000 §9.1 describes path validation using socket tuples; this helper is
/// used by tests/tools that need to assert listener bindings.
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
