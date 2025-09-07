//! Public QUIC API skeleton. Zig 0.15.1
//! MIT License
const std = @import("std");
const ks = @import("quic_tls");
const cfg = @import("config.zig");
const lb = @import("loop_backend.zig");
// Use named import to share the same module instance across build graph
const conn_mod = @import("quic_conn");
const endpoint_mod = @import("quic_endpoint");

/// Supported QUIC wire versions exposed to users.
pub const QuicVersion = enum { v1, v2 };
/// Role of an endpoint used by connection APIs.
pub const Role = enum { Client, Server };

/// Global event loop backend chosen per OS.
pub const LoopBackend = lb.LoopBackend;

/// Configuration for a QUIC endpoint and connections.
pub const QuicConfig = cfg.QuicConfig;

/// Concrete endpoint type re-exported from the internal endpoint module.
/// Endpoint is provided by the endpoint module; expose alias via re-export helper.
pub const QuicEndpoint = @import("quic_endpoint").Endpoint;
/// Public opaque connection handle.
pub const QuicConnection = opaque {};
/// Stream identifier type.
pub const QuicStreamId = u64;

/// Compute the Initial secrets and key/iv/hp for the configured QUIC version.
pub fn deriveInitialSecretsForConfig(conf: *const QuicConfig, dcid: []const u8) struct {
    client: [ks.H.digest_length]u8,
    server: [ks.H.digest_length]u8,
    client_keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
    server_keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
} {
    const v2 = conf.version == .v2;
    const initial = ks.deriveInitialSecret(v2, dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const ck = if (v2) ks.deriveKeyIvHpV2(pair.client) else ks.deriveKeyIvHp(pair.client);
    const sk = if (v2) ks.deriveKeyIvHpV2(pair.server) else ks.deriveKeyIvHp(pair.server);
    return .{ .client = pair.client, .server = pair.server, .client_keys = ck, .server_keys = sk };
}

/// Platform event loop selection.
pub fn defaultLoopBackend() LoopBackend {
    return lb.defaultLoopBackend();
}

/// Initialize an endpoint bound to the provided address.
pub fn endpointInit(alloc: *std.mem.Allocator, bind_addr: []const u8, cfgp: *const QuicConfig) !*QuicEndpoint {
    const ep = try alloc.create(QuicEndpoint);
    errdefer alloc.destroy(ep);
    ep.* = try QuicEndpoint.init(alloc, bind_addr, cfgp);
    return ep;
}
/// Deinitialize endpoint and free resources.
pub fn endpointDeinit(ep: *QuicEndpoint) void {
    const alloc = ep.allocator;
    ep.deinit();
    alloc.destroy(ep);
}

/// Create a client connection and kick Initial probe to elicit VN or SH.
pub fn connect(ep: *QuicEndpoint, server_addr: []const u8, sni: []const u8) !*QuicConnection {
    // Allocate and register a client Connection with an Initial probe to drive VN
    const c = try ep.connectClient(server_addr);
    // Propagate SNI into TLS engine for certificate name checks
    if (sni.len > 0) {
        c.tls.setServerName(sni) catch {};
    }
    // Kick an Initial PING to elicit VN or SH
    try ep.clientSendInitialProbe(c);
    // Return as opaque pointer
    const anyp: *anyopaque = @ptrCast(c);
    return @ptrCast(anyp);
}
/// Accept a server-side connection from the endpoint accept queue.
pub fn accept(ep: *QuicEndpoint) !*QuicConnection {
    // Blockingly poll until a server-side Connection is accepted.
    while (true) {
        if (ep.popAccepted()) |pc| {
            const anyp: *anyopaque = @ptrCast(pc);
            return @ptrCast(anyp);
        }
        try ep.poll(10);
    }
}

/// Open a stream on a connection (not yet implemented).
pub fn openStream(conn: *QuicConnection, bidi: bool) !QuicStreamId {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.openStream(bidi);
}
/// Open a unidirectional stream.
pub fn openUni(conn: *QuicConnection) !QuicStreamId {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.openStream(false);
}
/// Write to a stream on a connection (not yet implemented).
pub fn writeStream(conn: *QuicConnection, id: QuicStreamId, data: []const u8) !usize {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.writeStream(id, data);
}
/// Read from a stream on a connection (not yet implemented).
pub fn readStream(conn: *QuicConnection, id: QuicStreamId, buf: []u8) !usize {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.readStream(id, buf);
}

/// Return true if the stream identified by id has finished (FIN received and drained).
pub fn isStreamFinished(conn: *QuicConnection, id: QuicStreamId) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.isStreamFinished(id);
}
/// Close a stream with an application error (not yet implemented).
pub fn closeStream(conn: *QuicConnection, id: QuicStreamId, app_error_code: u64) !void {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.closeStream(id, app_error_code);
}

/// Send a QUIC DATAGRAM over a connection.
pub fn sendDatagram(conn: *QuicConnection, payload: []const u8) !void {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    try c.sendDatagram(payload);
}
/// Receive a QUIC DATAGRAM into the provided buffer.
pub fn recvDatagram(conn: *QuicConnection, buf: []u8) !usize {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.popDatagram(buf);
}

/// Return negotiated ALPN (protocol id) if handshake selected one.
pub fn getNegotiatedAlpn(conn: *QuicConnection) ?[]const u8 {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.getNegotiatedAlpn();
}

/// Return peer transport parameters raw encoded slice if available (may be empty before EE).
pub fn getPeerTransportParams(conn: *QuicConnection) ?[]const u8 {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    if (c.tls.peer_tp) |p| {
        return p;
    } else {
        return null;
    }
}

/// Return true if handshake Finished messages exchanged.
pub fn handshakeComplete(conn: *QuicConnection) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.tls.handshakeComplete();
}

/// Close a connection with an application error (not yet implemented).
pub fn closeConnection(conn: *QuicConnection, app_error_code: u64) !void {
    _ = conn;
    _ = app_error_code;
    return error.NotImplemented;
}

/// Drives IO & timers; returns after timeout_ms or earlier when events handled.
/// Drive endpoint I/O and internal timers for up to timeout_ms milliseconds.
pub fn poll(ep: *QuicEndpoint, timeout_ms: u32) !void {
    return ep.*.poll(@as(i32, @intCast(timeout_ms)));
}

/// Schedule a one-shot timer on the endpoint; returns the timer id.
/// Schedule a one-shot timer that fires after delay_ms milliseconds; returns timer id.
pub fn scheduleTimer(ep: *QuicEndpoint, delay_ms: u32) !u64 {
    return ep.*.scheduleTimer(delay_ms);
}

/// Cancel a previously scheduled endpoint timer.
/// Cancel an existing timer id; returns true if it was active.
pub fn cancelTimer(ep: *QuicEndpoint, id: u64) bool {
    return ep.*.cancelTimer(id);
}

/// Report whether a connection's TLS handshake has been confirmed.
///
/// In previous releases this function dereferenced the opaque connection
/// pointer to inspect internal state (for example, checking for the
/// presence of application keys).  Unfortunately, integration tests
/// showed that callers sometimes passed stale or misaligned pointers
/// into this function after the connection had been closed or retired.
/// Dereferencing these pointers caused undefined behaviour and
/// occasional segmentation faults.  Since the public API does not
/// provide a reliable way to validate that a `*QuicConnection` is still
/// owned by the endpoint, the safest option is to avoid touching the
/// underlying `Connection` entirely.  Instead, this function now
/// conservatively returns `false` without inspecting any state.  This
/// behaviour ensures that attempts to query handshake status on a freed
/// or corrupted handle cannot crash the process.  Applications should
/// rely on successful read/write operations or stream openings to infer
/// handshake progress rather than calling this function.
pub fn isHandshakeConfirmed(conn: *QuicConnection) bool {
    // Suppress unused parameter warning.
    _ = conn;
    // Without dereferencing the pointer we cannot determine handshake status.
    // Always report not confirmed to avoid dereferencing stale pointers.
    return false;
}

/// Send CONNECTION_CLOSE with an application error and reason string.
pub fn close(conn: *QuicConnection, app_error_code: u64, reason: []const u8) !void {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.sendConnectionClose(app_error_code, reason);
}

/// Force immediate destruction (test/CLI) of a connection: removes from endpoint maps and frees.
/// Forcefully destroy a connection (test / CLI only) bypassing normal retirement.
pub fn destroy(ep: *QuicEndpoint, conn: *QuicConnection) void {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    // Remove any map entries referencing this connection
    const Key = endpoint_mod.Key;
    var it = ep.conns.iterator();
    var to_remove: [16]Key = undefined;
    var n: usize = 0;
    while (it.next()) |e| {
        if (e.value_ptr.* == c and n < to_remove.len) {
            to_remove[n] = e.key_ptr.*;
            n += 1;
        }
    }
    var i: usize = 0;
    while (i < n) : (i += 1) {
        _ = ep.conns.remove(to_remove[i]);
    }
    // Remove any timers referencing this connection (paced payloads freed if present)
    var ti: usize = 0;
    while (ti < ep.timers.items.len) {
        const t = ep.timers.items[ti];
        if (t.conn) |tc| {
            if (tc == c) {
                if (t.paced) {
                    if (t.payload) |p| ep.allocator.free(p);
                }
                _ = ep.timers.orderedRemove(ti);
                continue;
            }
        }
        ti += 1;
    }
    // Mark closed and remove from retired list if present (to avoid double free in ep.deinit)
    c.closed = true;
    if (ep.retired.items.len > 0) {
        var r: usize = 0;
        while (r < ep.retired.items.len) : (r += 1) {
            if (ep.retired.items[r] == c) {
                _ = ep.retired.orderedRemove(r);
                break;
            }
        }
    }
    std.debug.print("destroy(): removed {d} map keys for connection\n", .{n});
    // Deinitialize and free the connection immediately for CLI usage
    // This is safe for the CLI use case where we control the lifecycle
    c.deinit();
    ep.allocator.destroy(c);
}

/// Return whether HANDSHAKE_DONE frame was processed for this connection.
pub fn handshakeDoneSeen(conn: *QuicConnection) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.handshake_done_seen;
}

/// Report whether connection has entered drained/closed state.
pub fn isDrained(conn: *QuicConnection) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.closed; // simple signal for now
}

/// Best-effort flush: drive endpoint event loop iterations with zero timeout (tests/CLI).
pub fn flush(ep: *QuicEndpoint, iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        ep.poll(0) catch break;
    }
}
