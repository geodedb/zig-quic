//! Public QUIC API skeleton. Zig 0.14.1
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

/// Concrete endpoint type.
// Endpoint is provided by the endpoint module; expose alias via re-export helper
pub const QuicEndpoint = @import("quic_endpoint").Endpoint;
/// Public opaque connection handle
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
pub fn poll(ep: *QuicEndpoint, timeout_ms: u32) !void {
    return ep.*.poll(@as(i32, @intCast(timeout_ms)));
}

/// Schedule a one-shot timer on the endpoint; returns the timer id.
pub fn scheduleTimer(ep: *QuicEndpoint, delay_ms: u32) !u64 {
    return ep.*.scheduleTimer(delay_ms);
}

/// Cancel a previously scheduled endpoint timer.
pub fn cancelTimer(ep: *QuicEndpoint, id: u64) bool {
    return ep.*.cancelTimer(id);
}

pub fn isHandshakeConfirmed(conn: *QuicConnection) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.app_tx_keys != null; // heuristic: 1-RTT keys ready
}

pub fn close(conn: *QuicConnection, app_error_code: u64, reason: []const u8) !void {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.sendConnectionClose(app_error_code, reason);
}

/// Force immediate destruction (test/CLI) of a connection: removes from endpoint maps and frees.
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
    std.debug.print("destroy(): removed {d} map keys for connection\n", .{n});
    c.deinit();
    ep.allocator.destroy(c);
}

pub fn isDrained(conn: *QuicConnection) bool {
    const c: *conn_mod.Connection = @ptrCast(@alignCast(conn));
    return c.closed; // simple signal for now
}

/// Best-effort flush: poll endpoint a few iterations with zero timeout to drive timers & RX.
pub fn flush(ep: *QuicEndpoint, iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        ep.poll(0) catch break;
    }
}
