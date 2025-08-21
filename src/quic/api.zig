//! Public QUIC API skeleton. Zig 0.14.1
//! MIT License
const std = @import("std");
const ks = @import("quic_tls");
const endpoint_mod = @import("endpoint.zig");
const lb = @import("loop_backend.zig");
// Use named import to share the same module instance across build graph
const conn_mod = @import("quic_conn");

/// Supported QUIC wire versions exposed to users.
pub const QuicVersion = enum { v1, v2 };
/// Role of an endpoint used by connection APIs.
pub const Role = enum { Client, Server };

/// Global event loop backend chosen per OS.
pub const LoopBackend = lb.LoopBackend;

/// Configuration for a QUIC endpoint and connections.
pub const QuicConfig = struct {
    version: QuicVersion = .v1,
    alpn: []const []const u8,
    cc: enum { newreno, cubic } = .newreno,
    enable_datagram: bool = false,
    enable_spin_bit: bool = false,
    grease: bool = true,
    // RFC 9368 Compatible Version Negotiation toggle
    compatible_vn: bool = false,
    // Enable sending QUIC Retry on first Initial without a valid token (server only)
    enable_retry: bool = false,
    // Secret used to MAC stateless Retry tokens (server). If null, a default built-in secret is used.
    token_secret: ?[]const u8 = null,
    // Token expiry in milliseconds from issuance (server)
    token_expiry_ms: u32 = 60000,
    max_idle_timeout_ms: u32 = 30000,
    max_udp_payload: u16 = 1350,
    cert_path: ?[]const u8 = null, // server
    key_path: ?[]const u8 = null, // server
    ca_path: ?[]const u8 = null, // client trust store (optional)
    allow_insecure: bool = false, // for tests only
};

/// Concrete endpoint type.
pub const QuicEndpoint = endpoint_mod.Endpoint;
/// Public opaque connection handle
pub const QuicConnection = opaque {};
/// Stream identifier type.
pub const QuicStreamId = u64;

/// Compute the Initial secrets and key/iv/hp for the configured QUIC version.
pub fn deriveInitialSecretsForConfig(cfg: *const QuicConfig, dcid: []const u8) struct {
    client: [ks.H.digest_length]u8,
    server: [ks.H.digest_length]u8,
    client_keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
    server_keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
} {
    const v2 = cfg.version == .v2;
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
pub fn endpointInit(alloc: *std.mem.Allocator, bind_addr: []const u8, cfg: *const QuicConfig) !*QuicEndpoint {
    const ep = try alloc.create(QuicEndpoint);
    ep.* = try QuicEndpoint.init(alloc, bind_addr, cfg);
    return ep;
}
/// Deinitialize endpoint and free resources.
pub fn endpointDeinit(ep: *QuicEndpoint) void {
    ep.deinit();
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
