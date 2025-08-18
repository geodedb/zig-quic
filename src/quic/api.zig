//! Public QUIC API skeleton. Zig 0.13.0
//! MIT License
const std = @import("std");
const ks = @import("tls/key_schedule.zig");

pub const QuicVersion = enum { v1, v2 };
pub const Role = enum { Client, Server };

/// Global event loop backend chosen per OS.
pub const LoopBackend = enum { epoll, kqueue, iocp };

/// Configuration for a QUIC endpoint and connections.
pub const QuicConfig = struct {
    version: QuicVersion = .v1,
    alpn: []const []const u8,
    cc: enum { newreno, cubic } = .newreno,
    enable_datagram: bool = false,
    enable_spin_bit: bool = false,
    grease: bool = true,
    max_idle_timeout_ms: u32 = 30000,
    max_udp_payload: u16 = 1350,
    cert_path: ?[]const u8 = null, // server
    key_path: ?[]const u8 = null, // server
    ca_path: ?[]const u8 = null, // client trust store (optional)
    allow_insecure: bool = false, // for tests only
};

pub const QuicEndpoint = opaque {};
pub const QuicConnection = opaque {};
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
    return switch (std.Target.current.os.tag) {
        .linux => .epoll,
        .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd, .dragonfly => .kqueue,
        .windows => .iocp,
        else => .epoll,
    };
}

pub fn endpointInit(alloc: *std.mem.Allocator, bind_addr: []const u8, cfg: *const QuicConfig) !*QuicEndpoint {
    _ = alloc;
    _ = bind_addr;
    _ = cfg;
    return error.NotImplemented;
}
pub fn endpointDeinit(ep: *QuicEndpoint) void {
    _ = ep;
}

pub fn connect(ep: *QuicEndpoint, server_addr: []const u8, sni: []const u8) !*QuicConnection {
    _ = ep;
    _ = server_addr;
    _ = sni;
    return error.NotImplemented;
}
pub fn accept(ep: *QuicEndpoint) !*QuicConnection {
    _ = ep;
    return error.NotImplemented;
}

pub fn openStream(conn: *QuicConnection, bidi: bool) !QuicStreamId {
    _ = conn;
    _ = bidi;
    return error.NotImplemented;
}
pub fn writeStream(conn: *QuicConnection, id: QuicStreamId, data: []const u8) !usize {
    _ = conn;
    _ = id;
    _ = data;
    return error.NotImplemented;
}
pub fn readStream(conn: *QuicConnection, id: QuicStreamId, buf: []u8) !usize {
    _ = conn;
    _ = id;
    _ = buf;
    return error.NotImplemented;
}
pub fn closeStream(conn: *QuicConnection, id: QuicStreamId, app_error_code: u64) !void {
    _ = conn;
    _ = id;
    _ = app_error_code;
    return error.NotImplemented;
}

pub fn sendDatagram(conn: *QuicConnection, payload: []const u8) !void {
    _ = conn;
    _ = payload;
    return error.NotImplemented;
}
pub fn recvDatagram(conn: *QuicConnection, buf: []u8) !usize {
    _ = conn;
    _ = buf;
    return error.NotImplemented;
}

pub fn closeConnection(conn: *QuicConnection, app_error_code: u64) !void {
    _ = conn;
    _ = app_error_code;
    return error.NotImplemented;
}

/// Drives IO & timers; returns after timeout_ms or earlier when events handled.
pub fn poll(ep: *QuicEndpoint, timeout_ms: u32) !void {
    _ = ep;
    _ = timeout_ms;
    return error.NotImplemented;
}
