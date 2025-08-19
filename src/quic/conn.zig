// MIT License
// Minimal QUIC connection handle and socket address utils
const std = @import("std");
const posix = std.posix;
const tls13 = @import("tls/tls13.zig");
const packet = @import("packet.zig");

pub const Role = enum { Client, Server };

pub const SockAddr = struct {
    storage: posix.sockaddr.storage = undefined,
    len: u32 = 0,

    pub fn setFrom(ai: *const posix.addrinfo) SockAddr {
        var s: SockAddr = .{};
        const src = ai.addr.?.*;
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..ai.addrlen], @as([*]const u8, @ptrCast(&src))[0..ai.addrlen]);
        s.len = @intCast(ai.addrlen);
        return s;
    }

    pub fn family(self: *const SockAddr) u16 {
        return self.storage.family;
    }

    pub fn eq(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.len != b.len) return false;
        if (a.storage.family != b.storage.family) return false;
        const pa = @as([*]const u8, @ptrCast(&a.storage))[0..a.len];
        const pb = @as([*]const u8, @ptrCast(&b.storage))[0..b.len];
        return std.mem.eql(u8, pa, pb);
    }

    /// Helper to build an IPv4 sockaddr for tests.
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port_host: u16) SockAddr {
        var s: SockAddr = .{};
        var sin: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port_host),
            .addr = std.mem.nativeToBig(u32, (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d)),
            .zero = .{0} ** 8,
        };
        s.len = @intCast(@sizeOf(posix.sockaddr.in));
        @memcpy(@as([*]u8, @ptrCast(&s.storage))[0..s.len], @as([*]const u8, @ptrCast(&sin))[0..s.len]);
        return s;
    }
};

pub const Cid = struct {
    len: u8 = 0,
    bytes: [20]u8 = undefined,
};

pub const Connection = struct {
    id: u64,
    role: Role,
    sock_fd: posix.fd_t,
    peer: SockAddr,
    tls_inbox: std.ArrayList(u8),
    tls: tls13.Engine,
    // Derived handshake traffic secrets (once both hellos present)
    hs_client: ?[tls13.H.digest_length]u8 = null,
    hs_server: ?[tls13.H.digest_length]u8 = null,
    // Cached QUIC Handshake keys for RX/TX once derived
    hs_rx_keys: ?packet.InitialKeys = null,
    hs_tx_keys: ?packet.InitialKeys = null,
    // 1-RTT application keys
    app_rx_keys: ?packet.AeadKeys = null,
    app_tx_keys: ?packet.AeadKeys = null,
    // PN counters per space (simplified)
    pn_handshake_tx: u32 = 1,
    pn_app_tx: u32 = 1,
    // Peer-provided Initial DCID/SCID from first Initial we saw (for reply headers)
    peer_initial_dcid: Cid = .{},
    peer_initial_scid: Cid = .{},
    // Our chosen SCID to advertise in server flight
    our_scid: Cid = .{},
    // Switch flag to drop Initial keys/processing once Handshake packets are seen
    initial_keys_dropped: bool = false,

    pub fn init(self: *Connection, alloc: *std.mem.Allocator, role: Role, sock_fd: posix.fd_t, peer: SockAddr) void {
        self.id = 0;
        self.role = role;
        self.sock_fd = sock_fd;
        self.peer = peer;
        self.tls_inbox = std.ArrayList(u8).init(alloc.*);
        self.tls = tls13.Engine.init(alloc.*, if (role == .Client) .Client else .Server);
        self.hs_client = null;
        self.hs_server = null;
        self.hs_rx_keys = null;
        self.hs_tx_keys = null;
        self.app_rx_keys = null;
        self.app_tx_keys = null;
        self.pn_handshake_tx = 1;
        self.pn_app_tx = 1;
        self.peer_initial_dcid = .{};
        self.peer_initial_scid = .{};
        self.our_scid = .{};
        self.initial_keys_dropped = false;
        // Generate a simple random SCID (8 bytes) for server role.
        if (role == .Server) {
            self.our_scid.len = 8;
            std.crypto.random.bytes(self.our_scid.bytes[0..self.our_scid.len]);
        }
    }

    pub fn deinit(self: *Connection) void {
        self.tls_inbox.deinit();
        self.tls.deinit();
    }

    /// Send a datagram to the connection's peer.
    pub fn send(self: *const Connection, data: []const u8) !usize {
        const sa_ptr: *const posix.sockaddr = @ptrCast(&self.peer.storage);
        return posix.sendto(self.sock_fd, data, 0, sa_ptr, self.peer.len);
    }

    /// Append CRYPTO stream bytes into the inbox and feed TLS engine.
    pub fn pushCrypto(self: *Connection, data: []const u8) !void {
        try self.tls_inbox.appendSlice(data);
        self.tls.onCryptoRecv(data);
        // Attempt to compute handshake secrets if test ecdhe_secret has been set
        if (self.tls.computeHandshakeSecrets()) |hs| {
            self.hs_client = hs.client;
            self.hs_server = hs.server;
            self.deriveHandshakeKeys(false);
        }
        // Attempt to compute application secrets
        if (self.tls.computeApplicationSecrets()) |ap| {
            self.deriveAppKeys(ap.client, ap.server, false);
        }
    }

    fn deriveHandshakeKeys(self: *Connection, version_v2: bool) void {
        if (self.hs_client == null or self.hs_server == null) return;
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) self.hs_client.? else self.hs_server.?;
        const tx_secret = if (self.role == .Server) self.hs_server.? else self.hs_client.?;
        const rx = tls13.deriveQuicHandshakeKeys(rx_secret, version_v2);
        const tx = tls13.deriveQuicHandshakeKeys(tx_secret, version_v2);
        self.hs_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.hs_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
    }

    fn deriveAppKeys(self: *Connection, client_app: [tls13.H.digest_length]u8, server_app: [tls13.H.digest_length]u8, version_v2: bool) void {
        // Assign rx/tx according to role
        const rx_secret = if (self.role == .Server) client_app else server_app;
        const tx_secret = if (self.role == .Server) server_app else client_app;
        const rx = tls13.deriveQuicAppKeys(rx_secret, version_v2);
        const tx = tls13.deriveQuicAppKeys(tx_secret, version_v2);
        self.app_rx_keys = .{ .key = rx.key, .iv = rx.iv, .hp = rx.hp };
        self.app_tx_keys = .{ .key = tx.key, .iv = tx.iv, .hp = tx.hp };
    }

    /// Record peer's Initial DCID/SCID (copied) for use in reply headers.
    pub fn setPeerInitialCids(self: *Connection, dcid: []const u8, scid: []const u8) void {
        const dl: u8 = @intCast(@min(dcid.len, self.peer_initial_dcid.bytes.len));
        self.peer_initial_dcid.len = dl;
        if (dl > 0) @memcpy(self.peer_initial_dcid.bytes[0..dl], dcid[0..dl]);
        const sl: u8 = @intCast(@min(scid.len, self.peer_initial_scid.bytes.len));
        self.peer_initial_scid.len = sl;
        if (sl > 0) @memcpy(self.peer_initial_scid.bytes[0..sl], scid[0..sl]);
    }
};
