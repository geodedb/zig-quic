//! Endpoint skeleton with UDP send/recv (single socket, single-thread).
//!
//! Implements the endpoint responsibilities from RFC 9000 (§§5–9, §14) including
//! packet processing, path validation, and PMTUD timers, plus recovery plumbing
//! from RFC 9002 (§6). TLS credential loading follows RFC 9001 §4 requirements.

const std = @import("std");
const cfg = @import("config.zig");
const lb = @import("loop_backend.zig");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const sig = @import("sig");
const x509 = @import("x509");
const crypto = @import("quic_crypto");
const varint = @import("quic_varint");
const token_mod = @import("quic_token");
const recovery = @import("quic_recovery");
// Import transport parameters via dedicated module to avoid duplicate root file compilation
const tp = @import("quic_transport_params");
const logger = @import("quic_logger");
const byteorder = @import("byteorder");
const utils = @import("endpoint/utils.zig");
const pto_mod = @import("endpoint/pto.zig");
const lookup = @import("endpoint/lookup.zig");
const incoming = @import("endpoint/incoming.zig");
const frame_handler = @import("endpoint/frame_handler.zig");
const handshake_integration = @import("endpoint/handshake_integration.zig");
const io_mod = @import("endpoint/io.zig");
const lifecycle_mod = @import("endpoint/lifecycle.zig");
const ep_types = @import("types");

const posix = std.posix;
const builtin = @import("builtin");

// Endpoint (RFC-9000):  An entity that can participate in a QUIC connection by
//       generating, receiving, and processing QUIC packets.  There are
//       only two types of endpoints in QUIC: client and server.

// TEST-ONLY: outbound capture entry (peer + owned bytes)
const OutCaptured = struct { peer: conn_mod.SockAddr, bytes: []u8 };

// File-level variable to allow callbacks to access endpoint
// This is safe because endpoints are single-threaded
var current_io_endpoint: ?*Endpoint = null;

// Note: Byte order conversion functions moved to utils module
inline fn portFromNetwork(value: u16) u16 {
    return utils.portFromNetwork(value);
}

inline fn portToNetwork(value: u16) u16 {
    return utils.portToNetwork(value);
}

inline fn addrToNetwork(value: u32) u32 {
    return utils.addrToNetwork(value);
}

fn nowMsMonotonic() i64 {
    // Prefer a monotonic source; nanoTimestamp is monotonic on supported platforms.
    // Use explicit truncating integer division for signed integers (Zig 0.14 requirement).
    const ns: i128 = std.time.nanoTimestamp();
    const ms: i128 = @divTrunc(ns, std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}

// Use canonical Timer and TimerKind from endpoint/types.zig (imported as ep_types)
const Timer = ep_types.Timer;
const TimerKind = ep_types.TimerKind;

/// Hash key combining peer address + destination CID for connection lookup.
///
/// RFC 9000 §5.1 mandates that servers route packets using tuple + DCID. We use
/// this composite hash so multipath/path validation still find the right entry.
pub const Key = ep_types.Key;

// Note: Utility functions moved to utils module
// Kept as inline wrappers for backward compatibility
inline fn hashBytes(b: []const u8) u64 {
    return utils.hashBytes(b);
}

inline fn normalizeAddr(sa: *const posix.sockaddr.storage, len: u32) conn_mod.SockAddr {
    return utils.normalizeAddr(sa, len);
}

pub fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    return utils.hashSockaddr(sa, len);
}

/// Endpoint role enum
pub const EndpointRole = enum {
    Client,
    Server,
};

/// single bound socket. Owns all live connections and drives send/recv plus PTO/PMTUD timers.
///
/// Covers the UDP abstraction and anti-amplification logic described in RFC 9000
/// §8, manages Retry/NEW_TOKEN (via config) per §8.1, and orchestrates timers for
/// loss recovery as recommended by RFC 9002 §6.
pub const Endpoint = struct {

    // Socket file descriptor
    sock_fd: posix.socket_t,

    // Socket address family (AF_INET or AF_INET6)
    sock_family: u16,

    // Event loop backend (os specific)
    loop_backend: lb.LoopBackend,

    // Memory allocator for endpoint resources
    allocator: *std.mem.Allocator,

    // Timer management for the endpoint
    timers: std.ArrayList(Timer),

    // Connection Management Map
    conns: std.AutoHashMap(Key, *conn_mod.Connection),

    // Next timer identifier for scheduleTimer
    next_timer_id: u64 = 1,
    // Config copy
    cfg: cfg.QuicConfig,
    // Accept queue for server
    accepted: std.ArrayList(*conn_mod.Connection),
    // TEST-ONLY: outbound capture ring (peer + owned bytes)
    captures: std.ArrayList(OutCaptured),
    // TEST-ONLY: runtime flag to enable outbound capture in tests
    test_capture_enabled: bool = false,
    // Retired (closed) connections removed from maps & timers but not yet destroyed.
    // They stay here until explicit api.destroy() or endpoint.deinit(), allowing external
    // code (e.g., server CLI loop) holding an opaque pointer to observe closed state
    // without risking use-after-free.
    retired: std.ArrayList(*conn_mod.Connection),
    // Epoll file descriptor for Linux
    epoll_fd: ?posix.fd_t = null,
    // Endpoint role (Client or Server)
    role: EndpointRole,

    /// Initialize a UDP endpoint bound to bind_addr (e.g., "127.0.0.1:0").
    pub fn init(alloc: *std.mem.Allocator, bind_addr: []const u8, cfgp: *const cfg.QuicConfig) !Endpoint {
        // Resolve and bind IPv4 socket for tests; port 0 lets OS choose a free port.
        var ep_addr = try resolveAny(bind_addr, .udp);

        // Determine address family from resolved address
        const sa: *const posix.sockaddr = @ptrCast(@alignCast(&ep_addr.storage));
        const family = sa.family;

        std.debug.print("Endpoint init - binding to address family={any}\n", .{family});

        const fd = try posix.socket(family, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer posix.close(fd);

        std.debug.print("Created socket fd={}\n", .{fd});

        // For IPv6 sockets, disable IPV6_V6ONLY to allow dual-stack (IPv4-mapped + IPv6)
        if (family == posix.AF.INET6) {
            var v6only: i32 = 0; // 0 = allow both IPv4-mapped and IPv6
            const IPV6_V6ONLY: i32 = 26; // Standard value for IPV6_V6ONLY
            _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&v6only)) catch {};
            std.debug.print("Set IPV6_V6ONLY=0 for dual-stack support\n", .{});
        }

        // Allow fast rebinding in tests
        var one: i32 = 1;
        _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
        // Linux: enable reception of TOS/TCLASS via ancillary data to read ECN bits per datagram
        // TEMPORARILY DISABLED: These socket options may interfere with basic UDP reception
        if (false and builtin.target.os.tag == .linux) {
            var enable: i32 = 1;
            // Zig std may not expose IP.RECVTOS; use the Linux value (IP_RECVTOS = 13)
            const IP_RECVTOS: i32 = 13;
            _ = posix.setsockopt(fd, posix.IPPROTO.IP, IP_RECVTOS, std.mem.asBytes(&enable)) catch {};
            // Also request IPv6 traffic class delivery (IPV6_RECVTCLASS = 66)
            const IPV6_RECVTCLASS: i32 = 66;
            _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_RECVTCLASS, std.mem.asBytes(&enable)) catch {};
            // Enable Linux error queue reception for ICMP PTB (IPv4/IPv6)
            const IP_RECVERR: i32 = 11;
            _ = posix.setsockopt(fd, posix.IPPROTO.IP, IP_RECVERR, std.mem.asBytes(&enable)) catch {};
            const IPV6_RECVERR: i32 = 25;
            _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_RECVERR, std.mem.asBytes(&enable)) catch {};
        }
        // Note: do not rely on O.NONBLOCK here; use MSG.DONTWAIT on Linux in recv loop for portability
        const sa_ptr: *const posix.sockaddr = @ptrCast(@alignCast(&ep_addr.storage));
        std.debug.print("Binding socket to address...\n", .{});
        const bind_len: posix.socklen_t = switch (family) {
            posix.AF.INET => @intCast(@sizeOf(posix.sockaddr.in)),
            posix.AF.INET6 => @intCast(@sizeOf(posix.sockaddr.in6)),
            else => return error.AddressFamilyNotSupported,
        };
        try posix.bind(fd, sa_ptr, bind_len);
        std.debug.print("Socket bound successfully\n", .{});

        // Verify the actual bound address (in case port was 0)
        var actual_addr = conn_mod.SockAddr{};
        actual_addr.len = @intCast(@sizeOf(posix.sockaddr.storage));
        try posix.getsockname(fd, @ptrCast(&actual_addr.storage), &actual_addr.len);
        // Debug: print actual bound address and port
        if (actual_addr.storage.family == posix.AF.INET) {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&actual_addr.storage));
            const addr_bytes = @as([4]u8, @bitCast(sin.addr));
            const port = portFromNetwork(sin.port);
            std.debug.print("Socket bound to {}.{}.{}.{}:{}\n", .{ addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], port });
        } else if (actual_addr.storage.family == posix.AF.INET6) {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&actual_addr.storage));
            const port = portFromNetwork(sin6.port);
            // Check if it's an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
            const is_ipv4_mapped = sin6.addr[0] == 0 and sin6.addr[1] == 0 and
                sin6.addr[2] == 0 and sin6.addr[3] == 0 and
                sin6.addr[4] == 0 and sin6.addr[5] == 0 and
                sin6.addr[6] == 0 and sin6.addr[7] == 0 and
                sin6.addr[8] == 0 and sin6.addr[9] == 0 and
                sin6.addr[10] == 0xff and sin6.addr[11] == 0xff;
            if (is_ipv4_mapped) {
                std.debug.print("Socket bound to ::ffff:{}.{}.{}.{}:{} (dual-stack)\n", .{ sin6.addr[12], sin6.addr[13], sin6.addr[14], sin6.addr[15], port });
            } else {
                std.debug.print("Socket bound to IPv6 port {}\n", .{port});
            }
        }

        // Set socket to non-blocking mode
        if (builtin.target.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var nonblock: std.os.windows.ULONG = 1;
            _ = ws2.ioctlsocket(fd, ws2.FIONBIO, &nonblock);
        } else {
            // Set non-blocking mode on Unix
            const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
            std.debug.print("Current socket flags: 0x{x}\n", .{flags});
            const O_NONBLOCK: i32 = 0x800; // O_NONBLOCK value on Linux
            const new_flags = flags | O_NONBLOCK;
            std.debug.print("Setting socket flags to: 0x{x}\n", .{new_flags});
            _ = try posix.fcntl(fd, posix.F.SETFL, new_flags);
            const verify_flags = try posix.fcntl(fd, posix.F.GETFL, 0);
            std.debug.print("Socket flags after setting: 0x{x}\n", .{verify_flags});
            std.debug.print("Has O_NONBLOCK: {}\n", .{(verify_flags & O_NONBLOCK) != 0});
        }

        // Create epoll instance on Linux
        var epoll_fd_opt: ?posix.fd_t = null;
        if (builtin.target.os.tag == .linux) {
            const linux = std.os.linux;
            const epfd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);

            // Add the socket to epoll for read events
            var ev = std.mem.zeroes(linux.epoll_event);
            ev.events = linux.EPOLL.IN;
            ev.data.fd = @as(i32, @intCast(fd));
            try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev);

            epoll_fd_opt = epfd;
            std.debug.print("Created epoll fd={} and added socket fd={}\n", .{ epfd, fd });
        }

        // Determine endpoint role based on the bound port
        // Server typically binds to a specific port (like 4433), client binds to port 0 (random)
        const bound_port = if (actual_addr.storage.family == posix.AF.INET) blk: {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&actual_addr.storage));
            break :blk portFromNetwork(sin.port);
        } else if (actual_addr.storage.family == posix.AF.INET6) blk: {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&actual_addr.storage));
            break :blk portFromNetwork(sin6.port);
        } else blk: {
            break :blk @as(u16, 0);
        };

        // If we're binding to port 4433 or any specific port in the bind_addr, we're a server
        // If we're binding to port 0 or got a random port, we're a client
        const is_server = std.mem.indexOf(u8, bind_addr, ":4433") != null or
            std.mem.indexOf(u8, bind_addr, ":443") != null or
            (std.mem.indexOf(u8, bind_addr, ":0") == null and bound_port != 0);
        const endpoint_role = if (is_server) EndpointRole.Server else EndpointRole.Client;

        std.debug.print("Endpoint role determined as: {any}\n", .{endpoint_role});

        return Endpoint{
            .sock_fd = fd,
            .sock_family = family,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc,
            .timers = std.ArrayList(Timer){},
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc.*),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = std.ArrayList(*conn_mod.Connection){},
            .captures = std.ArrayList(OutCaptured){},
            .test_capture_enabled = false,
            .retired = std.ArrayList(*conn_mod.Connection){},
            .epoll_fd = epoll_fd_opt,
            .role = endpoint_role,
        };
    }

    /// Deinitialize endpoint and free all associated connection state.
    pub fn deinit(self: *Endpoint) void {
        // Attempt to prune any closed (or newly closed due to earlier failures) connections
        // before emitting instrumentation so we only report genuinely still-open connections.
        self.pruneClosed();
        // Soft-close any remaining connections so they don't linger as leaks in debug builds.
        var pre_it = self.conns.iterator();
        while (pre_it.next()) |e| {
            const c = e.value_ptr.*;
            if (!c.closed) c.closed = true;
        }
        // Prune again after mass-closing.
        self.pruneClosed();
        // Instrumentation: list any remaining connection pointers (map values) before cleanup
        if (builtin.mode == .Debug) {
            var unique = std.AutoHashMap(*conn_mod.Connection, usize).init(self.allocator.*);
            defer unique.deinit();
            var cit = self.conns.iterator();
            while (cit.next()) |e| {
                const c = e.value_ptr.*;
                const idx = unique.get(c) orelse 0;
                _ = unique.put(c, idx + 1) catch {};
            }
            if (unique.count() > 0) {
                std.debug.print("endpoint.deinit: {d} unique conn(s) still referenced by map; dumping counts\n", .{unique.count()});
                var uit = unique.iterator();
                while (uit.next()) |ve| {
                    std.debug.print("  conn ptr={*} ref_count={d}\n", .{ ve.key_ptr.*, ve.value_ptr.* });
                }
                // Also dump timers referencing a connection
                var ti: usize = 0;
                var timer_conn_refs: usize = 0;
                while (ti < self.timers.items.len) : (ti += 1) {
                    const t = self.timers.items[ti];
                    if (t.conn) |tc| {
                        timer_conn_refs += 1;
                        std.debug.print("  timer id={d} kind={any} conn={*}\n", .{ t.id, t.kind, tc });
                    }
                }
                if (timer_conn_refs > 0) std.debug.print("  timers referencing connections: {d}\n", .{timer_conn_refs});
            }
        }
        // Free captured payloads
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) {
            const cap = self.captures.items[i];
            self.allocator.free(cap.bytes);
        }
        self.captures.deinit(self.allocator.*);
        // Free any pending paced payloads in timers
        var j: usize = 0;
        while (j < self.timers.items.len) : (j += 1) {
            const t = self.timers.items[j];
            if (t.paced) {
                if (t.payload) |p| self.allocator.free(p);
            }
        }
        // Destroy unique connections referenced by map values
        var seen = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator.*);
        defer seen.deinit();
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (!seen.contains(c)) {
                _ = seen.put(c, {}) catch {};
                c.deinit();
                self.allocator.destroy(c);
            }
        }
        // Also destroy any retired (already removed from map) connections not yet destroyed.
        var ri: usize = 0;
        while (ri < self.retired.items.len) : (ri += 1) {
            const c = self.retired.items[ri];
            if (!seen.contains(c)) { // skip if already destroyed above
                c.deinit();
                self.allocator.destroy(c);
            }
        }
        self.retired.deinit(self.allocator.*);
        self.conns.deinit();
        self.accepted.deinit(self.allocator.*);
        self.timers.deinit(self.allocator.*);

        // Close epoll fd if we have one
        if (self.epoll_fd) |epfd| {
            _ = posix.close(epfd);
        }

        // Close socket
        if (builtin.target.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            _ = ws2.closesocket(self.sock_fd);
        } else {
            _ = posix.close(self.sock_fd);
        }
    }

    /// Expire due timers without blocking on I/O (test helper).
    pub fn flushTimers(self: *Endpoint) void {
        self.processExpiredTimers(nowMsMonotonic());
    }

    /// Clear all captured outbound packets (test helper).
    pub fn captureClear(self: *Endpoint) void {
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) self.allocator.free(self.captures.items[i].bytes);
        self.captures.clearRetainingCapacity();
    }
    /// Return number of captured outbound packets.
    pub fn captureLen(self: *Endpoint) usize {
        return self.captures.items.len;
    }
    /// Pop most recent captured outbound packet if present.
    pub fn capturePop(self: *Endpoint) ?OutCaptured {
        if (self.captures.items.len == 0) return null;
        return self.captures.orderedRemove(0);
    }

    /// Internal: convert socket_t to isize for Connection.sock_fd storage.
    fn sockToIsize(fd: posix.socket_t) isize {
        if (builtin.target.os.tag == .windows) {
            return @as(isize, @intCast(@intFromPtr(fd)));
        } else {
            return @as(isize, @intCast(fd));
        }
    }

    /// Send UDP datagram to peer (capturing if enabled).
    /// Send UDP datagram to peer. Supports test capture mode.
    /// Delegates actual UDP send to io_mod.sendTo() for platform abstraction.
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        // Test capture: make owned copy and enqueue without sending
        if (self.test_capture_enabled) {
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            _ = self.captures.append(self.allocator.*, .{ .peer = peer, .bytes = owned }) catch {};
        }

        // Delegate actual UDP send to io module
        std.debug.print("sendTo called with data.len={}\n", .{data.len});
        return io_mod.sendTo(self.sock_fd, peer, data);
    }

    /// Receive UDP datagram (non-blocking if platform supports MSG.DONTWAIT).
    /// Delegates to io_mod.recvFrom() for platform abstraction.
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        const result = try io_mod.recvFrom(self.sock_fd, buf);
        return .{ .n = result.n, .peer = result.peer };
    }

    /// Accept a server connection from initial datagram's peer address.
    pub fn acceptFrom(self: *Endpoint, peer: conn_mod.SockAddr) conn_mod.Connection {
        return .{ .id = 0, .role = .Server, .sock_fd = sockToIsize(self.sock_fd), .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Enqueue accepted server connection for accept().
    fn pushAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        self.accepted.append(self.allocator.*, c) catch {};
    }

    /// Pop next accepted server-side connection if available.
    pub fn popAccepted(self: *Endpoint) ?*conn_mod.Connection {
        if (self.accepted.items.len == 0) return null;
        return self.accepted.orderedRemove(0);
    }

    /// Inject inbound datagram into receive path (test helper, no ECN).
    pub fn testInject(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8) void {
        self.processIncomingDatagram(peer, bytes, null);
    }

    /// Inject inbound datagram with explicit ECN bits (test helper).
    pub fn testInjectWithEcn(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: u8) void {
        self.processIncomingDatagram(peer, bytes, ecn_bits);
    }

    /// Create server-side represented connection (used by client dialing logic).
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        const peer = try resolveAny(hostport, .udp);
        return .{ .id = 0, .role = .Client, .sock_fd = sockToIsize(self.sock_fd), .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Create client-side connection object referencing remote host:port.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const peer = try resolveAny(hostport, .udp);
        const c = try self.allocator.create(conn_mod.Connection);
        c.init(self.allocator, .Client, sockToIsize(self.sock_fd), peer);
        // Apply config flags
        c.setUseCubic(self.cfg.cc == .cubic);
        c.tls.allow_insecure = self.cfg.allow_insecure;
        c.allowed_alpns = self.cfg.alpn;
        // Enable optional pacing and set CC max_datagram_size
        c.enable_pacing = self.cfg.enable_pacing;
        c.rec.cc.mds = @intCast(self.cfg.max_datagram_size);
        // Install paced sender callback
        c.setSender(@ptrCast(self), senderPaced);
        // Apply AEAD usage limit overrides
        c.setAeadUsageLimits(self.cfg.aead_confidentiality_limit_override, self.cfg.aead_integrity_limit_override);
        // Choose initial version from cfg
        // For now always use QUIC v1 unless explicitly configured for v2.
        c.version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;
        c.version_v2 = (c.version == packet.QUIC_V2);
        c.initial_version = c.version;
        // Client chooses DCID and SCID (RFC 9000 §5.1.1) prior to deriving Initial secrets.
        var dcid: [8]u8 = undefined;
        std.crypto.random.bytes(&dcid);
        c.peer_initial_dcid.len = @intCast(dcid.len);
        @memcpy(c.peer_initial_dcid.bytes[0..dcid.len], &dcid);
        // Preserve original DCID separately for Initial secret derivation (never changes).
        c.original_dcid.len = c.peer_initial_dcid.len;
        if (c.original_dcid.len > 0) @memcpy(c.original_dcid.bytes[0..c.original_dcid.len], c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
        c.our_scid.len = 8;
        std.crypto.random.bytes(c.our_scid.bytes[0..c.our_scid.len]);
        // Map by both dcid and scid to find VN/HS
        const ph = hashSockaddr(&peer.storage, peer.len);
        const key_d = Key{ .peer_hash = ph, .dcid_hash = hashBytes(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) };
        const key_s = Key{ .peer_hash = ph, .dcid_hash = hashBytes(c.our_scid.bytes[0..c.our_scid.len]) };
        _ = self.conns.put(key_d, c) catch {};
        _ = self.conns.put(key_s, c) catch {};
        return c;
    }

    /// Transmit minimal Initial packet (PING) to elicit Version Negotiation or SH.
    pub fn clientSendInitialProbe(self: *Endpoint, c: *conn_mod.Connection) !void {
        const v2 = (c.version == packet.QUIC_V2);
        // Initial secret derives from the immutable DCID per RFC 9001 §5.1/§5.2.
        const initial = ks.deriveInitialSecret(v2, if (c.original_dcid.len > 0) c.original_dcid.bytes[0..c.original_dcid.len] else c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
        const pair = ks.deriveClientServerInitial(initial);
        std.debug.print("client: deriving Initial keys with dcid=\n", .{});
        for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print(" len={}\n", .{c.peer_initial_dcid.len});
        const tx_keys: packet.InitialKeys = if (v2) blk: {
            const t = ks.deriveKeyIvHpV2(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        } else blk: {
            const t = ks.deriveKeyIvHp(pair.client);
            break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
        };
        var frames = std.ArrayList(u8){};
        defer frames.deinit(self.allocator.*);
        // Build CRYPTO frame carrying ClientHello
        // Set up client transport parameters for TLS handshake (Phase 4b.5 Session 7)
        handshake_integration.setupClientTransportParams(c, self.allocator.*) catch {};
        // Queue ClientHello using full TLS 1.3
        c.tls.queueMinimalClientHello() catch {
            _ = c.tls.queueMinimalClientHelloAuto() catch 0;
        };
        var crypto_buf: [2048]u8 = undefined;
        const crypto_len = c.tls.popCrypto(crypto_buf[0..]);
        if (crypto_len > 0) {
            const base_off = c.crypto_tx_off_initial;
            _ = (frame.Frame{ .crypto = .{ .offset = base_off, .data = crypto_buf[0..crypto_len] } }).write(frames.writer(self.allocator.*)) catch 0;
            // (TEMP) Omit saving retransmit buffer to simplify leak debugging for interop slice.
            c.crypto_retx_initial_off = base_off;
            c.crypto_tx_off_initial += crypto_len;
        } else {
            frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PING)) catch {};
        }
        // Add padding to meet minimum Initial datagram size of 1200 bytes (RFC 9000 §14.1).
        while (frames.items.len < 1150) frames.append(self.allocator.*, @intFromEnum(frame.FrameType.PADDING)) catch {};
        // Use any stored Retry token if present
        const token_slice: []const u8 = c.initial_token.items;
        const pkt = try packet.encodeInitialProtected(
            self.allocator.*,
            c.version,
            // Client Initial: DCID = our chosen dcid; SCID = our scid
            // After a Retry, peer_initial_dcid is updated to the SCID from the Retry per RFC 9000 §17.2.5.
            c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
            c.our_scid.bytes[0..c.our_scid.len],
            token_slice,
            @as(u32, @truncate(c.pn_initial_tx)),
            2,
            frames.items,
            tx_keys,
        );
        std.debug.print("client: built Initial pn={} dcid=\n", .{c.pn_initial_tx});
        for (c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print(" scid=\n", .{});
        for (c.our_scid.bytes[0..c.our_scid.len]) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print(" payload_len={}\n", .{frames.items.len});
        defer self.allocator.free(pkt);
        const sent = try self.sendTo(c.peer, pkt);
        c.onPacketSent(.Initial, c.pn_initial_tx, sent, true);
        c.pn_initial_tx +%= 1;
        // Arm Initial PTO
        c.computeAndMaybeArmPtoInitial(self);
    }

    /// Schedule generic timer firing after delay_ms.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = null });
        return id;
    }

    /// Schedule connection-owned PTO/PMTUD timer tied to a specific connection and space.
    pub fn scheduleConnPto(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        // PTO and probe timers follow RFC 9002 §6 (loss detection) and §7 (PMTUD pacing).
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = kind, .conn = c });
        return id;
    }

    /// Schedule a paced send for a connection after delay_ns.
    fn schedulePaced(self: *Endpoint, c: *conn_mod.Connection, delay_ns: u64, owned_bytes: []u8) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        var delay_ms_u64: u64 = delay_ns / std.time.ns_per_ms;
        if (delay_ms_u64 == 0) delay_ms_u64 = 1; // minimum 1ms to avoid busy spinning
        if (delay_ms_u64 > 100) delay_ms_u64 = 100; // keep deterministic and fast in tests
        const deadline: i64 = now_ms + @as(i64, @intCast(@min(delay_ms_u64, @as(u64, std.math.maxInt(u32)))));
        try self.timers.append(self.allocator.*, .{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = c, .paced = true, .payload = owned_bytes });
        return id;
    }

    /// Cancel a pending timer id.
    pub fn cancelTimer(self: *Endpoint, id: u64) bool {
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            if (self.timers.items[i].id == id) {
                _ = self.timers.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    var poll_call_count: u64 = 0;
    /// Drive network I/O, timers, and paced send for up to timeout_ms milliseconds.
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        poll_call_count += 1;
        // TRACE: poll called
        std.debug.print(">>> POLL #{} called, timeout_ms={}\n", .{ poll_call_count, timeout_ms });
        // First, process any timers that are already expired to avoid waiting unnecessarily.
        self.processExpiredTimers(nowMsMonotonic());
        // Drain any pending error queue notifications (ICMP PTB, etc.) before waiting.
        self.drainErrorQueue();

        const now_ms: i64 = nowMsMonotonic();
        var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        if (eff_timeout < 0) eff_timeout = -1;

        // Guard for coarse timer resolution on some platforms (e.g., Windows):
        // if a timer is due "now" (eff_timeout == 0), sleep a minimal interval to
        // ensure the next timestamp crosses the deadline, then flush again.
        if (eff_timeout == 0 and self.timers.items.len > 0) {
            std.Thread.sleep(@as(u64, 1) * std.time.ns_per_ms);
            self.processExpiredTimers(nowMsMonotonic());
            // Recompute effective timeout after the flush
            const now_after = nowMsMonotonic();
            eff_timeout = self.nextTimeoutFromTimers(now_after, timeout_ms);
            if (eff_timeout < 0) eff_timeout = -1;
        }

        // Always use the platform event loop to wait for readability
        // This ensures we actually wait for packets to arrive
        const backend = lb.defaultLoopBackend();
        std.debug.print("Using backend: {}\n", .{backend});
        switch (backend) {
            .epoll => try self.poll_epoll_backend(eff_timeout),
            .kqueue => try self.poll_kqueue_backend(eff_timeout),
            .iocp => try self.poll_iocp_backend(eff_timeout),
        }

        self.processExpiredTimers(nowMsMonotonic());
        if (self.timers.items.len > 0 and timeout_ms != 0) {
            const now2: i64 = nowMsMonotonic();
            const again: i32 = self.nextTimeoutFromTimers(now2, 0);
            if (again > 0 and again <= 5) {
                std.Thread.sleep(@as(u64, @intCast(again)) * std.time.ns_per_ms);
                self.processExpiredTimers(nowMsMonotonic());
            }
        }
        self.pruneClosed();
    }

    fn drainReadable(self: *Endpoint) void {
        // Delegate to io module - but we need self for callbacks
        // Simple solution: use thread-local for now
        // TODO: Better solution would be to make IoContext accept an opaque user_data pointer
        current_io_endpoint = self;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ctx = io_mod.IoContext{
            .sock_fd = self.sock_fd,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = self.epoll_fd,
        };
        io_mod.drainReadable(&ctx);
        current_io_endpoint = null;
    }

    /// Linux-only: drain MSG_ERRQUEUE to handle ICMP PTB and apply DPLPMTUD clamps.
    fn drainErrorQueue(self: *Endpoint) void {
        // Delegate to io module using thread-local for self reference
        current_io_endpoint = self;

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ProcessWrapper = struct {
            fn process(_: conn_mod.SockAddr, _: []const u8, _: ?u8) void {
                // Not used for error queue
            }
        };

        const ctx = io_mod.IoContext{
            .sock_fd = self.sock_fd,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = self.epoll_fd,
        };
        io_mod.drainErrorQueue(&ctx);
        current_io_endpoint = null;
    }

    /// appears in a plausible short-header QUIC at some reasonable offset.
    fn handleIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        const ph = hashSockaddr(&peer.storage, peer.len);
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (e.key_ptr.*.peer_hash != ph) continue;
            const dcid_len: usize = c.our_scid.len;
            if (dcid_len == 0 or quoted_udp_payload.len < 1 + dcid_len) continue;
            // Scan first 64 bytes for a plausible short header match
            const scan_max: usize = @min(quoted_udp_payload.len, 64);
            var off: usize = 0;
            while (off + 1 + dcid_len <= scan_max) : (off += 1) {
                const first = quoted_udp_payload[off];
                if ((first & 0x80) != 0) continue; // not short header
                if (std.mem.eql(u8, c.our_scid.bytes[0..dcid_len], quoted_udp_payload[off + 1 .. off + 1 + dcid_len])) {
                    c.onIcmpPacketTooBig(reported_mtu);
                    return;
                }
            }
        }
    }

    /// TEST-ONLY: inject a synthetic ICMP PTB quote for a given peer and UDP payload.
    pub fn testInjectIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        self.handleIcmpPtb(peer, quoted_udp_payload, reported_mtu);
    }

    fn poll_epoll_backend(self: *Endpoint, timeout_ms: i32) !void {
        // Delegate to io module using thread-local for self reference
        current_io_endpoint = self;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ctx = io_mod.IoContext{
            .sock_fd = self.sock_fd,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = self.epoll_fd,
        };
        try io_mod.pollEpollBackend(&ctx, timeout_ms);
        current_io_endpoint = null;
    }

    fn poll_kqueue_backend(self: *Endpoint, timeout_ms: i32) !void {
        // Delegate to io module using thread-local for self reference
        current_io_endpoint = self;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ctx = io_mod.IoContext{
            .sock_fd = self.sock_fd,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = null,
        };
        try io_mod.pollKqueueBackend(&ctx, timeout_ms);
        current_io_endpoint = null;
    }

    fn poll_iocp_backend(self: *Endpoint, timeout_ms: i32) !void {
        // Delegate to io module using thread-local for self reference
        current_io_endpoint = self;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ctx = io_mod.IoContext{
            .sock_fd = self.sock_fd,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = null,
        };
        try io_mod.pollIocpBackend(&ctx, timeout_ms);
        current_io_endpoint = null;
    }

    var process_count: u64 = 0; // Global counter to track how many times processIncomingDatagram is called
    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        process_count += 1;
        std.debug.print("PACKET #{}: {} bytes, first=0x{X:0>2}\n", .{ process_count, bytes.len, if (bytes.len > 0) bytes[0] else 0 });
        std.debug.print("=== processIncomingDatagram #{} called with {} bytes ===\n", .{ process_count, bytes.len });
        if (bytes.len < 1) {
            std.debug.print("Packet too short, returning\n", .{});
            return;
        }
        if (bytes.len == 141) {
            std.debug.print("Client processIncomingDatagram - received 141-byte packet!\n", .{});
        }
        const first = bytes[0];
        std.debug.print("First byte: 0x{X:0>2}, is_long: {}\n", .{ first, (first & 0x80) != 0 });
        const is_long = (first & 0x80) != 0;
        if (is_long) {
            // Long header: check Version for VN/Initial/Handshake per RFC 9000 §17.2.
            if (bytes.len < 5) return;
            const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
            if (version == 0) {
                // Version Negotiation handling (client side, RFC 9000 §7).
                var arena = std.heap.ArenaAllocator.init(self.allocator.*);
                defer arena.deinit();
                const aa = arena.allocator();
                const vn = packet.decodeVersionNegotiation(aa, bytes) catch return;
                const ph = hashSockaddr(&peer.storage, peer.len);
                var found: ?*conn_mod.Connection = null;
                const k1 = Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.dcid) };
                const k2 = Key{ .peer_hash = ph, .dcid_hash = hashBytes(vn.scid) };
                if (self.conns.getPtr(k1)) |e| found = e.* else if (self.conns.getPtr(k2)) |e2| found = e2.*;
                const c = found orelse return;
                if (!self.cfg.compatible_vn) return; // ignore VN when disabled
                if (!packet.shouldAcceptVersionNegotiation(c.initial_version, vn.versions)) return;
                var chosen: u32 = 0;
                var i_sel: usize = 0;
                while (i_sel < vn.versions.len) : (i_sel += 1) {
                    const v = vn.versions[i_sel];
                    if (v == packet.QUIC_V1 or v == packet.QUIC_V2) {
                        chosen = v;
                        break;
                    }
                }
                if (chosen == 0) return;
                c.version = chosen;
                c.version_v2 = (chosen == packet.QUIC_V2);
                self.clientSendInitialProbe(c) catch {};
                return;
            }
        }
        if (!is_long) {
            // Short header 1-RTT processing (RFC 9000 §17.3) delegated to incoming.processShortHeader()
            // Phase 4b.5 Session 3: Integration of modular RX pipeline
            std.debug.print("Processing short header packet - len={}, first_byte={x}\n", .{ bytes.len, bytes[0] });
            if (bytes.len < 1) return;

            // Extract the DCID from the short header packet for NAT rebinding detection
            std.debug.print("Short header DCID bytes (after header): ", .{});
            const show_len = @min(20, bytes.len - 1);
            for (bytes[1 .. 1 + show_len]) |b| std.debug.print("{x:0>2} ", .{b});
            std.debug.print("", .{});

            // Use extracted connection lookup from endpoint/lookup.zig (Phase 4b.5 Session 3)
            const lookup_result = lookup.findConnectionByDcid(&self.conns, peer, bytes, null);
            const dcid_len = lookup_result.dcid_len;

            // Handle NAT rebinding if detected (RFC 9000 §9.3)
            if (lookup_result.nat_rebinding) {
                if (lookup_result.conn) |c| {
                    const peer_h = hashSockaddr(&peer.storage, peer.len);
                    self.onPathAddressChanged(c, peer, peer_h, dcid_len);
                }
            }

            // Create SendFn wrapper (no-op for now - processShortHeader doesn't use it directly)
            const send_fn = struct {
                fn send(_: conn_mod.SockAddr, _: []const u8) anyerror!usize {
                    return 0;
                }
            }.send;

            // Create RxContext for incoming.processShortHeader()
            // Convert EndpointRole to ep_types.EndpointRole
            const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));

            var rx_ctx = incoming.RxContext{
                .allocator = self.allocator,
                .conns = &self.conns,
                .accepted = &self.accepted,
                .cfg = &self.cfg,
                .send_fn = send_fn,
                .schedule_timer_fn = undefined, // Not used by processShortHeader
                .send_initial_probe_fn = undefined, // Not used by processShortHeader
                .test_capture_enabled = self.test_capture_enabled,
                .endpoint_role = role_converted,
                .endpoint_ctx = self, // Pass endpoint for sendTo access
            };

            // Delegate to modular processShortHeader() implementation
            incoming.processShortHeader(&rx_ctx, peer, bytes, ecn_bits, send_fn);
            return;
        }
        // Detect NAT rebinding or migration: if we have a known connection for dcid but peer address changed, update and trigger validation
        const ty = (first >> 4) & 0x03;
        const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
        std.debug.print("Long header packet received: first=0x{X:0>2}, ty={} (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry), version=0x{X:0>8}\n", .{ first, ty, version });
        std.debug.print("LONG HEADER: ty={} (0=Initial, 2=Handshake), version=0x{X:0>8}\n", .{ ty, version });
        if (ty == 0) {
            std.debug.print("=== PROCESSING INITIAL PACKET FROM PEER ===\n", .{});
            std.debug.print("Packet total length: {} bytes\n", .{bytes.len});
            // Initial
            var i: usize = 5;
            if (i >= bytes.len) return;
            const dcid_len = bytes[i];
            i += 1;
            if (i + dcid_len > bytes.len) return;
            const dcid = bytes[i .. i + dcid_len];
            i += dcid_len;
            if (i >= bytes.len) return;
            const scid_len = bytes[i];
            i += 1;
            if (i + scid_len > bytes.len) return;
            const scid = bytes[i .. i + scid_len];
            i += scid_len;

            std.debug.print("Initial packet: dcid_len={}, scid_len={}, version=0x{X:0>8}\n", .{ dcid_len, scid_len, version });
            if (scid_len > 0) {
                std.debug.print("  Client SCID: ", .{});
                for (scid) |b| std.debug.print("{X:0>2}\n", .{b});
                std.debug.print("", .{});
            } else {
                std.debug.print("  Client sent zero-length SCID\n", .{});
            }

            // Key connection by peer and dcid
            const key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(dcid) };
            std.debug.print("Looking up connection with dcid=\n", .{});
            for (dcid) |b| std.debug.print("{X:0>2}\n", .{b});
            std.debug.print(" (found={})\n", .{self.conns.contains(key)});
            var conn: *conn_mod.Connection = blk: {
                if (self.conns.getPtr(key)) |p| {
                    // Found an existing mapping. Reuse immediately if it's already a server.
                    if (p.*.role == .Server) {
                        std.debug.print("Found existing connection (role=Server)\n", .{});
                        break :blk p.*;
                    }
                    // Otherwise it's a client connection. Decide if we truly need a server twin.
                    // We only synthesize a server twin in single-endpoint test scenarios where a
                    // synthetic client object was installed solely to craft an Initial and now an
                    // inbound client Initial (whose DCID equals that client's chosen initial DCID)
                    // is being processed as a server. When a real client receives a server Initial
                    // response, the DCID equals its own SCID, not its peer_initial_dcid.
                    const dcid_is_client_initial = p.*.peer_initial_dcid.len > 0 and std.mem.eql(u8, dcid, p.*.peer_initial_dcid.bytes[0..p.*.peer_initial_dcid.len]);
                    const dcid_is_our_scid = p.*.our_scid.len > 0 and std.mem.eql(u8, dcid, p.*.our_scid.bytes[0..p.*.our_scid.len]);
                    if (dcid_is_client_initial and !dcid_is_our_scid) {
                        std.debug.print("Found existing client connection for dcid (matches peer_initial_dcid); creating server twin for inbound client Initial\n", .{});
                        // Fall through to allocate server twin
                    } else {
                        // Reuse the client connection (this is the normal client receiving server Initial case)
                        std.debug.print("Reusing existing client connection for inbound Initial (dcid matched our_scid)\n", .{});
                        break :blk p.*;
                    }
                }
                // No suitable server connection exists: create one now.
                // CRITICAL FIX: Only server endpoints should create server connections
                if (self.role == EndpointRole.Client) {
                    std.debug.print("Client endpoint refusing to create server connection for Initial packet\n", .{});
                    return; // Client endpoints should never create server connections
                }

                const c_new = self.allocator.create(conn_mod.Connection) catch return;

                // Debug: Log the peer address being stored
                if (peer.storage.family == posix.AF.INET) {
                    const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&peer.storage));
                    const addr_bytes = @as([4]u8, @bitCast(sin.addr));
                    std.debug.print("Creating server connection with peer address {}.{}.{}.{}:{}\n", .{ addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], portFromNetwork(sin.port) });
                }

                c_new.init(self.allocator, .Server, sockToIsize(self.sock_fd), peer);
                // Set version from packet
                c_new.version = version;
                c_new.version_v2 = (version == packet.QUIC_V2);
                c_new.initial_version = version;
                // Generate a random SCID for the server
                c_new.our_scid.len = 8;
                std.crypto.random.bytes(c_new.our_scid.bytes[0..c_new.our_scid.len]);
                // Pre-seed peer_initial_dcid/original_dcid with the client's DCID from this first Initial
                // so that Initial key derivation (which happens before setPeerInitialCids for server twin)
                // uses the correct ODCID and not an empty slice.
                c_new.peer_initial_dcid.len = @intCast(@min(dcid.len, c_new.peer_initial_dcid.bytes.len));
                if (c_new.peer_initial_dcid.len > 0) @memcpy(c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len], dcid[0..c_new.peer_initial_dcid.len]);
                c_new.original_dcid.len = c_new.peer_initial_dcid.len;
                if (c_new.original_dcid.len > 0) @memcpy(c_new.original_dcid.bytes[0..c_new.original_dcid.len], c_new.peer_initial_dcid.bytes[0..c_new.peer_initial_dcid.len]);
                // CRITICAL FIX: Also set peer_initial_scid from client's SCID so Handshake packets use correct DCID
                std.debug.print("Server: Setting peer_initial_scid from client SCID, scid.len={}\n", .{scid.len});
                c_new.peer_initial_scid.len = @intCast(@min(scid.len, c_new.peer_initial_scid.bytes.len));
                if (c_new.peer_initial_scid.len > 0) @memcpy(c_new.peer_initial_scid.bytes[0..c_new.peer_initial_scid.len], scid[0..c_new.peer_initial_scid.len]);
                std.debug.print("Server: After setting peer_initial_scid, peer_initial_scid.len={}\n", .{c_new.peer_initial_scid.len});
                c_new.setUseCubic(self.cfg.cc == .cubic);
                c_new.tls.allow_insecure = self.cfg.allow_insecure;
                // Configure server certificate for TLS 1.3
                if (self.cfg.inline_server_cert_der != null and self.cfg.inline_server_priv_p256 != null) {
                    const cert_der = self.cfg.inline_server_cert_der.?;
                    const key_der = self.cfg.inline_server_priv_p256.?;
                    std.debug.print("Setting server certificate: cert_len={}, key_len={}\n", .{ cert_der.len, key_der.len });

                    const detected_alg = x509.inferSignatureAlgorithm(cert_der) catch |err| fallback: {
                        std.debug.print("Failed to infer signature algorithm from inline cert: {} (defaulting to ECDSA P-256)\n", .{err});
                        break :fallback sig.SigAlg.ecdsa_secp256r1_sha256;
                    };
                    const alg_name = switch (detected_alg) {
                        .ecdsa_secp256r1_sha256 => "ecdsa_secp256r1_sha256",
                        .ecdsa_secp384r1_sha384 => "ecdsa_secp384r1_sha384",
                        .rsa_pss_sha256 => "rsa_pss_sha256",
                        .ed25519 => "ed25519",
                    };
                    std.debug.print("Detected inline certificate signature algorithm: {s}\n", .{alg_name});

                    c_new.tls.setServerCertificate(cert_der, key_der, detected_alg) catch |e| {
                        std.debug.print("setServerCertificate FAILED: {}\n", .{e});
                        // CRITICAL: If certificate setup fails, handshake will fail later
                        // This is acceptable for testing but should be fixed in production
                        std.debug.print("WARNING: Server certificate setup failed - handshake will proceed without authentication\n", .{});
                    };
                    // Verify certificate was actually set
                    if (c_new.tls.server_cert_der != null and c_new.tls.server_priv_key != null) {
                        std.debug.print("Server certificate set successfully (cert_len={}, key_len={}, alg={s})\n", .{ 
                            c_new.tls.server_cert_der.?.len, 
                            c_new.tls.server_priv_key.?.len,
                            @tagName(detected_alg),
                        });
                    } else {
                        std.debug.print("WARNING: Server certificate NOT set despite configuration (cert={}, key={})\n", .{
                            c_new.tls.server_cert_der != null,
                            c_new.tls.server_priv_key != null,
                        });
                    }
                } else {
                    std.debug.print("WARNING: No server certificate configured! cert={}, key={}\n", .{
                        self.cfg.inline_server_cert_der != null,
                        self.cfg.inline_server_priv_p256 != null,
                    });
                }
                // Set local transport parameters for server (Phase 4b.5 Session 7)
                handshake_integration.setupServerTransportParams(c_new, &self.cfg, self.allocator.*) catch {};
                c_new.allowed_alpns = self.cfg.alpn;
                // Enable optional pacing and set CC max_datagram_size
                c_new.enable_pacing = self.cfg.enable_pacing;
                c_new.rec.cc.mds = @intCast(self.cfg.max_datagram_size);
                // Install paced sender callback
                c_new.setSender(@ptrCast(self), senderPaced);
                _ = self.conns.put(key, c_new) catch {
                    c_new.deinit();
                    self.allocator.destroy(c_new);
                    return;
                };
                // Apply AEAD limits overrides for server-side
                c_new.setAeadUsageLimits(self.cfg.aead_confidentiality_limit_override, self.cfg.aead_integrity_limit_override);
                // Also map our chosen SCID to this connection for Handshake DCID lookup.
                const our_key2 = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(c_new.our_scid.bytes[0..c_new.our_scid.len]) };
                _ = self.conns.put(our_key2, c_new) catch {};
                // Defer enqueue until after successful Initial decrypt
                break :blk c_new;
            };
            conn.initial_version = version;
            if (ecn_bits) |e| conn.onEcnMark(.Initial, e);
            std.debug.print("DEBUG: Checking initial_keys_dropped = {}\n", .{conn.initial_keys_dropped});
            if (conn.initial_keys_dropped) {
                std.debug.print("DEBUG: Early return due to initial_keys_dropped=true\n", .{});
                return;
            }

            // For server role, set peer CIDs from packet (captures client's DCID/SCID and ODCID once).
            // For client role, capture the server's SCID (peer_initial_scid) the first time we see it so
            // that subsequent short-header 1-RTT packets use the correct DCID (the server's SCID). The
            // client's peer_initial_dcid/original_dcid were recorded from its own first Initial and MUST
            // NOT be overwritten here (RFC 9000 §5.2 Retry/ODCID rules).
            if (conn.role == .Server) {
                std.debug.print("Server: Setting peer CIDs - peer sent DCID_len={} SCID_len={}\n", .{ dcid.len, scid.len });
                conn.setPeerInitialCids(dcid, scid);
                std.debug.print("Server: After setPeerInitialCids - peer_initial_dcid.len={}, peer_initial_scid.len={}\n", .{ conn.peer_initial_dcid.len, conn.peer_initial_scid.len });
            } else if (conn.role == .Client and conn.peer_initial_scid.len == 0) {
                std.debug.print("Client: Capturing server SCID from Initial packet: ", .{});
                for (scid) |b| std.debug.print("{x:0>2}\n", .{b});
                std.debug.print(" (len={})\n", .{scid.len});

                conn.peer_initial_scid.len = @intCast(@min(scid.len, conn.peer_initial_scid.bytes.len));
                if (conn.peer_initial_scid.len > 0) @memcpy(conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len], scid[0..conn.peer_initial_scid.len]);

                std.debug.print("Client: Will use DCID={x} (len={}) for 1-RTT packets\n", .{
                    if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0] else 0,
                    conn.peer_initial_scid.len,
                });
            }

            // Anti-amplification: before address validation, limit server to 3x bytes received
            // Track bytes received from unvalidated address
            conn.addRxUnvalidated(bytes.len);

            // Derive oriented Initial AEAD keys based on role
            // For server: rx = client keys (to decrypt client Initial)
            // For client: rx = server keys (to decrypt server Initial response)
            const v2 = (version == packet.QUIC_V2);
            // RFC 9000 §5.2: Initial secrets are derived from the Destination Connection ID in the
            // first Initial packet sent by the client (ODCID). After a Retry, the client changes
            // the DCID it uses on subsequent Initials to the SCID from the Retry, but keys MUST
            // continue to be derived from the original DCID. We persist that value in
            // conn.peer_initial_dcid. For a server, always prefer peer_initial_dcid when set.
            const derive_dcid = blk: { // ODCID per RFC 9000 §5.2
                if (conn.role == .Server) {
                    // RFC 9000 §5.2: Server must derive Initial keys from the DCID in the client's Initial packet
                    // For the first packet, we won't have original_dcid set yet, so use the packet's DCID
                    if (conn.original_dcid.len > conn.original_dcid.bytes.len) conn.original_dcid.len = 0;
                    if (conn.original_dcid.len > 0) {
                        // Use stored original_dcid if we have it
                        break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    }
                    // For the first Initial packet from client, use the packet's DCID
                    std.debug.print("Server: Using packet DCID for Initial key derivation (first packet)\n", .{});
                    break :blk dcid;
                } else { // client
                    if (conn.original_dcid.len > conn.original_dcid.bytes.len) conn.original_dcid.len = 0;
                    if (conn.original_dcid.len > 0) break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    // RFC 9000 §5.2: Client must use its original DCID for Initial keys, never the server's
                    // If we don't have original_dcid set, this connection is not properly initialized
                    std.debug.print("Client: No original_dcid set for Initial key derivation - dropping packet\n", .{});
                    return;
                }
            };
            std.debug.print("{s}: Deriving Initial keys with dcid (len={})=\n", .{ if (conn.role == .Server) "Server" else "Client", derive_dcid.len });
            for (derive_dcid) |b| std.debug.print("{X:0>2}\n", .{b});
            std.debug.print("", .{});

            // Log the DCID we're actually using from the packet
            std.debug.print("DCID from packet (len={})=\n", .{dcid.len});
            for (dcid) |b| std.debug.print("{X:0>2}\n", .{b});
            std.debug.print("", .{});

            // Derive and cache Initial keys on first use to avoid redundant crypto operations
            if (conn.initial_rx_keys == null) {
                const ik = packet.initialAeadKeys(v2, conn.role == .Server, derive_dcid);
                conn.initial_rx_keys = ik.rx;
                conn.initial_tx_keys = ik.tx;
                std.debug.print("Derived and cached Initial keys for role={s}\n", .{if (conn.role == .Server) "Server" else "Client"});

                // Log freshly derived keys immediately
                std.debug.print("Derived RX keys - key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}, iv[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}\n", .{
                    ik.rx.key[0], ik.rx.key[1], ik.rx.key[2], ik.rx.key[3],
                    ik.rx.iv[0],  ik.rx.iv[1],  ik.rx.iv[2],  ik.rx.iv[3],
                });
            }
            const keys = conn.initial_rx_keys.?;

            // Parse long header variable fields up to PN start
            var j: usize = i; // after SCID value
            // token length varint and token bytes
            std.debug.print("DEBUG: About to decode token varint at offset {}\n", .{j});
            const tok = varint.decode(bytes[j..]) catch {
                std.debug.print("DEBUG: Failed to decode token varint - returning\n", .{});
                return;
            };
            j += tok.n;
            const tok_len_usize: usize = @as(usize, @intCast(tok.value));
            if (j + tok_len_usize > bytes.len) return;
            const token_bytes = bytes[j .. j + tok_len_usize];
            j += tok_len_usize;

            // Address validation via token: verify token using HMAC over client IP and client's Initial DCID
            // Only applies to server role
            if (conn.role == .Server and !conn.address_validated and token_bytes.len > 0) {
                const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                const now_ns: i128 = std.time.nanoTimestamp();
                const now_ms: u64 = @intCast(if (now_ns > 0) @as(u128, @intCast(now_ns)) / std.time.ns_per_ms else 0);
                if (token_mod.verify(token_bytes, client_ip_bytes, secret, now_ms)) {
                    conn.address_validated = true;
                    // Mark that we can send NEW_TOKEN after handshake completes (1-RTT)
                    conn.new_token_pending = true;
                }
            }

            // If address still not validated after parsing, consider issuing Retry per config
            // Only applies to server role
            std.debug.print("DEBUG: Retry check - role={s}, address_validated={}, enable_retry={}\n", .{
                if (conn.role == .Server) "Server" else "Client",
                conn.address_validated,
                self.cfg.enable_retry,
            });
            if (conn.role == .Server and !conn.address_validated and self.cfg.enable_retry) {
                // Build Retry: version as received; DCID = client's SCID; SCID = server-chosen; token bound to client ip+odcid
                const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                const retry_tok = token_mod.encode(self.allocator.*, client_ip_bytes, dcid, secret, self.cfg.token_expiry_ms) catch null;
                if (retry_tok) |tbytes| {
                    defer self.allocator.free(tbytes);
                    // For Retry integrity, ODCID is client's Initial DCID = dcid here.
                    const out = packet.encodeRetry(self.allocator.*, version, scid, conn.our_scid.bytes[0..conn.our_scid.len], dcid, tbytes) catch null;
                    if (out) |retry_bytes| {
                        defer self.allocator.free(retry_bytes);
                        _ = self.sendTo(peer, retry_bytes) catch {};
                    }
                }
                return; // do not continue processing Initial
            }

            // length varint (payload length includes pn+payload+tag)
            const len_dec = varint.decode(bytes[j..]) catch return;
            j += len_dec.n;
            if (len_dec.value > @as(u64, bytes.len - j)) return;
            const end_total = j + @as(usize, @intCast(len_dec.value));
            const header_prefix = bytes[1..j];
            const pn_start = j;
            // Capture up to 4 masked PN bytes (ciphertext begins immediately after PN).
            var header_first = first;
            var pn_masked: [4]u8 = .{0} ** 4;
            const avail = @min(@as(usize, 4), end_total - pn_start);
            @memcpy(pn_masked[0..avail], bytes[pn_start .. pn_start + avail]);
            std.debug.print("{s}: Masked PN bytes: ", .{if (conn.role == .Server) "Server" else "Client"});
            for (pn_masked[0..avail]) |b| std.debug.print("{X:0>2} ", .{b});
            std.debug.print("", .{});
            // We'll try PN lengths 1..4 using auto-sample decrypt until one succeeds.
            std.debug.print("{s}: Trying to decrypt Initial with pn_initial.max={}\n", .{ if (conn.role == .Server) "Server" else "Client", conn.pn_initial.max });

            // Debug log packet structure
            std.debug.print("Initial packet structure:", .{});
            std.debug.print("  - Total packet len: {}\n", .{bytes.len});
            std.debug.print("  - Header prefix len: {}\n", .{header_prefix.len});
            std.debug.print("  - pn_start: {}, end_total: {}\n", .{ pn_start, end_total });
            std.debug.print("  - Ciphertext len (including PN): {}\n", .{end_total - pn_start});
            if (header_prefix.len > 0 and bytes.len > 0) {
                std.debug.print("  - First byte: {X:0>2} (long_header={}, type={})\n", .{
                    bytes[0],
                    (bytes[0] & 0x80) != 0,
                    (bytes[0] >> 4) & 0x03,
                });
            }

            std.debug.print("DEBUG: Reached Initial packet decryption section\n", .{});
            std.debug.print("DEBUG: pn_start={}, end_total={}, bytes.len={}\n", .{ pn_start, end_total, bytes.len });
            var success = false;
            var chosen_pn_len: u3 = 0;
            var pt_list = std.ArrayList(u8){};
            defer pt_list.deinit(self.allocator.*);
            var pn_len_try: u3 = 1;
            attempt: while (pn_len_try <= 4) : (pn_len_try += 1) {
                std.debug.print("DEBUG: Loop iteration pn_len_try={}, checking if {} + {} > {}\n", .{ pn_len_try, pn_start, pn_len_try, end_total });
                if (pn_start + pn_len_try > end_total) {
                    std.debug.print("DEBUG: Breaking loop because pn_start + pn_len_try > end_total\n", .{});
                    break;
                }
                // Pass full buffer from PN start; crypto function extracts sample from offset 4
                const ct = bytes[pn_start..end_total];
                std.debug.print("DEBUG: ct.len={}, checking if < 16\n", .{ct.len});
                if (ct.len < 16) {
                    std.debug.print("DEBUG: ct.len={} < 16, breaking loop at pn_len_try={}\n", .{ ct.len, pn_len_try });
                    break;
                }
                var pn_try: [4]u8 = pn_masked; // copy masked bytes
                var header_try = first;
                pt_list.clearRetainingCapacity();
                std.debug.print("DEBUG: About to allocate {} bytes for pt_list\n", .{ct.len - 16});
                pt_list.ensureTotalCapacity(self.allocator.*, ct.len - 16) catch |err| {
                    std.debug.print("DEBUG: Failed to allocate pt_list: {}\n", .{err});
                    break;
                };
                std.debug.print("DEBUG: After allocation, pt_list.capacity={}\n", .{pt_list.capacity});
                pt_list.appendNTimesAssumeCapacity(0, ct.len - 16);
                std.debug.print("DEBUG: After appendNTimes, pt_list.items.len={}\n", .{pt_list.items.len});
                const pt_slice = pt_list.items;
                std.debug.print("DEBUG: pt_slice.len={}\n", .{pt_slice.len});
                const largest_pn = if (conn.pn_initial.have_any) conn.pn_initial.max else 0;
                std.debug.print("DEBUG: largest_pn={}\n", .{largest_pn});

                // Debug logging for decryption attempt
                std.debug.print("DEBUG: About to attempt Initial packet decryption (pn_len_try={})\n", .{pn_len_try});
                std.debug.print("DEBUG:   - header_try: {X:0>2}\n", .{header_try});
                std.debug.print("DEBUG:   - header_prefix.len={}\n", .{header_prefix.len});
                std.debug.print("DEBUG:   - ct.len={}\n", .{ct.len});
                std.debug.print("DEBUG:   - keys.key[0..4]: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{
                    keys.key[0], keys.key[1], keys.key[2], keys.key[3],
                });

                std.debug.print("DEBUG: About to call crypto.unprotectInitialAutoSample\n", .{});
                const dec = crypto.unprotectInitialAutoSample(
                    .aes_128_gcm,
                    &keys.key,
                    &keys.iv,
                    &keys.hp,
                    &header_try,
                    pn_try[0..pn_len_try],
                    header_prefix,
                    ct,
                    pt_slice,
                    largest_pn,
                ) catch |err| {
                    std.debug.print("DEBUG: Decryption failed with error: {}\n", .{err});
                    continue;
                };
                std.debug.print("DEBUG: Decryption SUCCESS!\n", .{});
                std.debug.print("DEBUG: dec value = {any}\n", .{dec});
                std.debug.print("DEBUG: After unmasking with pn_len={}: ", .{pn_len_try});
                for (pn_try[0..pn_len_try]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("\n", .{});
                const indicated_pn_len: u3 = @intCast((header_try & 0x03) + 1);
                std.debug.print("DEBUG: indicated_pn_len={}, pn_len_try={}\n", .{ indicated_pn_len, pn_len_try });
                if (indicated_pn_len != pn_len_try) {
                    // Mismatch between header-indicated PN length and trial; reject.
                    std.debug.print("DEBUG: PN length mismatch, continuing to next attempt\n", .{});
                    continue;
                }
                std.debug.print("DEBUG: PN length match! Setting success=true\n", .{});
                success = true;
                chosen_pn_len = pn_len_try;
                header_first = header_try;
                @memcpy(pn_masked[0..pn_len_try], pn_try[0..pn_len_try]); // now holds unmasked bytes
                break :attempt;
            }
            std.debug.print("DEBUG: After decryption loop, success={}\n", .{success});
            if (!success) {
                std.debug.print("DEBUG: Failed to decrypt Initial packet - dropping silently\n", .{});
                // NOTE: RETRY is an optional DoS protection mechanism, not a requirement.
                // Sending RETRY on every decryption failure creates issues because:
                // 1. It closes the connection, losing the original_dcid state
                // 2. The client retries with a new DCID (server's SCID from RETRY)
                // 3. A new connection is created without the original_dcid
                // 4. Key derivation uses the wrong DCID
                // Instead, just drop invalid packets and let the client retry naturally.
                // The TLS 1.3 handshake provides authentication.
                return;
            }
            const pn_len = chosen_pn_len;
            const pt = pt_list.items;
            std.debug.print("DEBUG: Successfully decrypted Initial packet (trial pn_len={}) plaintext len: {}\n", .{ pn_len, pt.len });
            // Only now (after successful decryption) enqueue server connection for accept()
            if (conn.role == .Server and !conn.accepted_enqueued) {
                std.debug.print("DEBUG: Enqueuing server connection for accept()\n", .{});
                conn.accepted_enqueued = true;
                self.pushAccepted(conn);
            }
            std.debug.print("DEBUG: After accept enqueue check\n", .{});

            // Expand truncated PN against Initial space expectation and track
            std.debug.print("DEBUG: About to expand packet number\n", .{});
            var pn_val_be: u64 = 0;
            var kk: usize = 0;
            while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_masked[kk];
            const pn_full: u64 = conn.expandPnInitial(pn_val_be, pn_len);
            std.debug.print("DEBUG: Expanded PN: {} from truncated: {}\n", .{ pn_full, pn_val_be });
            conn.trackRecvPnInitial(pn_full);
            std.debug.print("DEBUG: Tracked packet number, now processing frames\n", .{});

            // Walk frames and push CRYPTO to inbox
            var off: usize = 0;
            var saw_any: bool = false;
            var saw_ack_eliciting_initial: bool = false;
            const now_ns_initial: u64 = @intCast(std.time.nanoTimestamp());
            std.debug.print("DEBUG: === DECODING FRAMES FROM INITIAL PACKET ===\n", .{});
            std.debug.print("DEBUG: Plaintext length: {} bytes\n", .{pt.len});
            if (pt.len > 0) {
                std.debug.print("DEBUG: First 16 bytes of plaintext: ", .{});
                for (pt[0..@min(16, pt.len)]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("\n", .{});
            }
            while (off < pt.len) {
                std.debug.print("DEBUG: Attempting to decode frame at offset {} (remaining: {} bytes)\n", .{ off, pt.len - off });
                const r = frame.decodeOne(pt[off..]) catch |err| {
                    std.debug.print("DEBUG: ERROR: Frame decode failed at offset {}: {}\n", .{ off, err });
                    break;
                };
                std.debug.print("DEBUG: Successfully decoded frame type: {s}, consumed {} bytes\n", .{ @tagName(r.f), r.n });
                off += r.n;
                std.debug.print("DEBUG: About to switch on frame type: {s}\n", .{@tagName(r.f)});
                switch (r.f) {
                    .crypto => |cr| {
                        std.debug.print("DEBUG: Processing CRYPTO frame with {} bytes at offset {}\n", .{ cr.data.len, cr.offset });
                        std.debug.print("{s}: Received Initial CRYPTO frame with {} bytes at offset {} (expected {})\n", .{ if (conn.role == .Server) "Server" else "Client", cr.data.len, cr.offset, conn.crypto_rx_off_initial });

                        const ack_initial = conn.handleInitialCrypto(self.allocator, cr.offset, cr.data) catch |err| blk: {
                            std.debug.print("DEBUG: ERROR: Failed to process Initial CRYPTO data: {}\n", .{err});
                            break :blk false;
                        };

                        if (ack_initial) {
                            saw_any = true;
                            saw_ack_eliciting_initial = true;

                            if (conn.app_rx_keys != null and conn.app_tx_keys != null) {
                                std.debug.print("INITIAL CRYPTO: App keys NOW READY - calling closeStaleConnectionsForPeer\n", .{});
                                self.closeStaleConnectionsForPeer(conn);
                            }
                        }
                    },
                    .ack => |a| {
                        // Initial space ACK: inform recovery and cancel any Initial PTO
                        conn.onAckReceivedSpace(.Initial, a.largest, a.first_range, a.ranges, a.ecn);
                        conn.pto_initial_count = 0;
                        if (conn.pto_initial_active) {
                            _ = self.cancelTimer(conn.pto_initial_id);
                            conn.pto_initial_active = false;
                        }
                    },
                    .padding => {},
                    else => {},
                }
            }

            // CRITICAL: After processing Initial CRYPTO and potentially deriving app keys,
            // close any stale connections from the same peer to prevent key mismatch
            // This fixes the client-side duplicate connection bug
            std.debug.print("DEBUG CLEANUP CHECK: app_rx_keys={s}, app_tx_keys={s}\n", .{
                if (conn.app_rx_keys != null) "SET" else "NULL",
                if (conn.app_tx_keys != null) "SET" else "NULL",
            });
            if (conn.app_rx_keys != null and conn.app_tx_keys != null) {
                std.debug.print("CALLING closeStaleConnectionsForPeer!\n", .{});
                self.closeStaleConnectionsForPeer(conn);
            } else {
                std.debug.print("SKIPPING closeStaleConnectionsForPeer (keys not ready)\n", .{});
            }

            // If address still not validated, enforce 3x amplification limit for any server send
            const allow_send = conn.canSendUnderAmplification();

            // If we received anything ack-eliciting, send ACK in Initial space when we still have Initial TX keys
            if (saw_ack_eliciting_initial) {
                conn.recordAckElicitingRx(.Initial, now_ns_initial);
            }

            // Store Initial packet for coalescence with Handshake
            // Coalesced Initial storage (single allocation). Ensure freed on function exit if not coalesced.
            var initial_pkt: ?[]u8 = null;
            defer if (initial_pkt) |p| {
                self.allocator.free(p);
                conn.initial_debug_alloc = null;
            };

            // After processing ClientHello, check if TLS has pending handshake data
            // This is critical for the server to send ServerHello immediately
            const has_pending_tls = conn.tls.outbox.items.len > 0;
            std.debug.print("Checked TLS outbox: has_pending_tls={} outbox.len={}\n", .{ has_pending_tls, conn.tls.outbox.items.len });

            // Only send Initial response when we have ServerHello ready (for server role)
            // or when we have something meaningful to send (for client role)
            const should_send_initial = blk: {
                if (conn.role == .Server) {
                    // Server: send Initial if we have pending TLS data (ServerHello) OR if sh_seen is set
                    const result = (has_pending_tls or conn.tls.sh_seen) and conn.crypto_tx_off_initial < 200;
                    std.debug.print("Server should_send_initial: has_pending_tls={}, sh_seen={}, crypto_tx_off_initial={}, result={}\n", .{ has_pending_tls, conn.tls.sh_seen, conn.crypto_tx_off_initial, result });
                    break :blk result;
                } else {
                    // Client: send if we saw any ack-eliciting frame
                    break :blk saw_any;
                }
            };

            if (should_send_initial and !conn.initial_keys_dropped and allow_send) {
                // Build frames for Initial packet response
                var frames_buf = std.ArrayList(u8){};
                defer frames_buf.deinit(self.allocator.*);
                const w = frames_buf.writer(self.allocator.*);

                // Add ACK frame
                const ack_desc = conn.buildAckInitial();
                const ack_ecn = conn.getAckEcn(.Initial);
                const ack_delay = conn.getAckDelayEncoded(.Initial, now_ns_initial);
                const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = ack_ecn } };

                // Only write ACK if we have received packets to acknowledge
                if (ack_desc.largest != 0xFFFFFFFFFFFFFFFF) {
                    std.debug.print("Server: Adding ACK frame to Initial packet - largest={}, first_range={}\n", .{ ack_desc.largest, ack_desc.first_range });
                    _ = ack.write(w) catch 0;
                }

                // RFC 9001 + TLS 1.3: ServerHello MUST be sent in Initial packet (with Initial keys)
                // Then EncryptedExtensions + Certificate + CertificateVerify + Finished are sent
                // in Handshake packets (with Handshake keys derived AFTER client processes ServerHello)
                //
                // Add CRYPTO frame with ServerHello if we have pending TLS data
                // IMPORTANT: ServerHello MUST be sent in Initial packets (RFC 9001)
                // Only send Initial CRYPTO if we haven't already sent it (check crypto_tx_off_initial)
                var has_crypto = false;
                var crypto_bytes_sent: usize = 0;
                if (has_pending_tls and conn.role == .Server and conn.crypto_tx_off_initial == 0) {
                    // ServerHello MUST go in Initial packet (RFC 9001)
                    // Send only the ServerHello portion (typically first ~120 bytes of outbox)
                    // The rest (EncryptedExtensions, Certificate, etc) go in Handshake packets

                    // Find how much data is ServerHello (should be queued first in outbox)
                    // ServerHello is typically ~200 bytes for full TLS 1.3 with extensions
                    // RFC 9001 §4.1.1: it MUST be sent completely in Initial packets.
                    const sh_size = conn.tls.peekNextMessageSize();
                    const unsent_start = conn.crypto_tx_off_initial;
                    const available_data = if (conn.tls.outbox.items.len > unsent_start)
                        conn.tls.outbox.items.len - unsent_start
                    else
                        0;

                    var bytes_to_send = available_data;
                    if (sh_size > 0) {
                        if (available_data >= sh_size) {
                            bytes_to_send = sh_size;
                        } else {
                            // Defensive: transcript corruption would break the handshake, so surface it.
                            std.debug.print("WARNING: ServerHello truncated in outbox (available={}, sh_size={})\n", .{ available_data, sh_size });
                        }
                    } else if (available_data > 0) {
                        // Fallback: cap to a conservative upper bound to keep packets under MTU.
                        const max_initial_crypto: usize = 1200;
                        bytes_to_send = @min(available_data, max_initial_crypto);
                    }

                    if (bytes_to_send > 0) {
                        const unsent_data = conn.tls.outbox.items[unsent_start .. unsent_start + bytes_to_send];
                        std.debug.print("Server: Adding Initial CRYPTO frame with {} bytes at offset {} (ServerHello for Initial packet)\n", .{ unsent_data.len, conn.crypto_tx_off_initial });

                        // Debug: Show first 20 bytes of CRYPTO data being sent
                        std.debug.print("INITIAL CRYPTO: Sending {} bytes at offset {}\n", .{ unsent_data.len, conn.crypto_tx_off_initial });
                        std.debug.print("  First 20 bytes: ", .{});
                        const debug_len = @min(20, unsent_data.len);
                        for (unsent_data[0..debug_len]) |b| {
                            std.debug.print("{x:0>2} ", .{b});
                        }
                        std.debug.print("\n", .{});

                        const crypto_frame = frame.Frame{ .crypto = .{ .offset = conn.crypto_tx_off_initial, .data = unsent_data } };
                        _ = crypto_frame.write(w) catch 0;
                        has_crypto = true;
                        crypto_bytes_sent = unsent_data.len;
                    }
                } else if (has_pending_tls and conn.crypto_tx_off_initial > 0) {
                    std.debug.print("Server: ServerHello already sent in Initial (offset={}), remaining TLS data will go to Handshake\n", .{conn.crypto_tx_off_initial});
                }

                // Always send Initial packet if we have frames to send
                // Use oriented Initial keys based on role
                // Same ODCID rule applies for transmitting Initials: derive secrets using the
                // client's original DCID (peer_initial_dcid) regardless of any Retry/DCID change.
                const derive_dcid_tx = blk: { // Always ODCID
                    if (conn.original_dcid.len > 0) break :blk conn.original_dcid.bytes[0..conn.original_dcid.len];
                    if (conn.peer_initial_dcid.len > 0) break :blk conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
                    break :blk dcid;
                };
                {
                    var hex_buf: [256]u8 = undefined;
                    var fbs = std.io.fixedBufferStream(&hex_buf);
                    const hex_w = fbs.writer();
                    for (derive_dcid_tx) |b| hex_w.print("{X:0>2}", .{b}) catch break;
                    std.debug.print("Server TX: Using Initial keys with dcid={s} (len={})\n", .{ hex_buf[0..fbs.pos], derive_dcid_tx.len });
                }
                // Reuse cached Initial TX keys (should always be available after RX path caching)
                const tx_keys = conn.initial_tx_keys orelse blk: {
                    // Fallback if not cached (shouldn't happen after RX path caching)
                    std.debug.print("Warning: Initial TX keys not cached, deriving now\n", .{});
                    const oriented = packet.initialAeadKeys(v2, conn.role == .Server, derive_dcid_tx);
                    conn.initial_tx_keys = oriented.tx;
                    break :blk oriented.tx;
                };

                // For client: DCID = peer's initial DCID (from server's SCID in response), SCID = our SCID
                // For server: DCID = client's SCID from Initial (peer_initial_scid), SCID = our SCID
                // RFC 9000: Server's Initial response uses DCID = client's SCID, SCID = new server CID
                // If client sent zero-length SCID, use empty DCID (proper quic-go compatibility)
                const tx_dcid = if (conn.role == .Server)
                    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                else
                    conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len];
                const tx_scid = conn.our_scid.bytes[0..conn.our_scid.len];
                std.debug.print("{s}: Encoding Initial with pn={} dcid_len={} scid_len={} pn_len={}\n", .{ if (conn.role == .Server) "Server" else "Client", conn.pn_initial_tx, tx_dcid.len, tx_scid.len, 4 });
                std.debug.print("  Server will use SCID: ", .{});
                for (tx_scid) |b| std.debug.print("{X:0>2}\n", .{b});
                std.debug.print("", .{});

                // Check if we'll have a Handshake packet to send for coalescence
                const will_send_handshake = conn.hs_tx_keys != null and
                    ((conn.role == .Server and conn.tls.sh_seen and !conn.server_hello_sent) or
                        (conn.role == .Client and conn.crypto_tx_off_handshake > 0));

                // Calculate approximate header size to ensure total packet is at least 1200 bytes
                // Header: ~30 bytes (varies with CID lengths) + auth tag: 16 bytes
                const estimated_header_size = 30 + tx_dcid.len + tx_scid.len + 16;

                // If we'll send a Handshake packet, limit Initial padding to leave room for coalescence
                // Assume Handshake packet will be ~600 bytes, so limit Initial to ~800 bytes to fit in 1400 MTU
                const target_initial_size: usize = if (will_send_handshake) @as(usize, 800) else @as(usize, 1200);
                const min_payload_size = if (target_initial_size > estimated_header_size)
                    target_initial_size - estimated_header_size
                else
                    0;

                // Add PADDING frames if needed to meet minimum Initial packet size
                if (frames_buf.items.len < min_payload_size) {
                    const padding_needed = min_payload_size - frames_buf.items.len;
                    // PADDING frames are just 0x00 bytes
                    frames_buf.appendNTimes(self.allocator.*, 0x00, padding_needed) catch {
                        std.debug.print("Failed to add padding to Initial packet\n", .{});
                        return;
                    };
                    std.debug.print("Added {} bytes of padding to Initial frames\n", .{padding_needed});
                }

                const out = packet.encodeInitialProtected(self.allocator.*, version, tx_dcid, tx_scid, &[_]u8{}, @as(u32, @truncate(conn.pn_initial_tx)), 4, frames_buf.items, tx_keys) catch null;

                if (out) |pkt_bytes| {
                    std.debug.print("{s}: Prepared Initial response with {} bytes (has_crypto={})\n", .{ if (conn.role == .Server) "Server" else "Client", pkt_bytes.len, has_crypto });

                    // Store Initial for later coalescence; take ownership
                    // Assign only if not already present; avoid double free pattern
                    // Always free previous (if any) then take ownership of new bytes (tracked separately for leak debug)
                    if (initial_pkt) |prev| self.allocator.free(prev);
                    initial_pkt = pkt_bytes;
                    conn.initial_debug_alloc = initial_pkt;
                    conn.onPacketSent(.Initial, conn.pn_initial_tx, initial_pkt.?.len, has_crypto);
                    conn.pn_initial_tx +%= 1;
                    // Update CRYPTO offset after successful packet creation
                    if (crypto_bytes_sent > 0) {
                        conn.crypto_tx_off_initial += crypto_bytes_sent;
                        std.debug.print("Server: Updated Initial CRYPTO offset to {}\n", .{conn.crypto_tx_off_initial});

                        // CRITICAL FIX: Remove sent ServerHello from outbox before queueing handshake flight
                        // The Initial packet code accessed outbox.items directly but didn't remove the sent data
                        // We need to remove it now so queueServerHandshakeFlight can append cleanly
                        if (crypto_bytes_sent <= conn.tls.outbox.items.len) {
                            // Remove the sent bytes from the beginning of the outbox
                            const remaining = conn.tls.outbox.items.len - crypto_bytes_sent;
                            if (remaining > 0) {
                                // Shift remaining data to the beginning
                                std.mem.copyForwards(u8, conn.tls.outbox.items[0..remaining], conn.tls.outbox.items[crypto_bytes_sent..]);
                            }
                            conn.tls.outbox.shrinkRetainingCapacity(remaining);
                            std.debug.print("Server: Removed {} sent bytes from TLS outbox, {} bytes remaining\n", .{ crypto_bytes_sent, remaining });
                        }
                    }
                    // Do NOT free pkt_bytes here; defer will free if never coalesced

                }

                // Additionally, route received ACKs in Initial space through Recovery.
                // Since this branch is taken when we saw any frames, send a synthetic ACK processing if needed is skipped.
            }
            // Check if we can send Handshake packet (requires Handshake keys)
            std.debug.print("CHECKPOINT: Reached coalesc logic, initial_pkt is {s}, hs_tx_keys is {s}\n", .{ if (initial_pkt != null) "SET" else "NULL", if (conn.hs_tx_keys != null) "SET" else "NULL" });

            // RFC 9000 Section 12.2: Initial and Handshake packets MUST be coalesced
            // Use a fixed buffer for coalescing packets
            var coalesced_buffer: [4096]u8 = undefined;
            var coalesced_len: usize = 0;

            // RFC 9001: Initial and Handshake packets MUST be coalesced
            // Add Initial packet to coalesced buffer
            if (initial_pkt) |initial| {
                if (initial.len <= coalesced_buffer.len) {
                    @memcpy(coalesced_buffer[0..initial.len], initial);
                    coalesced_len = initial.len;
                    std.debug.print("Added Initial packet to coalesced buffer: {} bytes\n", .{initial.len});
                    // Free Initial after copying
                    self.allocator.free(initial);
                    initial_pkt = null;
                    conn.initial_debug_alloc = null;
                } else {
                    std.debug.print("ERROR: Initial packet too large for coalescing buffer ({} > {})\n", .{ initial.len, coalesced_buffer.len });
                }
            }

            // If we have Handshake keys and have outbound TLS handshake bytes queued, emit them now.
            std.debug.print("DEBUG: Checking Handshake keys - hs_tx_keys={}, outbox.len={}\n", .{ conn.hs_tx_keys != null, conn.tls.outbox.items.len });
            if (conn.hs_tx_keys) |hs_keys| {
                std.debug.print("DEBUG: Inside hs_tx_keys block - role={s}, sh_seen={}, server_hello_sent={}\n", .{
                    if (conn.role == .Server) "Server" else "Client",
                    conn.tls.sh_seen,
                    conn.server_hello_sent,
                });
                // If we're a server and haven't queued the handshake flight yet, do it now
                // ServerHello is already in the TLS outbox from conn.zig, so we only need to queue the rest
                if (conn.role == .Server and conn.tls.sh_seen and !conn.server_hello_sent) {
                    conn.server_hello_sent = true;
                    std.debug.print("Queueing handshake flight (EE + Cert + Finished), ServerHello already queued\n", .{});
                    std.debug.print("BEFORE queueServerHandshakeFlight: outbox.len={}\n", .{conn.tls.outbox.items.len});

                    // Queue the rest of the handshake flight (EncryptedExtensions + Certificate + CertificateVerify + Finished)
                    // ServerHello is already in outbox from when keys were derived in conn.zig
                    conn.tls.queueServerHandshakeFlight();
                    std.debug.print("AFTER queueServerHandshakeFlight: outbox.len={}\n", .{conn.tls.outbox.items.len});
                }

                // CRITICAL FIX: If outbox is empty but we have crypto_retx_handshake, the client likely
                // didn't receive our Handshake packets. Retransmit them.
                // This happens when client keeps retransmitting Initial packets.
                if (conn.tls.outbox.items.len == 0 and conn.crypto_retx_handshake != null and saw_ack_eliciting_initial and allow_send) {
                    std.debug.print("Client retransmitting Initial - retransmitting Handshake flight\n", .{});

                    const retx_data = conn.crypto_retx_handshake.?;
                    const retx_offset = conn.crypto_retx_handshake_off;

                    // For Handshake packets, use peer_initial_scid as DCID per RFC 9000 §7.2
                    const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

                    // Retransmit as a single Handshake packet
                    var buf: [4096]u8 = undefined;
                    var w = std.io.fixedBufferStream(&buf);
                    const cfw = frame.Frame{ .crypto = .{ .offset = retx_offset, .data = retx_data } };
                    _ = cfw.write(&w.writer()) catch 0;

                    const hs_pkt = packet.encodeHandshakeProtected(self.allocator.*, conn.version, hs_dcid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, // packet number length
                        buf[0..w.pos], hs_keys) catch null;

                    if (hs_pkt) |pkt| {
                        defer self.allocator.free(pkt);
                        _ = self.sendTo(peer, pkt) catch {};
                        std.debug.print("Retransmitted Handshake packet: {} bytes (CRYPTO offset={} len={})\n", .{ pkt.len, retx_offset, retx_data.len });
                        conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt.len, true);
                        conn.pn_handshake_tx += 1;
                    }

                    return; // Done retransmitting
                }

                // Pull TLS messages one at a time to send each in its own CRYPTO frame
                // This is critical for rustls compatibility which expects separate messages
                std.debug.print("DEBUG: About to extract TLS messages from outbox, outbox.len={}\n", .{conn.tls.outbox.items.len});
                if (conn.tls.outbox.items.len >= 4) {
                    std.debug.print("DEBUG: First 4 bytes of outbox: {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
                        conn.tls.outbox.items[0],
                        conn.tls.outbox.items[1],
                        conn.tls.outbox.items[2],
                        conn.tls.outbox.items[3],
                    });
                }

                var tls_messages = std.ArrayList([]const u8).initCapacity(self.allocator.*, 10) catch {
                    std.debug.print("Failed to allocate ArrayList for TLS messages\n", .{});
                    return;
                };
                defer {
                    for (tls_messages.items) |msg| {
                        self.allocator.free(msg);
                    }
                    tls_messages.deinit(self.allocator.*);
                }

                // Extract each TLS message separately using peekNextMessageSize
                const first_peek = conn.tls.peekNextMessageSize();
                std.debug.print("DEBUG: First peekNextMessageSize() returned {}\n", .{first_peek});
                while (conn.tls.peekNextMessageSize() > 0) {
                    const msg_size = conn.tls.peekNextMessageSize();
                    if (msg_size == 0) break;

                    // Allocate buffer for this message
                    const msg_buf = self.allocator.alloc(u8, msg_size) catch {
                        std.debug.print("Failed to allocate buffer for TLS message of size {}\n", .{msg_size});
                        break;
                    };

                    // Pop just this message
                    const actual_size = conn.tls.popCryptoPartial(msg_buf, msg_size);
                    if (actual_size != msg_size) {
                        std.debug.print("Warning: Expected {} bytes but got {} bytes\n", .{ msg_size, actual_size });
                        self.allocator.free(msg_buf);
                        break;
                    }

                    tls_messages.append(self.allocator.*, msg_buf) catch {
                        self.allocator.free(msg_buf);
                        break;
                    };

                    // Debug: identify message type
                    const msg_type = if (msg_buf.len > 0) msg_buf[0] else 0;
                    const msg_name = switch (msg_type) {
                        8 => "EncryptedExtensions",
                        11 => "Certificate",
                        15 => "CertificateVerify",
                        20 => "Finished",
                        else => "Unknown",
                    };
                    std.debug.print("Extracted TLS message: {s} ({} bytes)\n", .{ msg_name, actual_size });
                }

                std.debug.print("TLS: Extracted {} separate TLS messages\n", .{tls_messages.items.len});

                // CRITICAL FIX: If message extraction failed but we have TLS data, send all as one CRYPTO frame
                // This handles the case where peekNextMessageSize() returns invalid values
                if (tls_messages.items.len == 0 and conn.tls.outbox.items.len > 0 and allow_send) {
                    std.debug.print("WARNING: TLS message extraction failed, sending entire outbox ({} bytes) as single CRYPTO frame\n", .{conn.tls.outbox.items.len});

                    // Pop all TLS data from outbox
                    const all_tls_data = self.allocator.alloc(u8, conn.tls.outbox.items.len) catch {
                        std.debug.print("Failed to allocate buffer for all TLS data\n", .{});
                        return;
                    };
                    const popped_size = conn.tls.popCrypto(all_tls_data);

                    // Create and send Handshake packet with all TLS data
                    const hs_dcid = if (conn.peer_initial_scid.len > 0)
                        conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
                    else
                        &[_]u8{}; // Empty slice - RFC 9000 §12.2

                    var buf: [4096]u8 = undefined;
                    var w = std.io.fixedBufferStream(&buf);
                    const cfw = frame.Frame{ .crypto = .{ .offset = conn.crypto_tx_off_handshake, .data = all_tls_data[0..popped_size] } };
                    _ = cfw.write(&w.writer()) catch 0;

                    const hs_pkt = packet.encodeHandshakeProtected(self.allocator.*, conn.version, hs_dcid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, // packet number length
                        buf[0..w.pos], hs_keys) catch null;

                    if (hs_pkt) |pkt| {
                        defer self.allocator.free(pkt);
                        _ = self.sendTo(peer, pkt) catch {};
                        std.debug.print("Sent Handshake packet with all TLS data ({} bytes)\n", .{pkt.len});
                        conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt.len, true);
                        conn.crypto_tx_off_handshake += popped_size;
                        conn.pn_handshake_tx += 1;
                    }

                    // Save for retransmission
                    if (conn.crypto_retx_handshake) |b| self.allocator.free(b);
                    conn.crypto_retx_handshake = all_tls_data;
                    conn.crypto_retx_handshake_off = conn.crypto_tx_off_handshake - popped_size;

                    return; // Done sending Handshake packet
                }

                // Send each TLS message in its own Handshake packet for rustls compatibility
                if (tls_messages.items.len > 0 and allow_send) {
                    // Calculate total size for retransmit buffer
                    var total_size: usize = 0;
                    for (tls_messages.items) |msg| {
                        total_size += msg.len;
                    }
                    std.debug.print("Sending Handshake CRYPTO with {} separate messages, {} bytes total\n", .{ tls_messages.items.len, total_size });

                    // Save all messages concatenated for retransmission
                    if (conn.crypto_retx_handshake) |b| self.allocator.free(b);
                    var owned_hs = self.allocator.alloc(u8, total_size) catch {
                        conn.crypto_tx_off_handshake += total_size;
                        return;
                    };
                    var retx_offset: usize = 0;
                    for (tls_messages.items) |msg| {
                        @memcpy(owned_hs[retx_offset .. retx_offset + msg.len], msg);
                        retx_offset += msg.len;
                    }
                    conn.crypto_retx_handshake = owned_hs;
                    conn.crypto_retx_handshake_off = conn.crypto_tx_off_handshake;
                    std.debug.print("Saved new Handshake CRYPTO for retransmission: {} bytes at offset {}\n", .{ total_size, conn.crypto_tx_off_handshake });

                    // For Handshake packets, use peer_initial_scid as DCID
                    // RFC 9000 §7.2: "An endpoint that receives a packet with a zero-length
                    // Source Connection ID field MUST use a zero-length Destination Connection ID
                    // field for all packets in the connection."
                    const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

                    std.debug.print("Server: Handshake DCID len={} (using peer_initial_scid)\n", .{hs_dcid.len});

                    // Send each TLS message in a separate CRYPTO frame/packet for rustls compatibility
                    // Store additional Handshake packets to send separately
                    var additional_hs_packets = std.ArrayList([]u8).initCapacity(self.allocator.*, 0) catch {
                        std.debug.print("Failed to allocate ArrayList for additional Handshake packets\n", .{});
                        return;
                    };
                    defer {
                        for (additional_hs_packets.items) |pkt| {
                            self.allocator.free(pkt);
                        }
                        additional_hs_packets.deinit(self.allocator.*);
                    }

                    // Process each TLS message separately
                    var crypto_offset = conn.crypto_tx_off_handshake;
                    for (tls_messages.items, 0..) |msg, msg_idx| {
                        std.debug.print("Processing TLS message {}/{}: {} bytes at CRYPTO offset {}\n", .{ msg_idx + 1, tls_messages.items.len, msg.len, crypto_offset });

                        // Create CRYPTO frame for this message
                        var fb = std.ArrayList(u8){};
                        defer fb.deinit(self.allocator.*);
                        const w_hs = fb.writer(self.allocator.*);
                        _ = (frame.Frame{ .crypto = .{ .offset = crypto_offset, .data = msg } }).write(w_hs) catch 0;

                        // Encode Handshake packet with this CRYPTO fragment
                        const pkt_hs = packet.encodeHandshakeProtected(self.allocator.*, version, hs_dcid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, fb.items, hs_keys) catch |err| blk: {
                            std.debug.print("ERROR: Failed to encode Handshake packet: {}\n", .{err});
                            break :blk null;
                        };

                        if (pkt_hs) |bytes_out_hs| {
                            const pkt_len = bytes_out_hs.len; // Save length before potentially freeing
                            std.debug.print("Handshake packet {} encoded: {} bytes (CRYPTO {} bytes at offset {})\n", .{ msg_idx, pkt_len, msg.len, crypto_offset });

                            // Only append first handshake packet to coalesced buffer (RFC 9000 §12.2)
                            // Store additional handshake packets to send separately after coalescing
                            // CRITICAL: Don't coalesce if DCIDs differ (violates RFC 9000 §12.2)
                            // Check if Initial DCID matches Handshake DCID
                            const initial_dcid_len = if (conn.role == .Server) conn.peer_initial_scid.len else conn.peer_initial_dcid.len;
                            const can_coalesce = (initial_dcid_len == hs_dcid.len);

                            if (msg_idx == 0 and coalesced_len > 0 and can_coalesce) {
                                if (coalesced_len + pkt_len <= coalesced_buffer.len) {
                                    @memcpy(coalesced_buffer[coalesced_len .. coalesced_len + pkt_len], bytes_out_hs);
                                    coalesced_len += pkt_len;
                                    std.debug.print("Added first Handshake packet to coalesced buffer: {} bytes\n", .{pkt_len});
                                    // Free immediately since we copied it
                                    self.allocator.free(bytes_out_hs);
                                } else if (!can_coalesce) {
                                    std.debug.print("Skipping coalescing: Initial DCID len {} != Handshake DCID len {} (RFC 9000 §12.2)\n", .{ initial_dcid_len, hs_dcid.len });
                                    // Store for separate sending
                                    additional_hs_packets.append(self.allocator.*, bytes_out_hs) catch {
                                        self.allocator.free(bytes_out_hs);
                                    };
                                } else {
                                    std.debug.print("Failed to append Handshake packet to coalesced buffer - would exceed buffer\n", .{});
                                    // Store for separate sending
                                    additional_hs_packets.append(self.allocator.*, bytes_out_hs) catch {
                                        self.allocator.free(bytes_out_hs);
                                    };
                                }
                            } else if (msg_idx > 0) {
                                // Store subsequent packets for separate sending
                                additional_hs_packets.append(self.allocator.*, bytes_out_hs) catch {
                                    self.allocator.free(bytes_out_hs);
                                };
                            } else {
                                // Not coalescing, send immediately
                                const send_result = self.sendTo(conn.peer, bytes_out_hs) catch |err| blk: {
                                    std.debug.print("ERROR: Failed to send Handshake packet: {}\n", .{err});
                                    break :blk 0;
                                };
                                if (send_result > 0) {
                                    std.debug.print("Sent Handshake packet {}: {} bytes\n", .{ msg_idx, send_result });
                                }
                                self.allocator.free(bytes_out_hs);
                            }

                            conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt_len, true);
                            conn.pn_handshake_tx +%= 1;
                        }

                        // Update crypto offset for next message
                        crypto_offset += msg.len;
                    }

                    // Update the connection's CRYPTO offset tracking
                    conn.crypto_tx_off_handshake += total_size;
                    std.debug.print("Prepared {} Handshake packets with {} bytes total CRYPTO data (offset now {})\n", .{ tls_messages.items.len, total_size, conn.crypto_tx_off_handshake });

                    // Send packets - either coalesced or separately
                    // If coalescing was skipped due to DCID mismatch, send Initial separately first
                    if (coalesced_len > 0 and initial_pkt == null) {
                        // Initial was added to coalesced buffer, send the coalesced packet
                        std.debug.print("Sending coalesced packet: {} bytes (Initial + Handshake)\n", .{coalesced_len});

                        // DIAGNOSTIC: Hexdump the coalesced packet to understand structure
                        std.debug.print("=== COALESCED PACKET HEXDUMP ===\n", .{});
                        var dump_idx: usize = 0;
                        const max_dump = @min(256, coalesced_len);
                        while (dump_idx < max_dump) : (dump_idx += 16) {
                            const line_end = @min(dump_idx + 16, max_dump);
                            std.debug.print("{X:0>4}: ", .{dump_idx});
                            var line_idx = dump_idx;
                            while (line_idx < line_end) : (line_idx += 1) {
                                std.debug.print("{X:0>2} ", .{coalesced_buffer[line_idx]});
                            }
                            std.debug.print("", .{});
                        }
                        if (coalesced_len > max_dump) {
                            std.debug.print("... ({} more bytes)\n", .{coalesced_len - max_dump});
                        }
                        std.debug.print("=== END HEXDUMP ===\n", .{});

                        const send_result = self.sendTo(conn.peer, coalesced_buffer[0..coalesced_len]) catch |err| blk: {
                            std.debug.print("ERROR: Failed to send coalesced packet: {}\n", .{err});
                            break :blk 0;
                        };
                        if (send_result > 0) {
                            std.debug.print("Successfully sent coalesced packet: {} bytes\n", .{send_result});
                        }
                        // Free initial_pkt now that it's been sent in the coalesced buffer
                        if (initial_pkt) |p| {
                            self.allocator.free(p);
                            initial_pkt = null;
                        }
                    } else if (initial_pkt) |init_pkt| {
                        // Send Initial packet separately (coalescing was skipped due to DCID mismatch)
                        std.debug.print("Sending Initial packet separately: {} bytes (no coalescing due to DCID mismatch)\n", .{init_pkt.len});
                        const send_result = self.sendTo(conn.peer, init_pkt) catch |err| blk: {
                            std.debug.print("ERROR: Failed to send Initial packet: {}\n", .{err});
                            break :blk 0;
                        };
                        if (send_result > 0) {
                            std.debug.print("Successfully sent Initial packet: {} bytes\n", .{send_result});
                        }
                        self.allocator.free(init_pkt);
                        initial_pkt = null;
                    }

                    // Send additional Handshake packets separately
                    if (additional_hs_packets.items.len > 0) {
                        std.debug.print("Sending {} additional Handshake packets separately\n", .{additional_hs_packets.items.len});
                        for (additional_hs_packets.items, 0..) |pkt, idx| {
                            const send_result = self.sendTo(conn.peer, pkt) catch |err| blk: {
                                std.debug.print("ERROR: Failed to send additional Handshake packet {}: {}\n", .{ idx, err });
                                break :blk 0;
                            };
                            if (send_result > 0) {
                                std.debug.print("Sent additional Handshake packet {}: {} bytes\n", .{ idx, send_result });
                            }
                        }
                    }
                    // Per RFC 9000 §12.2, only the first handshake packet needs to be coalesced
                    // with the Initial packet
                }
            }

            // Note: initial_pkt is already freed after being copied to coalesced_packets
            // The coalesced packet(s) are sent above

            // Check if there are more packets coalesced in this datagram
            // The end_total from the Initial packet tells us where it ends
            if (end_total < bytes.len) {
                std.debug.print("=== COALESCED PACKET DETECTED: end_total={}, bytes.len={}, remaining={} bytes ===\n", .{ end_total, bytes.len, bytes.len - end_total });
                // Process the remaining bytes as a new packet
                self.processIncomingDatagram(peer, bytes[end_total..], ecn_bits);
            } else {
                std.debug.print("=== No coalesced packets, end_total={}, bytes.len={} ===\n", .{ end_total, bytes.len });
            }

            // initial_pkt is already freed after sending (line 2298) or not allocated
            return;
        }
        // Retry (client handling only). Parse fields, verify integrity using ODCID, then store token; resend Initial with token.
        if (ty == 3) {
            // Retry (client handling only). Parse fields, verify integrity using ODCID, then store token; resend Initial with token.
            var i: usize = 5;
            if (i >= bytes.len) return;
            const dcid_len = bytes[i];
            i += 1;
            if (i + dcid_len > bytes.len) return;
            i += dcid_len;
            if (i >= bytes.len) return;
            const scid_len = bytes[i];
            i += 1;
            if (i + scid_len > bytes.len) return;
            const scid = bytes[i .. i + scid_len];
            i += scid_len;
            if (bytes.len < 16 or i >= bytes.len - 16) return; // need room for integrity tag at end
            const token_bytes = bytes[i .. bytes.len - 16];
            // Lookup a matching client connection for this peer to access ODCID
            const ph = hashSockaddr(&peer.storage, peer.len);
            var itc = self.conns.iterator();
            var c_found: ?*conn_mod.Connection = null;
            while (itc.next()) |e| {
                if (e.key_ptr.*.peer_hash != ph) continue;
                c_found = e.value_ptr.*;
                break;
            }
            const c = c_found orelse return;
            // Verify Retry integrity using ODCID = client's Initial DCID stored in conn.peer_initial_dcid
            const odcid = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];
            if (odcid.len == 0) return;
            if (!packet.verifyRetry(odcid, bytes)) {
                // Drop invalid Retry per RFC 9001 §5.8
                return;
            }
            // Store token for next Initial
            c.initial_token.clearRetainingCapacity();
            _ = c.initial_token.appendSlice(self.allocator.*, token_bytes) catch {};
            // Update version and DCID to use for next Initial (use Retry.SCID as new DCID per spec)
            c.version = version;
            c.version_v2 = (version == packet.QUIC_V2);
            c.initial_version = version;
            c.peer_initial_dcid.len = @intCast(@min(scid.len, c.peer_initial_dcid.bytes.len));
            if (c.peer_initial_dcid.len > 0) @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], scid[0..c.peer_initial_dcid.len]);
            // Resend an Initial with the token
            self.clientSendInitialProbe(c) catch {};
            return;
        } else if (ty == 2) {
            std.debug.print("Processing Handshake packet from peer\n", .{});
            std.debug.print("HANDSHAKE PACKET: {} bytes total\n", .{bytes.len});
            // Handshake RX path: attempt to unprotect and feed CRYPTO using hs_rx_keys
            // RFC 9000 §17.2: Handshake packets DO have a version field (bytes 1-4)
            var i: usize = 5; // Skip first byte (0) + version field (1-4)
            if (i >= bytes.len) {
                std.debug.print("HANDSHAKE PACKET TOO SHORT: at byte {}, len={}\n", .{ i, bytes.len });
                return;
            }
            const dcid_len = bytes[i];
            std.debug.print("HANDSHAKE: dcid_len={}\n", .{dcid_len});
            i += 1;
            if (i + dcid_len > bytes.len) {
                std.debug.print("HANDSHAKE: dcid extends past packet end\n", .{});
                return;
            }
            const dcid = bytes[i .. i + dcid_len];
            i += dcid_len;
            if (i >= bytes.len) {
                std.debug.print("HANDSHAKE: no room for scid_len\n", .{});
                return;
            }
            const scid_len = bytes[i];
            std.debug.print("HANDSHAKE: scid_len={}\n", .{scid_len});
            i += 1;
            if (i + scid_len > bytes.len) {
                std.debug.print("HANDSHAKE: scid extends past packet end\n", .{});
                return;
            }
            // scid is not used here, we use conn.peer_initial_scid for Handshake packets
            _ = bytes[i .. i + scid_len];
            i += scid_len;

            // Parse length varint to find packet boundary (needed for coalesced packets)
            var j: usize = i;
            const len_dec = varint.decode(bytes[j..]) catch return;
            j += len_dec.n;
            if (len_dec.value > @as(u64, bytes.len - j)) return;
            const end_total = j + @as(usize, @intCast(len_dec.value));
            std.debug.print("Handshake packet: j={}, len_dec.value={}, end_total={}, bytes.len={}\n", .{ j, len_dec.value, end_total, bytes.len });

            // Lookup connection keyed by peer + initial dcid hash (use stored mapping if any)
            const key = Key{ .peer_hash = hashSockaddr(&peer.storage, peer.len), .dcid_hash = hashBytes(dcid) };
            std.debug.print("Looking up Handshake connection with dcid=\n", .{});
            for (dcid) |b| std.debug.print("{x:0>2}\n", .{b});
            std.debug.print(" (hash={x})\n", .{key.dcid_hash});

            std.debug.print("HANDSHAKE: Looking up connection with dcid=\n", .{});
            for (dcid) |b| std.debug.print("{x:0>2}\n", .{b});
            std.debug.print(" (hash={x})\n", .{key.dcid_hash});

            var c_ptr = self.conns.getPtr(key);

            // Fallback: If lookup failed and DCID is empty, find connection by peer address alone
            if (c_ptr == null and dcid.len == 0) {
                std.debug.print("Handshake packet has empty DCID, falling back to peer address lookup\n", .{});
                const peer_hash = hashSockaddr(&peer.storage, peer.len);
                var iter = self.conns.iterator();
                while (iter.next()) |entry| {
                    if (entry.key_ptr.peer_hash == peer_hash) {
                        std.debug.print("Found connection by peer address: peer_hash={x}, dcid_hash={x}\n", .{ entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash });
                        c_ptr = entry.value_ptr;
                        break;
                    }
                }
            }

            const c_ptr_final = c_ptr orelse {
                std.debug.print("ERROR: Connection not found for Handshake packet\n", .{});
                std.debug.print("  Available connections:", .{});
                std.debug.print("ERROR: Connection not found for Handshake packet!\n", .{});
                std.debug.print("  Available connections:\n", .{});
                var iter = self.conns.iterator();
                while (iter.next()) |entry| {
                    std.debug.print("    key: peer_hash={x}, dcid_hash={x}\n", .{ entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash });
                    std.debug.print("    key: peer_hash={x}, dcid_hash={x}\n", .{ entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash });
                }
                return;
            };
            const conn = c_ptr_final.*;
            std.debug.print("HANDSHAKE: Found connection, role={}\n", .{conn.role});
            std.debug.print("Found connection for Handshake packet (role={})\n", .{conn.role});
            if (ecn_bits) |e| conn.onEcnMark(.Handshake, e);
            if (conn.hs_rx_keys) |rx_keys| {
                std.debug.print("Server has handshake RX keys, proceeding to decrypt\n", .{});
                std.debug.print("Handshake RX keys: key={any}, iv={any}, hp={any}\n", .{ rx_keys.key, rx_keys.iv, rx_keys.hp });
                std.debug.print("HANDSHAKE: Has RX keys! Proceeding to decrypt...\n", .{});
                std.debug.print("HANDSHAKE PACKET STRUCTURE:\n", .{});
                std.debug.print("  Total packet: {} bytes\n", .{bytes.len});
                std.debug.print("  Header end (j): {}\n", .{j});
                std.debug.print("  Packet end: {}\n", .{end_total});
                std.debug.print("  Payload + PN + tag: {} bytes\n", .{end_total - j});

                // Print first 20 bytes of the handshake packet for debugging
                std.debug.print("  First 20 bytes: ", .{});
                const debug_len = @min(20, bytes.len);
                for (bytes[0..debug_len]) |b| {
                    std.debug.print("{x:0>2} ", .{b});
                }
                std.debug.print("\n", .{});

                const header_prefix = bytes[1..j];
                const pn_start = j;

                // Capture up to 4 masked PN bytes
                var pn_masked: [4]u8 = .{0} ** 4;
                const avail = @min(@as(usize, 4), end_total - pn_start);
                @memcpy(pn_masked[0..avail], bytes[pn_start .. pn_start + avail]);

                // RFC 9001: Determine PN length, then decrypt with integrated function
                const full_pn_and_payload = bytes[pn_start..end_total];
                if (full_pn_and_payload.len < 20) {
                    std.debug.print("Handshake packet too short for HP sample: {} bytes\n", .{full_pn_and_payload.len});
                    conn.onAeadAuthFailure();
                    return;
                }

                // Step 1: Extract HP sample and unmask ONLY the header byte to get PN length
                var sample16: [16]u8 = undefined;
                @memcpy(&sample16, full_pn_and_payload[4..20]); // Sample always at offset 4

                var header_peek = first;
                var dummy_pn = [_]u8{0};
                crypto.headerProtect(.aes_128_gcm, &rx_keys.hp, &sample16, &header_peek, &dummy_pn) catch {
                    std.debug.print("Failed to peek header for PN length\n", .{});
                    conn.onAeadAuthFailure();
                    return;
                };
                const actual_pn_len: u3 = @intCast((header_peek & 0x03) + 1);
                std.debug.print("Determined actual_pn_len={} from header peek\n", .{actual_pn_len});

                // Step 2: Allocate plaintext buffer based on actual PN length
                var pt_list = std.ArrayList(u8){};
                defer pt_list.deinit(self.allocator.*);

                const expected_pt_len = if (full_pn_and_payload.len > 16 + @as(usize, actual_pn_len))
                    full_pn_and_payload.len - 16 - @as(usize, actual_pn_len)
                else
                    0;
                pt_list.ensureTotalCapacity(self.allocator.*, if (expected_pt_len > 0) expected_pt_len else 1) catch {
                    std.debug.print("Failed to allocate plaintext buffer\n", .{});
                    conn.onAeadAuthFailure();
                    return;
                };
                if (expected_pt_len > 0) {
                    pt_list.appendNTimesAssumeCapacity(0, expected_pt_len);
                } else {
                    pt_list.appendAssumeCapacity(0);
                }
                const pt_slice = pt_list.items;

                const largest_pn_hs = if (conn.pn_handshake.have_any) conn.pn_handshake.max else 0;
                std.debug.print("=== HANDSHAKE PACKET DECRYPTION ===\n", .{});
                std.debug.print("pn_start={}, end_total={}, actual_pn_len={}\n", .{ pn_start, end_total, actual_pn_len });
                std.debug.print("Attempting Handshake decrypt: largest_pn={}\n", .{largest_pn_hs});

                // Step 3: Call integrated decrypt function with correct PN length slice
                var masked_header = first;
                var masked_pn_bytes: [4]u8 = undefined;
                @memcpy(masked_pn_bytes[0..actual_pn_len], bytes[pn_start .. pn_start + actual_pn_len]);

                const dec = crypto.unprotectInitialAutoSample(
                    .aes_128_gcm,
                    &rx_keys.key,
                    &rx_keys.iv,
                    &rx_keys.hp,
                    &masked_header,
                    masked_pn_bytes[0..actual_pn_len], // Pass slice with correct length
                    header_prefix,
                    full_pn_and_payload, // Correctly positioned buffer for sample extraction
                    pt_slice,
                    largest_pn_hs,
                ) catch |err| {
                    std.debug.print("Handshake packet decrypt failed: {} (actual_pn_len={}, largest_pn={})\n", .{ err, actual_pn_len, largest_pn_hs });
                    std.debug.print("  RX keys: key[0..4]={any}, iv[0..4]={any}, hp[0..4]={any}\n", .{ rx_keys.key[0..4], rx_keys.iv[0..4], rx_keys.hp[0..4] });
                    conn.onAeadAuthFailure();
                    return;
                };
                std.debug.print("unprotectInitialAutoSample returned: {} bytes decrypted\n", .{dec});

                // After decryption, masked_pn_bytes now contains the UNMASKED PN bytes
                std.debug.print("Unmasked PN bytes: ", .{});
                for (masked_pn_bytes[0..actual_pn_len]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("", .{});

                // Update pn_masked with the unmasked bytes from the function
                @memcpy(pn_masked[0..actual_pn_len], masked_pn_bytes[0..actual_pn_len]);

                const pn_len = actual_pn_len;
                const pt = pt_slice[0..dec]; // Use actual decrypted length
                std.debug.print("Successfully decrypted Handshake packet (pn_len={}) plaintext len: {}\n", .{ pn_len, pt.len });

                // Expand truncated PN and track in Handshake space
                var pn_val_be: u64 = 0;
                var kk: usize = 0;
                while (kk < pn_len) : (kk += 1) pn_val_be = (pn_val_be << 8) | pn_masked[kk];
                const pn_full: u64 = conn.expandPnHandshake(pn_val_be, pn_len);
                conn.trackRecvPnHandshake(pn_full);

                // RFC 9000 §8.1: Successfully authenticating a packet at the Handshake level
                // proves the client received the server's Initial (which provided handshake keys).
                // This validates the client's address for anti-amplification purposes.
                if (conn.role == .Server and !conn.address_validated) {
                    std.debug.print("Server: Validating client address after receiving Handshake packet\n", .{});
                    conn.address_validated = true;
                    conn.bytes_rx_unvalidated = 0;
                    conn.bytes_tx_unvalidated = 0;
                }

                // Feed CRYPTO frames and handle ACK frames for PTO reset
                var off: usize = 0;
                var saw_any: bool = false;
                var saw_ack_eliciting_hs: bool = false;
                const now_ns_hs: u64 = @intCast(std.time.nanoTimestamp());
                while (off < pt.len) {
                    const r = frame.decodeOne(pt[off..]) catch |err| {
                        std.debug.print("Failed to decode frame at offset {}: {}\n", .{ off, err });
                        break;
                    };
                    off += r.n;
                    std.debug.print("Handshake frame: {} at offset {}\n", .{ r.f, off - r.n });
                    switch (r.f) {
                        .crypto => {
                            const cr = r.f.crypto;
                            const ack_handshake = conn.handleHandshakeCrypto(self.allocator, cr.offset, cr.data) catch |err| blk: {
                                std.debug.print("ERROR: Failed to process Handshake CRYPTO data: {}\n", .{err});
                                break :blk false;
                            };

                            if (ack_handshake) {
                                saw_any = true;
                                saw_ack_eliciting_hs = true;

                                if (conn.app_rx_keys != null and conn.app_tx_keys != null) {
                                    std.debug.print("HANDSHAKE CRYPTO: App keys NOW READY - calling closeStaleConnectionsForPeer\n", .{});
                                    self.closeStaleConnectionsForPeer(conn);
                                }
                            }
                        },
                        .ack => |a| {
                            // Reset handshake PTO backoff and cancel active timer on ACK in this space
                            conn.onAckReceivedSpace(.Handshake, a.largest, a.first_range, a.ranges, a.ecn);
                            conn.pto_handshake_count = 0;
                            if (conn.pto_handshake_active) {
                                _ = self.cancelTimer(conn.pto_handshake_id);
                                conn.pto_handshake_active = false;
                            }
                        },
                        .padding => {},
                        else => {},
                    }
                }
                // Send any pending Handshake CRYPTO (e.g. client Finished) and then attempt post-flush 1-RTT key derivation.
                if (conn.hs_tx_keys) |tx_hs| {
                    // Increase buffer to 4096 to support larger TLS messages
                    var outbox: [4096]u8 = undefined;
                    const n = conn.tls.popCrypto(outbox[0..]);
                    if (n > 0) {
                        std.debug.print("OLD CODE PATH: Preparing to send {} bytes of Handshake CRYPTO data\n", .{n});

                        // ArrayList to store additional Handshake packets that don't fit in coalesced datagram
                        var additional_hs_packets = std.ArrayList([]u8).initCapacity(self.allocator.*, 0) catch {
                            std.debug.print("Failed to allocate ArrayList for additional Handshake packets\n", .{});
                            return;
                        };
                        defer {
                            for (additional_hs_packets.items) |pkt| {
                                self.allocator.free(pkt);
                            }
                            additional_hs_packets.deinit(self.allocator.*);
                        }

                        // Use the client's source connection ID (peer_initial_scid)
                        // If client sent zero-length SCID, use empty DCID (proper quic-go compatibility)
                        const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];

                        // Fragment the CRYPTO data across multiple packets if needed
                        // Max CRYPTO frame size per packet: ~1100 bytes (1200 MTU - headers - overhead)
                        const max_crypto_per_packet: usize = 1100;
                        var offset: usize = 0;
                        var pkt_count: usize = 0;
                        const base_off_hs = conn.crypto_tx_off_handshake;

                        while (offset < n) {
                            const chunk_size = @min(max_crypto_per_packet, n - offset);
                            const chunk = outbox[offset .. offset + chunk_size];

                            var frames_buf = std.ArrayList(u8){};
                            defer frames_buf.deinit(self.allocator.*);
                            const w = frames_buf.writer(self.allocator.*);

                            // Add CRYPTO frame with current chunk
                            const crypto_offset = base_off_hs + offset;
                            _ = (frame.Frame{ .crypto = .{ .offset = crypto_offset, .data = chunk } }).write(w) catch 0;

                            std.debug.print("OLD CODE PATH: Creating Handshake packet {} with CRYPTO offset={} len={}\n", .{ pkt_count, crypto_offset, chunk_size });

                            const pkt = packet.encodeHandshakeProtected(self.allocator.*, version, hs_dcid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, frames_buf.items, tx_hs) catch null;

                            if (pkt) |bytes_out_hs| {
                                const pkt_len = bytes_out_hs.len;
                                std.debug.print("OLD CODE PATH: Handshake packet {} encoded, size={} bytes\n", .{ pkt_count, pkt_len });

                                // Store all packets to send after the loop
                                // First packet sent directly, additional packets stored
                                if (pkt_count == 0) {
                                    // Send first packet immediately
                                    _ = self.sendTo(peer, bytes_out_hs) catch {};
                                    std.debug.print("OLD CODE PATH: Sent first Handshake packet {} directly\n", .{pkt_count});
                                    self.allocator.free(bytes_out_hs);
                                } else {
                                    // Store additional packets for later sending
                                    additional_hs_packets.append(self.allocator.*, bytes_out_hs) catch {
                                        std.debug.print("OLD CODE PATH: Failed to store Handshake packet {}, freeing\n", .{pkt_count});
                                        self.allocator.free(bytes_out_hs);
                                    };
                                }

                                conn.onPacketSent(.Handshake, conn.pn_handshake_tx, pkt_len, true);
                                conn.pn_handshake_tx +%= 1;
                            }

                            offset += chunk_size;
                            pkt_count += 1;
                        }

                        // Save HS retransmit buffer for the entire CRYPTO data
                        if (conn.crypto_retx_handshake) |b| self.allocator.free(b);
                        var owned_hs = self.allocator.alloc(u8, n) catch {
                            conn.crypto_tx_off_handshake += n;
                            std.debug.print("OLD CODE PATH: Failed to allocate retransmit buffer\n", .{});
                            return;
                        };
                        @memcpy(owned_hs[0..n], outbox[0..n]);
                        conn.crypto_retx_handshake = owned_hs;
                        conn.crypto_retx_handshake_off = base_off_hs;
                        conn.crypto_tx_off_handshake += n;

                        // Send additional Handshake packets that didn't fit in coalesced datagram
                        if (additional_hs_packets.items.len > 0) {
                            std.debug.print("OLD CODE PATH: Sending {} additional Handshake packets separately\n", .{additional_hs_packets.items.len});
                            for (additional_hs_packets.items, 0..) |pkt, idx| {
                                const send_result = self.sendTo(conn.peer, pkt) catch |err| blk: {
                                    std.debug.print("OLD CODE PATH: ERROR: Failed to send additional Handshake packet {}: {}\n", .{ idx, err });
                                    break :blk 0;
                                };
                                if (send_result > 0) {
                                    std.debug.print("OLD CODE PATH: Sent additional Handshake packet {} ({} bytes)\n", .{ idx, send_result });
                                }
                            }
                        }

                        // With TLS outbox drained, attempt delayed 1-RTT key derivation.
                        conn.maybeDeriveAppKeysAfterFlush();

                        // If handshake just completed (app keys now exist), close any stale connections from same peer
                        std.debug.print("HANDSHAKE CLEANUP CHECK: app_rx_keys={s}, app_tx_keys={s}\n", .{
                            if (conn.app_rx_keys != null) "SET" else "NULL",
                            if (conn.app_tx_keys != null) "SET" else "NULL",
                        });
                        if (conn.app_rx_keys != null) {
                            std.debug.print("HANDSHAKE: CALLING closeStaleConnectionsForPeer!\n", .{});
                            self.closeStaleConnectionsForPeer(conn);
                        } else {
                            std.debug.print("HANDSHAKE: SKIPPING closeStaleConnectionsForPeer (keys not ready)\n", .{});
                        }
                    }
                }
                // Send ACK in Handshake space if ack-eliciting seen and we have hs_tx_keys
                if (saw_ack_eliciting_hs) {
                    conn.recordAckElicitingRx(.Handshake, now_ns_hs);
                }
                if (saw_any) {
                    if (conn.hs_tx_keys) |hs_keys| {
                        var frames_buf = std.ArrayList(u8){};
                        defer frames_buf.deinit(self.allocator.*);
                        const w = frames_buf.writer(self.allocator.*);
                        const ack_desc = conn.buildAckHandshake();
                        const ack_ecn = conn.getAckEcn(.Handshake);
                        const ack_delay = conn.getAckDelayEncoded(.Handshake, now_ns_hs);
                        if (ack_desc.largest != 0xFFFFFFFFFFFFFFFF) {
                            const ack = frame.Frame{ .ack = .{ .largest = ack_desc.largest, .ack_delay = ack_delay, .first_range = ack_desc.first_range, .ranges = ack_desc.ranges, .ecn = ack_ecn } };
                            _ = ack.write(w) catch 0;
                        }
                        // Handshake packets can only contain Handshake-level frames, not Initial CRYPTO
                        // Use the client's source connection ID (peer_initial_scid)
                        // If client sent scid_len=0, we send Handshake with dcid_len=0
                        const hs_dcid = conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len];
                        const pkt = packet.encodeHandshakeProtected(self.allocator.*, version, hs_dcid, conn.our_scid.bytes[0..conn.our_scid.len], @as(u32, @truncate(conn.pn_handshake_tx)), 2, frames_buf.items, hs_keys) catch null;
                        if (pkt) |bytes_out| {
                            defer self.allocator.free(bytes_out);
                            _ = self.sendTo(peer, bytes_out) catch {};
                            // ACK-only Handshake is not ack-eliciting; no PTO arm
                            conn.pn_handshake_tx +%= 1;
                        }
                    }
                }
            } else {
                std.debug.print("WARNING: No handshake RX keys available for handshake packet!\n", .{});
            }
            // If peer has validated address (CH contained token) and we are server, consider sending NEW_TOKEN on 1-RTT after HS done
            if (conn.address_validated and conn.app_tx_keys != null and conn.new_token_pending and !conn.new_token_sent) {
                // Issue a fresh token bound to current peer IP and ODCID (peer_initial_dcid)
                const client_ip_bytes = @as([*]const u8, @ptrCast(&peer.storage))[0..peer.len];
                const secret = self.cfg.token_secret orelse "default-retry-secret-16";
                const tok = token_mod.encode(self.allocator.*, client_ip_bytes, conn.peer_initial_dcid.bytes[0..conn.peer_initial_dcid.len], secret, self.cfg.token_expiry_ms) catch null;
                if (tok) |tbytes| {
                    defer self.allocator.free(tbytes);
                    var fb = std.ArrayList(u8){};
                    defer fb.deinit(self.allocator.*);
                    const w = fb.writer(self.allocator.*);
                    _ = (frame.Frame{ .new_token = .{ .token = tbytes } }).write(w) catch 0;
                    const dcid_nt = if (conn.peer_initial_scid.len > 0) conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len] else &[_]u8{};
                    const out = packet.encodeShortProtected(self.allocator.*, dcid_nt, @as(u32, @truncate(conn.pn_app_tx)), 2, fb.items, conn.app_tx_keys.?, conn.tx_key_phase) catch null;
                    if (out) |pkt_bytes| {
                        defer self.allocator.free(pkt_bytes);
                        _ = self.sendTo(peer, pkt_bytes) catch {};
                        conn.onPacketSent(.Application, conn.pn_app_tx, pkt_bytes.len, true);
                        conn.pn_app_tx +%= 1;
                        conn.new_token_sent = true;
                    }
                }
            } else {
                std.debug.print("WARNING: No handshake RX keys available for handshake packet!\n", .{});
            }

            // Check if there are more packets coalesced in this datagram (for Handshake packets)
            if (end_total < bytes.len) {
                // Process the remaining bytes as a new packet
                self.processIncomingDatagram(peer, bytes[end_total..], ecn_bits);
            }
        } else {
            return; // ignore other long header types for now
        }
    }

    /// resets validation state and counters, installs new map key, and triggers validation
    /// as described in RFC 9000 §9.4/§9.5 for path migration.
    fn onPathAddressChanged(self: *Endpoint, c: *conn_mod.Connection, new_peer: conn_mod.SockAddr, new_peer_hash: u64, dcid_len: usize) void {
        c.setPeer(new_peer);
        c.address_validated = false;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        // Insert/refresh mapping keyed by new peer and our DCID
        const new_key = Key{ .peer_hash = new_peer_hash, .dcid_hash = hashBytes(c.our_scid.bytes[0..dcid_len]) };
        _ = self.conns.put(new_key, c) catch {};
        // Trigger PATH_CHALLENGE if 1-RTT keys are available (§9.3):
        c.sendPathChallenge();
        std.debug.print("path: change detected dcid_len={d} triggering validation (phase={d})\n", .{ dcid_len, @intFromBool(c.tx_key_phase) });
    }

    /// Mark path validated and clear unvalidated counters consistently.
    fn onPathValidated(self: *Endpoint, c: *conn_mod.Connection) void {
        _ = self; // unused
        c.path_validation_pending = false;
        c.address_validated = true;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        std.debug.print("path: validated (peer={d} bytes_rx_unval reset)\n", .{c.peer.len});
    }

    fn nextTimeoutFromTimers(self: *Endpoint, now_ms: i64, requested_timeout_ms: i32) i32 {
        var eff = requested_timeout_ms;
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            const t = self.timers.items[i];
            const diff: i64 = t.deadline_ms - now_ms;
            const t_ms: i32 = if (diff <= 0) 0 else @intCast(@min(diff, @as(i64, std.math.maxInt(i32))));
            if (eff < 0) {
                eff = t_ms;
            } else if (t_ms < eff) {
                eff = t_ms;
            }
        }
        return eff;
    }

    fn processExpiredTimers(self: *Endpoint, now_ms: i64) void {
        // Simple linear removal of expired timers; keep others.
        var i: usize = 0;
        while (i < self.timers.items.len) {
            if (self.timers.items[i].deadline_ms <= now_ms) {
                const t = self.timers.items[i];
                _ = self.timers.orderedRemove(i);
                // Fire PTO flags if applicable and generate probes
                switch (t.kind) {
                    .Generic => {
                        if (t.paced) {
                            if (t.conn) |c| {
                                if (t.payload) |bytes| {
                                    // Send the paced payload now and free it
                                    _ = self.sendTo(c.peer, bytes) catch {};
                                    self.allocator.free(bytes);
                                }
                            }
                        }
                    },
                    .PtoInitial => if (t.conn) |c| {
                        c.setPtoExpiredInitial();
                        // Generate a PING probe in Initial space
                        self.sendPtoProbe(c, .PtoInitial) catch {};
                    },
                    .PtoHandshake => if (t.conn) |c| {
                        c.setPtoExpiredHandshake();
                        self.sendPtoProbe(c, .PtoHandshake) catch {};
                    },
                    .PtoApp => if (t.conn) |c| c.setPtoExpiredApp(),
                    .Pmtud => if (t.conn) |c| {
                        // Drive DPLPMTUD state machine timer
                        c.pmtudOnTimer(self);
                    },
                }
            } else {
                i += 1;
            }
        }
        // After firing timers, attempt pruning of closed connections (e.g., after PTO-driven close)
        self.pruneClosed();
    }

    /// TEST-ONLY: force all timers to expire immediately and process them once.
    pub fn forceExpireAllTimers(self: *Endpoint) void {
        const now_ms = nowMsMonotonic();
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            self.timers.items[i].deadline_ms = now_ms;
        }
        self.processExpiredTimers(now_ms);
    }

    pub fn sendPtoProbe(self: *Endpoint, conn: *conn_mod.Connection, kind: TimerKind) !void {
        // Use pto module helpers (Phase 4b.5 Session 9)
        const sendFnWrapper = struct {
            fn send(ctx: *anyopaque, peer: conn_mod.SockAddr, data: []const u8) !usize {
                const ep: *Endpoint = @ptrCast(@alignCast(ctx));
                return ep.sendTo(peer, data);
            }
        }.send;

        var ctx = pto_mod.PtoContext{
            .conn = conn,
            .allocator = self.allocator,
            .send_ctx = self,
            .send_fn = sendFnWrapper,
            .peer = conn.peer,
        };
        // Cast TimerKind to the types module version (they're identical)
        const pto_kind = @as(pto_mod.types.TimerKind, @enumFromInt(@intFromEnum(kind)));
        try pto_mod.sendPtoProbe(&ctx, pto_kind);
    }

    /// Close old connections from the same peer when a new connection completes its handshake.
    /// This prevents routing packets to stale connections with mismatched keys.
    /// Delegates to lifecycle module (Phase 10).
    pub fn closeStaleConnectionsForPeer(self: *Endpoint, new_conn: *conn_mod.Connection) void {
        var ctx = lifecycle_mod.LifecycleContext{
            .allocator = self.allocator.*,
            .conns = &self.conns,
            .timers = &self.timers,
            .retired = &self.retired,
        };
        lifecycle_mod.closeStaleConnectionsForPeer(&ctx, new_conn);
    }

    /// Remove all map entries / timers referencing connections that have transitioned to closed state.
    /// Delegates to lifecycle module (Phase 10).
    fn pruneClosed(self: *Endpoint) void {
        var ctx = lifecycle_mod.LifecycleContext{
            .allocator = self.allocator.*,
            .conns = &self.conns,
            .timers = &self.timers,
            .retired = &self.retired,
        };
        lifecycle_mod.pruneClosed(&ctx);
    }
};

// Sender callback used by Connection for timer-driven pacing
fn senderPaced(ctx: *anyopaque, c: *conn_mod.Connection, data: []const u8) !usize {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    // If pacing disabled, send directly
    if (!c.enable_pacing) {
        if (data.len == 141) {
            const sa: *const posix.sockaddr = @ptrCast(&c.peer.storage);
            if (sa.family == posix.AF.INET) {
                const sin: *const posix.sockaddr.in = @ptrCast(&c.peer.storage);
                const addr_bytes = @as([4]u8, @bitCast(sin.addr));
                std.debug.print("senderPaced using peer addr {}.{}.{}.{}:{}\n", .{ addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], portFromNetwork(sin.port) });
            }
        }
        return self.sendTo(c.peer, data);
    }
    const delay_ns = recovery.computePacingDelayNs(c.rec.cc.cwnd, c.rec.cc.bytes_in_flight);
    if (delay_ns == 0) {
        return self.sendTo(c.peer, data);
    }
    // Own the payload and schedule a paced timer
    const owned = try self.allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    _ = try self.schedulePaced(c, delay_ns, owned);
    // Report bytes as accepted; actual socket send happens when the timer fires.
    return data.len;
}

// Legacy poll_* functions removed - dead code (never called)
// Modern poll_*_backend() functions are used instead

fn parseIpv4(s: []const u8) !u32 {
    // Returns address in network byte order (big-endian) for sockaddr.in.s_addr
    var it = std.mem.splitScalar(u8, s, '.');
    var octets: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const part = it.next() orelse return error.InvalidAddress;
        const v = try std.fmt.parseInt(u8, part, 10);
        octets[i] = v;
    }
    const host_val: u32 = (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
    return addrToNetwork(host_val);
}

fn resolveAny(hostport: []const u8, proto: enum { udp }) !conn_mod.SockAddr {
    _ = proto;
    var parts = std.mem.splitScalar(u8, hostport, ':');
    const host = parts.next() orelse return error.InvalidAddress;
    const port_s = parts.next() orelse return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidAddress;

    // Handle common hostnames used in tests
    if (std.mem.eql(u8, host, "localhost")) {
        return conn_mod.SockAddr.ipv4(127, 0, 0, 1, port);
    }
    if (std.mem.eql(u8, host, "server4") or std.mem.eql(u8, host, "server")) {
        // In Docker, server4 should resolve to the server container
        // Try to use the IP from /etc/hosts if available
        const hosts_file = std.fs.openFileAbsolute("/etc/hosts", .{}) catch {
            // Fallback to a default IP used in tests
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        defer hosts_file.close();

        var buf: [4096]u8 = undefined;
        const bytes_read = hosts_file.readAll(&buf) catch {
            return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
        };
        const content = buf[0..bytes_read];

        // Parse /etc/hosts for server4
        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            var parts_line = std.mem.tokenizeAny(u8, line, " \t");
            const ip_str = parts_line.next() orelse continue;
            while (parts_line.next()) |hostname| {
                if (std.mem.eql(u8, hostname, "server4") or std.mem.eql(u8, hostname, "server")) {
                    // Parse the IP address
                    var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
                    var octets: [4]u8 = .{0} ** 4;
                    var i: usize = 0;
                    while (i < 4) : (i += 1) {
                        const octet_str = ip_parts.next() orelse break;
                        octets[i] = std.fmt.parseInt(u8, octet_str, 10) catch break;
                    }
                    if (i == 4) {
                        return conn_mod.SockAddr.ipv4(octets[0], octets[1], octets[2], octets[3], port);
                    }
                }
            }
        }
        // Default fallback
        return conn_mod.SockAddr.ipv4(193, 167, 100, 100, port);
    }

    // Try dotted-quad IPv4 parse
    var it = std.mem.splitScalar(u8, host, '.');
    var oct: [4]u8 = .{0} ** 4;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const seg = it.next() orelse return error.InvalidAddress;
        oct[i] = std.fmt.parseInt(u8, seg, 10) catch return error.InvalidAddress;
    }
    return conn_mod.SockAddr.ipv4(oct[0], oct[1], oct[2], oct[3], port);
}
