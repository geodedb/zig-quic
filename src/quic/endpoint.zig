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
const client_mod = @import("endpoint/client.zig");
const io_mod = @import("endpoint/io.zig");
const lifecycle_mod = @import("endpoint/lifecycle.zig");
const ep_types = @import("types");
const transport_mod = @import("endpoint/transport.zig");

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

    // Transport abstraction (Phase 8a: optional, fallback to sock_fd if null)
    // When provided, endpoint uses this instead of direct UDP socket operations
    transport: ?transport_mod.Transport = null,

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
        var ep_addr = try utils.resolveAny(bind_addr, .udp);

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

    /// Initialize endpoint with custom transport (Phase 8a: enables loopback testing).
    /// This method allows creating an endpoint with a pluggable transport backend
    /// (e.g., loopback for testing) instead of a real UDP socket.
    pub fn initWithTransport(
        alloc: *std.mem.Allocator,
        transport: transport_mod.Transport,
        cfgp: *const cfg.QuicConfig,
    ) !Endpoint {
        // Get local address from transport
        const local_addr = try transport.getLocalAddr();

        // Determine role: default to Server, can be overridden later
        const endpoint_role = EndpointRole.Server;

        return Endpoint{
            .sock_fd = @as(posix.socket_t, @intCast(-1)), // Not used with transport
            .sock_family = local_addr.storage.family,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc,
            .transport = transport, // Phase 8a: provide transport
            .timers = std.ArrayList(Timer){},
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc.*),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = std.ArrayList(*conn_mod.Connection){},
            .captures = std.ArrayList(OutCaptured){},
            .test_capture_enabled = false,
            .retired = std.ArrayList(*conn_mod.Connection){},
            .epoll_fd = null, // No epoll with transport abstraction
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
    /// Phase 8a: Uses transport abstraction if available, otherwise delegates to io_mod.
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        // Test capture: make owned copy and enqueue without sending
        if (self.test_capture_enabled) {
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            _ = self.captures.append(self.allocator.*, .{ .peer = peer, .bytes = owned }) catch {};
        }

        // Phase 8a: Use transport if available, otherwise fallback to direct UDP
        if (self.transport) |*t| {
            return try t.send(peer, data);
        }

        // Fallback: Delegate actual UDP send to io module (backward compatibility)
        std.debug.print("sendTo called with data.len={}\n", .{data.len});
        return io_mod.sendTo(self.sock_fd, peer, data);
    }

    /// Receive UDP datagram (non-blocking if platform supports MSG.DONTWAIT).
    /// Phase 8a: Uses transport abstraction if available, otherwise delegates to io_mod.
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        // Phase 8a: Use transport if available, otherwise fallback to direct UDP
        if (self.transport) |*t| {
            const result = try t.recv(buf);
            return .{ .n = result.n, .peer = result.peer };
        }

        // Fallback: Delegate to io module for platform abstraction (backward compatibility)
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
        const peer = try utils.resolveAny(hostport, .udp);
        return .{ .id = 0, .role = .Client, .sock_fd = sockToIsize(self.sock_fd), .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Create client-side connection object referencing remote host:port.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const peer = try utils.resolveAny(hostport, .udp);
        const ph = hashSockaddr(&peer.storage, peer.len);
        const version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;

        // Delegate to client module for connection creation
        const c = try client_mod.createClientConnection(
            self.allocator,
            peer,
            self.sock_fd,
            self.cfg,
            version,
            &self.conns,
            ph,
        );

        // Install paced sender callback (requires Endpoint context)
        c.setSender(@ptrCast(self), senderPaced);

        return c;
    }

    /// Transmit minimal Initial packet (PING) to elicit Version Negotiation or SH.
    pub fn clientSendInitialProbe(self: *Endpoint, c: *conn_mod.Connection) !void {
        // Set up client transport parameters for TLS handshake
        handshake_integration.setupClientTransportParams(c, self.allocator.*) catch {};

        // Delegate to client module for Initial packet construction and sending
        var ctx = client_mod.ClientContext{
            .allocator = self.allocator,
            .conn = c,
            .sender_ctx = @ptrCast(self),
            .send_fn = &Endpoint.sendToWrapper,
            .peer = c.peer,
        };
        try client_mod.sendInitialProbe(&ctx);

        // Arm Initial PTO (requires Endpoint context)
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
    /// Phase 8a: Uses transport abstraction if available, otherwise uses platform-specific backend.
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        poll_call_count += 1;
        // TRACE: poll called
        std.debug.print(">>> POLL #{} called, timeout_ms={}\n", .{ poll_call_count, timeout_ms });

        // Phase 8a: If using transport abstraction, use simplified poll path
        if (self.transport) |*t| {
            // Process expired timers first
            self.processExpiredTimers(nowMsMonotonic());

            // Calculate effective timeout based on next timer
            const now_ms: i64 = nowMsMonotonic();
            var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
            if (eff_timeout < 0) eff_timeout = -1;

            // Poll transport (may be no-op for loopback)
            try t.poll(eff_timeout);

            // Drain all available packets
            var buf: [4096]u8 = undefined;
            while (true) {
                const result = self.recvFrom(&buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    return err;
                };

                // Process the received packet
                self.processIncomingDatagram(result.peer, buf[0..result.n], null);
            }

            // Process timers that may have fired during packet processing
            self.processExpiredTimers(nowMsMonotonic());
            self.pruneClosed();
            return;
        }

        // Fallback: Original poll implementation for direct UDP
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

        // Delegate to platform-specific poll backend
        const backend = lb.defaultLoopBackend();
        std.debug.print("Using backend: {}\n", .{backend});
        try self.callPollBackend(backend, eff_timeout);

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

    /// Helper: Create IoContext and call platform-specific poll backend.
    fn callPollBackend(self: *Endpoint, backend: lb.LoopBackend, timeout_ms: i32) !void {
        current_io_endpoint = self;
        defer current_io_endpoint = null;

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
            .epoll_fd = if (backend == .epoll) self.epoll_fd else null,
        };

        switch (backend) {
            .epoll => try io_mod.pollEpollBackend(&ctx, timeout_ms),
            .kqueue => try io_mod.pollKqueueBackend(&ctx, timeout_ms),
            .iocp => try io_mod.pollIocpBackend(&ctx, timeout_ms),
        }
    }

    // Helper: Wrapper for sendTo to match incoming.SendFn signature
    fn sendToWrapper(ctx: ?*anyopaque, peer: conn_mod.SockAddr, data: []const u8) anyerror!usize {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.sendTo(peer, data);
    }

    // Helper: Wrapper for scheduleTimer to match incoming.ScheduleTimerFn signature
    fn scheduleTimerWrapper(ctx: ?*anyopaque, conn: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.scheduleTimer(conn, kind, delay_ms);
    }

    // Helper: Wrapper for clientSendInitialProbe to match incoming.SendInitialProbeFn signature
    fn clientSendInitialProbeWrapper(ctx: ?*anyopaque, conn: *conn_mod.Connection) anyerror!void {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.clientSendInitialProbe(conn);
    }

    // Helper: Process Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8)
    fn processRetryPacket(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, version: u32) void {
        // Parse Retry header
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
        if (bytes.len < 16 or i >= bytes.len - 16) return; // Need room for integrity tag
        const token_bytes = bytes[i .. bytes.len - 16];

        // Lookup matching client connection
        const ph = hashSockaddr(&peer.storage, peer.len);
        var itc = self.conns.iterator();
        var c_found: ?*conn_mod.Connection = null;
        while (itc.next()) |e| {
            if (e.key_ptr.*.peer_hash != ph) continue;
            c_found = e.value_ptr.*;
            break;
        }
        const c = c_found orelse return;

        // Verify Retry integrity using ODCID
        const odcid = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];
        if (odcid.len == 0) return;
        if (!packet.verifyRetry(odcid, bytes)) return;

        // Store token and update version/DCID for next Initial
        c.initial_token.clearRetainingCapacity();
        _ = c.initial_token.appendSlice(self.allocator.*, token_bytes) catch {};
        c.version = version;
        c.version_v2 = (version == packet.QUIC_V2);
        c.initial_version = version;
        c.peer_initial_dcid.len = @intCast(@min(scid.len, c.peer_initial_dcid.bytes.len));
        if (c.peer_initial_dcid.len > 0) @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], scid[0..c.peer_initial_dcid.len]);

        // Resend Initial with token
        self.clientSendInitialProbe(c) catch {};
    }

    var process_count: u64 = 0;
    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        process_count += 1;
        std.debug.print("PACKET #{}: {} bytes, first=0x{X:0>2}\n", .{ process_count, bytes.len, if (bytes.len > 0) bytes[0] else 0 });

        if (bytes.len < 1) return;

        const first = bytes[0];
        const is_long = (first & 0x80) != 0;

        // Create RxContext for delegation to incoming.zig modules
        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));

        // Temporarily set global endpoint pointer for callbacks
        current_io_endpoint = self;
        defer current_io_endpoint = null;

        var rx_ctx = incoming.RxContext{
            .allocator = self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = struct {
                fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                    const ep = current_io_endpoint.?;
                    return ep.sendTo(peer_addr, data);
                }
            }.send,
            .schedule_timer_fn = struct {
                fn schedule(conn: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
                    const ep = current_io_endpoint.?;
                    return ep.scheduleConnPto(conn, kind, delay_ms);
                }
            }.schedule,
            .send_initial_probe_fn = struct {
                fn probe(conn: *conn_mod.Connection) anyerror!void {
                    const ep = current_io_endpoint.?;
                    return ep.clientSendInitialProbe(conn);
                }
            }.probe,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
        };

        // Short header: Delegate to incoming.processShortHeader()
        if (!is_long) {
            // Handle NAT rebinding detection
            const lookup_result = lookup.findConnectionByDcid(&self.conns, peer, bytes, null);
            if (lookup_result.nat_rebinding) {
                if (lookup_result.conn) |c| {
                    const peer_h = hashSockaddr(&peer.storage, peer.len);
                    self.onPathAddressChanged(c, peer, peer_h, lookup_result.dcid_len);
                }
            }
            incoming.processShortHeader(&rx_ctx, peer, bytes, ecn_bits, rx_ctx.send_fn);
            return;
        }

        // Long header: Parse version and packet type
        if (bytes.len < 5) return;
        const version: u32 = (@as(u32, bytes[1]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 8) | @as(u32, bytes[4]);
        const ty = (first >> 4) & 0x03;

        // Version Negotiation: Delegate to incoming.processVersionNegotiation()
        if (version == 0) {
            incoming.processVersionNegotiation(&rx_ctx, peer, bytes);
            return;
        }

        // Initial: Delegate to incoming.processInitial()
        if (ty == 0) {
            incoming.processInitial(&rx_ctx, peer, bytes, version);
            return;
        }

        // Retry: Delegate to helper function
        if (ty == 3) {
            self.processRetryPacket(peer, bytes, version);
            return;
        }

        // Handshake: Delegate to incoming.processHandshake()
        if (ty == 2) {
            incoming.processHandshake(&rx_ctx, peer, bytes, version, ecn_bits, rx_ctx.send_fn);
            return;
        }
    }

    /// Replaced processIncomingDatagram - kept for reference during Phase 13
    fn _OLD_processIncomingDatagram_REPLACED(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        _ = self;
        _ = peer;
        _ = bytes;
        _ = ecn_bits;
        // This function has been replaced by the thin coordinator above.
        // The old implementation (1,708 lines) is preserved in endpoint.zig.phase13_p2_4_backup
        @panic("OLD processIncomingDatagram called - should never happen");
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
// Helper functions parseIpv4() and resolveAny() moved to utils.zig
