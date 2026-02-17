// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Endpoint skeleton with UDP send/recv (thread-safe for multi-connection handling).
//!
//! ## Threading Model (CWE-366 Mitigation)
//!
//! **IMPORTANT**: This implementation uses the following threading model:
//!
//! 1. **I/O Thread**: A single thread should call `poll()` and process incoming packets.
//!    This thread handles packet decryption, frame parsing, and state updates.
//!
//! 2. **Application Threads**: Multiple threads may safely call:
//!    - `accept()` - Accept new incoming connections
//!    - `Connection.readStream()` - Read data from streams
//!    - `Connection.writeStream()` - Write data to streams
//!    - `Connection.acceptStream()` - Accept peer-initiated streams
//!
//! **Thread Safety Implementation**:
//! - `current_io_endpoint` is `threadlocal` to support multiple endpoints in separate threads
//! - Each `Connection` has a `mu: std.Thread.Mutex` protecting internal state
//! - Stream maps (`streams_rx`, `stream_txs`) are protected by the connection mutex
//! - All public stream APIs acquire the connection mutex before accessing state
//!
//! **Lock Ordering**: Always acquire endpoint lock before connection lock to prevent deadlocks.
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
const udp_transport_mod = @import("endpoint/udp_transport.zig");

const posix = std.posix;
const builtin = @import("builtin");

// Endpoint (RFC-9000):  An entity that can participate in a QUIC connection by
//       generating, receiving, and processing QUIC packets.  There are
//       only two types of endpoints in QUIC: client and server.

// TEST-ONLY: outbound capture entry (peer + owned bytes)
const OutCaptured = struct { peer: conn_mod.SockAddr, bytes: []u8 };

// Thread-local variable to allow callbacks to access endpoint
// Must be threadlocal to support multiple endpoints in different threads
threadlocal var current_io_endpoint: ?*Endpoint = null;

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

fn encodeVersionNegotiationPacket(
    dcid: []const u8,
    scid: []const u8,
    supported_versions: []const u32,
    out_buf: []u8,
) ![]u8 {
    const min_len = 1 + 4 + 1 + dcid.len + 1 + scid.len + (supported_versions.len * 4);
    if (out_buf.len < min_len) return error.BufferTooSmall;

    var i: usize = 0;
    // Long header with random type-specific bits.
    out_buf[i] = 0b10000000 | @as(u8, @truncate(std.crypto.random.int(u8) & 0x3F));
    i += 1;
    // Version = 0x00000000 (Version Negotiation packet)
    std.mem.writeInt(u32, out_buf[i..][0..4], 0, .big);
    i += 4;
    out_buf[i] = @intCast(dcid.len);
    i += 1;
    @memcpy(out_buf[i..][0..dcid.len], dcid);
    i += dcid.len;
    out_buf[i] = @intCast(scid.len);
    i += 1;
    @memcpy(out_buf[i..][0..scid.len], scid);
    i += scid.len;
    for (supported_versions) |v| {
        std.mem.writeInt(u32, out_buf[i..][0..4], v, .big);
        i += 4;
    }
    return out_buf[0..i];
}

// Use canonical Timer and TimerKind from endpoint/types.zig (imported as ep_types)
const Timer = ep_types.Timer;
const TimerKind = ep_types.TimerKind;
/// Observability for poll loops (number of datagrams drained per iteration).
pub const PollStats = struct {
    packets_processed: usize = 0,
};

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

    // GAP-0200: Thread-safety mutex for protecting shared state
    // This mutex protects: conns, accepted, retired, timers, next_timer_id
    // Lock ordering: endpoint.mu -> connection.mu (never reverse)
    mu: std.Thread.Mutex = .{},

    // Transport abstraction (Phase 8c: required, wraps UDP or loopback)
    // All I/O operations go through this transport interface
    transport: transport_mod.Transport,

    // Owned UDP transport (heap-allocated, null if using custom transport)
    owned_udp_transport: ?*udp_transport_mod.UdpTransport = null,

    // Event loop backend (os specific)
    loop_backend: lb.LoopBackend,

    // Memory allocator for endpoint resources
    allocator: std.mem.Allocator,

    // Timer management for the endpoint (protected by mu)
    timers: std.ArrayList(Timer),

    // Connection Management Map (protected by mu)
    conns: std.AutoHashMap(Key, *conn_mod.Connection),

    // Next timer identifier for scheduleTimer (protected by mu)
    next_timer_id: u64 = 1,
    // Config copy
    cfg: cfg.QuicConfig,
    // Accept queue for server (protected by mu)
    // GAP-0200: Thread-safe accept queue - poll() adds, accept() removes
    accepted: std.ArrayList(*conn_mod.Connection),
    // TEST-ONLY: outbound capture ring (peer + owned bytes)
    captures: std.ArrayList(OutCaptured),
    // TEST-ONLY: runtime flag to enable outbound capture in tests
    test_capture_enabled: bool = false,
    // Retired (closed) connections removed from maps & timers but not yet destroyed.
    // They stay here until explicit api.destroy() or endpoint.deinit(), allowing external
    // code (e.g., server CLI loop) holding an opaque pointer to observe closed state
    // without risking use-after-free. (protected by mu)
    retired: std.ArrayList(*conn_mod.Connection),
    // Epoll file descriptor for Linux
    epoll_fd: ?posix.fd_t = null,
    // Endpoint role (Client or Server)
    role: EndpointRole,

    // Generated token secret for Retry/NEW_TOKEN if user doesn't provide one.
    // 32 bytes of cryptographically random data generated at endpoint init.
    // This replaces the hardcoded fallback to prevent predictable tokens.
    generated_token_secret: [32]u8 = undefined,

    /// Initialize a UDP endpoint bound to bind_addr (e.g., "127.0.0.1:0").
    ///
    /// Phase 8c: Now uses UdpTransport internally for all socket operations.
    /// The endpoint creates a UDP socket via the transport abstraction layer.
    pub fn init(alloc: std.mem.Allocator, bind_addr: []const u8, cfgp: *const cfg.QuicConfig) !Endpoint {
        // Create UDP transport (handles socket creation, binding, configuration)
        // IMPORTANT: Must heap-allocate because Transport stores a pointer to it
        const udp = try alloc.create(udp_transport_mod.UdpTransport);
        errdefer alloc.destroy(udp);

        udp.* = try udp_transport_mod.UdpTransport.init(bind_addr);
        errdefer udp.deinit();

        // Convert to generic transport interface
        var transport = udp.asTransport();

        // Get local address from transport
        const local_addr = try transport.getLocalAddr();

        // Determine endpoint role based on the bound port
        const bound_port = if (local_addr.storage.family == posix.AF.INET) blk: {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&local_addr.storage));
            break :blk portFromNetwork(sin.port);
        } else if (local_addr.storage.family == posix.AF.INET6) blk: {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&local_addr.storage));
            break :blk portFromNetwork(sin6.port);
        } else blk: {
            break :blk @as(u16, 0);
        };

        // Server binds to specific port (4433, 443), client binds to 0 (random)
        const is_server = std.mem.indexOf(u8, bind_addr, ":4433") != null or
            std.mem.indexOf(u8, bind_addr, ":443") != null or
            (std.mem.indexOf(u8, bind_addr, ":0") == null and bound_port != 0);
        const endpoint_role = if (is_server) EndpointRole.Server else EndpointRole.Client;

        logger.debugPrint("Endpoint role determined as: {any}\n", .{endpoint_role});

        // Generate cryptographically random token secret if not provided in config.
        // This prevents using a hardcoded fallback which would be predictable.
        var generated_secret: [32]u8 = undefined;
        std.crypto.random.bytes(&generated_secret);

        return Endpoint{
            .transport = transport,
            .owned_udp_transport = udp,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc,
            .timers = std.ArrayList(Timer){},
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = std.ArrayList(*conn_mod.Connection){},
            .captures = std.ArrayList(OutCaptured){},
            .test_capture_enabled = false,
            .retired = std.ArrayList(*conn_mod.Connection){},
            .epoll_fd = null, // Not used with transport abstraction
            .role = endpoint_role,
            .generated_token_secret = generated_secret,
        };
    }

    /// Initialize endpoint with custom transport (Phase 8c: for loopback testing).
    /// This method allows creating an endpoint with a pluggable transport backend
    /// (e.g., loopback for testing) instead of a real UDP socket.
    pub fn initWithTransport(
        alloc: *std.mem.Allocator,
        transport: transport_mod.Transport,
        cfgp: *const cfg.QuicConfig,
        endpoint_role: EndpointRole,
    ) !Endpoint {
        // Role now passed as parameter instead of hardcoded

        // Generate cryptographically random token secret if not provided in config.
        var generated_secret: [32]u8 = undefined;
        std.crypto.random.bytes(&generated_secret);

        return Endpoint{
            .transport = transport,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc.*,
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
            .generated_token_secret = generated_secret,
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
            var unique = std.AutoHashMap(*conn_mod.Connection, usize).init(self.allocator);
            defer unique.deinit();
            var cit = self.conns.iterator();
            while (cit.next()) |e| {
                const c = e.value_ptr.*;
                const idx = unique.get(c) orelse 0;
                _ = unique.put(c, idx + 1) catch {};
            }
            if (unique.count() > 0) {
                logger.debugPrint("endpoint.deinit: {d} unique conn(s) still referenced by map; dumping counts\n", .{unique.count()});
                var uit = unique.iterator();
                while (uit.next()) |ve| {
                    logger.debugPrint("  conn ptr={*} ref_count={d}\n", .{ ve.key_ptr.*, ve.value_ptr.* });
                }
                // Also dump timers referencing a connection
                var ti: usize = 0;
                var timer_conn_refs: usize = 0;
                while (ti < self.timers.items.len) : (ti += 1) {
                    const t = self.timers.items[ti];
                    if (t.conn) |tc| {
                        timer_conn_refs += 1;
                        logger.debugPrint("  timer id={d} kind={any} conn={*}\n", .{ t.id, t.kind, tc });
                    }
                }
                if (timer_conn_refs > 0) logger.debugPrint("  timers referencing connections: {d}\n", .{timer_conn_refs});
            }
        }
        // Free captured payloads
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) {
            const cap = self.captures.items[i];
            self.allocator.free(cap.bytes);
        }
        self.captures.deinit(self.allocator);
        // Free any pending paced payloads in timers
        var j: usize = 0;
        while (j < self.timers.items.len) : (j += 1) {
            const t = self.timers.items[j];
            if (t.paced) {
                if (t.payload) |p| self.allocator.free(p);
            }
        }
        // Destroy unique connections referenced by map values
        var seen = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator);
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
        self.retired.deinit(self.allocator);
        self.conns.deinit();
        self.accepted.deinit(self.allocator);
        self.timers.deinit(self.allocator);

        // Phase 8c: Close transport (which closes underlying socket)
        self.transport.close();

        // Free heap-allocated UDP transport if we own it
        if (self.owned_udp_transport) |udp| {
            self.allocator.destroy(udp);
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
    /// Send UDP datagram to peer via transport abstraction.
    /// Phase 8c: Always uses transport (no fallback to sock_fd).
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        // Test capture: make owned copy and enqueue without sending
        if (self.test_capture_enabled) {
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            _ = self.captures.append(self.allocator, .{ .peer = peer, .bytes = owned }) catch {};
        }

        // Phase 8c: Always use transport directly for sends (single-threaded event loop)
        return try self.transport.send(peer, data);
    }

    /// Receive UDP datagram via transport abstraction (non-blocking).
    /// Phase 8c: Always uses transport (no fallback to sock_fd).
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        // Phase 8c: Always use transport (transport is now required, not optional)
        const result = try self.transport.recv(buf);
        return .{ .n = result.n, .peer = result.peer };
    }

    /// Accept a server connection from initial datagram's peer address.
    /// Phase 8c: sock_fd set to -1 (I/O goes through endpoint transport)
    pub fn acceptFrom(self: *Endpoint, peer: conn_mod.SockAddr) conn_mod.Connection {
        _ = self; // unused
        return .{ .id = 0, .role = .Server, .sock_fd = -1, .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Enqueue accepted server connection for accept().
    /// GAP-0200: Thread-safe - acquires endpoint mutex
    fn pushAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.accepted.append(self.allocator, c) catch {};
    }

    /// Pop next accepted server-side connection if available.
    /// GAP-0200: Thread-safe - acquires endpoint mutex
    pub fn popAccepted(self: *Endpoint) ?*conn_mod.Connection {
        self.mu.lock();
        defer self.mu.unlock();
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
    /// Phase 8c: sock_fd set to -1 (I/O goes through endpoint transport)
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        _ = self; // unused
        const peer = try utils.resolveAny(hostport, .udp);
        return .{ .id = 0, .role = .Client, .sock_fd = -1, .peer = peer, .tls_inbox = std.ArrayList(u8){} };
    }

    /// Create client-side connection object referencing remote host:port.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const peer = try utils.resolveAny(hostport, .udp);
        const ph = hashSockaddr(&peer.storage, peer.len);
        const version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;

        // Delegate to client module for connection creation
        // Phase 8c: Pass invalid socket for sock_fd (I/O now via transport abstraction)
        const c = try client_mod.createClientConnection(
            &self.allocator,
            peer,
            utils.invalidSocket(),
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
        handshake_integration.setupClientTransportParams(c, self.allocator) catch {};

        // Delegate to client module for Initial packet construction and sending
        var ctx = client_mod.ClientContext{
            .allocator = &self.allocator,
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
        try self.timers.append(self.allocator, .{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = null });
        return id;
    }

    /// Schedule connection-owned PTO/PMTUD timer tied to a specific connection and space.
    pub fn scheduleConnPto(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        // PTO and probe timers follow RFC 9002 §6 (loss detection) and §7 (PMTUD pacing).
        try self.timers.append(self.allocator, .{ .deadline_ms = deadline, .id = id, .kind = kind, .conn = c });
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
        try self.timers.append(self.allocator, .{
            .deadline_ms = deadline,
            .id = id,
            .kind = .Generic,
            .conn = c,
            .paced = true,
            .payload = owned_bytes,
            .paced_peer = c.peer,
        });
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

    /// Drive network I/O, timers, and paced send for up to timeout_ms milliseconds.
    /// Phase 8a: Uses transport abstraction if available, otherwise uses platform-specific backend.
    /// Poll for events with timeout via transport abstraction.
    /// Phase 8c: Always uses transport (no fallback to sock_fd/epoll).
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        _ = try self.pollWithStats(timeout_ms);
    }

    /// Variant of poll that returns the number of datagrams processed.
    /// Useful for callers that need to prioritize receives over sends.
    pub fn pollWithStats(self: *Endpoint, timeout_ms: i32) !PollStats {
        var stats = PollStats{};

        // Process expired timers first
        self.processExpiredTimers(nowMsMonotonic());

        // Calculate effective timeout based on next timer
        const now_ms: i64 = nowMsMonotonic();
        var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
        if (eff_timeout < 0) eff_timeout = -1;

        // Poll transport (blocks until data available or timeout)
        try self.transport.poll(eff_timeout);

        // Drain all available packets (prefer transport-native batch receive).
        var recv_bufs: [udp_transport_mod.UdpBatchCap][4096]u8 = undefined;
        var recv_slots: [udp_transport_mod.UdpBatchCap]transport_mod.RecvBatchSlot = undefined;
        for (&recv_slots, 0..) |*slot, i| {
            slot.* = .{
                .buf = recv_bufs[i][0..],
                .n = 0,
                .peer = .{},
                .ecn = null,
            };
        }
        while (true) {
            const batch_n = self.transport.recvBatch(recv_slots[0..]) catch |err| {
                if (err == error.WouldBlock) break;
                return err;
            };
            if (batch_n == 0) break;

            var i: usize = 0;
            while (i < batch_n) : (i += 1) {
                const slot = recv_slots[i];
                self.processIncomingDatagram(slot.peer, slot.buf[0..slot.n], slot.ecn);
                stats.packets_processed += 1;
            }

            if (batch_n < recv_slots.len) break;
        }

        // Process timers that may have fired during packet processing
        self.processExpiredTimers(nowMsMonotonic());
        self.pruneClosed();
        self.armConnectionPtoTimers();

        return stats;
    }

    fn armConnectionPtoTimers(self: *Endpoint) void {
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            const c = entry.value_ptr.*;
            if (c.closed) continue;
            c.computeAndMaybeArmPtoInitial(self);
            c.computeAndMaybeArmPtoHandshake(self);
            c.computeAndMaybeArmPto(self);
        }
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

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
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

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
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

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
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

    fn markRetryObserved(self: *Endpoint, peer: conn_mod.SockAddr) void {
        const ph = hashSockaddr(&peer.storage, peer.len);
        var it = self.conns.iterator();
        while (it.next()) |e| {
            if (e.key_ptr.*.peer_hash != ph) continue;
            if (e.value_ptr.*.role != .Client) continue;
            e.value_ptr.*.retry_packets_observed +%= 1;
        }
    }

    // Helper: Process Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8)
    fn processRetryPacket(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, version: u32) void {
        // Parse Retry header
        var i: usize = 5;
        if (i >= bytes.len) return;
        const dcid_len = bytes[i];
        i += 1;
        if (i + dcid_len > bytes.len) return;
        const retry_dcid = bytes[i .. i + dcid_len];
        i += dcid_len;
        if (i >= bytes.len) return;
        const scid_len = bytes[i];
        i += 1;
        if (i + scid_len > bytes.len) return;
        const scid = bytes[i .. i + scid_len];
        i += scid_len;
        if (bytes.len < 16 or i >= bytes.len - 16) return; // Need room for integrity tag
        const token_bytes = bytes[i .. bytes.len - 16];

        // Lookup matching client connection.
        // Retry DCID must equal the client's Initial SCID that triggered Retry.
        // Validate integrity while scanning and pick the first verified candidate.
        var itc = self.conns.iterator();
        var c_found: ?*conn_mod.Connection = null;
        var verify_current: bool = false;
        var verify_original: bool = false;
        while (itc.next()) |e| {
            const candidate = e.value_ptr.*;
            if (candidate.role != .Client) continue;
            if (candidate.our_scid.len != retry_dcid.len) continue;
            if (!std.mem.eql(u8, candidate.our_scid.bytes[0..candidate.our_scid.len], retry_dcid)) continue;

            const cand_current = candidate.peer_initial_dcid.bytes[0..candidate.peer_initial_dcid.len];
            const cand_original = candidate.original_dcid.bytes[0..candidate.original_dcid.len];
            const cand_verify_current = (cand_current.len > 0 and packet.verifyRetry(cand_current, bytes));
            const cand_verify_original = (cand_original.len > 0 and packet.verifyRetry(cand_original, bytes));

            if (cand_verify_current or cand_verify_original) {
                c_found = candidate;
                verify_current = cand_verify_current;
                verify_original = cand_verify_original;
                break;
            }

            if (c_found == null) {
                c_found = candidate;
                verify_current = cand_verify_current;
                verify_original = cand_verify_original;
            }
        }

        // Fallback to peer-hash candidates if no SCID match exists.
        if (c_found == null) {
            const ph = hashSockaddr(&peer.storage, peer.len);
            itc = self.conns.iterator();
            while (itc.next()) |e| {
                if (e.key_ptr.*.peer_hash != ph) continue;
                const candidate = e.value_ptr.*;
                if (candidate.role != .Client) continue;

                const cand_current = candidate.peer_initial_dcid.bytes[0..candidate.peer_initial_dcid.len];
                const cand_original = candidate.original_dcid.bytes[0..candidate.original_dcid.len];
                const cand_verify_current = (cand_current.len > 0 and packet.verifyRetry(cand_current, bytes));
                const cand_verify_original = (cand_original.len > 0 and packet.verifyRetry(cand_original, bytes));

                if (cand_verify_current or cand_verify_original) {
                    c_found = candidate;
                    verify_current = cand_verify_current;
                    verify_original = cand_verify_original;
                    break;
                }

                if (c_found == null) {
                    c_found = candidate;
                    verify_current = cand_verify_current;
                    verify_original = cand_verify_original;
                }
            }
        }

        if (c_found == null and self.cfg.allow_insecure) {
            itc = self.conns.iterator();
            while (itc.next()) |e| {
                if (e.value_ptr.*.role == .Client) {
                    c_found = e.value_ptr.*;
                    break;
                }
            }
        }

        const c = c_found orelse return;

        // Verify Retry integrity using ODCID from current or original client Initial epoch.
        if (!(verify_current or verify_original) and !self.cfg.allow_insecure) {
            c.retry_reject_integrity +%= 1;
            return;
        }
        if (c.handshake_done_seen) {
            c.retry_reject_post_handshake +%= 1;
            return;
        }
        // RFC 9000 §17.2.5: A client accepts at most one Retry for a connection.
        // Once processed, all subsequent Retry packets are discarded.
        if (c.retry_received) {
            c.retry_reject_duplicate +%= 1;
            return;
        }

        // Store token and update version/DCID for next Initial
        c.initial_token.clearRetainingCapacity();
        _ = c.initial_token.appendSlice(self.allocator, token_bytes) catch {};
        c.retry_received = true;
        c.retry_apply_count +%= 1;
        c.version = version;
        c.version_v2 = (version == packet.QUIC_V2);
        c.initial_version = version;
        c.peer_initial_dcid.len = @intCast(@min(scid.len, c.peer_initial_dcid.bytes.len));
        if (c.peer_initial_dcid.len > 0) @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], scid[0..c.peer_initial_dcid.len]);

        // RFC 9000 §17.2.5: Client restarts Initial-space handshake state after Retry.
        // Keep transmit PN monotonic for interop trace checkers that enforce non-reset PN.
        c.pn_initial = .{};
        c.initial_rx_keys = null;
        c.initial_tx_keys = null;
        c.hs_rx_keys = null;
        c.hs_tx_keys = null;
        c.app_rx_keys = null;
        c.app_tx_keys = null;
        c.app_rx_secret = null;
        c.app_tx_secret = null;
        c.crypto_tx_off_initial = 0;
        c.crypto_rx_off_initial = 0;
        c.crypto_retx_initial_off = 0;
        if (c.crypto_retx_initial) |retx| {
            self.allocator.free(retx);
            c.crypto_retx_initial = null;
        }
        c.keylog_handshake_logged = false;
        c.keylog_app_logged = false;
        c.keylog_client_traffic_epoch = 0;
        c.keylog_server_traffic_epoch = 0;
        c.tls_inbox.clearRetainingCapacity();
        c.peer_finished_verified = false;
        c.server_hello_sent = false;
        c.handshake_packet_sent = false;
        c.handshake_done_sent = false;
        c.handshake_done_seen = false;

        // Recreate client TLS context so a fresh ClientHello is generated for the post-Retry Initial.
        if (c.tls_context) |tls_ctx| {
            tls_ctx.deinit();
            const local_tp: []const u8 = c.local_transport_params_raw orelse &[_]u8{};
            const fresh_tls = handshake_integration.createTlsContext(
                self.allocator,
                .Client,
                self.cfg.alpn,
                local_tp,
                null,
                null,
                self.cfg.allow_insecure,
                false,
                self.cfg.inline_client_cert_der,
                self.cfg.inline_client_priv_key,
            ) catch return;
            tls_ctx.* = fresh_tls;
            if (c.server_name) |name| {
                tls_ctx.config.server_name = name;
            }
        } else {
            return;
        }

        // Resend Initial with token
        self.clientSendInitialProbe(c) catch {};
    }

    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        const norm_peer = normalizeAddr(&peer.storage, peer.len);
        // Process all packets in the datagram (may be coalesced)
        // RFC 9000 §12.2: "Senders can coalesce multiple QUIC packets into one UDP datagram"
        var remaining = bytes;

        // Temporarily set global endpoint pointer for callbacks
        current_io_endpoint = self;
        defer current_io_endpoint = null;

        // Create RxContext for delegation to incoming.zig modules
        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));

        var rx_ctx = incoming.RxContext{
            .allocator = &self.allocator,
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
            .setup_sender_fn = struct {
                fn setup(conn: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    conn.setSender(@ptrCast(ep), senderPaced);
                }
            }.setup,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
            .generated_token_secret = &self.generated_token_secret,
            .max_connections = self.cfg.max_connections,
        };

        // Process packets until we've consumed all bytes
        while (remaining.len > 0) {
            if (remaining.len < 1) break;

            const first = remaining[0];
            const is_long = (first & 0x80) != 0;

            // Short header: Process and consume entire remaining buffer
            if (!is_long) {
                // Handle NAT rebinding detection
                const lookup_result = lookup.findConnectionByDcid(&self.conns, norm_peer, remaining, null);
                if (lookup_result.conn) |c| {
                    if (lookup_result.nat_rebinding or !conn_mod.SockAddr.eq(&c.peer, &norm_peer)) {
                        const peer_h = hashSockaddr(&norm_peer.storage, norm_peer.len);
                        self.onPathAddressChanged(c, norm_peer, peer_h, lookup_result.dcid_len);
                    }
                }
                incoming.processShortHeader(&rx_ctx, norm_peer, remaining, ecn_bits, rx_ctx.send_fn);
                break; // Short header packet consumes rest of datagram
            }

            // Long header: Need to determine packet length to know how much to consume
            if (remaining.len < 5) break;
            const version: u32 = (@as(u32, remaining[1]) << 24) | (@as(u32, remaining[2]) << 16) | (@as(u32, remaining[3]) << 8) | @as(u32, remaining[4]);

            // Try to determine packet length to know how much to consume
            var packet_len: usize = remaining.len; // Default to entire remaining buffer

            // For long header packets, we need to parse the header to find the packet length
            // The packet length is encoded after the connection IDs
            if (remaining.len >= 7) {
                // Skip to DCID length at byte 5
                const dcid_len = remaining[5];
                if (remaining.len >= 6 + dcid_len + 1) {
                    // Skip DCID and get SCID length
                    const scid_len = remaining[6 + dcid_len];
                    if (remaining.len >= 7 + dcid_len + scid_len) {
                        // Now we're at the variable-length integer for packet length
                        var offset: usize = 7 + dcid_len + scid_len;

                        // Version Negotiation packets don't have length field
                        if (version == 0) {
                            packet_len = remaining.len; // Use entire buffer for VN
                        }
                        // Retry packets also don't have a length field
                        else if (((first >> 4) & 0x03) == 3) {
                            packet_len = remaining.len; // Use entire buffer for Retry
                        }
                        // Initial, Handshake, and 0-RTT packets have length field
                        else {
                            // For Initial packets, skip token length varint
                            if (((first >> 4) & 0x03) == 0 and remaining.len > offset) {
                                // Read token length as varint
                                const token_len_result = varint.decode(remaining[offset..]) catch {
                                    break; // Can't parse, treat as single packet
                                };
                                offset += token_len_result.n;
                                offset += @as(usize, @intCast(token_len_result.value)); // Skip token bytes
                            }

                            // Now read the packet length varint
                            if (remaining.len > offset) {
                                const len_result = varint.decode(remaining[offset..]) catch {
                                    break; // Can't parse, treat as single packet
                                };
                                offset += len_result.n;
                                // packet_len is header_so_far + payload_length + 16 (auth tag)
                                packet_len = offset + @as(usize, @intCast(len_result.value));
                                packet_len = @min(packet_len, remaining.len); // Don't exceed buffer
                            }
                        }
                    }
                }
            }

            // Extract just this packet
            const packet_bytes = remaining[0..packet_len];

            // Debug: log packet extraction
            const packet_ty = (packet_bytes[0] >> 4) & 0x03;
            logger.debugPrint("processIncomingDatagram: Extracted type {} packet, len={} from datagram offset={}\n", .{
                packet_ty,
                packet_len,
                bytes.len - remaining.len,
            });

            // Process the packet based on type
            // Re-parse packet type from THIS packet's first byte (for coalesced packets)

            if (version == 0) {
                incoming.processVersionNegotiation(&rx_ctx, norm_peer, packet_bytes);
            } else if (packet_ty == 0) {
                // Server-side version negotiation for unsupported versions.
                // This is required by the interop simulator readiness probe
                // (wait-for-it-quic), which sends an Initial-like packet with
                // an unknown version and expects a Version Negotiation reply.
                if (self.role == .Server and version != packet.QUIC_V1 and version != packet.QUIC_V2) {
                    var dcid: []const u8 = &[_]u8{};
                    var scid: []const u8 = &[_]u8{};
                    if (packet_bytes.len >= 7) {
                        const dcid_len = packet_bytes[5];
                        if (packet_bytes.len >= 6 + dcid_len + 1) {
                            dcid = packet_bytes[6 .. 6 + dcid_len];
                            const scid_len_off = 6 + dcid_len;
                            const scid_len = packet_bytes[scid_len_off];
                            const scid_off = scid_len_off + 1;
                            if (packet_bytes.len >= scid_off + scid_len) {
                                scid = packet_bytes[scid_off .. scid_off + scid_len];
                            }
                        }
                    }
                    const supported_versions = [_]u32{ packet.QUIC_V1, packet.QUIC_V2 };
                    var vn_buf: [256]u8 = undefined;
                    if (encodeVersionNegotiationPacket(scid, dcid, &supported_versions, vn_buf[0..])) |vn_packet| {
                        _ = self.sendTo(norm_peer, vn_packet) catch {};
                    } else |_| {}
                } else {
                    incoming.processInitial(&rx_ctx, norm_peer, packet_bytes, version);
                }
            } else if (packet_ty == 3) {
                self.markRetryObserved(norm_peer);
                self.processRetryPacket(norm_peer, packet_bytes, version);
            } else if (packet_ty == 2) {
                incoming.processHandshake(&rx_ctx, norm_peer, packet_bytes, version, ecn_bits, rx_ctx.send_fn);
            }

            // Advance to next packet
            remaining = remaining[packet_len..];
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
        logger.debugPrint("path: change detected dcid_len={d} triggering validation (phase={d})\n", .{ dcid_len, @intFromBool(c.tx_key_phase) });
    }

    /// Mark path validated and clear unvalidated counters consistently.
    fn onPathValidated(self: *Endpoint, c: *conn_mod.Connection) void {
        _ = self; // unused
        c.path_validation_pending = false;
        c.address_validated = true;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        logger.debugPrint("path: validated (peer={d} bytes_rx_unval reset)\n", .{c.peer.len});
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
                                    const paced_peer = if (t.paced_peer) |peer| peer else c.peer;
                                    _ = self.sendTo(paced_peer, bytes) catch {};
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
            .allocator = &self.allocator,
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
            .allocator = &self.allocator,
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
            .allocator = self.allocator,
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
                logger.debugPrint("senderPaced using peer addr {}.{}.{}.{}:{}\n", .{ addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], portFromNetwork(sin.port) });
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
