// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! High-level QUIC transport layer providing connection and stream management.
//! This layer provides a convenient interface for building QUIC applications.
//!
//! RFC 9000 §7 and §10 outline endpoint responsibilities (handshake, timeout,
//! connection lifecycle) that this abstraction orchestrates. Stream helpers map
//! directly to §§2–4, while TLS handling aligns with RFC 9001 §4.

const std = @import("std");
const logger = @import("quic_logger");
const builtin = @import("builtin");
const api = @import("quic_api");

/// Zig 0.16.0 compat: milliTimestamp() was removed.
fn milliTimestamp() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// Zig 0.16 compat: replacement for removed std.time.nanoTimestamp().
fn nanoTimestampCompat() i128 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

/// Zig 0.16.0 compat: std.Thread.sleep() was removed.
fn nanosleep(ns: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

/// Errors that can occur during QUIC operations.
pub const QuicError = error{
    InitFailed,
    ConnectionFailed,
    StreamFailed,
    WriteError,
    ReadError,
    InvalidAddress,
    CertificateError,
    EndpointInitFailed,
    AcceptFailed,
    HandshakeFailed,
    HandshakeError,
    Timeout,
    WouldBlock,
    Closed,
    InvalidState,
    TransportParametersFailed,
    FlowControlViolation,
    ProtocolViolation,
    IdleTimeout,
    ConnectionClosed,
};

/// Readers-writer synchronization for endpoint poll() vs concurrent stream I/O.
///
/// Endpoint poll mutates connection stream state for all active connections.
/// Handler threads doing read/write on the same connection tree must not race
/// with poll's mutable map access.
pub const PollSync = struct {
    mu: std.Io.Mutex = std.Io.Mutex.init,
    cv: std.Io.Condition = .init,
    poll_requested: bool = false,
    active_io_count: u32 = 0,

    pub fn enterIo(self: *PollSync) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        while (self.poll_requested) {
            self.cv.wait(io, &self.mu) catch break;
        }
        self.active_io_count += 1;
    }

    pub fn leaveIo(self: *PollSync) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.active_io_count > 0) self.active_io_count -= 1;
        if (self.active_io_count == 0) self.cv.signal(io);
    }

    pub fn enterPoll(self: *PollSync) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        self.poll_requested = true;
        while (self.active_io_count > 0) {
            self.cv.wait(io, &self.mu) catch break;
        }
    }

    pub fn leavePoll(self: *PollSync) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        self.poll_requested = false;
        self.cv.broadcast(io);
    }
};

/// High-level QUIC transport for managing endpoints and connections.
pub const QuicTransport = struct {
    allocator: std.mem.Allocator,
    config: Config,
    endpoint: ?*api.QuicEndpoint = null,
    connections: std.ArrayList(*QuicConnection),
    connections_mutex: std.Io.Mutex = std.Io.Mutex.init,
    pending_destroy: std.ArrayList(*api.QuicConnection),
    pending_destroy_mutex: std.Io.Mutex = std.Io.Mutex.init,
    poll_sync: PollSync = .{},
    /// Path to the TLS certificate file.
    cert_path: ?[]const u8,
    /// Path to the TLS private key file.
    key_path: ?[]const u8,
    /// Internal QUIC configuration object.
    quic_config: ?*api.QuicConfig = null,

    /// Configuration options for the QUIC transport.
    pub const Config = struct {
        address: []const u8 = "0.0.0.0",
        port: u16 = 7567,
        // Implementation guard to cap concurrent connections; not normative.
        max_connections: usize = 1000,
        // RFC 9000 §10.1 idle timeout (converted to transport config later)
        idle_timeout_ms: u64 = 30000,
        // RFC 9000 §4.1 STREAM flow control credit (per-stream offset limit)
        max_stream_data: u64 = 10 * 1024 * 1024, // 10MB per stream
        // RFC 9000 §4.2 connection-level flow control (MAX_DATA)
        max_data: u64 = 100 * 1024 * 1024, // 100MB per connection
        /// Path to the TLS certificate file.
        /// Required for secure server operation.
        cert_path: ?[]const u8 = null,
        /// Path to the TLS private key file.
        /// Required for secure server operation.
        key_path: ?[]const u8 = null,
        /// Optional path to CA certificate for client authentication (RFC 9001 §4.4.2).
        ca_path: ?[]const u8 = null,
        /// Controls TLS certificate validation only. When true, self-signed and
        /// expired certificates are accepted. Does NOT affect Retry integrity
        /// verification, connection ID matching, or amplification protection.
        /// For development and testing only — never enable in production.
        allow_insecure: bool = false,
        /// Auto-generate a self-signed certificate if cert/key are missing. Off by default.
        auto_generate_certs: bool = false,
        /// Require client certificate authentication (mTLS). Server only.
        require_client_cert: bool = false,
    };

    /// Initializes a new QUIC transport with the given configuration.
    pub fn init(allocator: std.mem.Allocator, config: Config) !QuicTransport {
        return QuicTransport{
            .allocator = allocator,
            .config = config,
            .connections = try std.ArrayList(*QuicConnection).initCapacity(allocator, 0),
            .pending_destroy = try std.ArrayList(*api.QuicConnection).initCapacity(allocator, 0),
            .cert_path = config.cert_path,
            .key_path = config.key_path,
        };
    }

    /// Deinitializes the transport, closing all connections and releasing resources.
    pub fn deinit(self: *QuicTransport) void {
        self.drainPendingDestroy();

        self.connections_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        var conns = self.connections;
        self.connections = .empty;
        self.connections_mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        for (conns.items) |conn| {
            const inner = conn.quic_connection orelse conn.inner;
            conn.close();
            if (self.endpoint) |ep| {
                api.destroy(ep, inner);
            } else {
                inner.deinit();
            }
            self.allocator.destroy(conn);
        }
        conns.deinit(self.allocator);

        self.drainPendingDestroy();
        self.pending_destroy.deinit(self.allocator);
        // Now deinitialize endpoint
        if (self.endpoint) |ep| {
            api.endpointDeinit(ep);
            self.endpoint = null;
        }
        if (self.quic_config) |cfg| {
            // Free any loaded certificate data
            if (cfg.inline_server_cert_der) |cert| {
                self.allocator.free(cert);
            }
            if (cfg.inline_server_priv_p256) |key| {
                self.allocator.free(key);
            }
            self.allocator.destroy(cfg);
            self.quic_config = null;
        }
    }

    /// Starts listening for incoming QUIC connections on the configured address and port.
    ///
    /// RFC 9000 §7.1 requires servers to validate client addresses before
    /// completing the handshake; this listener ensures Initial padding and
    /// optional Retry support via the shared `QuicConfig` knobs. Certificate
    /// loading adheres to RFC 9001 §4.4 expectations for TLS server endpoints.
    pub fn listen(self: *QuicTransport) !void {
        // CANARY: REQ=REQ-GQL-074; FEATURE="Network Transport"; ASPECT=QUICListener; STATUS=TESTED; TEST=e2e_quic_startup; OWNER=wire; UPDATED=2025-09-25

        const cert_path = self.cert_path orelse {
            logger.debugPrint("{{\"component\":\"transport\",\"error\":\"missing certificate path\"}}\n", .{});
            return QuicError.CertificateError;
        };
        const key_path = self.key_path orelse {
            logger.debugPrint("{{\"component\":\"transport\",\"error\":\"missing private key path\"}}\n", .{});
            return QuicError.CertificateError;
        };

        // Check if certificates exist
        var cert_exists = true;
        std.Io.Dir.cwd().access(std.Io.Threaded.global_single_threaded.io(), cert_path, .{}) catch {
            cert_exists = false;
        };
        var key_exists = true;
        std.Io.Dir.cwd().access(std.Io.Threaded.global_single_threaded.io(), key_path, .{}) catch {
            key_exists = false;
        };

        const bind_host = if (std.mem.eql(u8, self.config.address, "localhost"))
            "127.0.0.1"
        else
            self.config.address;
        const bind_addr = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ bind_host, self.config.port });
        defer self.allocator.free(bind_addr);

        // Auto-generate self-signed certificates only when explicitly enabled.
        if (!cert_exists or !key_exists) {
            if (self.config.auto_generate_certs) {
                try self.generateSelfSignedCert(cert_path, key_path);
                logger.debugPrint("TLS_CERT_AUTOGENERATED cert_path=\"{s}\" key_path=\"{s}\"\n", .{ cert_path, key_path });
                cert_exists = true;
                key_exists = true;
            } else {
                logger.debugPrint("{{\"component\":\"transport\",\"error\":\"certificate or key missing\"}}\n", .{});
                return QuicError.CertificateError;
            }
        }

        // Print startup JSON exactly once
        logger.debugPrint("{{\"component\":\"transport\",\"transport\":\"quic\",\"tls\":\"true\",\"port\":{}}}\n", .{self.config.port});
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"server startup\",\"use_tls\":true,\"cert_exists\":{},\"key_exists\":{}}}\n", .{ cert_exists, key_exists });

        // Load certificate files (TLS required)
        var inline_cert_der: ?[]u8 = null;
        var inline_priv_key: ?[]u8 = null;
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"loading certificate files\",\"cert_path\":\"{s}\",\"key_path\":\"{s}\"}}\n", .{ cert_path, key_path });

        const tls_io = std.Io.Threaded.global_single_threaded.io();
        const cert_file = std.Io.Dir.cwd().openFile(tls_io, cert_path, .{}) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to open certificate file\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ cert_path, err });
            return QuicError.CertificateError;
        };
        defer cert_file.close(tls_io);

        const cert_stat = try cert_file.stat(tls_io);
        const cert_size = cert_stat.size;
        const cert_pem = try self.allocator.alloc(u8, cert_size);
        defer self.allocator.free(cert_pem);
        _ = try cert_file.readPositionalAll(tls_io, cert_pem, 0);
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"loaded certificate\",\"size\":{}}}\n", .{cert_size});

        inline_cert_der = api.pem.parseCertificate(self.allocator, cert_pem) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to parse certificate\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ cert_path, err });
            return QuicError.CertificateError;
        };

        const key_file = std.Io.Dir.cwd().openFile(tls_io, key_path, .{}) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to open private key file\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ key_path, err });
            if (inline_cert_der) |cert| self.allocator.free(cert);
            return QuicError.CertificateError;
        };
        defer key_file.close(tls_io);

        const key_stat = try key_file.stat(tls_io);
        const key_size = key_stat.size;
        const key_pem = try self.allocator.alloc(u8, key_size);
        defer self.allocator.free(key_pem);
        _ = try key_file.readPositionalAll(tls_io, key_pem, 0);
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"loaded private key\",\"size\":{}}}\n", .{key_size});

        inline_priv_key = api.pem.parsePrivateKey(self.allocator, key_pem) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to parse private key\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ key_path, err });
            if (inline_cert_der) |cert| self.allocator.free(cert);
            return QuicError.CertificateError;
        };

        // Initialize QUIC with TLS
        const cfg = try self.allocator.create(api.QuicConfig);
        cfg.* = .{
            .version = .v1,
            .allow_insecure = self.config.allow_insecure,
            .alpn = &[_][]const u8{"quic-zig/1"},
            .cc = .newreno,
            .enable_datagram = false,
            .enable_spin_bit = false,
            .grease = true,
            .compatible_vn = false,
            .enable_retry = false,
            .token_secret = null,
            .token_expiry_ms = 60000,
            .enable_pacing = false,
            .max_datagram_size = 1200,
            .max_idle_timeout_ms = @intCast(self.config.idle_timeout_ms),
            .max_udp_payload = 1350,
            .cert_path = cert_path,
            .key_path = key_path,
            .ca_path = if (self.config.ca_path) |p| p else null,
            .aead_confidentiality_limit_override = null,
            .aead_integrity_limit_override = null,
            .max_connections = self.config.max_connections,
            .inline_server_cert_der = inline_cert_der,
            .inline_server_priv_p256 = inline_priv_key,
            .require_client_cert = self.config.require_client_cert,
        };

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"initializing endpoint\",\"bind_addr\":\"{s}\"}}\n", .{bind_addr});
        self.endpoint = try api.endpointInit(&self.allocator, bind_addr, cfg);
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"endpoint initialized successfully\"}}\n", .{});

        // Print startup log in JSON format
        if (self.config.ca_path != null) {
            logger.debugPrint("{{\"level\":\"INFO\",\"msg\":\"mTLS: client certs required\"}}\n", .{});
        }
        logger.debugPrint("{{\"component\":\"transport\",\"transport\":\"quic\",\"tls\":\"true\",\"port\":{d}}}\n", .{self.config.port});
    }

    fn generateSelfSignedCert(self: *QuicTransport, cert_path: []const u8, key_path: []const u8) !void {
        const gen_io = std.Io.Threaded.global_single_threaded.io();
        if (std.fs.path.dirname(cert_path)) |dir| {
            std.Io.Dir.cwd().createDirPath(gen_io, dir) catch {};
        }
        if (std.fs.path.dirname(key_path)) |dir| {
            std.Io.Dir.cwd().createDirPath(gen_io, dir) catch {};
        }

        // Generate self-signed certificate using OpenSSL command
        const result = try std.process.run(self.allocator, gen_io, .{
            .argv = &[_][]const u8{
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "365",
                "-subj",
                "/CN=localhost",
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .exited or result.term.exited != 0) {
            return QuicError.CertificateError;
        }

        // Set secure permissions (0600)
        // On Windows, chmod is not supported, so we skip permission changes
        if (builtin.os.tag != .windows) {
            const cert_file = try std.Io.Dir.cwd().openFile(gen_io, cert_path, .{});
            defer cert_file.close(gen_io);
            try cert_file.setPermissions(gen_io, std.Io.File.Permissions.fromMode(0o600));

            const key_file = try std.Io.Dir.cwd().openFile(gen_io, key_path, .{});
            defer key_file.close(gen_io);
            try key_file.setPermissions(gen_io, std.Io.File.Permissions.fromMode(0o600));
        }
    }

    /// Process deferred connection destructions queued by worker threads.
    /// Must be called by the polling thread.
    pub fn drainPendingDestroy(self: *QuicTransport) void {
        self.pending_destroy_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.pending_destroy_mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        if (self.pending_destroy.items.len == 0) return;

        self.poll_sync.enterPoll();
        defer self.poll_sync.leavePoll();

        for (self.pending_destroy.items) |inner_conn| {
            if (self.endpoint) |ep| {
                api.destroy(ep, inner_conn);
            } else {
                inner_conn.deinit();
            }
        }
        self.pending_destroy.clearRetainingCapacity();
    }

    fn wrapAcceptedConnection(self: *QuicTransport, quic_conn: *api.QuicConnection) !*QuicConnection {
        const conn = try self.allocator.create(QuicConnection);
        conn.* = QuicConnection{
            .allocator = self.allocator,
            .quic_connection = quic_conn,
            .inner = quic_conn,
            .streams = .empty,
            .poll_sync = &self.poll_sync,
        };

        self.connections_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.connections_mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        try self.connections.append(self.allocator, conn);
        return conn;
    }

    /// Accepts an incoming QUIC connection from a client.
    ///
    /// Blocks for up to ~3 seconds waiting for a connection with incoming
    /// streams (completed handshake per RFC 9000 §7.2).
    ///
    /// This method drives endpoint polling internally so it can be used as
    /// the sole event driver.  For lower idle-CPU usage, prefer calling
    /// poll() on a dedicated thread and using tryAccept() or
    /// waitForAccepted() to dequeue connections.
    pub fn accept(self: *QuicTransport) !*QuicConnection {
        if (self.endpoint) |ep| {
            var pending_conn: ?*api.QuicConnection = null;
            const deadline = milliTimestamp() + 3000;

            while (milliTimestamp() < deadline) {
                self.drainPendingDestroy();

                // Drive one poll cycle to process packets / advance handshakes.
                self.poll_sync.enterPoll();
                ep.poll(50) catch |err| {
                    self.poll_sync.leavePoll();
                    return err;
                };
                self.poll_sync.leavePoll();

                if (pending_conn == null) {
                    pending_conn = api.tryAccept(ep);
                }
                if (pending_conn) |qc| {
                    if (api.hasIncomingStreams(qc)) {
                        return self.wrapAcceptedConnection(qc);
                    }
                }
            }

            if (pending_conn) |qc| {
                return self.wrapAcceptedConnection(qc);
            }
            return QuicError.WouldBlock;
        }
        return QuicError.InvalidState;
    }

    /// Attempt to accept without blocking.
    ///
    /// This is a lightweight O(1) check of the accepted queue.  It does NOT
    /// call poll() — the caller must ensure poll() is driven separately
    /// (e.g. on a dedicated thread or interleaved in the event loop) so that
    /// incoming packets are processed and connections reach the accepted queue.
    ///
    /// Previous behaviour called ep.poll(10) on every invocation, which caused
    /// ~40% idle CPU when called in a loop due to repeated PollSync locking,
    /// timer processing, and syscall overhead.
    pub fn tryAccept(self: *QuicTransport) ?*QuicConnection {
        const ep = self.endpoint orelse return null;
        const qc = api.tryAccept(ep) orelse return null;
        return self.wrapAcceptedConnection(qc) catch null;
    }

    /// Block until a connection is available or timeout expires.
    ///
    /// Unlike accept(), this does NOT drive endpoint polling.  The caller
    /// must ensure poll() is called on a separate thread so that incoming
    /// packets are processed and the handshake completes.  Uses a condition
    /// variable internally so idle CPU is near zero.
    pub fn waitForAccepted(self: *QuicTransport, timeout_ms: u32) ?*QuicConnection {
        const ep = self.endpoint orelse return null;
        const qc = api.waitForAccepted(ep, timeout_ms) orelse return null;
        return self.wrapAcceptedConnection(qc) catch null;
    }

    /// Remove, close, and reclaim a connection wrapper.
    pub fn destroyConnection(self: *QuicTransport, conn: *QuicConnection) void {
        self.connections_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        var idx: usize = 0;
        while (idx < self.connections.items.len) {
            if (self.connections.items[idx] == conn) {
                _ = self.connections.swapRemove(idx);
                break;
            }
            idx += 1;
        }
        self.connections_mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        const inner = conn.quic_connection orelse conn.inner;
        conn.close();
        self.pending_destroy_mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        self.pending_destroy.append(self.allocator, inner) catch {
            inner.deinit();
        };
        self.pending_destroy_mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        self.allocator.destroy(conn);
    }

    /// Polls the endpoint for network events with the specified timeout in milliseconds.
    ///
    /// RFC 9000 §6 mandates timers for loss detection and idle timeout. We feed
    /// the endpoint so that PTO/idle timers managed by recovery (RFC 9002) fire.
    pub fn poll(self: *QuicTransport, timeout_ms: u32) !void {
        if (self.endpoint) |ep| {
            const timeout_i32: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            self.poll_sync.enterPoll();
            defer self.poll_sync.leavePoll();
            try api.poll(ep, timeout_i32);
        }
    }
};

/// Represents an active QUIC connection that can manage multiple streams.
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    quic_connection: ?*api.QuicConnection,
    /// Compatibility alias used by geode integration.
    inner: *api.QuicConnection,
    streams: std.ArrayList(*QuicStream),
    streams_init: bool = false,
    next_stream_id: usize = 0,
    poll_sync: ?*PollSync = null,

    /// Closes the connection and all associated streams.
    pub fn close(self: *QuicConnection) void {
        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        // Close all streams (idempotent) if initialized
        if (self.streams_init) {
            for (self.streams.items) |s| {
                s.close();
                self.allocator.destroy(s);
            }
            self.streams.deinit(self.allocator);
            self.streams_init = false;
        }
        // Send CONNECTION_CLOSE and keep endpoint-owned reclamation in transport.
        if (self.quic_connection) |qc| {
            api.closeConnection(qc, 0) catch |err| {
                logger.warn("closeConnection during deinit failed: {s}", .{@errorName(err)});
            };
            self.quic_connection = null;
        }
    }

    /// Accepts an incoming bidirectional stream on this connection.
    ///
    /// RFC 9000 §2.1 permits peers to open bidirectional streams subject to
    /// MAX_STREAMS credit. The underlying API enforces those limits before this
    /// helper returns a live `QuicStream`.
    pub fn acceptStream(self: *QuicConnection) !*QuicStream {
        // CANARY: REQ=REQ-GQL-074; FEATURE="Network Transport"; ASPECT=QUICStream; STATUS=TESTED; TEST=TestCANARY_REQ_GQL_074_QUICStream; OWNER=wire; UPDATED=2025-09-22

        const stream = try self.allocator.create(QuicStream);
        errdefer self.allocator.destroy(stream);

        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        const qc = self.quic_connection orelse return QuicError.StreamFailed;

        // Accept a QUIC stream - this will check for existing streams first
        // then fall back to waiting for new ones
        const stream_id = try api.acceptStream(qc);

        stream.* = QuicStream{
            .allocator = self.allocator,
            .quic_stream_id = stream_id,
            .parent_connection = self,
            .stream_id = @intCast(stream_id),
            .poll_sync = self.poll_sync,
        };

        if (!self.streams_init) {
            self.streams = try std.ArrayList(*QuicStream).initCapacity(self.allocator, 0);
            self.streams_init = true;
        }
        try self.streams.append(self.allocator, stream);
        return stream;
    }

    /// Opens a new stream on this connection, either bidirectional or unidirectional.
    ///
    /// RFC 9000 §3.1 describes stream state machines. We return a handle that
    /// keeps the stream ID for later RESET/FIN signalling.
    pub fn openStream(self: *QuicConnection, bidirectional: bool) !*QuicStream {
        // CANARY: REQ=REQ-GQL-074; FEATURE="Network Transport"; ASPECT=QUICStreamOpen; STATUS=TESTED; TEST=TestCANARY_REQ_GQL_074_QUICStreamOpen; OWNER=wire; UPDATED=2025-09-22

        const stream = try self.allocator.create(QuicStream);
        errdefer self.allocator.destroy(stream);

        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        const qc = self.quic_connection orelse return QuicError.StreamFailed;
        const stream_id = try api.openStream(qc, bidirectional);
        stream.* = QuicStream{
            .allocator = self.allocator,
            .quic_stream_id = stream_id,
            .parent_connection = self,
            .stream_id = @intCast(stream_id),
            .poll_sync = self.poll_sync,
        };

        if (!self.streams_init) {
            self.streams = try std.ArrayList(*QuicStream).initCapacity(self.allocator, 0);
            self.streams_init = true;
        }
        try self.streams.append(self.allocator, stream);
        return stream;
    }

    pub fn hasIncomingStreams(self: *QuicConnection) bool {
        const qc = self.quic_connection orelse return false;
        return api.hasIncomingStreams(qc);
    }

    pub fn isDrained(self: *QuicConnection) bool {
        const qc = self.quic_connection orelse return true;
        return api.isDrained(qc);
    }

    pub fn isHandshakeConfirmed(self: *QuicConnection) bool {
        const qc = self.quic_connection orelse return false;
        return api.isHandshakeConfirmed(qc);
    }

    pub fn getPeerCertificateDer(self: *QuicConnection) ?[]const u8 {
        const qc = self.quic_connection orelse return null;
        const tls_ctx = qc.tls_context orelse return null;
        const chain = tls_ctx.peer_cert_chain orelse return null;
        if (chain.len == 0) return null;
        return chain[0];
    }

    pub fn destroyStream(self: *QuicConnection, stream: *QuicStream) void {
        var idx: usize = 0;
        while (idx < self.streams.items.len) {
            if (self.streams.items[idx] == stream) {
                _ = self.streams.swapRemove(idx);
                break;
            }
            idx += 1;
        }
        self.allocator.destroy(stream);
    }
};

/// Represents a QUIC stream for reading and writing data.
pub const QuicStream = struct {
    allocator: std.mem.Allocator,
    quic_stream_id: ?api.QuicStreamId,
    parent_connection: *QuicConnection,
    stream_id: usize = 0,
    read_buffer: []u8 = &[_]u8{},
    poll_sync: ?*PollSync = null,

    /// Closes the stream, releasing any associated resources.
    ///
    /// RFC 9000 §3.1 allows either side to abruptly terminate via RESET_STREAM
    /// (or FIN). This helper optionally forces RESET when an environment flag is
    /// set, enabling tests that exercise §19.4 error propagation.
    pub fn close(self: *QuicStream) void {
        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        // Best-effort, idempotent: avoid vendor close by default to reduce teardown races.
        // Enable explicit stream close only when GEODE_QUIC_FORCE_STREAM_CLOSE=1.
        if (self.quic_stream_id) |sid| {
            const force_stream_close = if (std.c.getenv("GEODE_QUIC_FORCE_STREAM_CLOSE")) |_| true else false;
            if (force_stream_close) {
                if (self.parent_connection.quic_connection) |qc| {
                    api.closeStream(qc, sid, 0) catch |err| {
                        logger.warn("closeStream during deinit failed for stream {d}: {s}", .{ sid, @errorName(err) });
                    };
                }
            }
            self.quic_stream_id = null;
        }
    }

    /// Writes data to the stream.
    pub fn write(self: *QuicStream, data: []const u8) !usize {
        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        if (self.quic_stream_id) |sid| {
            const qc = self.parent_connection.quic_connection orelse return QuicError.StreamFailed;
            return api.writeStream(qc, sid, data, false);
        }
        return QuicError.StreamFailed;
    }

    /// Writes all data to the stream, handling fragmentation internally.
    pub fn writeAll(self: *QuicStream, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try self.write(data[written..]);
            if (n == 0) return QuicError.WriteError;
            written += n;
        }
    }

    /// Reads data from the stream into the provided buffer, returning the number of bytes read.
    pub fn read(self: *QuicStream, buf: []u8) !usize {
        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }

        if (self.quic_stream_id) |sid| {
            const qc = self.parent_connection.quic_connection orelse return QuicError.StreamFailed;
            return api.readStream(qc, sid, buf);
        }
        return QuicError.StreamFailed;
    }

    /// Reads data until the buffer is full or the stream ends, returning total bytes read.
    pub fn readAll(self: *QuicStream, buf: []u8) !usize {
        var total_read: usize = 0;
        while (total_read < buf.len) {
            const n = try self.read(buf[total_read..]);
            if (n == 0) break;
            total_read += n;
        }
        return total_read;
    }

    /// Reads a line of text from the stream, up to max_size bytes, returning an allocated buffer.
    pub fn readLine(self: *QuicStream, max_size: usize) ![]u8 {
        var buf = try self.allocator.alloc(u8, max_size);
        defer self.allocator.free(buf);

        var pos: usize = 0;
        var retry_count: usize = 0;
        const max_retries: usize = 100;
        while (pos < max_size) {
            var one: [1]u8 = undefined;
            const n = self.read(&one) catch |err| {
                if (err == error.WouldBlock and pos == 0) return error.WouldBlock;
                if (err == error.WouldBlock) {
                    retry_count += 1;
                    if (retry_count > max_retries) return error.UnexpectedEndOfStream;
                    // Zig 0.16.0: Io.Condition has no timedWait. Simulate with a
                    // poll loop: sleep a small slice, then retry the read. 5 ms
                    // matches the waitForAccepted (endpoint.zig:~582) and
                    // PollSync.waitForPoll (geode src/transport/quic.zig:~119)
                    // cadences — sub-ms slices starve the main thread of
                    // ep.poll() calls and stall the handshake.
                    nanosleep(5 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };

            if (n == 0) {
                if (pos == 0) return error.EndOfStream;
                return error.UnexpectedEndOfStream;
            }
            buf[pos] = one[0];
            pos += 1;
            retry_count = 0;
            if (one[0] == '\n') break;
        }
        if (pos == 0) return error.EndOfStream;
        const out = try self.allocator.alloc(u8, pos);
        @memcpy(out, buf[0..pos]);
        return out;
    }

    pub fn finish(self: *QuicStream) !void {
        if (self.poll_sync) |ps| ps.enterIo();
        defer {
            if (self.poll_sync) |ps| ps.leaveIo();
        }
        const sid = self.quic_stream_id orelse return QuicError.StreamFailed;
        const qc = self.parent_connection.quic_connection orelse return QuicError.StreamFailed;
        _ = try api.writeStream(qc, sid, &.{}, true);
    }
};

/// Client-side QUIC support for connecting to QUIC servers.
pub const QuicClient = struct {
    allocator: std.mem.Allocator,
    endpoint: ?*api.QuicEndpoint = null,
    quic_connection: ?*api.QuicConnection = null,
    server_addr: []const u8 = "",
    server_port: u16 = 7567,
    is_quic: bool = false,
    quic_config: ?*api.QuicConfig = null,

    /// Initializes a new QUIC client.
    pub fn init(allocator: std.mem.Allocator) QuicClient {
        return QuicClient{
            .allocator = allocator,
        };
    }

    /// Deinitializes the client, closing connections and releasing resources.
    pub fn deinit(self: *QuicClient) void {
        // Close connection first, then endpoint. The vendored QUIC may crash if closed during handshake;
        // skip active close by default and rely on endpoint teardown/OS to reclaim unless forced via env.
        const force_close = if (std.c.getenv("GEODE_QUIC_FORCE_CLOSE")) |_| true else false;
        if (self.quic_connection) |conn| {
            if (force_close) {
                api.closeConnection(conn, 0) catch |err| {
                    logger.warn("closeConnection during QuicClient.deinit failed: {s}", .{@errorName(err)});
                };
            }
            self.quic_connection = null;
        }
        if (self.endpoint) |ep| {
            api.endpointDeinit(ep);
            self.endpoint = null;
        }
        if (self.quic_config) |cfg| {
            self.allocator.destroy(cfg);
            self.quic_config = null;
        }
    }

    /// Connects to a QUIC server at the specified address and port.
    pub fn connect(self: *QuicClient, address: []const u8, port: u16) !void {
        return self.connectInsecure(address, port, false);
    }

    /// Connects to a QUIC server with optional insecure mode (allows self-signed certificates).
    pub fn connectInsecure(self: *QuicClient, address: []const u8, port: u16, allow_insecure: bool) !void {
        const normalized_address = if (std.mem.eql(u8, address, "localhost"))
            "127.0.0.1"
        else
            address;

        const server_addr_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ normalized_address, port });
        defer self.allocator.free(server_addr_str);

        const cfg = try self.allocator.create(api.QuicConfig);
        cfg.* = .{
            .version = .v1,
            .alpn = &[_][]const u8{"quic-zig/1"},
            .cc = .newreno,
            .enable_datagram = false,
            .enable_spin_bit = false,
            .grease = true,
            .compatible_vn = false,
            .enable_retry = false,
            .token_secret = null,
            .token_expiry_ms = 60000,
            .enable_pacing = false,
            .max_datagram_size = 1200,
            .max_idle_timeout_ms = 300000,
            .max_udp_payload = 1350,
            .cert_path = null,
            .key_path = null,
            .ca_path = null,
            .allow_insecure = allow_insecure,
            .aead_confidentiality_limit_override = null,
            .aead_integrity_limit_override = null,
            .inline_server_cert_der = null,
            .inline_server_priv_p256 = null,
        };
        self.quic_config = cfg;

        // Create client endpoint
        const bind_addr = "0.0.0.0:0";
        self.endpoint = try api.endpointInit(&self.allocator, bind_addr, cfg);

        // With insecure mode, use localhost SNI to match self-signed CN defaults.
        const sni = if (allow_insecure) "localhost" else normalized_address;
        self.quic_connection = try api.connect(self.endpoint.?, server_addr_str, sni);

        self.is_quic = true;
        self.server_addr = normalized_address;
        self.server_port = port;
    }

    /// Extended connection with custom CA, certificate, and key paths for mutual TLS authentication.
    pub fn connectEx(self: *QuicClient, address: []const u8, port: u16, ca: ?[]const u8, cert: ?[]const u8, key: ?[]const u8) !void {
        const normalized_address = if (std.mem.eql(u8, address, "localhost"))
            "127.0.0.1"
        else
            address;

        const server_addr_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ normalized_address, port });
        defer self.allocator.free(server_addr_str);

        const cfg = try self.allocator.create(api.QuicConfig);
        errdefer self.allocator.destroy(cfg);
        const has_ca = ca != null;
        if (!has_ca) {
            // Fail closed: do not implicitly disable certificate verification.
            // Callers must provide a CA bundle (recommended) or explicitly opt into
            // insecure verification via `connectInsecure(...)` for testing only.
            //
            // Use `warn` (not `err`): the returned `QuicError.CertificateError`
            // is the API contract that callers act on, and at the default
            // `LOG_LEVEL=err` the warn message is gated out — leaving test
            // stderr clean (the geode-compat test deliberately exercises this
            // path via `expectError`, and any stderr write turns Zig's build
            // runner into emitting a misleading "failed command:" diagnostic
            // even when the test exits 0). Operators tuning `LOG_LEVEL=warn`
            // or lower still see the guidance.
            logger.warn("quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)", .{});
            return QuicError.CertificateError;
        }
        cfg.* = .{
            .version = .v1,
            .alpn = &[_][]const u8{"quic-zig/1"},
            .cc = .newreno,
            .enable_datagram = false,
            .enable_spin_bit = false,
            .grease = true,
            .compatible_vn = false,
            .enable_retry = false,
            .token_secret = null,
            .token_expiry_ms = 60000,
            .enable_pacing = false,
            .max_datagram_size = 1200,
            .max_idle_timeout_ms = 300000,
            .max_udp_payload = 1350,
            .cert_path = if (cert) |p| p else null,
            .key_path = if (key) |p| p else null,
            .ca_path = ca.?,
            .allow_insecure = false,
            .aead_confidentiality_limit_override = null,
            .aead_integrity_limit_override = null,
            .inline_server_cert_der = null,
            .inline_server_priv_p256 = null,
        };
        self.quic_config = cfg;

        // Create client endpoint
        const bind_addr = "0.0.0.0:0";
        self.endpoint = try api.endpointInit(&self.allocator, bind_addr, cfg);

        self.quic_connection = try api.connect(self.endpoint.?, server_addr_str, normalized_address);

        self.is_quic = true;
        self.server_addr = normalized_address;
        self.server_port = port;
    }

    /// Waits for the TLS handshake to complete with a timeout.
    pub fn waitForHandshake(self: *QuicClient, timeout_secs: u32) !void {
        if (!self.is_quic or self.quic_connection == null) {
            return QuicError.InvalidState;
        }

        const timeout_ns = @as(u64, timeout_secs) * std.time.ns_per_s;
        const start = nanoTimestampCompat();
        while (nanoTimestampCompat() - start < timeout_ns) {
            // poll(10) blocks on epoll/kqueue for up to 10ms — no additional sleep needed (PAR-007)
            try self.endpoint.?.poll(10);
            if (api.isHandshakeConfirmed(self.quic_connection.?)) return;
        }
        return QuicError.HandshakeError;
    }

    pub fn openStream(self: *QuicClient, bidirectional: bool) !*QuicClientStream {
        const qc = self.quic_connection orelse return QuicError.InvalidState;
        const ep = self.endpoint orelse return QuicError.InvalidState;
        const stream_id = try api.openStream(qc, bidirectional);
        const stream = try self.allocator.create(QuicClientStream);
        stream.* = .{
            .allocator = self.allocator,
            .quic_stream_id = stream_id,
            .quic_connection = qc,
            .client = self,
            .endpoint = ep,
        };
        return stream;
    }

    /// Opens a new bidirectional stream on the connection.
    pub fn getStream(self: *QuicClient) !*QuicClientStream {
        return self.openStream(true);
    }

    pub fn poll(self: *QuicClient, timeout_ms: u32) !void {
        if (self.endpoint) |ep| {
            const timeout_i32: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            try api.poll(ep, timeout_i32);
        }
    }
};

/// Represents a client-side QUIC stream for reading and writing data.
pub const QuicClientStream = struct {
    allocator: std.mem.Allocator,
    quic_stream_id: ?api.QuicStreamId,
    quic_connection: *api.QuicConnection,
    client: ?*QuicClient,
    endpoint: *api.QuicEndpoint,

    pub fn write(self: *QuicClientStream, data: []const u8) !usize {
        const sid = self.quic_stream_id orelse return QuicError.StreamFailed;
        return api.writeStream(self.quic_connection, sid, data, false);
    }

    /// Writes all data to the stream, polling to ensure delivery.
    pub fn writeAll(self: *QuicClientStream, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try self.write(data[written..]);
            if (n == 0) return QuicError.WriteError;
            written += n;
        }
    }

    /// Reads data from the stream into the buffer with automatic retries and polling.
    pub fn read(self: *QuicClientStream, buf: []u8) !usize {
        const sid = self.quic_stream_id orelse return QuicError.StreamFailed;
        const n = api.readStream(self.quic_connection, sid, buf) catch |err| {
            if (err == error.WouldBlock) {
                self.endpoint.poll(10) catch |poll_err| {
                    logger.warn("poll during read (WouldBlock) failed: {s}", .{@errorName(poll_err)});
                };
                return error.WouldBlock;
            }
            return err;
        };
        if (n == 0) {
            self.endpoint.poll(10) catch |poll_err| {
                logger.warn("poll during read (zero-byte) failed: {s}", .{@errorName(poll_err)});
            };
        }
        return n;
    }

    /// Reads a line of text from the stream, up to max_size bytes, returning an allocated buffer.
    pub fn readLine(self: *QuicClientStream, max_size: usize) ![]u8 {
        return self.readLineWithInterrupt(max_size, null);
    }

    pub fn readLineWithInterrupt(
        self: *QuicClientStream,
        max_size: usize,
        interrupt_check: ?*const fn () bool,
    ) ![]u8 {
        var temp = try self.allocator.alloc(u8, max_size);
        defer self.allocator.free(temp);
        var pos: usize = 0;
        var retry_count: usize = 0;
        const max_retries: usize = 20;

        while (pos < max_size) {
            if (interrupt_check) |check_fn| {
                if (check_fn()) return error.Interrupted;
            }

            var one: [1]u8 = undefined;
            const n = self.read(&one) catch |err| {
                if (err == error.WouldBlock and pos == 0) return error.WouldBlock;
                if (err == error.WouldBlock) {
                    retry_count += 1;
                    if (retry_count > max_retries) {
                        if (pos == 0) return error.WouldBlock;
                        return error.UnexpectedEndOfStream;
                    }
                    // poll(10) blocks for up to 10ms — no additional sleep needed (PAR-007)
                    self.endpoint.poll(10) catch |poll_err| {
                        logger.warn("poll during readLine retry failed: {s}", .{@errorName(poll_err)});
                    };
                    continue;
                }
                return err;
            };

            if (n == 0) {
                if (pos == 0) return error.WouldBlock;
                retry_count += 1;
                if (retry_count > max_retries) return error.UnexpectedEndOfStream;
                // poll(10) blocks for up to 10ms — no additional sleep needed (PAR-007)
                self.endpoint.poll(10) catch |poll_err| {
                    logger.warn("poll during readLine zero-byte retry failed: {s}", .{@errorName(poll_err)});
                };
                continue;
            }

            temp[pos] = one[0];
            pos += 1;
            retry_count = 0;
            if (one[0] == '\n') break;
        }

        if (pos == 0) return error.EndOfStream;
        const out = try self.allocator.alloc(u8, pos);
        @memcpy(out, temp[0..pos]);
        return out;
    }

    pub fn close(self: *QuicClientStream) void {
        if (self.quic_stream_id) |sid| {
            api.closeStream(self.quic_connection, sid, 0) catch |err| {
                logger.warn("closeStream during QuicClientStream.close failed for stream {d}: {s}", .{ sid, @errorName(err) });
            };
            self.quic_stream_id = null;
        }
        self.allocator.destroy(self);
    }

    /// Deinitializes the stream and frees its resources.
    pub fn deinit(self: *QuicClientStream) void {
        self.close();
    }

    pub fn finish(self: *QuicClientStream) !void {
        const sid = self.quic_stream_id orelse return QuicError.StreamFailed;
        _ = try api.writeStream(self.quic_connection, sid, &.{}, true);
    }
};
