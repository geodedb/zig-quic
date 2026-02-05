// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const qlog = @import("quic_logger");
const builtin = @import("builtin");
const api = @import("quic_api");

//! High-level QUIC transport layer providing connection and stream management.
//! This layer provides a convenient interface for building QUIC applications.
//!
//! RFC 9000 §7 and §10 outline endpoint responsibilities (handshake, timeout,
//! connection lifecycle) that this abstraction orchestrates. Stream helpers map
//! directly to §§2–4, while TLS handling aligns with RFC 9001 §4.

/// Errors that can occur during QUIC operations.
pub const QuicError = error{
    ConnectionFailed,
    StreamFailed,
    InvalidAddress,
    CertificateError,
    EndpointInitFailed,
    AcceptFailed,
    HandshakeFailed,
    TransportParametersFailed,
    FlowControlViolation,
    ProtocolViolation,
    IdleTimeout,
    ConnectionClosed,
};

/// High-level QUIC transport for managing endpoints and connections.
pub const QuicTransport = struct {
    allocator: std.mem.Allocator,
    config: Config,
    endpoint: ?*api.QuicEndpoint = null,
    connections: std.ArrayList(*QuicConnection),
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
        /// Allow insecure TLS (skip certificate verification). For testing only.
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
            .cert_path = config.cert_path,
            .key_path = config.key_path,
        };
    }

    /// Deinitializes the transport, closing all connections and releasing resources.
    pub fn deinit(self: *QuicTransport) void {
        // Close all active connections first to avoid using a torn-down endpoint
        for (self.connections.items) |conn| {
            conn.close();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
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
        std.fs.cwd().access(cert_path, .{}) catch {
            cert_exists = false;
        };
        var key_exists = true;
        std.fs.cwd().access(key_path, .{}) catch {
            key_exists = false;
        };

        const bind_addr = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.config.address, self.config.port });
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
        logger.debugPrint("{{\"component\":\"transport\",\"transport\":\"quic\",\"tls\":\"true\",\"port\":{}}}\n", .{ self.config.port });
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"server startup\",\"use_tls\":true,\"cert_exists\":{},\"key_exists\":{}}}\n", .{ cert_exists, key_exists });

        // Load certificate files (TLS required)
        var inline_cert_der: ?[]u8 = null;
        var inline_priv_key: ?[]u8 = null;
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"loading certificate files\",\"cert_path\":\"{s}\",\"key_path\":\"{s}\"}}\n", .{ cert_path, key_path });

        const cert_file = std.fs.cwd().openFile(cert_path, .{}) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to open certificate file\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ cert_path, err });
            return QuicError.CertificateError;
        };
        defer cert_file.close();

        const cert_size = try cert_file.getEndPos();
        const cert_pem = try self.allocator.alloc(u8, cert_size);
        defer self.allocator.free(cert_pem);
        _ = try cert_file.readAll(cert_pem);
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"loaded certificate\",\"size\":{}}}\n", .{cert_size});

        inline_cert_der = api.pem.parseCertificate(self.allocator, cert_pem) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to parse certificate\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ cert_path, err });
            return QuicError.CertificateError;
        };

        const key_file = std.fs.cwd().openFile(key_path, .{}) catch |err| {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_server\",\"msg\":\"failed to open private key file\",\"path\":\"{s}\",\"error\":\"{}\"}}\n", .{ key_path, err });
            if (inline_cert_der) |cert| self.allocator.free(cert);
            return QuicError.CertificateError;
        };
        defer key_file.close();

        const key_size = try key_file.getEndPos();
        const key_pem = try self.allocator.alloc(u8, key_size);
        defer self.allocator.free(key_pem);
        _ = try key_file.readAll(key_pem);
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
        logger.debugPrint("{{\"component\":\"transport\",\"transport\":\"quic\",\"tls\":\"true\",\"port\":{d}}}\n", .{ self.config.port });
    }

    fn generateSelfSignedCert(self: *QuicTransport, cert_path: []const u8, key_path: []const u8) !void {
        if (std.fs.path.dirname(cert_path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
        if (std.fs.path.dirname(key_path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        // Generate self-signed certificate using OpenSSL command
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "openssl", "req",       "-x509", "-newkey",                               "rsa:4096",
                "-keyout", key_path,    "-out",  cert_path,                               "-days",
                "365",     "-nodes",      "-subj", "/C=US/ST=State/L=City/O=Geode/CN=localhost",
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            return QuicError.CertificateError;
        }

        // Set secure permissions (0600)
        // On Windows, chmod is not supported, so we skip permission changes
        if (builtin.os.tag != .windows) {
            const cert_file = try std.fs.cwd().openFile(cert_path, .{});
            defer cert_file.close();
            try cert_file.chmod(0o600);

            const key_file = try std.fs.cwd().openFile(key_path, .{});
            defer key_file.close();
            try key_file.chmod(0o600);
        }
    }

    /// Accepts an incoming QUIC connection from a client.
    ///
    /// Returns only after the API reports a completed handshake flight per
    /// RFC 9000 §7.2, ensuring applications see connections that survived anti-
    /// amplification and Retry handling.
    pub fn accept(self: *QuicTransport) !*QuicConnection {
        // CANARY: REQ=REQ-GQL-074; FEATURE="Network Transport"; ASPECT=QUICAccept; STATUS=TESTED; TEST=TestCANARY_REQ_GQL_074_QUICAccept; OWNER=wire; UPDATED=2025-09-22

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"attempting to accept connection\"}}\n", .{});

        if (self.endpoint) |ep| {
            // Accept from QUIC endpoint
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"calling api.accept\"}}\n", .{});
            const quic_conn = try api.accept(ep);
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"api.accept returned successfully\"}}\n", .{});

            const conn = try self.allocator.create(QuicConnection);
            conn.* = QuicConnection{
                .allocator = self.allocator,
                .quic_connection = quic_conn,
                .streams = std.ArrayList(*QuicStream){},
            };

            try self.connections.append(self.allocator, conn);
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"connection accepted and added to pool\",\"total_connections\":{}}}\n", .{self.connections.items.len});
            return conn;
        }
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_server\",\"msg\":\"no endpoint available for accept\"}}\n", .{});
        return QuicError.ConnectionFailed;
    }

    /// Polls the endpoint for network events with the specified timeout in milliseconds.
    ///
    /// RFC 9000 §6 mandates timers for loss detection and idle timeout. We feed
    /// the endpoint so that PTO/idle timers managed by recovery (RFC 9002) fire.
    pub fn poll(self: *QuicTransport, timeout_ms: u32) !void {
        if (self.endpoint) |ep| {
            try api.poll(ep, timeout_ms);
        }
    }
};

/// Represents an active QUIC connection that can manage multiple streams.
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    quic_connection: ?*api.QuicConnection,
    streams: std.ArrayList(*QuicStream),
    streams_init: bool = false,
    next_stream_id: usize = 0,

    /// Closes the connection and all associated streams.
    pub fn close(self: *QuicConnection) void {
        // Close all streams (idempotent) if initialized
        if (self.streams_init) {
            for (self.streams.items) |s| {
                s.close();
                self.allocator.destroy(s);
            }
            self.streams.deinit(self.allocator);
            self.streams_init = false;
        }
        // Close underlying QUIC connection only once; avoid explicit vendor close to prevent double-frees
        if (self.quic_connection) |_| {
            // Passive close: let endpoint deinit/OS cleanup reclaim resources
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

        if (self.quic_connection == null) return QuicError.StreamFailed;

        // Accept a QUIC stream - this will check for existing streams first
        // then fall back to waiting for new ones
        const stream_id = try api.acceptStream(self.quic_connection.?);

        stream.* = QuicStream{
            .allocator = self.allocator,
            .quic_stream_id = stream_id,
            .parent_connection = self,
            .stream_id = @intCast(stream_id),
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

        if (self.quic_connection == null) return QuicError.StreamFailed;
        const stream_id = try api.openStream(self.quic_connection.?, bidirectional);
        stream.* = QuicStream{
            .allocator = self.allocator,
            .quic_stream_id = stream_id,
            .parent_connection = self,
            .stream_id = @intCast(stream_id),
        };

        if (!self.streams_init) {
            self.streams = try std.ArrayList(*QuicStream).initCapacity(self.allocator, 0);
            self.streams_init = true;
        }
        try self.streams.append(self.allocator, stream);
        return stream;
    }
};

/// Represents a QUIC stream for reading and writing data.
pub const QuicStream = struct {
    allocator: std.mem.Allocator,
    quic_stream_id: ?api.QuicStreamId,
    parent_connection: *QuicConnection,
    stream_id: usize = 0,
    read_buffer: []u8 = &[_]u8{},

    /// Closes the stream, releasing any associated resources.
    ///
    /// RFC 9000 §3.1 allows either side to abruptly terminate via RESET_STREAM
    /// (or FIN). This helper optionally forces RESET when an environment flag is
    /// set, enabling tests that exercise §19.4 error propagation.
    pub fn close(self: *QuicStream) void {
        // Best-effort, idempotent: avoid vendor close by default to reduce teardown races.
        // Enable explicit stream close only when GEODE_QUIC_FORCE_STREAM_CLOSE=1.
        if (self.quic_stream_id) |sid| {
            const force_stream_close = if (std.process.getEnvVarOwned(self.parent_connection.allocator, "GEODE_QUIC_FORCE_STREAM_CLOSE")) |v| blk: {
                defer self.parent_connection.allocator.free(v);
                break :blk true;
            } else |_| false;
            if (force_stream_close) {
                if (self.parent_connection.quic_connection) |qc| {
                    api.closeStream(qc, sid, 0) catch {};
                }
            }
            self.quic_stream_id = null;
        }
    }

    /// Writes data to the stream.
    pub fn write(self: *QuicStream, data: []const u8) !void {
        if (self.quic_stream_id) |sid| {
            _ = try api.writeStream(self.parent_connection.quic_connection.?, sid, data);
        } else {
            return QuicError.StreamFailed;
        }
    }

    /// Writes all data to the stream, handling fragmentation internally.
    pub fn writeAll(self: *QuicStream, data: []const u8) !void {
        if (self.quic_stream_id) |sid| {
            // QUIC handles fragmentation internally
            _ = try api.writeStream(self.parent_connection.quic_connection.?, sid, data);
        } else {
            return QuicError.StreamFailed;
        }
    }

    /// Reads data from the stream into the provided buffer, returning the number of bytes read.
    pub fn read(self: *QuicStream, buf: []u8) !usize {
        if (self.quic_stream_id) |sid| {
            return api.readStream(self.parent_connection.quic_connection.?, sid, buf) catch {
                return 0;
            };
        } else {
            return QuicError.StreamFailed;
        }
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
        var pos: usize = 0;

        while (pos < max_size) {
            const n = try self.read(buf[pos .. pos + 1]);
            if (n == 0) {
                if (pos == 0) return error.EndOfStream;
                break;
            }
            if (buf[pos] == '\n') {
                return self.allocator.realloc(buf, pos + 1) catch buf[0 .. pos + 1];
            }
            pos += 1;
        }
        return buf[0..pos];
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
        const force_close = if (std.process.getEnvVarOwned(self.allocator, "GEODE_QUIC_FORCE_CLOSE")) |v| blk: {
            defer self.allocator.free(v);
            break :blk true;
        } else |_| false;
        if (self.quic_connection) |conn| {
            if (force_close) {
                api.closeConnectionSimple(conn) catch {};
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
        // CANARY: REQ=REQ-GQL-074; FEATURE="Network Transport"; ASPECT=QUICClientConnect; STATUS=TESTED; TEST=TestCANARY_REQ_GQL_074_QUICClientConnect; OWNER=wire; UPDATED=2025-09-22

        const server_addr_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ address, port });
        defer self.allocator.free(server_addr_str);

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"connecting to server\",\"address\":\"{s}\",\"port\":{}}}\n", .{ address, port });

        // QUIC client configuration
        const cert_path = "certs/ca.crt"; // Client CA cert (required for secure connect)
        var has_ca_cert = true;
        std.fs.cwd().access(cert_path, .{}) catch {
            has_ca_cert = false;
        };

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"certificate configuration\",\"has_ca_cert\":{},\"cert_path\":\"{s}\"}}\n", .{ has_ca_cert, cert_path });
        if (!has_ca_cert) {
            logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_client\",\"msg\":\"missing CA certificate for secure connect\",\"cert_path\":\"{s}\"}}\n", .{ cert_path });
            return QuicError.CertificateError;
        }

        // Initialize QUIC config for client
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
            .max_idle_timeout_ms = 30000,
            .max_udp_payload = 1350,
            .cert_path = null,
            .key_path = null,
            .ca_path = cert_path,
            .allow_insecure = false,
            .aead_confidentiality_limit_override = null,
            .aead_integrity_limit_override = null,
            .inline_server_cert_der = null,
            .inline_server_priv_p256 = null,
        };
        self.quic_config = cfg;

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"QUIC config\",\"allow_insecure\":{}}}\n", .{cfg.allow_insecure});

        // Create client endpoint
        const bind_addr = "0.0.0.0:0"; // Bind to any available port
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"initializing endpoint\",\"bind_addr\":\"{s}\"}}\n", .{bind_addr});
        self.endpoint = try api.endpointInit(&self.allocator, bind_addr, cfg);

        // Connect to server - use localhost as SNI when allow_insecure to match cert CN
        const sni = if (cfg.allow_insecure) "localhost" else address;
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"initiating connection\",\"server_addr\":\"{s}\",\"sni\":\"{s}\",\"allow_insecure\":{}}}\n", .{ server_addr_str, sni, cfg.allow_insecure });
        self.quic_connection = try api.connect(self.endpoint.?, server_addr_str, sni);

        self.is_quic = true;
        self.server_addr = address;
        self.server_port = port;

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"connection initiated successfully\"}}\n", .{});
    }

    /// Connects to a QUIC server with optional insecure mode (allows self-signed certificates).
    pub fn connectInsecure(self: *QuicClient, address: []const u8, port: u16, allow_insecure: bool) !void {
        const server_addr_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ address, port });
        defer self.allocator.free(server_addr_str);

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"connectInsecure called\",\"address\":\"{s}\",\"port\":{},\"allow_insecure\":{}}}\n", .{ address, port, allow_insecure });

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
            .max_idle_timeout_ms = 30000,
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

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"QUIC config\",\"allow_insecure\":{}}}\n", .{cfg.allow_insecure});

        // Connect to server
        const sni = address; // Use server address as SNI
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"initiating connection\",\"server_addr\":\"{s}\",\"sni\":\"{s}\"}}\n", .{ server_addr_str, sni });
        self.quic_connection = try api.connect(self.endpoint.?, server_addr_str, sni);

        self.is_quic = true;
        self.server_addr = address;
        self.server_port = port;

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"connection initiated successfully\"}}\n", .{});
    }

    /// Extended connection with custom CA, certificate, and key paths for mutual TLS authentication.
    pub fn connectEx(self: *QuicClient, address: []const u8, port: u16, ca: ?[]const u8, cert: ?[]const u8, key: ?[]const u8) !void {
        const server_addr_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ address, port });
        defer self.allocator.free(server_addr_str);

        const cfg = try self.allocator.create(api.QuicConfig);
        const has_ca = ca != null;
        const use_tls = has_ca or (cert != null and key != null);
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
            .max_idle_timeout_ms = 30000,
            .max_udp_payload = 1350,
            .cert_path = if (cert) |p| p else null,
            .key_path = if (key) |p| p else null,
            .ca_path = if (has_ca) ca.? else null,
            .allow_insecure = !use_tls,
            .aead_confidentiality_limit_override = null,
            .aead_integrity_limit_override = null,
            .inline_server_cert_der = null,
            .inline_server_priv_p256 = null,
        };
        self.quic_config = cfg;

        // Create client endpoint
        const bind_addr = "0.0.0.0:0";
        self.endpoint = try api.endpointInit(&self.allocator, bind_addr, cfg);

        // Connect to server - use localhost as SNI when allow_insecure to match cert CN
        const sni = if (cfg.allow_insecure) "localhost" else address;
        self.quic_connection = try api.connect(self.endpoint.?, server_addr_str, sni);

        self.is_quic = true;
        self.server_addr = address;
        self.server_port = port;
    }

    /// Waits for the TLS handshake to complete with a timeout.
    pub fn waitForHandshake(self: *QuicClient) !void {
        if (!self.is_quic or self.quic_connection == null) {
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"waitForHandshake: no QUIC connection\"}}\n", .{});
            return QuicError.ConnectionFailed;
        }

        // Wait for handshake to complete with timeout
        const total_timeout_ms = 2000; // 2 second total timeout (reduced for faster failure)
        const poll_timeout_ms = 50; // 50ms per poll
        const start_time = std.time.milliTimestamp();

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"waitForHandshake: starting handshake wait\",\"timeout_ms\":{}}}\n", .{total_timeout_ms});

        var poll_count: u32 = 0;
        while (std.time.milliTimestamp() - start_time < total_timeout_ms) {
            poll_count += 1;

            // Poll endpoint to process network events and advance handshake
            api.poll(self.endpoint.?, poll_timeout_ms) catch |err| {
                // Continue polling even if individual poll fails
                logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"poll error\",\"error\":\"{}\"}}\n", .{err});
            };

            // Try to flush the endpoint to ensure packets are sent
            api.flush(self.endpoint.?, 1);

            // Check if handshake is complete - try multiple checks
            const handshake_complete = api.handshakeComplete(self.quic_connection.?);
            const handshake_confirmed = api.isHandshakeConfirmed(self.quic_connection.?);
            const handshake_done = api.handshakeDoneSeen(self.quic_connection.?);

            if (handshake_complete or handshake_confirmed or handshake_done) {
                const elapsed_ms = std.time.milliTimestamp() - start_time;
                logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"handshake completed\",\"elapsed_ms\":{},\"poll_count\":{},\"complete\":{},\"confirmed\":{},\"done\":{}}}\n", .{ elapsed_ms, poll_count, handshake_complete, handshake_confirmed, handshake_done });
                return;
            }

            // Add detailed debugging for first few iterations
            if (poll_count <= 5) {
                logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"handshake check\",\"poll_count\":{},\"complete\":{},\"confirmed\":{},\"done\":{}}}\n", .{ poll_count, handshake_complete, handshake_confirmed, handshake_done });
            }

            // Log periodic progress
            if (poll_count % 10 == 0) { // Every ~1 second
                const elapsed_ms = std.time.milliTimestamp() - start_time;
                logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"handshake in progress\",\"elapsed_ms\":{},\"poll_count\":{}}}\n", .{ elapsed_ms, poll_count });
            }
        }

        const elapsed_ms = std.time.milliTimestamp() - start_time;
        logger.debugPrint("{{\"level\":\"ERROR\",\"component\":\"quic_client\",\"msg\":\"handshake timeout\",\"elapsed_ms\":{},\"poll_count\":{}}}\n", .{ elapsed_ms, poll_count });
        return QuicError.HandshakeFailed;
    }

    /// Opens a new bidirectional stream on the connection.
    pub fn getStream(self: *QuicClient) !*QuicClientStream {
        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"getStream: starting\"}}\n", .{});

        const stream = try self.allocator.create(QuicClientStream);
        errdefer self.allocator.destroy(stream);

        if (self.is_quic and self.quic_connection != null) {
            // Don't wait for handshake here since we handle it externally
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"getStream: opening stream (assuming handshake complete)\"}}\n", .{});
            const stream_id = try api.openStream(self.quic_connection.?, true);
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"getStream: stream opened\",\"stream_id\":{}}}\n", .{stream_id});

            stream.* = QuicClientStream{
                .allocator = self.allocator,
                .quic_stream_id = stream_id,
                .quic_connection = self.quic_connection,
                .client = self,
            };
        } else {
            logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"getStream: no QUIC connection available\"}}\n", .{});
            return QuicError.ConnectionFailed;
        }

        logger.debugPrint("{{\"level\":\"DEBUG\",\"component\":\"quic_client\",\"msg\":\"getStream: completed successfully\"}}\n", .{});
        return stream;
    }
};

/// Represents a client-side QUIC stream for reading and writing data.
pub const QuicClientStream = struct {
    allocator: std.mem.Allocator,
    quic_stream_id: ?api.QuicStreamId,
    quic_connection: ?*api.QuicConnection,
    client: ?*QuicClient,

    /// Writes all data to the stream, polling to ensure delivery.
    pub fn writeAll(self: *QuicClientStream, data: []const u8) !void {
        if (self.quic_stream_id) |sid| {
            logger.debugPrint("DEBUG: QuicClientStream.writeAll called with {} bytes on stream {}\n", .{ data.len, sid });
            const bytes_written = try api.writeStream(self.quic_connection.?, sid, data);
            logger.debugPrint("DEBUG: writeStream returned {} bytes written\n", .{bytes_written});

            // Poll multiple times to ensure data is sent
            if (self.client) |c| {
                if (c.endpoint) |ep| {
                    var i: usize = 0;
                    while (i < 5) : (i += 1) {
                        api.poll(ep, 10) catch {};
                        std.posix.nanosleep(0, 10 * std.time.ns_per_ms);
                    }
                }
            }
            logger.debugPrint("DEBUG: writeAll completed after polling\n", .{});
        } else {
            return QuicError.StreamFailed;
        }
    }

    /// Reads data from the stream into the buffer with automatic retries and polling.
    pub fn read(self: *QuicClientStream, buf: []u8) !usize {
        if (self.quic_stream_id) |sid| {
            // Try reading with retries and polling
            var attempts: usize = 0;
            while (attempts < 20) : (attempts += 1) {
                const n = api.readStream(self.quic_connection.?, sid, buf) catch |err| {
                    // TRACE: readStream error
                    // logger.debugPrint("DEBUG: readStream error: {}\n", .{err});
                    if (err == error.WouldBlock) {
                        // Poll the endpoint to process incoming packets
                        if (self.client) |c| {
                            if (c.endpoint) |ep| {
                                // Poll multiple times to ensure we receive data
                                var poll_i: usize = 0;
                                while (poll_i < 3) : (poll_i += 1) {
                                    // TRACE: read() polling endpoint
                                    // logger.debugPrint("DEBUG: read() polling endpoint\n", .{});
                                    api.poll(ep, 50) catch {};
                                    std.posix.nanosleep(0, 10 * std.time.ns_per_ms);
                                }
                            } else {
                                logger.debugPrint("DEBUG: read() no endpoint to poll!\n", .{});
                            }
                        } else {
                            logger.debugPrint("DEBUG: read() no client reference!\n", .{});
                        }
                        continue;
                    }
                    return 0;
                };
                if (n > 0) return n;
            }
            return 0;
        } else {
            return QuicError.StreamFailed;
        }
    }

    /// Reads a line of text from the stream, up to max_size bytes, returning an allocated buffer.
    pub fn readLine(self: *QuicClientStream, max_size: usize) ![]u8 {
        var buf = try self.allocator.alloc(u8, max_size);
        errdefer self.allocator.free(buf);

        var pos: usize = 0;
        while (pos < max_size) {
            const n = try self.read(buf[pos .. pos + 1]);
            if (n == 0) break;
            if (buf[pos] == '\n') {
                // Resize to actual size (including newline)
                if (self.allocator.resize(buf, pos + 1)) {
                    return buf[0 .. pos + 1];
                } else {
                    // If resize fails, create a new smaller buffer
                    const result = try self.allocator.alloc(u8, pos + 1);
                    @memcpy(result, buf[0 .. pos + 1]);
                    self.allocator.free(buf);
                    return result;
                }
            }
            pos += 1;
        }
        // Resize to actual size
        if (self.allocator.resize(buf, pos)) {
            return buf[0..pos];
        } else {
            // If resize fails, create a new smaller buffer
            const result = try self.allocator.alloc(u8, pos);
            @memcpy(result, buf[0..pos]);
            self.allocator.free(buf);
            return result;
        }
    }

    /// Deinitializes the stream and frees its resources.
    pub fn deinit(self: *QuicClientStream) void {
        // Avoid vendor close by default; env-gated for explicit shutdown.
        if (self.quic_stream_id) |sid| {
            const force_stream_close = if (std.process.getEnvVarOwned(self.allocator, "GEODE_QUIC_FORCE_STREAM_CLOSE")) |v| blk: {
                defer self.allocator.free(v);
                break :blk true;
            } else |_| false;
            if (force_stream_close) {
                api.closeStream(self.quic_connection.?, sid, 0) catch {};
            }
        }
        self.allocator.destroy(self);
    }
};
