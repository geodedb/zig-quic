//! High-level QUIC client library
//!
//! This module provides a simplified, ergonomic API for building QUIC clients.
//! It wraps the low-level transport primitives in src/quic/api.zig with higher-level
//! abstractions including automatic connection management, stream lifecycle handling,
//! and connection pooling.
//!
//! Example usage:
//! ```zig
//! var client = try QuicClient.init(allocator, .{
//!     .alpn = &[_][]const u8{"h3"},
//!     .allow_insecure = true,
//! });
//! defer client.deinit();
//!
//! var conn = try client.connect("example.com", 443, "example.com");
//! defer conn.close();
//!
//! try conn.waitForHandshake();
//!
//! var stream = try conn.openStream(true);
//! defer stream.close();
//!
//! try stream.write("Hello, QUIC!");
//! const response = try stream.readAll(allocator);
//! ```

const std = @import("std");
const api = @import("quic_api");

/// High-level QUIC client with connection management
pub const QuicClient = struct {
    allocator: std.mem.Allocator,
    endpoint: *api.QuicEndpoint,
    config: ClientConfig,

    /// Configuration for the QUIC client
    pub const ClientConfig = struct {
        /// ALPN protocols to negotiate (e.g., "h3", "hq-interop")
        alpn: []const []const u8 = &[_][]const u8{},
        /// Allow self-signed certificates for testing
        allow_insecure: bool = false,
        /// Enable DATAGRAM extension (RFC 9221)
        enable_datagram: bool = false,
        /// Enable compatible version negotiation
        compatible_vn: bool = true,
        /// Local bind address (use "0.0.0.0:0" for auto)
        bind_address: []const u8 = "0.0.0.0:0",
        /// Idle timeout in milliseconds
        idle_timeout_ms: u32 = 30000,
        /// Maximum number of concurrent bidirectional streams
        max_concurrent_bidi_streams: u64 = 100,
        /// Maximum number of concurrent unidirectional streams
        max_concurrent_uni_streams: u64 = 100,
        /// Initial flow control window for connections (bytes)
        initial_max_data: u64 = 10 * 1024 * 1024, // 10 MB
        /// Initial flow control window for streams (bytes)
        initial_max_stream_data_bidi_local: u64 = 1 * 1024 * 1024, // 1 MB
        initial_max_stream_data_bidi_remote: u64 = 1 * 1024 * 1024, // 1 MB
        initial_max_stream_data_uni: u64 = 1 * 1024 * 1024, // 1 MB
    };

    /// Initialize a new QUIC client
    pub fn init(allocator: std.mem.Allocator, user_config: ClientConfig) !QuicClient {
        const cfg = api.QuicConfig{
            .alpn = user_config.alpn,
            .allow_insecure = user_config.allow_insecure,
            .enable_datagram = user_config.enable_datagram,
            .compatible_vn = user_config.compatible_vn,
            .enable_retry = false, // Client doesn't use retry
            .token_secret = null,
            .token_expiry_ms = 0,
        };

        const endpoint = try api.endpointInit(&allocator, user_config.bind_address, &cfg);
        errdefer api.endpointDeinit(endpoint);

        return QuicClient{
            .allocator = allocator,
            .endpoint = endpoint,
            .config = user_config,
        };
    }

    /// Clean up the client and all resources
    pub fn deinit(self: *QuicClient) void {
        api.endpointDeinit(self.endpoint);
    }

    /// Connect to a server and return a connection handle
    pub fn connect(
        self: *QuicClient,
        address: []const u8,
        port: u16,
        server_name: []const u8,
    ) !*QuicConnection {
        // Format the server address
        var addr_buf: [256]u8 = undefined;
        const server_addr = try std.fmt.bufPrint(&addr_buf, "{s}:{d}", .{ address, port });

        // Connect using the low-level API
        const raw_conn = try api.connect(self.endpoint, server_addr, server_name);
        errdefer api.destroy(self.endpoint, raw_conn);

        // Wrap in our high-level connection
        const conn = try self.allocator.create(QuicConnection);
        errdefer self.allocator.destroy(conn);

        conn.* = QuicConnection{
            .allocator = self.allocator,
            .endpoint = self.endpoint,
            .raw_conn = raw_conn,
            .server_name = try self.allocator.dupe(u8, server_name),
        };

        return conn;
    }

    /// Poll the endpoint to process incoming packets and timers
    pub fn poll(self: *QuicClient, timeout_ms: i32) !void {
        try api.poll(self.endpoint, timeout_ms);
    }

    /// Flush pending operations (useful for testing)
    pub fn flush(self: *QuicClient, iterations: usize) void {
        api.flush(self.endpoint, iterations);
    }
};

/// High-level QUIC connection handle
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    endpoint: *api.QuicEndpoint,
    raw_conn: *api.Connection,
    server_name: []const u8,

    /// Close the connection gracefully
    pub fn close(self: *QuicConnection) void {
        api.destroy(self.endpoint, self.raw_conn);
        self.allocator.free(self.server_name);
        self.allocator.destroy(self);
    }

    /// Close the connection with an application error code
    pub fn closeWithError(self: *QuicConnection, error_code: u64, reason: []const u8) !void {
        try api.close(self.raw_conn, error_code, reason);
    }

    /// Wait for the TLS handshake to complete
    pub fn waitForHandshake(self: *QuicConnection) !void {
        var attempts: usize = 0;
        while (!api.handshakeComplete(self.raw_conn) and attempts < 1000) : (attempts += 1) {
            try api.poll(self.endpoint, 10);
        }

        if (!api.handshakeComplete(self.raw_conn)) {
            return error.HandshakeTimeout;
        }
    }

    /// Check if the handshake is complete
    pub fn isHandshakeComplete(self: *QuicConnection) bool {
        return api.handshakeComplete(self.raw_conn);
    }

    /// Check if 1-RTT keys are confirmed
    pub fn isHandshakeConfirmed(self: *QuicConnection) bool {
        return api.isHandshakeConfirmed(self.raw_conn);
    }

    /// Get the negotiated ALPN protocol
    pub fn getNegotiatedAlpn(self: *QuicConnection) ?[]const u8 {
        return api.getNegotiatedAlpn(self.raw_conn);
    }

    /// Open a new stream (bidirectional or unidirectional)
    pub fn openStream(self: *QuicConnection, bidirectional: bool) !*QuicStream {
        const stream_id = try api.openStream(self.raw_conn, bidirectional);

        const stream = try self.allocator.create(QuicStream);
        errdefer self.allocator.destroy(stream);

        stream.* = QuicStream{
            .allocator = self.allocator,
            .endpoint = self.endpoint,
            .conn = self.raw_conn,
            .stream_id = stream_id,
            .bidirectional = bidirectional,
        };

        return stream;
    }

    /// Accept an incoming stream from the peer
    pub fn acceptStream(self: *QuicConnection) !*QuicStream {
        const stream_id = try api.acceptStream(self.raw_conn);

        // Determine if it's bidirectional based on stream ID
        // Per RFC 9000 §2.1: lowest two bits indicate stream type
        const is_bidi = (stream_id & 0x2) == 0;

        const stream = try self.allocator.create(QuicStream);
        errdefer self.allocator.destroy(stream);

        stream.* = QuicStream{
            .allocator = self.allocator,
            .endpoint = self.endpoint,
            .conn = self.raw_conn,
            .stream_id = stream_id,
            .bidirectional = is_bidi,
        };

        return stream;
    }

    /// Check if there are incoming streams waiting to be accepted
    pub fn hasIncomingStreams(self: *QuicConnection) bool {
        return api.hasIncomingStreams(self.raw_conn);
    }

    /// Send a DATAGRAM frame (RFC 9221)
    pub fn sendDatagram(self: *QuicConnection, data: []const u8) !usize {
        return api.sendDatagram(self.raw_conn, data);
    }

    /// Receive a DATAGRAM frame (RFC 9221)
    pub fn recvDatagram(self: *QuicConnection, buffer: []u8) !usize {
        return api.recvDatagram(self.raw_conn, buffer);
    }

    /// Check if the connection is drained (closed)
    pub fn isDrained(self: *QuicConnection) bool {
        return api.isDrained(self.raw_conn);
    }
};

/// High-level QUIC stream handle
pub const QuicStream = struct {
    allocator: std.mem.Allocator,
    endpoint: *api.QuicEndpoint,
    conn: *api.Connection,
    stream_id: api.QuicStreamId,
    bidirectional: bool,

    /// Close the stream
    pub fn close(self: *QuicStream) void {
        _ = api.closeStream(self.conn, self.stream_id, 0) catch {};
        self.allocator.destroy(self);
    }

    /// Close the stream with an error code
    pub fn closeWithError(self: *QuicStream, error_code: u64) !void {
        try api.closeStream(self.conn, self.stream_id, error_code);
    }

    /// Write data to the stream
    pub fn write(self: *QuicStream, data: []const u8) !usize {
        return api.writeStream(self.conn, self.stream_id, data, false);
    }

    /// Write all data to the stream, retrying if necessary
    pub fn writeAll(self: *QuicStream, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try api.writeStream(self.conn, self.stream_id, data[written..], false);
            if (n == 0) {
                // Flow control blocked, poll to make progress
                try api.poll(self.endpoint, 10);
            } else {
                written += n;
            }
        }
    }

    /// Write data and mark the stream as finished (send FIN)
    pub fn writeAndFinish(self: *QuicStream, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const is_last = (written + 1024 >= data.len);
            const chunk_end = @min(data.len, written + 1024);
            const n = try api.writeStream(
                self.conn,
                self.stream_id,
                data[written..chunk_end],
                is_last,
            );
            if (n == 0) {
                try api.poll(self.endpoint, 10);
            } else {
                written += n;
            }
        }
        // If we didn't send FIN yet, send it now
        if (data.len == 0 or written == data.len) {
            _ = try api.writeStream(self.conn, self.stream_id, &[_]u8{}, true);
        }
    }

    /// Read data from the stream
    pub fn read(self: *QuicStream, buffer: []u8) !usize {
        return api.readStream(self.conn, self.stream_id, buffer);
    }

    /// Read all available data from the stream until FIN
    pub fn readAll(self: *QuicStream, allocator: std.mem.Allocator) ![]u8 {
        var data = std.ArrayList(u8).init(allocator);
        errdefer data.deinit();

        var buffer: [4096]u8 = undefined;
        while (true) {
            const n = api.readStream(self.conn, self.stream_id, &buffer) catch |err| {
                if (err == error.Done or err == error.StreamNotFound) {
                    break;
                }
                return err;
            };

            if (n == 0) {
                // Check if stream is finished
                if (api.isStreamFinished(self.conn, self.stream_id)) {
                    break;
                }
                // Poll to make progress
                api.poll(self.endpoint, 10) catch {};
                continue;
            }

            try data.appendSlice(buffer[0..n]);

            if (api.isStreamFinished(self.conn, self.stream_id)) {
                break;
            }
        }

        return data.toOwnedSlice();
    }

    /// Check if the stream has received FIN in both directions
    pub fn isFinished(self: *QuicStream) bool {
        return api.isStreamFinished(self.conn, self.stream_id);
    }

    /// Get the stream ID
    pub fn getId(self: *QuicStream) api.QuicStreamId {
        return self.stream_id;
    }
};
