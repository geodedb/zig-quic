//! High-level QUIC client library for Zig
//!
//! This module provides ergonomic, high-level abstractions over the QUIC transport
//! implementation in src/quic. It's designed to make building QUIC applications
//! simple while still providing access to advanced features.
//!
//! ## Features
//! - Simple client and server APIs
//! - Automatic connection and stream lifecycle management
//! - Bidirectional and unidirectional streams
//! - DATAGRAM support (RFC 9221)
//! - Flow control handling
//! - TLS 1.3 integration with ALPN negotiation
//!
//! ## Example Client
//! ```zig
//! const quic = @import("quic");
//!
//! var client = try quic.QuicClient.init(allocator, .{
//!     .alpn = &[_][]const u8{"my-proto"},
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
//! try stream.writeAll("Hello!");
//! const response = try stream.readAll(allocator);
//! defer allocator.free(response);
//! ```
//!
//! ## Example Server
//! ```zig
//! const quic = @import("quic");
//!
//! var server = try quic.QuicServer.init(allocator, .{
//!     .alpn = &[_][]const u8{"my-proto"},
//!     .bind_port = 4433,
//! });
//! defer server.deinit();
//!
//! while (true) {
//!     server.poll(100) catch {};
//!
//!     var conn = server.tryAccept() orelse continue;
//!     defer conn.close();
//!
//!     try conn.waitForHandshake();
//!
//!     var stream = try conn.acceptStream();
//!     defer stream.close();
//!
//!     const data = try stream.readAll(allocator);
//!     defer allocator.free(data);
//!
//!     try stream.writeAndFinish("Hello back!");
//! }
//! ```

const client = @import("client.zig");
const server = @import("server.zig");

// Re-export client types
pub const QuicClient = client.QuicClient;
pub const QuicConnection = client.QuicConnection;
pub const QuicStream = client.QuicStream;

// Re-export server types
pub const QuicServer = server.QuicServer;
pub const ServerConnection = server.ServerConnection;
pub const ServerStream = server.ServerStream;

// Re-export from the low-level API for convenience
pub const api = @import("quic_api");
