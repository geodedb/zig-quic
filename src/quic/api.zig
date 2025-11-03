// API module for QUIC implementation
pub const pem = @import("pem.zig");

// Import the actual config
const config = @import("config.zig");
pub const QuicConfig = config.QuicConfig;

// Import endpoint for QuicEndpoint
const endpoint = @import("endpoint.zig");
pub const QuicEndpoint = endpoint.Endpoint;

// Import loop backend
const loop_backend = @import("loop_backend.zig");
pub const LoopBackend = loop_backend.LoopBackend;

// Basic types
pub const QuicVersion = enum { v1, v2 };
pub const Role = enum { Client, Server };

const std = @import("std");

// Re-export Connection from the conn module
const conn_mod = @import("quic_conn");
pub const Connection = conn_mod.Connection;
pub const QuicConnection = conn_mod.Connection;  // Alias for compatibility

// Endpoint functions
pub fn endpointInit(alloc: *std.mem.Allocator, bind_addr: []const u8, cfg: *const QuicConfig) !*QuicEndpoint {
    const ep = try alloc.create(QuicEndpoint);
    ep.* = try endpoint.Endpoint.init(alloc, bind_addr, cfg);
    return ep;
}

pub fn endpointDeinit(ep: *QuicEndpoint) void {
    const allocator = ep.allocator;
    ep.deinit();
    allocator.destroy(ep);
}

// Connection functions
pub fn connect(ep: *QuicEndpoint, server_addr: []const u8, server_name: []const u8) !*Connection {
    return ep.connect(server_addr, server_name);
}

pub fn accept(ep: *QuicEndpoint) ?*Connection {
    return ep.popAccepted();
}

pub fn tryAccept(ep: *QuicEndpoint) ?*Connection {
    return ep.popAccepted();
}

// Poll the endpoint for events
pub fn poll(ep: *QuicEndpoint, timeout_ms: i32) !void {
    return ep.poll(timeout_ms);
}

// Other functions that might be needed
pub fn defaultLoopBackend() LoopBackend {
    return loop_backend.defaultLoopBackend();
}

// Re-export crypto function
const crypto_mod = @import("quic_crypto");
pub fn deriveInitialSecretsForConfig(dst_conn_id: []const u8, quic_version: u32, is_server: bool) crypto_mod.InitialSecrets {
    return crypto_mod.deriveInitialSecretsForConfig(dst_conn_id, quic_version, is_server);
}

// Connection status functions
pub fn isDrained(conn: *Connection) bool {
    _ = conn; // Mark as unused
    // TODO: Implement actual drained state check
    // For now, return false to keep connections active
    return false;
}

pub fn destroy(ep: *QuicEndpoint, conn: *Connection) void {
    _ = ep; // Mark as unused
    _ = conn; // Mark as unused
    // TODO: Implement proper connection cleanup
}

// Datagram functions
pub fn recvDatagram(conn: *Connection, buffer: []u8) !usize {
    _ = conn; // Mark as unused
    _ = buffer; // Mark as unused
    // TODO: Implement datagram receive
    return 0;
}

pub fn sendDatagram(conn: *Connection, data: []const u8) !usize {
    _ = conn; // Mark as unused
    // TODO: Implement datagram send
    return data.len;
}

// Stream functions
pub fn acceptStream(conn: *Connection) !u64 {
    _ = conn; // Mark as unused
    // TODO: Implement stream accept
    return 0;
}

pub fn readStream(conn: *Connection, stream_id: u64, buffer: []u8) !usize {
    _ = conn; // Mark as unused
    _ = stream_id; // Mark as unused
    _ = buffer; // Mark as unused
    // TODO: Implement stream read
    return 0;
}

pub fn writeStream(conn: *Connection, stream_id: u64, data: []const u8) !usize {
    _ = conn; // Mark as unused
    _ = stream_id; // Mark as unused
    // TODO: Implement stream write
    return data.len;
}