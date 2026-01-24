// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Transport abstraction for QUIC endpoint
//!
//! Enables pluggable transport backends (UDP, loopback, etc.) while maintaining
//! performance and type safety.
//!
//! This module defines the Transport interface that endpoint.zig uses. Concrete
//! implementations (UdpTransport, LoopbackTransportAdapter) are provided in
//! test code or endpoint initialization.

const std = @import("std");
const conn_mod = @import("quic_conn");

/// Socket address type (common across transports)
pub const SockAddr = conn_mod.SockAddr;

/// Result of receive operation
pub const RecvResult = struct {
    /// Number of bytes received
    n: usize,

    /// Peer address
    peer: SockAddr,

    /// ECN marking (if available)
    ecn: ?u8 = null,
};

/// Transport backend interface
///
/// This is a fat pointer pattern: function pointers + context pointer
/// Zero-cost abstraction when statically dispatched via inlining
pub const Transport = struct {
    /// Send function pointer
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,

    /// Receive function pointer
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,

    /// Poll function pointer (optional, for event-driven I/O)
    pollFn: ?*const fn (ctx: *anyopaque, timeout_ms: i32) anyerror!void,

    /// Close function pointer
    closeFn: *const fn (ctx: *anyopaque) void,

    /// Get local address function pointer
    getLocalAddrFn: *const fn (ctx: *anyopaque) anyerror!SockAddr,

    /// Opaque context pointer (cast to concrete type in implementations)
    context: *anyopaque,

    /// Send packet to peer
    pub fn send(self: *Transport, peer: SockAddr, data: []const u8) !usize {
        return self.sendFn(self.context, peer, data);
    }

    /// Receive packet from any peer
    pub fn recv(self: *Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.context, buf);
    }

    /// Poll for events (if supported)
    pub fn poll(self: *Transport, timeout_ms: i32) !void {
        if (self.pollFn) |poll_fn| {
            try poll_fn(self.context, timeout_ms);
        }
    }

    /// Close transport
    pub fn close(self: *Transport) void {
        self.closeFn(self.context);
    }

    /// Get local bound address
    pub fn getLocalAddr(self: *Transport) !SockAddr {
        return self.getLocalAddrFn(self.context);
    }
};
