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

/// One receive slot for batched datagram I/O.
pub const RecvBatchSlot = struct {
    /// Backing buffer to receive datagram bytes into.
    buf: []u8,
    /// Number of bytes written in this slot.
    n: usize = 0,
    /// Source peer address.
    peer: SockAddr = .{},
    /// Optional ECN marking.
    ecn: ?u8 = null,
};

/// One outbound datagram item for batched send.
pub const SendBatchItem = struct {
    peer: SockAddr,
    data: []const u8,
};

/// Transport backend interface
///
/// This is a fat pointer pattern: function pointers + context pointer
/// Zero-cost abstraction when statically dispatched via inlining
pub const Transport = struct {
    /// Send function pointer
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,

    /// Optional batched send function pointer.
    sendBatchFn: ?*const fn (ctx: *anyopaque, items: []const SendBatchItem) anyerror!usize = null,

    /// Receive function pointer
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,

    /// Optional batched receive function pointer.
    recvBatchFn: ?*const fn (ctx: *anyopaque, slots: []RecvBatchSlot) anyerror!usize = null,

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

    /// Send multiple packets to peers.
    ///
    /// If the backend does not provide native batched send, this falls back to
    /// per-packet send calls.
    pub fn sendBatch(self: *Transport, items: []const SendBatchItem) !usize {
        if (items.len == 0) return 0;
        if (self.sendBatchFn) |send_batch_fn| {
            return send_batch_fn(self.context, items);
        }
        var sent: usize = 0;
        for (items) |it| {
            const n = try self.send(it.peer, it.data);
            if (n != it.data.len) return error.ShortWrite;
            sent += 1;
        }
        return sent;
    }

    /// Receive packet from any peer
    pub fn recv(self: *Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.context, buf);
    }

    /// Receive multiple packets into preallocated slots.
    ///
    /// If the backend does not provide native batched receive, this falls back
    /// to repeated single-packet receives until WouldBlock or slots are filled.
    pub fn recvBatch(self: *Transport, slots: []RecvBatchSlot) !usize {
        if (slots.len == 0) return 0;
        if (self.recvBatchFn) |recv_batch_fn| {
            return recv_batch_fn(self.context, slots);
        }
        var filled: usize = 0;
        while (filled < slots.len) : (filled += 1) {
            const r = self.recv(slots[filled].buf) catch |err| {
                if (err == error.WouldBlock) {
                    if (filled == 0) return error.WouldBlock;
                    return filled;
                }
                return err;
            };
            slots[filled].n = r.n;
            slots[filled].peer = r.peer;
            slots[filled].ecn = r.ecn;
        }
        return filled;
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
