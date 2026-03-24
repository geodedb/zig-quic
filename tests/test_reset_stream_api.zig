// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Tests for QUIC-H3-001 through QUIC-H3-004: stream reset, datagram plumbing,
//! readiness flags, and flow-control writable signals.
//!
//! These tests validate the public API surface and Connection-level behaviour
//! without requiring a live network handshake (test-mode send is a no-op).

const std = @import("std");
const conn_mod = @import("quic_conn");
const api = @import("quic_api");

fn makeConn(a: *std.mem.Allocator) conn_mod.Connection {
    var c: conn_mod.Connection = undefined;
    c.init(a, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    c.our_scid.len = 0;
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.peer_finished_verified = true; // hasConfirmedAppTxKeys requires both fields
    return c;
}

// =========================================================================
// QUIC-H3-001: resetStream() API
// =========================================================================

test "resetStream: marks stream 0 TX as aborted" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.stream_opened = true;
    c.stream_send_off = 42;

    // In test mode, send() is a no-op; encoding may propagate errors but the
    // critical assertion is that the aborted flag gets set before the send.
    c.resetStream(0, 0x0100) catch {};
    try std.testing.expect(c.stream_send_aborted);
}

test "resetStream: marks per-stream TX as aborted" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.ensureStreamTxInit();
    _ = c.stream_txs.put(4, .{ .off = 100, .peer_max_stream_data = 1024 }) catch unreachable;

    c.resetStream(4, 0x0200) catch {};

    const st = c.stream_txs.getPtr(4).?;
    try std.testing.expect(st.aborted);
}

test "resetStream: returns InvalidStream for unknown stream" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    const result = c.resetStream(99, 0);
    try std.testing.expectError(error.InvalidStream, result);
}

test "resetStream: returns StreamStopped if stream 0 already aborted" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.stream_send_aborted = true;
    const result = c.resetStream(0, 0);
    try std.testing.expectError(error.StreamStopped, result);
}

test "handleResetStream: processes incoming reset for stream 0" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try c.pushStreamFrame(0, 0, "hello", false);
    c.handleResetStream(0, 0x01, 5);

    try std.testing.expect(c.stream_recv_aborted);
    try std.testing.expect(c.stream_recv_fin);
}

test "handleStopSending: marks stream TX aborted" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.stream_opened = true;
    c.stream_send_off = 10;

    c.handleStopSending(0, 0x01) catch {};
    try std.testing.expect(c.stream_send_aborted);
}

// =========================================================================
// QUIC-H3-002: hasDatagram API
// =========================================================================

test "hasDatagram: false when inbox empty" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try std.testing.expect(!api.hasDatagram(&c));
}

test "hasDatagram: true after pushDatagram" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try c.pushDatagram("hello");
    try std.testing.expect(api.hasDatagram(&c));
}

// =========================================================================
// QUIC-H3-003: pollReady readiness flags
// =========================================================================

test "pollReady: default flags on fresh connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    const ready = api.pollReady(&c);
    try std.testing.expect(!ready.has_incoming_streams);
    try std.testing.expect(!ready.has_datagram);
    try std.testing.expect(!ready.connection_closed);
    try std.testing.expect(!ready.has_writable_streams);
}

test "pollReady: connection_closed flag" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.closed = true;
    const ready = api.pollReady(&c);
    try std.testing.expect(ready.connection_closed);
}

test "pollReady: has_datagram flag" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try c.pushDatagram("test");
    const ready = api.pollReady(&c);
    try std.testing.expect(ready.has_datagram);
}

// =========================================================================
// QUIC-H3-004: Flow-control writable signals
// =========================================================================

test "hasWritableStreams: false initially" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try std.testing.expect(!api.hasWritableStreams(&c));
}

test "popWritableStream: returns null when empty" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    try std.testing.expect(api.popWritableStream(&c) == null);
}

test "writable_streams: manual enqueue and dequeue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    // Simulate what the frame handler does when MAX_STREAM_DATA unblocks a stream
    c.writable_streams.append(alloc, 4) catch unreachable;
    c.writable_streams.append(alloc, 8) catch unreachable;

    try std.testing.expect(api.hasWritableStreams(&c));
    try std.testing.expectEqual(@as(u64, 4), api.popWritableStream(&c).?);
    try std.testing.expectEqual(@as(u64, 8), api.popWritableStream(&c).?);
    try std.testing.expect(api.popWritableStream(&c) == null);
    try std.testing.expect(!api.hasWritableStreams(&c));
}

// =========================================================================
// API re-export: resetStream wrapper
// =========================================================================

test "api.resetStream: delegates to connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = makeConn(&alloc);
    defer c.deinit();

    c.stream_opened = true;
    api.resetStream(&c, 0, 0x42) catch {};
    try std.testing.expect(c.stream_send_aborted);
}
