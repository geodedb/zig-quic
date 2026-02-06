//! Unit tests for endpoint/incoming.zig
//!
//! RFC References:
//! - RFC 9000 §12-17: Packet Processing and Formats
//! - RFC 9000 §6: Version Negotiation
//! - RFC 9001 §5: Packet Protection
//! - RFC 9000 §13.4: Explicit Congestion Notification
//! - RFC 9000 §12.2: Coalescing Packets
//! - RFC 9000 §12.4: Frames and Frame Types
//! - RFC 9000 §14.4: ICMP Packet Too Big Messages
//!
//! Coverage:
//! - Main receive loop: poll
//! - Packet dispatcher: processIncomingDatagram
//! - Version negotiation
//! - Per-type packet processing (Initial, Handshake, 1-RTT, Retry)
//! - Frame dispatching
//! - ECN processing
//! - Connection routing
//! - Coalesced packets
//! - PMTU discovery via ICMP
//!
//! Note: These tests document expected behavior for the incoming module.
//! Currently endpoint.zig contains the implementation. Tests designed for
//! future extraction to incoming.zig.
const std = @import("std");
const testing = std.testing;
const incoming = @import("incoming");
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const packet = @import("packet");
const endpoint_types = @import("endpoint/types");
const utils = @import("endpoint/utils");
var test_allocator = std.testing.allocator;
// =============================================================================
// Test Framework for Modular Extraction (Phase 4b.5 Session 2)
// =============================================================================
/// Mock state for tracking function pointer calls
const MockState = struct {
    send_called: bool = false,
    send_data: std.ArrayList(u8),
    schedule_timer_called: bool = false,
    timer_kind: ?endpoint_types.TimerKind = null,
    timer_delay_ms: u32 = 0,
    initial_probe_called: bool = false,
    probe_version: u32 = 0,
    fn init(_: std.mem.Allocator) MockState {
        return .{
            .send_data = std.ArrayList(u8){},
        };
    }
    fn deinit(self: *MockState) void {
        self.send_data.deinit(test_allocator);
    }
    fn reset(self: *MockState) void {
        self.send_called = false;
        self.send_data.clearRetainingCapacity();
        self.schedule_timer_called = false;
        self.timer_kind = null;
        self.timer_delay_ms = 0;
        self.initial_probe_called = false;
        self.probe_version = 0;
    }
};
/// Thread-local mock state (for single-threaded tests)
threadlocal var global_mock_state: ?*MockState = null;
/// Mock implementation of SendFn - tracks send calls
fn mockSendFn(peer: conn_mod.SockAddr, data: []const u8) anyerror!usize {
    _ = peer;
    if (global_mock_state) |state| {
        state.send_called = true;
        try state.send_data.appendSlice(test_allocator, data);
    }
    return data.len;
}
/// Mock implementation of ScheduleTimerFn - tracks timer scheduling
fn mockScheduleTimerFn(conn: *conn_mod.Connection, kind: endpoint_types.TimerKind, delay_ms: u32) anyerror!u64 {
    _ = conn;
    if (global_mock_state) |state| {
        state.schedule_timer_called = true;
        state.timer_kind = kind;
        state.timer_delay_ms = delay_ms;
    }
    return 1; // Mock timer ID
}
/// Mock implementation of SendInitialProbeFn - tracks Initial probe sends
fn mockSendInitialProbeFn(conn: *conn_mod.Connection) anyerror!void {
    if (global_mock_state) |state| {
        state.initial_probe_called = true;
        state.probe_version = conn.version;
    }
}

fn mockSetupSenderFn(_: *conn_mod.Connection) void {
    // Mock implementation - no-op for tests
}

/// Helper to create RxContext for testing
fn createTestRxContext(
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection),
    accepted: *std.ArrayList(*conn_mod.Connection),
    test_cfg: *const cfg.QuicConfig,
) incoming.RxContext {
    return .{
        .allocator = allocator,
        .conns = conns,
        .accepted = accepted,
        .cfg = test_cfg,
        .send_fn = mockSendFn,
        .schedule_timer_fn = mockScheduleTimerFn,
        .send_initial_probe_fn = mockSendInitialProbeFn,
        .setup_sender_fn = mockSetupSenderFn,
        .test_capture_enabled = false,
        .endpoint_role = .Server,
    };
}
// =============================================================================
// RxContext Tests (Phase 4b.5 Session 2)
// =============================================================================
test "RFC 9000 §12 - RxContext initializes with allocator" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    try testing.expectEqual(&alloc, ctx.allocator);
}
test "RFC 9000 §12 - RxContext holds connection routing table" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    try testing.expectEqual(&conns, ctx.conns);
}
test "RFC 9000 §12 - RxContext holds accepted connections queue" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    try testing.expectEqual(&accepted, ctx.accepted);
}
test "RFC 9000 §12 - RxContext holds endpoint configuration" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    try testing.expectEqual(&test_cfg, ctx.cfg);
}
test "RFC 9000 §12 - RxContext holds send callback" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    // Verify send_fn is set - function pointers are never null in Zig
    _ = ctx.send_fn;
}
test "RFC 9000 §12 - RxContext holds timer scheduling callback" {
    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    const ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);
    // Verify schedule_timer_fn is set - function pointers are never null in Zig
    _ = ctx.schedule_timer_fn;
}
// =============================================================================
// Mock Function Tests
// =============================================================================
test "RFC 9000 §12 - mockSendFn tracks send calls" {
    var mock_state = MockState.init(test_allocator);
    defer mock_state.deinit();
    global_mock_state = &mock_state;
    defer global_mock_state = null;
    const peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);
    const data = "test packet";
    const sent = try mockSendFn(peer, data);
    try testing.expect(mock_state.send_called);
    try testing.expectEqual(data.len, sent);
    try testing.expectEqualSlices(u8, data, mock_state.send_data.items);
}
test "RFC 9002 §6.2 - mockScheduleTimerFn tracks timer scheduling" {
    var mock_state = MockState.init(test_allocator);
    defer mock_state.deinit();
    global_mock_state = &mock_state;
    defer global_mock_state = null;
    var alloc = test_allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, 1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    const timer_id = try mockScheduleTimerFn(&conn, .PtoInitial, 1000);
    try testing.expect(mock_state.schedule_timer_called);
    try testing.expectEqual(endpoint_types.TimerKind.PtoInitial, mock_state.timer_kind.?);
    try testing.expectEqual(@as(u32, 1000), mock_state.timer_delay_ms);
    try testing.expectEqual(@as(u64, 1), timer_id);
}
test "RFC 9002 §6.2 - mockSendInitialProbeFn tracks Initial probe sends" {
    var mock_state = MockState.init(test_allocator);
    defer mock_state.deinit();
    global_mock_state = &mock_state;
    defer global_mock_state = null;
    var alloc = test_allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, 1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    conn.version = 0x00000001; // QUIC v1
    try mockSendInitialProbeFn(&conn);
    try testing.expect(mock_state.initial_probe_called);
    try testing.expectEqual(@as(u32, 0x00000001), mock_state.probe_version);
}
// =============================================================================
// ECN Extraction Tests (Phase 4b.5 Session 2)
// =============================================================================
test "RFC 3168 - extractEcnBits extracts 2-bit ECN field" {
    // ECN bits are the low 2 bits of IPv4 TOS / IPv6 Traffic Class
    try testing.expectEqual(@as(u8, 0b00), incoming.extractEcnBits(0b00000000));
    try testing.expectEqual(@as(u8, 0b01), incoming.extractEcnBits(0b00000001));
    try testing.expectEqual(@as(u8, 0b10), incoming.extractEcnBits(0b00000010));
    try testing.expectEqual(@as(u8, 0b11), incoming.extractEcnBits(0b00000011));
}
test "RFC 3168 - extractEcnBits ignores DSCP field" {
    // DSCP (Differentiated Services Code Point) is bits 2-7, should be ignored
    try testing.expectEqual(@as(u8, 0b00), incoming.extractEcnBits(0b11111100));
    try testing.expectEqual(@as(u8, 0b01), incoming.extractEcnBits(0b11111101));
    try testing.expectEqual(@as(u8, 0b10), incoming.extractEcnBits(0b11111110));
    try testing.expectEqual(@as(u8, 0b11), incoming.extractEcnBits(0b11111111));
}
test "RFC 9000 §13.4 - ECN codepoint values match RFC 3168" {
    // RFC 3168 defines four codepoints:
    // - 0b00: Not-ECT (Not ECN-Capable Transport)
    // - 0b01: ECT(1) (ECN-Capable Transport(1))
    // - 0b10: ECT(0) (ECN-Capable Transport(0))
    // - 0b11: CE (Congestion Experienced)
    try testing.expectEqual(@as(u2, 0b00), @intFromEnum(incoming.EcnCodepoint.NotEct));
    try testing.expectEqual(@as(u2, 0b01), @intFromEnum(incoming.EcnCodepoint.Ect1));
    try testing.expectEqual(@as(u2, 0b10), @intFromEnum(incoming.EcnCodepoint.Ect0));
    try testing.expectEqual(@as(u2, 0b11), @intFromEnum(incoming.EcnCodepoint.Ce));
}
test "RFC 9000 §13.4 - EcnCodepoint enum conversion from extracted bits" {
    // Test all four ECN codepoints
    const test_cases = [_]struct { tos: u8, expected: incoming.EcnCodepoint }{
        .{ .tos = 0b00000000, .expected = .NotEct },
        .{ .tos = 0b00000001, .expected = .Ect1 },
        .{ .tos = 0b00000010, .expected = .Ect0 },
        .{ .tos = 0b00000011, .expected = .Ce },
    };
    for (test_cases) |case| {
        const bits = incoming.extractEcnBits(case.tos);
        const codepoint: incoming.EcnCodepoint = @enumFromInt(bits);
        try testing.expectEqual(case.expected, codepoint);
    }
}

// =============================================================================
// Closed Connection Guard Tests (RFC 9000 §10.2)
// =============================================================================

test "RFC 9000 §10.2 - processFrames returns empty result for closed connection" {
    // RFC 9000 §10.2: An endpoint that is closing or draining MUST NOT process
    // further received packets. After CONNECTION_CLOSE is sent, frames for the
    // connection must be discarded to prevent accessing inconsistent state.
    var mock_state = MockState.init(test_allocator);
    defer mock_state.deinit();
    global_mock_state = &mock_state;
    defer global_mock_state = null;

    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    var ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);

    // Create a connection and mark it as closed
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.closed = true;

    // Create a dummy payload with a PING frame (type 0x01)
    const payload = &[_]u8{0x01};
    const peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);

    // processFrames should return early with empty result for closed connections
    const result = try incoming.processFrames(&ctx, &conn, peer, payload, mockSendFn);
    try testing.expect(!result.saw_ack_eliciting);
    // Verify that no data was sent (frames were not processed)
    try testing.expect(!mock_state.send_called);
}

test "RFC 9000 §10.2 - processFrames processes frames for non-closed connection" {
    // Verify that processFrames still works for open connections (regression check)
    var mock_state = MockState.init(test_allocator);
    defer mock_state.deinit();
    global_mock_state = &mock_state;
    defer global_mock_state = null;

    var alloc = test_allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(test_allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .{};
    defer accepted.deinit(test_allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    var ctx = createTestRxContext(&alloc, &conns, &accepted, &test_cfg);

    // Create a connection that is NOT closed
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    try testing.expect(!conn.closed);

    // Create a PING frame (type 0x01) - this is ack-eliciting per RFC 9000 §19.2
    const payload = &[_]u8{0x01};
    const peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);

    // processFrames should process the PING frame for non-closed connections
    const result = try incoming.processFrames(&ctx, &conn, peer, payload, mockSendFn);
    // PING is an ack-eliciting frame
    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// End of Unit Tests
// =============================================================================
//
// NOTE: Integration tests for processIncomingDatagram, processInitial,
// processHandshake, process1Rtt, and full packet processing require a complete
// Endpoint object with UDP socket, TLS integration, configuration, routing
// infrastructure, and mock Connection objects. These should be implemented as
// integration tests in a separate test suite once the integration test framework
// is ready.
//
// The unit tests above verify the mock infrastructure and helper functions that
// can be used for future integration testing.
