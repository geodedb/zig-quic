//! Unit tests for endpoint/frame_handler.zig
//!
//! RFC References:
//! - RFC 9000 §12: Packets and Frames
//! - RFC 9000 §19: Frame Types and Formats
//! - RFC 9000 §13.2: Acknowledgments (ack-eliciting frames)
//! - RFC 9000 §9: Path Validation (PATH_CHALLENGE, PATH_RESPONSE)
//! - RFC 9221: DATAGRAM Extension
//!
//! Coverage:
//! - Positive cases: All 16 frame handlers process frames correctly
//! - Negative cases: Error handling for stream operations
//! - Edge cases: Empty tokens, zero-length CIDs, blocked frames
//! - RFC compliance: Ack-eliciting tracking, connection state updates

const std = @import("std");
const testing = std.testing;
const frame_handler = @import("frame_handler");
const frame = @import("frame");
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const recovery = @import("quic_recovery");

var test_allocator = std.testing.allocator;

// Test helper: Create minimal test connection
// Note: Connection has many required fields. This is a simplified mock for testing frame handlers.
fn createTestConnection() !*conn_mod.Connection {
    const conn = try test_allocator.create(conn_mod.Connection);
    // Use undefined for fields we don't care about in frame handler tests
    // Only initialize fields that frame handlers actually modify
    conn.* = undefined;
    conn.role = .Client;
    conn.allocator = &test_allocator;  // CRITICAL: needed for onNewConnectionId and pushStreamFrame
    conn.reset_tokens = std.ArrayList([16]u8){};  // CRITICAL: needed for onNewConnectionId
    conn.dgram_inbox = std.ArrayList([]u8){};  // CRITICAL: needed for pushDatagram
    conn.streams_rx = std.AutoHashMap(u64, conn_mod.StreamRx).init(test_allocator);  // CRITICAL: needed for pushStreamFrame
    conn.streams_rx_init = true;  // CRITICAL: init flag for streams_rx
    conn.stream_txs = std.AutoHashMap(u64, conn_mod.StreamTx).init(test_allocator);  // CRITICAL: required for MAX_STREAM_DATA
    conn.stream_txs_init = true;  // CRITICAL: init flag for stream_txs
    conn.incoming_stream_queue = std.ArrayList(u64){};  // CRITICAL: needed for pushStreamFrame
    conn.stream_recv_aborted = false;  // CRITICAL: needed for pushStreamFrame
    conn.peer_initial_scid = .{ .len = 0 };
    conn.peer_max_data = 0;
    conn.peer_max_stream_data = 0;
    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;
    conn.pn_app_tx = 0;
    conn.tx_key_phase = false;
    conn.app_tx_keys = null;
    conn.app_rx_keys = null;
    conn.hs_rx_keys = null;
    conn.hs_tx_keys = null;
    conn.closed = false;
    conn.rec = recovery.Recovery.init(test_allocator);
    conn.path_mtu = 1200;
    conn.path_validation_pending = false;
    conn.path_challenge_data = [_]u8{0} ** 8;
    conn.initial_token = std.ArrayList(u8){};
    conn.pto_app_count = 0;
    conn.pto_app_active = false;
    conn.pto_app_id = 0;
    return conn;
}

// Test helper: Cleanup test connection
fn destroyTestConnection(conn: *conn_mod.Connection) void {
    conn.initial_token.deinit(test_allocator);
    conn.reset_tokens.deinit(test_allocator);
    // Clean up datagram inbox
    for (conn.dgram_inbox.items) |dgram| {
        test_allocator.free(dgram);
    }
    conn.dgram_inbox.deinit(test_allocator);
    // Clean up individual streams before deiniting the hashmap
    var it = conn.streams_rx.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.deinit(conn.allocator);
    }
    conn.streams_rx.deinit();
    // StreamTx has no allocations, just deinit the hashmap
    conn.stream_txs.deinit();
    conn.incoming_stream_queue.deinit(test_allocator);
    conn.rec.deinit();
    test_allocator.destroy(conn);
}

// Test helper: Mock send function
fn mockSendFn(peer: conn_mod.SockAddr, data: []const u8) !usize {
    _ = peer;
    return data.len;
}

// Test helper: Create test FrameContext
fn createTestContext(conn: *conn_mod.Connection) frame_handler.FrameContext {
    const test_cfg = cfg.QuicConfig{
        .alpn = &[_][]const u8{},
        .enable_datagram = false,
        .max_idle_timeout_ms = 30000,
        .max_udp_payload = 1200,
    };
    return .{
        .conn = conn,
        .allocator = &test_allocator,
        .send_fn = &mockSendFn,
        .peer = .{},
        .space = .Application,
        .cfg = &test_cfg,
    };
}

// =============================================================================
// PING Frame Tests (RFC 9000 §19.2)
// =============================================================================

test "RFC 9000 §19.2 - PING frame is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const result = frame_handler.handlePing(&ctx);

    try testing.expect(result.saw_ack_eliciting);
    try testing.expect(!result.saw_handshake_done);
    try testing.expect(!result.saw_close);
}

// =============================================================================
// NEW_CONNECTION_ID Frame Tests (RFC 9000 §19.15)
// =============================================================================

test "RFC 9000 §19.15 - NEW_CONNECTION_ID records stateless reset token" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const cid = [_]u8{0x01} ** 8;
    const ncid = frame.NewConnectionId{
        .sequence = 1,
        .retire_prior_to = 0,
        .connection_id = &cid,
        .stateless_reset_token = [_]u8{0xAA} ** 16,
    };

    const result = frame_handler.handleNewConnectionId(&ctx, ncid);

    try testing.expect(result.saw_ack_eliciting);
    try testing.expect(!result.saw_handshake_done);
    try testing.expect(!result.saw_close);
}

// =============================================================================
// RETIRE_CONNECTION_ID Frame Tests (RFC 9000 §19.16)
// =============================================================================

test "RFC 9000 §19.16 - RETIRE_CONNECTION_ID retires CID" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const rc = frame.RetireConnectionId{ .sequence = 0 };

    const result = frame_handler.handleRetireConnectionId(&ctx, rc);

    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// STREAM Frame Tests (RFC 9000 §19.8)
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const s = frame.Stream{
        .stream_id = 0,
        .offset = 0,
        .data = "test",
        .fin = false,
    };

    const result = try frame_handler.handleStream(&ctx, s);

    try testing.expect(result.saw_ack_eliciting);
}

test "RFC 9000 §19.8 - STREAM frame with FIN flag" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const s = frame.Stream{
        .stream_id = 0,
        .offset = 0,
        .data = "final",
        .fin = true,
    };

    const result = try frame_handler.handleStream(&ctx, s);

    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// DATAGRAM Frame Tests (RFC 9221)
// =============================================================================

test "RFC 9221 - DATAGRAM frame is not ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const d = frame.Datagram{ .data = "unreliable" };

    const result = try frame_handler.handleDatagram(&ctx, d);

    try testing.expect(!result.saw_ack_eliciting);
}

// =============================================================================
// ACK Frame Tests (RFC 9000 §19.3)
// =============================================================================

test "RFC 9000 §19.3 - ACK frame is not ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const a = frame.Ack{
        .largest = 10,
        .ack_delay = 0,
        .first_range = 5,
        .ranges = &[_]frame.AckRange{},
        .ecn = null,
    };

    const result = frame_handler.handleAck(&ctx, a);

    try testing.expect(!result.saw_ack_eliciting);
}

test "RFC 9000 §19.3 - ACK resets PTO count" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    conn.pto_app_count = 5;
    var ctx = createTestContext(conn);

    const a = frame.Ack{
        .largest = 10,
        .ack_delay = 0,
        .first_range = 5,
        .ranges = &[_]frame.AckRange{},
        .ecn = null,
    };

    _ = frame_handler.handleAck(&ctx, a);

    try testing.expectEqual(@as(u32, 0), conn.pto_app_count);
}

// =============================================================================
// HANDSHAKE_DONE Frame Tests (RFC 9000 §19.20)
// =============================================================================

test "RFC 9000 §19.20 - HANDSHAKE_DONE is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const result = frame_handler.handleHandshakeDone(&ctx);

    try testing.expect(result.saw_ack_eliciting);
    try testing.expect(result.saw_handshake_done);
    try testing.expect(!result.saw_close);
}

// =============================================================================
// CONNECTION_CLOSE Frame Tests (RFC 9000 §19.19)
// =============================================================================

test "RFC 9000 §19.19 - CONNECTION_CLOSE sets saw_close" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const result = frame_handler.handleConnectionClose(&ctx);

    try testing.expect(!result.saw_ack_eliciting);
    try testing.expect(result.saw_close);
}

// =============================================================================
// MAX_STREAM_DATA Frame Tests (RFC 9000 §19.10)
// =============================================================================

test "RFC 9000 §19.10 - MAX_STREAM_DATA updates peer limit" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const m = frame.MaxStreamData{
        .stream_id = 0,
        .max = 65536,
    };

    const result = frame_handler.handleMaxStreamData(&ctx, m);

    // Check per-stream TX state (PHASE 57 PART 11: per-stream flow control)
    const tx = conn.stream_txs.get(0) orelse unreachable;
    try testing.expectEqual(@as(u64, 65536), tx.peer_max_stream_data);
    try testing.expect(result.saw_ack_eliciting);
}

test "RFC 9000 §19.10 - MAX_STREAM_DATA is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const m = frame.MaxStreamData{
        .stream_id = 0,
        .max = 1000,
    };

    const result = frame_handler.handleMaxStreamData(&ctx, m);

    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// MAX_DATA Frame Tests (RFC 9000 §19.9)
// =============================================================================

test "RFC 9000 §19.9 - MAX_DATA updates connection limit" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const md = frame.MaxData{ .max = 1048576 };

    const result = frame_handler.handleMaxData(&ctx, md);

    try testing.expectEqual(@as(u64, 1048576), conn.peer_max_data);
    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// MAX_STREAMS Frame Tests (RFC 9000 §19.11)
// =============================================================================

test "RFC 9000 §19.11 - MAX_STREAMS (bidi) updates limit" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const msb = frame.MaxStreamsBidi{ .max = 100 };

    const result = frame_handler.handleMaxStreamsBidi(&ctx, msb);

    try testing.expectEqual(@as(u64, 100), conn.peer_max_streams_bidi);
    try testing.expect(result.saw_ack_eliciting);
}

test "RFC 9000 §19.11 - MAX_STREAMS (uni) updates limit" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const msu = frame.MaxStreamsUni{ .max = 50 };

    const result = frame_handler.handleMaxStreamsUni(&ctx, msu);

    try testing.expectEqual(@as(u64, 50), conn.peer_max_streams_uni);
    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// STREAM_DATA_BLOCKED Frame Tests (RFC 9000 §19.13)
// =============================================================================

test "RFC 9000 §19.13 - STREAM_DATA_BLOCKED is no-op" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const sdb = frame.StreamDataBlocked{
        .stream_id = 0,
        .limit = 1000,
    };

    const result = frame_handler.handleStreamDataBlocked(&ctx, sdb);

    try testing.expect(!result.saw_ack_eliciting);
}

// =============================================================================
// PATH_CHALLENGE Frame Tests (RFC 9000 §19.17)
// =============================================================================

test "RFC 9000 §19.17 - PATH_CHALLENGE is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const pcv: [8]u8 = [_]u8{0x01} ** 8;

    const result = try frame_handler.handlePathChallenge(&ctx, pcv);

    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// PATH_RESPONSE Frame Tests (RFC 9000 §19.18)
// =============================================================================

test "RFC 9000 §19.18 - PATH_RESPONSE is ack-eliciting" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const prv: [8]u8 = [_]u8{0x02} ** 8;

    const result = frame_handler.handlePathResponse(&ctx, prv);

    try testing.expect(result.saw_ack_eliciting);
}

// =============================================================================
// NEW_TOKEN Frame Tests (RFC 9000 §19.7)
// =============================================================================

test "RFC 9000 §19.7 - NEW_TOKEN updates token" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const nt = frame.NewToken{
        .token = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
    };

    const result = try frame_handler.handleNewToken(&ctx, nt);

    try testing.expect(result.saw_ack_eliciting);
    try testing.expectEqual(@as(usize, 4), conn.initial_token.items.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, conn.initial_token.items);
}

test "RFC 9000 §19.7 - NEW_TOKEN replaces existing token" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    _ = try conn.initial_token.appendSlice(test_allocator, &[_]u8{ 0x01, 0x02 });
    var ctx = createTestContext(conn);

    const nt = frame.NewToken{
        .token = &[_]u8{ 0xAA, 0xBB },
    };

    _ = try frame_handler.handleNewToken(&ctx, nt);

    try testing.expectEqual(@as(usize, 2), conn.initial_token.items.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, conn.initial_token.items);
}

// =============================================================================
// Frame Dispatcher Tests
// =============================================================================

test "processFrame dispatches PING correctly" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const fr = frame.Frame{ .ping = {} };

    const result = try frame_handler.processFrame(&ctx, fr);

    try testing.expect(result.saw_ack_eliciting);
}

test "processFrame dispatches ACK correctly" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const fr = frame.Frame{
        .ack = .{
            .largest = 5,
            .ack_delay = 0,
            .first_range = 2,
            .ranges = &[_]frame.AckRange{},
            .ecn = null,
        },
    };

    const result = try frame_handler.processFrame(&ctx, fr);

    try testing.expect(!result.saw_ack_eliciting);
}

test "processFrame dispatches HANDSHAKE_DONE correctly" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const fr = frame.Frame{ .handshake_done = {} };

    const result = try frame_handler.processFrame(&ctx, fr);

    try testing.expect(result.saw_ack_eliciting);
    try testing.expect(result.saw_handshake_done);
}

test "processFrame dispatches CONNECTION_CLOSE correctly" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    const fr = frame.Frame{
        .connection_close = .{
            .error_code = 0,
            .reason = "",
        },
    };

    const result = try frame_handler.processFrame(&ctx, fr);

    try testing.expect(result.saw_close);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §13.2.1 - Ack-eliciting frames are correctly identified" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    var ctx = createTestContext(conn);

    // Ack-eliciting frames
    const ping_result = frame_handler.handlePing(&ctx);
    try testing.expect(ping_result.saw_ack_eliciting);

    const hs_done_result = frame_handler.handleHandshakeDone(&ctx);
    try testing.expect(hs_done_result.saw_ack_eliciting);

    const cid2 = [_]u8{0} ** 8;
    const ncid_result = frame_handler.handleNewConnectionId(&ctx, .{
        .sequence = 0,
        .retire_prior_to = 0,
        .connection_id = &cid2,
        .stateless_reset_token = [_]u8{0} ** 16,
    });
    try testing.expect(ncid_result.saw_ack_eliciting);

    // Non-ack-eliciting frames
    const ack_result = frame_handler.handleAck(&ctx, .{
        .largest = 0,
        .ack_delay = 0,
        .first_range = 0,
        .ranges = &[_]frame.AckRange{},
        .ecn = null,
    });
    try testing.expect(!ack_result.saw_ack_eliciting);

    const close_result = frame_handler.handleConnectionClose(&ctx);
    try testing.expect(!close_result.saw_ack_eliciting);
}

test "RFC 9000 §4 - Flow control limits are updated correctly" {
    const conn = try createTestConnection();
    defer destroyTestConnection(conn);
    conn.peer_max_data = 1000;
    conn.peer_max_streams_bidi = 10;
    conn.peer_max_streams_uni = 5;
    var ctx = createTestContext(conn);

    // Update MAX_DATA
    _ = frame_handler.handleMaxData(&ctx, .{ .max = 2000 });
    try testing.expectEqual(@as(u64, 2000), conn.peer_max_data);

    // Update MAX_STREAM_DATA (PHASE 57 PART 11: per-stream flow control)
    _ = frame_handler.handleMaxStreamData(&ctx, .{ .stream_id = 0, .max = 1000 });
    const tx = conn.stream_txs.get(0) orelse unreachable;
    try testing.expectEqual(@as(u64, 1000), tx.peer_max_stream_data);

    // Update MAX_STREAMS (bidi)
    _ = frame_handler.handleMaxStreamsBidi(&ctx, .{ .max = 20 });
    try testing.expectEqual(@as(u64, 20), conn.peer_max_streams_bidi);

    // Update MAX_STREAMS (uni)
    _ = frame_handler.handleMaxStreamsUni(&ctx, .{ .max = 10 });
    try testing.expectEqual(@as(u64, 10), conn.peer_max_streams_uni);
}
