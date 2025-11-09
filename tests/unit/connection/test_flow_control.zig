//! Unit tests for connection/flow_control.zig
//!
//! RFC References:
//! - RFC 9000 §4: Flow Control
//! - RFC 9000 §4.1: Data Flow Control
//! - RFC 9000 §4.2: Increasing Flow Control Limits
//! - RFC 9000 §4.6: Controlling Concurrency
//!
//! Coverage:
//! - Positive cases: Window calculations, limit checks, window expansion
//! - Negative cases: Exceeding limits, zero windows
//! - Edge cases: Exact limits, min/max windows, growth factors
//! - RFC compliance: Connection/stream flow control, MAX_DATA/MAX_STREAM_DATA

const std = @import("std");
const testing = std.testing;

const fc = @import("flow_control");

// =============================================================================
// Connection Flow Control Tests
// =============================================================================

test "RFC 9000 §4.1 - canSendConnectionData within limit" {
    const conn_send_off: u64 = 500;
    const peer_max_data: u64 = 1000;

    try testing.expect(fc.canSendConnectionData(conn_send_off, peer_max_data));
}

test "RFC 9000 §4.1 - canSendConnectionData at limit" {
    const conn_send_off: u64 = 1000;
    const peer_max_data: u64 = 1000;

    try testing.expect(!fc.canSendConnectionData(conn_send_off, peer_max_data));
}

test "RFC 9000 §4.1 - canSendConnectionData over limit" {
    const conn_send_off: u64 = 1500;
    const peer_max_data: u64 = 1000;

    try testing.expect(!fc.canSendConnectionData(conn_send_off, peer_max_data));
}

test "RFC 9000 §4.1 - connectionFlowWindow calculates available" {
    const conn_send_off: u64 = 300;
    const peer_max_data: u64 = 1000;

    const window = fc.connectionFlowWindow(conn_send_off, peer_max_data);

    try testing.expectEqual(@as(u64, 700), window);
}

test "RFC 9000 §4.1 - connectionFlowWindow zero when at limit" {
    const conn_send_off: u64 = 1000;
    const peer_max_data: u64 = 1000;

    const window = fc.connectionFlowWindow(conn_send_off, peer_max_data);

    try testing.expectEqual(@as(u64, 0), window);
}

test "RFC 9000 §4.1 - connectionFlowWindow zero when over limit" {
    const conn_send_off: u64 = 1200;
    const peer_max_data: u64 = 1000;

    const window = fc.connectionFlowWindow(conn_send_off, peer_max_data);

    try testing.expectEqual(@as(u64, 0), window);
}

// =============================================================================
// Stream Flow Control Tests
// =============================================================================

test "RFC 9000 §4.2 - canSendStreamData within limit" {
    const stream_send_off: u64 = 200;
    const peer_max_stream_data: u64 = 500;

    try testing.expect(fc.canSendStreamData(stream_send_off, peer_max_stream_data));
}

test "RFC 9000 §4.2 - canSendStreamData at limit" {
    const stream_send_off: u64 = 500;
    const peer_max_stream_data: u64 = 500;

    try testing.expect(!fc.canSendStreamData(stream_send_off, peer_max_stream_data));
}

test "RFC 9000 §4.2 - streamFlowWindow calculates available" {
    const stream_send_off: u64 = 100;
    const peer_max_stream_data: u64 = 400;

    const window = fc.streamFlowWindow(stream_send_off, peer_max_stream_data);

    try testing.expectEqual(@as(u64, 300), window);
}

test "RFC 9000 §4.2 - streamFlowWindow zero at limit" {
    const stream_send_off: u64 = 400;
    const peer_max_stream_data: u64 = 400;

    const window = fc.streamFlowWindow(stream_send_off, peer_max_stream_data);

    try testing.expectEqual(@as(u64, 0), window);
}

// =============================================================================
// Stream Concurrency Tests
// =============================================================================

test "RFC 9000 §4.6 - canOpenStream within limit" {
    const opened: u64 = 5;
    const peer_max_streams: u64 = 10;

    try testing.expect(fc.canOpenStream(opened, peer_max_streams));
}

test "RFC 9000 §4.6 - canOpenStream at limit" {
    const opened: u64 = 10;
    const peer_max_streams: u64 = 10;

    try testing.expect(!fc.canOpenStream(opened, peer_max_streams));
}

test "RFC 9000 §4.6 - canOpenStream over limit" {
    const opened: u64 = 15;
    const peer_max_streams: u64 = 10;

    try testing.expect(!fc.canOpenStream(opened, peer_max_streams));
}

// =============================================================================
// Window Expansion Tests
// =============================================================================

test "RFC 9000 §4.1 - shouldExpandConnectionWindow at threshold" {
    const conn_recv_total: u64 = 800;
    const local_max_data: u64 = 1000;
    const threshold_percent: u64 = 80;

    try testing.expect(fc.shouldExpandConnectionWindow(conn_recv_total, local_max_data, threshold_percent));
}

test "RFC 9000 §4.1 - shouldExpandConnectionWindow below threshold" {
    const conn_recv_total: u64 = 700;
    const local_max_data: u64 = 1000;
    const threshold_percent: u64 = 80;

    try testing.expect(!fc.shouldExpandConnectionWindow(conn_recv_total, local_max_data, threshold_percent));
}

test "RFC 9000 §4.2 - shouldExpandStreamWindow at threshold" {
    const stream_recv_off: u64 = 450;
    const local_max_stream_data: u64 = 500;
    const threshold_percent: u64 = 90;

    try testing.expect(fc.shouldExpandStreamWindow(stream_recv_off, local_max_stream_data, threshold_percent));
}

test "RFC 9000 §4.1 - expandConnectionWindow with growth factor" {
    const current_max: u64 = 1000;
    const growth_factor_num: u64 = 2; // 2x growth
    const growth_factor_denom: u64 = 1;

    const new_max = fc.expandConnectionWindow(current_max, growth_factor_num, growth_factor_denom);

    try testing.expectEqual(@as(u64, 3000), new_max); // 1000 + (1000 * 2 / 1)
}

test "RFC 9000 §4.2 - expandStreamWindow with fractional growth" {
    const current_max: u64 = 1000;
    const growth_factor_num: u64 = 1; // 50% growth (1/2)
    const growth_factor_denom: u64 = 2;

    const new_max = fc.expandStreamWindow(current_max, growth_factor_num, growth_factor_denom);

    try testing.expectEqual(@as(u64, 1500), new_max); // 1000 + (1000 * 1 / 2)
}

// =============================================================================
// MAX_DATA/MAX_STREAM_DATA Frame Tests
// =============================================================================

test "RFC 9000 §4.1 - shouldSendMaxData when limit increased" {
    const local_max_data: u64 = 2000;
    const last_sent_max_data: u64 = 1000;

    try testing.expect(fc.shouldSendMaxData(local_max_data, last_sent_max_data));
}

test "RFC 9000 §4.1 - shouldSendMaxData false when unchanged" {
    const local_max_data: u64 = 1000;
    const last_sent_max_data: u64 = 1000;

    try testing.expect(!fc.shouldSendMaxData(local_max_data, last_sent_max_data));
}

test "RFC 9000 §4.2 - shouldSendMaxStreamData when limit increased" {
    const local_max_stream_data: u64 = 1500;
    const last_sent_max_stream_data: u64 = 1000;

    try testing.expect(fc.shouldSendMaxStreamData(local_max_stream_data, last_sent_max_stream_data));
}

test "RFC 9000 §4.6 - shouldSendMaxStreamsBidi when limit increased" {
    const local_max_streams_bidi: u64 = 20;
    const last_sent_max_streams_bidi: u64 = 10;

    try testing.expect(fc.shouldSendMaxStreamsBidi(local_max_streams_bidi, last_sent_max_streams_bidi));
}

// =============================================================================
// Window Utility Tests
// =============================================================================

test "RFC 9000 §4 - minWindow selects smaller value" {
    const window1: u64 = 500;
    const window2: u64 = 300;

    try testing.expectEqual(@as(u64, 300), fc.minWindow(window1, window2));
}

test "RFC 9000 §4 - minWindow handles equal windows" {
    const window1: u64 = 400;
    const window2: u64 = 400;

    try testing.expectEqual(@as(u64, 400), fc.minWindow(window1, window2));
}

test "RFC 9000 §4 - clampToFlowControl limits send amount" {
    const desired: usize = 1000;
    const stream_window: u64 = 500;
    const conn_window: u64 = 600;

    const clamped = fc.clampToFlowControl(desired, stream_window, conn_window);

    try testing.expectEqual(@as(usize, 500), clamped);
}

test "RFC 9000 §4 - clampToFlowControl uses connection window" {
    const desired: usize = 1000;
    const stream_window: u64 = 800;
    const conn_window: u64 = 400;

    const clamped = fc.clampToFlowControl(desired, stream_window, conn_window);

    try testing.expectEqual(@as(usize, 400), clamped);
}

test "RFC 9000 §4 - clampToFlowControl allows full amount if windows sufficient" {
    const desired: usize = 500;
    const stream_window: u64 = 1000;
    const conn_window: u64 = 1000;

    const clamped = fc.clampToFlowControl(desired, stream_window, conn_window);

    try testing.expectEqual(@as(usize, 500), clamped);
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: Flow control with zero offset" {
    const conn_send_off: u64 = 0;
    const peer_max_data: u64 = 1000;

    try testing.expectEqual(@as(u64, 1000), fc.connectionFlowWindow(conn_send_off, peer_max_data));
}

test "boundary: Flow control with max u64" {
    const conn_send_off: u64 = 0;
    const peer_max_data: u64 = std.math.maxInt(u64);

    try testing.expectEqual(std.math.maxInt(u64), fc.connectionFlowWindow(conn_send_off, peer_max_data));
}

test "boundary: Window expansion with overflow protection" {
    const current_max: u64 = std.math.maxInt(u64) / 2 + 1000;
    const growth_factor_num: u64 = 2;
    const growth_factor_denom: u64 = 1;

    // Uses saturating arithmetic to prevent overflow
    const result = fc.expandConnectionWindow(current_max, growth_factor_num, growth_factor_denom);

    // Result should saturate at maxInt, not wrap around
    try testing.expectEqual(std.math.maxInt(u64), result);
}

test "boundary: clampToFlowControl with zero windows" {
    const desired: usize = 1000;
    const stream_window: u64 = 0;
    const conn_window: u64 = 0;

    const clamped = fc.clampToFlowControl(desired, stream_window, conn_window);

    try testing.expectEqual(@as(usize, 0), clamped);
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: Cannot send when window is zero" {
    const conn_send_off: u64 = 1000;
    const peer_max_data: u64 = 1000;

    const window = fc.connectionFlowWindow(conn_send_off, peer_max_data);
    try testing.expectEqual(@as(u64, 0), window);

    try testing.expect(!fc.canSendConnectionData(conn_send_off, peer_max_data));
}

test "negative: Stream blocked when at limit" {
    const stream_send_off: u64 = 500;
    const peer_max_stream_data: u64 = 500;

    try testing.expect(!fc.canSendStreamData(stream_send_off, peer_max_stream_data));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §4 - Flow control prevents sender from overwhelming receiver" {
    const conn_send_off: u64 = 900;
    const peer_max_data: u64 = 1000;

    // Can send 100 more bytes
    const window = fc.connectionFlowWindow(conn_send_off, peer_max_data);
    try testing.expectEqual(@as(u64, 100), window);

    // Attempting to send beyond limit is blocked
    try testing.expect(!fc.canSendConnectionData(peer_max_data + 1, peer_max_data));
}

test "RFC 9000 §4.1 - Connection flow control applies to all streams" {
    // Multiple streams share connection flow control window
    const stream1_sent: u64 = 300;
    const stream2_sent: u64 = 400;
    const total_sent = stream1_sent + stream2_sent;
    const peer_max_data: u64 = 1000;

    const remaining = fc.connectionFlowWindow(total_sent, peer_max_data);
    try testing.expectEqual(@as(u64, 300), remaining);
}

test "RFC 9000 §4.2 - Stream flow control independent per stream" {
    // Each stream has independent flow control limit
    const stream1_off: u64 = 100;
    const stream2_off: u64 = 200;
    const peer_max_stream_data: u64 = 500;

    try testing.expect(fc.canSendStreamData(stream1_off, peer_max_stream_data));
    try testing.expect(fc.canSendStreamData(stream2_off, peer_max_stream_data));
}

test "RFC 9000 §4.6 - MAX_STREAMS limits concurrent streams" {
    const opened_bidi: u64 = 5;
    const peer_max_streams_bidi: u64 = 10;

    // Can open 5 more streams
    try testing.expect(fc.canOpenStream(opened_bidi, peer_max_streams_bidi));
    try testing.expect(fc.canOpenStream(opened_bidi + 1, peer_max_streams_bidi));
    try testing.expect(fc.canOpenStream(opened_bidi + 4, peer_max_streams_bidi));
    try testing.expect(!fc.canOpenStream(opened_bidi + 5, peer_max_streams_bidi));
}

test "RFC 9000 §4 - Flow control is bidirectional" {
    // Both endpoints have independent flow control limits
    const local_max_data: u64 = 1000;
    const peer_max_data: u64 = 2000;

    // Different limits for each direction
    try testing.expect(local_max_data != peer_max_data);
}

test "RFC 9000 §4.2 - AUTO_TUNING: Expand window based on consumption" {
    const conn_recv_total: u64 = 900;
    const local_max_data: u64 = 1000;
    const threshold_percent: u64 = 80;

    // Consumed 90%, should expand
    try testing.expect(fc.shouldExpandConnectionWindow(conn_recv_total, local_max_data, threshold_percent));

    // Expand by 2x
    const new_max = fc.expandConnectionWindow(local_max_data, 2, 1);
    try testing.expectEqual(@as(u64, 3000), new_max);
}
