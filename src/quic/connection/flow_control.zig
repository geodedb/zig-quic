// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Flow control helpers for connection and stream-level limits.
//!
//! RFC 9000 §4: Flow Control

const std = @import("std");

/// Check if connection-level flow control allows sending more data.
/// RFC 9000 §4.1: Connection Flow Control
pub fn canSendConnectionData(conn_send_off: u64, peer_max_data: u64) bool {
    return conn_send_off < peer_max_data;
}

/// Check if stream-level flow control allows sending more data.
/// RFC 9000 §4.2: Stream Flow Control
pub fn canSendStreamData(stream_send_off: u64, peer_max_stream_data: u64) bool {
    return stream_send_off < peer_max_stream_data;
}

/// Compute available window for connection-level flow control.
/// RFC 9000 §4.1: Connection Flow Control
pub fn connectionFlowWindow(conn_send_off: u64, peer_max_data: u64) u64 {
    if (conn_send_off >= peer_max_data) return 0;
    return peer_max_data - conn_send_off;
}

/// Compute available window for stream-level flow control.
/// RFC 9000 §4.2: Stream Flow Control
pub fn streamFlowWindow(stream_send_off: u64, peer_max_stream_data: u64) u64 {
    if (stream_send_off >= peer_max_stream_data) return 0;
    return peer_max_stream_data - stream_send_off;
}

/// Check if stream count is within limits.
/// RFC 9000 §4.6: Controlling Concurrency
pub fn canOpenStream(opened: u64, peer_max_streams: u64) bool {
    return opened < peer_max_streams;
}

/// Check if local receive window should be expanded based on consumption.
/// RFC 9000 §4.1: Data Flow Control
/// Returns true if the window should be expanded.
pub fn shouldExpandConnectionWindow(conn_recv_total: u64, local_max_data: u64, threshold_percent: u64) bool {
    const threshold = (local_max_data * threshold_percent) / 100;
    return conn_recv_total >= threshold;
}

/// Check if stream receive window should be expanded based on consumption.
/// RFC 9000 §4.2: Stream Flow Control
/// Returns true if the window should be expanded.
pub fn shouldExpandStreamWindow(stream_recv_off: u64, local_max_stream_data: u64, threshold_percent: u64) bool {
    const threshold = (local_max_stream_data * threshold_percent) / 100;
    return stream_recv_off >= threshold;
}

/// Compute new connection flow control limit with adaptive growth.
/// RFC 9000 §4.1: Connection Flow Control
pub fn expandConnectionWindow(current_max: u64, growth_factor_num: u64, growth_factor_denom: u64) u64 {
    // Saturating multiplication: if overflow, return maxInt
    const product, const overflowed = @mulWithOverflow(current_max, growth_factor_num);
    const growth = if (overflowed != 0) std.math.maxInt(u64) else product / growth_factor_denom;
    // Saturating addition
    const sum, const add_overflowed = @addWithOverflow(current_max, growth);
    return if (add_overflowed != 0) std.math.maxInt(u64) else sum;
}

/// Compute new stream flow control limit with adaptive growth.
/// RFC 9000 §4.2: Stream Flow Control
pub fn expandStreamWindow(current_max: u64, growth_factor_num: u64, growth_factor_denom: u64) u64 {
    // Saturating multiplication: if overflow, return maxInt
    const product, const overflowed = @mulWithOverflow(current_max, growth_factor_num);
    const growth = if (overflowed != 0) std.math.maxInt(u64) else product / growth_factor_denom;
    // Saturating addition
    const sum, const add_overflowed = @addWithOverflow(current_max, growth);
    return if (add_overflowed != 0) std.math.maxInt(u64) else sum;
}

/// Check if MAX_DATA frame should be sent (local limit increased since last sent).
pub fn shouldSendMaxData(local_max_data: u64, last_sent_max_data: u64) bool {
    return local_max_data > last_sent_max_data;
}

/// Check if MAX_STREAM_DATA frame should be sent.
pub fn shouldSendMaxStreamData(local_max_stream_data: u64, last_sent_max_stream_data: u64) bool {
    return local_max_stream_data > last_sent_max_stream_data;
}

/// Check if MAX_STREAMS_BIDI frame should be sent.
pub fn shouldSendMaxStreamsBidi(local_max_streams_bidi: u64, last_sent_max_streams_bidi: u64) bool {
    return local_max_streams_bidi > last_sent_max_streams_bidi;
}

/// Compute minimum of two flow control windows.
pub fn minWindow(window1: u64, window2: u64) u64 {
    return if (window1 < window2) window1 else window2;
}

/// Clamp send amount to available flow control windows.
/// RFC 9000 §4: Flow Control
pub fn clampToFlowControl(desired: usize, stream_window: u64, conn_window: u64) usize {
    const min_window = minWindow(stream_window, conn_window);
    if (desired > min_window) {
        return @intCast(min_window);
    }
    return desired;
}
