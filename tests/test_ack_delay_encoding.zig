const std = @import("std");
const quic = @import("../quic.zig");

// RFC 9000 §13.2 defines ACK delay encoding using ack_delay_exponent with a cap
// at max_ack_delay. Exercise the helper that computes the encoded value.
// Test that ack_delay is encoded using ack_delay_exponent and capped by max_ack_delay.
// Strategy: create a connection, manually set last_ack_eliciting_rx_* timestamps in past, call getAckDelayEncoded.
// We bypass full endpoint by instantiating Connection directly.

pub fn main() !void {}

test "ack_delay_encoding_basic_and_cap" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    // Use ipv4 helper for dummy peer
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Client, 0, peer);

    // Simulate applied transport params: ack_delay_exponent=3, max_ack_delay=25ms default
    conn.ack_delay_exponent = 3; // default already
    conn.max_ack_delay_ms = 25; // default already

    // Set last ack eliciting reception 8ms ago in Application space.
    const now_ns = std.time.nanoTimestamp();
    const eight_ms_ns: u64 = 8 * std.time.ns_per_ms;
    conn.last_ack_eliciting_rx_app_ns = now_ns - eight_ms_ns;
    const enc = conn.getAckDelayEncoded(.Application, now_ns);
    // Raw delay_us = 8000; shift by exponent 3 => 1000
    try std.testing.expect(enc == 1000);

    // Now exceed max_ack_delay: 100ms ago, but cap is 25ms, so delay_us=25000, >>3 = 3125
    const hundred_ms_ns: u64 = 100 * std.time.ns_per_ms;
    conn.last_ack_eliciting_rx_app_ns = now_ns - hundred_ms_ns;
    const enc2 = conn.getAckDelayEncoded(.Application, now_ns);
    try std.testing.expect(enc2 == 3125);
}
