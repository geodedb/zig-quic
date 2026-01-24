//! Unit tests for transport_params.zig - RFC 9000 §7.4, §18.2
//!
//! RFC References:
//! - RFC 9000 §7.4: Cryptographic and Transport Handshake
//! - RFC 9000 §18.2: Transport Parameter Definitions
//!
//! Coverage:
//! - Positive cases: Encode/decode roundtrip, validation success, default values
//! - Negative cases: Missing required parameters, out-of-range values
//! - Edge cases: Boundary values, Retry scenarios
//! - RFC compliance: Required parameter checks, limit enforcement

const std = @import("std");
const tp = @import("quic_transport_params");

fn hex(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 1 < s.len and j < N) : ({
        i += 2;
        j += 1;
    }) {
        const hi = std.fmt.charToDigit(s[i], 16) catch 0;
        const lo = std.fmt.charToDigit(s[i + 1], 16) catch 0;
        out[j] = @as(u8, @intCast(hi * 16 + lo));
    }
    return out;
}

// =============================================================================
// Encoding/Decoding Tests
// =============================================================================

test "RFC 9000 §18.2 - transport parameters encode/decode roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var vals: tp.TransportParams = .{
        .max_idle_timeout = 30000,
        .initial_max_data = 65536,
        .initial_max_stream_data_bidi_local = 8192,
        .initial_max_stream_data_bidi_remote = 4096,
        .initial_max_stream_data_uni = 2048,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
        .disable_active_migration = true,
        .active_connection_id_limit = 8,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .max_udp_payload_size = 1450,
        .stateless_reset_token = .{0x11} ** 16,
    };
    const iscid_arr = hex(8, "0011223344556677");
    const rscid_arr = hex(8, "8899aabbccddeeff");
    const iscid = try alloc.dupe(u8, &iscid_arr);
    const rscid = try alloc.dupe(u8, &rscid_arr);
    vals.initial_source_connection_id = iscid;
    vals.retry_source_connection_id = rscid;
    // Preferred address raw minimal dummy fulfilling size constraints
    // Layout: IPv4(4) + port(2) + IPv6(16) + port(2) + CID len(1) + CID(0) + stateless reset token(16) = 41 bytes
    var pref_buf: [41]u8 = undefined;
    @memset(pref_buf[0..], 0);
    const pref = try alloc.dupe(u8, &pref_buf);
    vals.preferred_address_raw = pref;

    const enc = try vals.encode(alloc);
    defer alloc.free(enc);

    const dec = try tp.TransportParams.decode(alloc, enc);
    defer {
        var d = dec;
        d.deinit(alloc);
    }
    // Free owned allocations created for encode inputs
    alloc.free(iscid);
    alloc.free(rscid);
    if (vals.preferred_address_raw) |p| alloc.free(p);

    try std.testing.expect(dec.max_idle_timeout.? == 30000);
    try std.testing.expect(dec.initial_max_data.? == 65536);
    try std.testing.expect(dec.initial_max_stream_data_bidi_local.? == 8192);
    try std.testing.expect(dec.initial_max_stream_data_bidi_remote.? == 4096);
    try std.testing.expect(dec.initial_max_stream_data_uni.? == 2048);
    try std.testing.expect(dec.initial_max_streams_bidi.? == 8);
    try std.testing.expect(dec.initial_max_streams_uni.? == 4);
    try std.testing.expect(dec.disable_active_migration == true);
    try std.testing.expect(dec.active_connection_id_limit.? == 8);
    try std.testing.expect(dec.ack_delay_exponent.? == 3);
    try std.testing.expect(dec.max_ack_delay.? == 25);
    try std.testing.expect(dec.max_udp_payload_size.? == 1450);
    try std.testing.expect(dec.stateless_reset_token.?[0] == 0x11);
    if (dec.initial_source_connection_id) |cid| try std.testing.expectEqual(@as(usize, 8), cid.len) else return error.Missing;
    if (dec.retry_source_connection_id) |cid| try std.testing.expectEqual(@as(usize, 8), cid.len) else return error.Missing;
    if (dec.preferred_address_raw) |p| try std.testing.expectEqual(@as(usize, 41), p.len) else return error.Missing;
}

// =============================================================================
// Validation Tests - Required Parameters
// =============================================================================

test "RFC 9000 §7.4 - server validate requires initial_source_connection_id" {
    const params: tp.TransportParams = .{
        .stateless_reset_token = .{0x42} ** 16,
        // Missing initial_source_connection_id
    };

    const result = params.validate(true, false);
    try std.testing.expectError(error.MissingRequiredParameter, result);
}

test "RFC 9000 §7.4 - server validate requires stateless_reset_token" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const iscid = try alloc.dupe(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    defer alloc.free(iscid);

    const params: tp.TransportParams = .{
        .initial_source_connection_id = iscid,
        // Missing stateless_reset_token
    };

    const result = params.validate(true, false);
    try std.testing.expectError(error.MissingRequiredParameter, result);
}

test "RFC 9000 §7.4.1 - server with Retry requires retry_source_connection_id" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const iscid = try alloc.dupe(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    defer alloc.free(iscid);

    const params: tp.TransportParams = .{
        .initial_source_connection_id = iscid,
        .stateless_reset_token = .{0x42} ** 16,
        // Missing retry_source_connection_id when retry_sent = true
    };

    const result = params.validate(true, true);
    try std.testing.expectError(error.MissingRequiredParameter, result);
}

test "RFC 9000 §7.4 - server validate success with all required parameters" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const iscid = try alloc.dupe(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    defer alloc.free(iscid);

    const params: tp.TransportParams = .{
        .initial_source_connection_id = iscid,
        .stateless_reset_token = .{0x42} ** 16,
    };

    try params.validate(true, false);
}

test "RFC 9000 §7.4 - server validate success with Retry parameters" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const iscid = try alloc.dupe(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    defer alloc.free(iscid);
    const rscid = try alloc.dupe(u8, &[_]u8{ 0x05, 0x06, 0x07, 0x08 });
    defer alloc.free(rscid);

    const params: tp.TransportParams = .{
        .initial_source_connection_id = iscid,
        .retry_source_connection_id = rscid,
        .stateless_reset_token = .{0x42} ** 16,
    };

    try params.validate(true, true);
}

test "RFC 9000 §7.4 - client validate has no required parameters" {
    const params: tp.TransportParams = .{};

    // Clients don't have required parameters
    try params.validate(false, false);
}

// =============================================================================
// Validation Tests - Parameter Limits
// =============================================================================

test "RFC 9000 §18.2 - max_udp_payload_size minimum 1200" {
    const params: tp.TransportParams = .{
        .max_udp_payload_size = 1199, // Below minimum
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §18.2 - max_udp_payload_size at minimum boundary (1200)" {
    const params: tp.TransportParams = .{
        .max_udp_payload_size = 1200, // Exactly at minimum
    };

    try params.checkLimits();
}

test "RFC 9000 §18.2 - ack_delay_exponent maximum 20" {
    const params: tp.TransportParams = .{
        .ack_delay_exponent = 21, // Above maximum
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §18.2 - ack_delay_exponent at maximum boundary (20)" {
    const params: tp.TransportParams = .{
        .ack_delay_exponent = 20, // Exactly at maximum
    };

    try params.checkLimits();
}

test "RFC 9000 §18.2 - max_ack_delay maximum 16383" {
    const params: tp.TransportParams = .{
        .max_ack_delay = 16384, // At 2^14, exceeds max
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §18.2 - max_ack_delay at maximum boundary (16383)" {
    const params: tp.TransportParams = .{
        .max_ack_delay = 16383, // Just below 2^14
    };

    try params.checkLimits();
}

test "RFC 9000 §18.2 - active_connection_id_limit minimum 2" {
    const params: tp.TransportParams = .{
        .active_connection_id_limit = 1, // Below minimum
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §18.2 - active_connection_id_limit at minimum boundary (2)" {
    const params: tp.TransportParams = .{
        .active_connection_id_limit = 2, // Exactly at minimum
    };

    try params.checkLimits();
}

test "RFC 9000 §4.6 - initial_max_streams_bidi maximum 2^60" {
    const params: tp.TransportParams = .{
        .initial_max_streams_bidi = (1 << 60) + 1, // Exceeds 2^60
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §4.6 - initial_max_streams_bidi at maximum boundary (2^60)" {
    const params: tp.TransportParams = .{
        .initial_max_streams_bidi = 1 << 60, // Exactly at 2^60
    };

    try params.checkLimits();
}

test "RFC 9000 §4.6 - initial_max_streams_uni maximum 2^60" {
    const params: tp.TransportParams = .{
        .initial_max_streams_uni = (1 << 60) + 1, // Exceeds 2^60
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §4.1 - initial_max_data maximum 2^62-1" {
    const params: tp.TransportParams = .{
        .initial_max_data = (1 << 62), // Exceeds 2^62-1
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §4.1 - initial_max_stream_data_bidi_local maximum 2^62-1" {
    const params: tp.TransportParams = .{
        .initial_max_stream_data_bidi_local = (1 << 62), // Exceeds 2^62-1
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §4.1 - initial_max_stream_data_bidi_remote maximum 2^62-1" {
    const params: tp.TransportParams = .{
        .initial_max_stream_data_bidi_remote = (1 << 62), // Exceeds 2^62-1
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §4.1 - initial_max_stream_data_uni maximum 2^62-1" {
    const params: tp.TransportParams = .{
        .initial_max_stream_data_uni = (1 << 62), // Exceeds 2^62-1
    };

    const result = params.checkLimits();
    try std.testing.expectError(error.InvalidTransportParams, result);
}

test "RFC 9000 §18.2 - checkLimits success with valid parameters" {
    const params: tp.TransportParams = .{
        .max_udp_payload_size = 1450,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .active_connection_id_limit = 8,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .initial_max_data = 65536,
        .initial_max_stream_data_bidi_local = 8192,
        .initial_max_stream_data_bidi_remote = 8192,
        .initial_max_stream_data_uni = 8192,
    };

    try params.checkLimits();
}

// =============================================================================
// Default Value Tests
// =============================================================================

test "RFC 9000 §18.2 - getMaxUdpPayloadSize default is 65527" {
    const params: tp.TransportParams = .{};

    const value = params.getMaxUdpPayloadSize();
    try std.testing.expectEqual(@as(u64, 65527), value);
}

test "RFC 9000 §18.2 - getMaxUdpPayloadSize returns set value" {
    const params: tp.TransportParams = .{
        .max_udp_payload_size = 1450,
    };

    const value = params.getMaxUdpPayloadSize();
    try std.testing.expectEqual(@as(u64, 1450), value);
}

test "RFC 9000 §18.2 - getAckDelayExponent default is 3" {
    const params: tp.TransportParams = .{};

    const value = params.getAckDelayExponent();
    try std.testing.expectEqual(@as(u64, 3), value);
}

test "RFC 9000 §18.2 - getAckDelayExponent returns set value" {
    const params: tp.TransportParams = .{
        .ack_delay_exponent = 10,
    };

    const value = params.getAckDelayExponent();
    try std.testing.expectEqual(@as(u64, 10), value);
}

test "RFC 9000 §18.2 - getMaxAckDelay default is 25" {
    const params: tp.TransportParams = .{};

    const value = params.getMaxAckDelay();
    try std.testing.expectEqual(@as(u64, 25), value);
}

test "RFC 9000 §18.2 - getMaxAckDelay returns set value" {
    const params: tp.TransportParams = .{
        .max_ack_delay = 100,
    };

    const value = params.getMaxAckDelay();
    try std.testing.expectEqual(@as(u64, 100), value);
}

test "RFC 9000 §18.2 - getActiveConnectionIdLimit default is 2" {
    const params: tp.TransportParams = .{};

    const value = params.getActiveConnectionIdLimit();
    try std.testing.expectEqual(@as(u64, 2), value);
}

test "RFC 9000 §18.2 - getActiveConnectionIdLimit returns set value" {
    const params: tp.TransportParams = .{
        .active_connection_id_limit = 10,
    };

    const value = params.getActiveConnectionIdLimit();
    try std.testing.expectEqual(@as(u64, 10), value);
}
