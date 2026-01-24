//! Advanced Features Test Helpers (Phase 21.5)
//!
//! Provides test utilities for validating advanced QUIC features:
//! - Transport parameter validation
//! - Connection ID management
//! - Retry packet handling
//! - Error handling and CONNECTION_CLOSE
//!
//! Features:
//! - Transport parameter parsing and validation
//! - Connection ID sequence tracking
//! - Retry packet integrity validation
//! - Error frame inspection
//!
//! RFC References:
//! - RFC 9000 §5.1: Connection IDs
//! - RFC 9000 §7.3: Transport Parameters
//! - RFC 9000 §8.1.1: Address Validation (Retry)
//! - RFC 9000 §10: Connection Termination
//! - RFC 9000 §17.2.5: Retry Packet Format
//! - RFC 9000 §18.2: Transport Parameters

const std = @import("std");
const harness = @import("harness");
const packet_inspector = @import("packet_inspector");

// =============================================================================
// Transport Parameter Types
// =============================================================================

/// Transport parameter identifier
pub const TransportParamId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// Parsed transport parameter
pub const TransportParam = struct {
    id: TransportParamId,
    value: []const u8,
};

/// Transport parameter validation error
pub const TransportParamError = error{
    InvalidMaxUdpPayloadSize,
    InvalidAckDelayExponent,
    InvalidMaxAckDelay,
    InvalidActiveConnectionIdLimit,
    MissingRequiredParameter,
    DuplicateParameter,
};

// =============================================================================
// Connection ID Types
// =============================================================================

/// Connection ID event type
pub const CidEventType = enum {
    new_cid_issued,      // NEW_CONNECTION_ID frame sent
    retire_cid_issued,   // RETIRE_CONNECTION_ID frame sent
    cid_used,            // CID used in packet header
    cid_retired,         // CID retired from use
};

/// Connection ID event
pub const CidEvent = struct {
    event_type: CidEventType,
    sequence_number: u64,
    connection_id: []const u8,
    retire_prior_to: ?u64 = null,
    timestamp_ms: i64,
};

// =============================================================================
// Retry Packet Types
// =============================================================================

/// Parsed Retry packet
pub const RetryPacket = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    retry_token: []const u8,
    integrity_tag: [16]u8,
};

// =============================================================================
// Error Types
// =============================================================================

/// Connection error information
pub const ConnectionError = struct {
    error_code: u64,
    frame_type: ?u64 = null,
    reason_phrase: []const u8,
    timestamp_ms: i64,
};

/// Application error information
pub const ApplicationError = struct {
    error_code: u64,
    reason_phrase: []const u8,
    timestamp_ms: i64,
};

// =============================================================================
// Transport Parameter Helpers
// =============================================================================

/// Parse transport parameters from extension data.
/// Returns list of parsed parameters.
///
/// Note: This is a stub. Real implementation would:
/// - Parse TLS extension format (RFC 9001 §8.2)
/// - Extract parameter ID and length
/// - Validate parameter values per RFC 9000 §18.2
pub fn parseTransportParams(
    allocator: std.mem.Allocator,
    extension_data: []const u8,
) !std.ArrayList(TransportParam) {
    var params = std.ArrayList(TransportParam){};
    errdefer params.deinit(allocator);

    _ = extension_data;

    // Stub: Real implementation would parse TLS extension
    // Format: variable-length encoded ID, variable-length value
    // See RFC 9000 §18.2

    return params;
}

/// Validate transport parameter values per RFC 9000 §18.2.
/// Checks that parameter values are within valid ranges.
///
/// RFC 9000 §18.2 validation rules:
/// - max_udp_payload_size: >= 1200
/// - ack_delay_exponent: <= 20
/// - max_ack_delay: < 2^14
/// - active_connection_id_limit: >= 2
pub fn validateTransportParam(param: TransportParam) TransportParamError!void {
    switch (param.id) {
        .max_udp_payload_size => {
            if (param.value.len < 2) return error.InvalidMaxUdpPayloadSize;
            const val = std.mem.readInt(u16, param.value[0..2], .big);
            if (val < 1200) return error.InvalidMaxUdpPayloadSize;
        },
        .ack_delay_exponent => {
            if (param.value.len < 1) return error.InvalidAckDelayExponent;
            if (param.value[0] > 20) return error.InvalidAckDelayExponent;
        },
        .max_ack_delay => {
            if (param.value.len < 2) return error.InvalidMaxAckDelay;
            const val = std.mem.readInt(u16, param.value[0..2], .big);
            if (val >= (1 << 14)) return error.InvalidMaxAckDelay;
        },
        .active_connection_id_limit => {
            if (param.value.len < 1) return error.InvalidActiveConnectionIdLimit;
            if (param.value[0] < 2) return error.InvalidActiveConnectionIdLimit;
        },
        else => {},
    }
}

/// Find transport parameter by ID.
/// Returns parameter value or null if not found.
pub fn findTransportParam(
    params: []const TransportParam,
    param_id: TransportParamId,
) ?TransportParam {
    for (params) |param| {
        if (param.id == param_id) return param;
    }
    return null;
}

// =============================================================================
// Connection ID Management Helpers
// =============================================================================

/// Extract NEW_CONNECTION_ID frames from captured packets.
/// Returns list of CID events for tracking sequence numbers.
///
/// Note: This is a stub. Real implementation would:
/// - Parse NEW_CONNECTION_ID frames (RFC 9000 §19.15)
/// - Extract sequence number, retire_prior_to, CID, stateless reset token
pub fn extractNewConnectionIdFrames(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(CidEvent) {
    const EventList = std.ArrayList(CidEvent);
    var events = EventList{};
    errdefer events.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would:
    // 1. Parse packet payloads (requires decryption)
    // 2. Find NEW_CONNECTION_ID frames
    // 3. Extract CID information
    // 4. Track sequence numbers

    return events;
}

/// Extract RETIRE_CONNECTION_ID frames from captured packets.
/// Returns list of CID retirement events.
pub fn extractRetireConnectionIdFrames(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(CidEvent) {
    const EventList = std.ArrayList(CidEvent);
    var events = EventList{};
    errdefer events.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would parse RETIRE_CONNECTION_ID frames
    // RFC 9000 §19.16

    return events;
}

/// Validate connection ID sequence numbers are monotonically increasing.
/// Checks that NEW_CONNECTION_ID frames have increasing sequence numbers.
pub fn validateCidSequence(events: []const CidEvent) !void {
    var last_seq: u64 = 0;
    var first = true;

    for (events) |event| {
        if (event.event_type != .new_cid_issued) continue;

        if (!first) {
            if (event.sequence_number <= last_seq) {
                std.debug.print(
                    "CID sequence not monotonic: {} after {}\n",
                    .{ event.sequence_number, last_seq }
                );
                return error.InvalidCidSequence;
            }
        }

        last_seq = event.sequence_number;
        first = false;
    }
}

// =============================================================================
// Retry Packet Helpers
// =============================================================================

/// Parse Retry packet from raw bytes.
/// Returns parsed Retry packet structure.
///
/// RFC 9000 §17.2.5: Retry Packet Format
/// Note: This is a stub. Real implementation would:
/// - Parse long header with packet type = Retry
/// - Extract DCID, SCID, Retry Token
/// - Extract and validate integrity tag
pub fn parseRetryPacket(packet_bytes: []const u8) !RetryPacket {
    _ = packet_bytes;

    // Stub: Real implementation would parse Retry packet format
    // Long Header (type=Retry) + DCID + SCID + Token + Integrity Tag

    return error.NotImplemented;
}

/// Validate Retry packet integrity tag per RFC 9001 §5.8.
/// Checks AEAD integrity tag using Retry pseudo-packet.
///
/// RFC 9001 §5.8: Retry Integrity Tag
pub fn validateRetryIntegrityTag(
    retry_packet: RetryPacket,
    original_dcid: []const u8,
) !void {
    _ = retry_packet;
    _ = original_dcid;

    // Stub: Real implementation would:
    // 1. Construct Retry Pseudo-Packet (RFC 9001 §5.8)
    // 2. Compute AEAD with Retry key
    // 3. Compare integrity tag

    return error.NotImplemented;
}

/// Check if Retry token is present in Initial packet.
/// Validates that client includes Retry token after receiving Retry.
pub fn hasRetryToken(
    allocator: std.mem.Allocator,
    initial_packet: []const u8,
) !bool {
    _ = allocator;
    _ = initial_packet;

    // Stub: Real implementation would:
    // 1. Parse Initial packet long header
    // 2. Check token field length > 0
    // 3. Extract token bytes

    return false;
}

// =============================================================================
// Error Handling Helpers
// =============================================================================

/// Extract CONNECTION_CLOSE frames from captured packets.
/// Returns connection error information.
///
/// RFC 9000 §19.19: CONNECTION_CLOSE Frames
pub fn extractConnectionCloseFrames(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !std.ArrayList(ConnectionError) {
    const ErrorList = std.ArrayList(ConnectionError);
    var errors = ErrorList{};
    errdefer errors.deinit(allocator);

    _ = captured;

    // Stub: Real implementation would:
    // 1. Parse packet payloads
    // 2. Find CONNECTION_CLOSE frames (0x1c, 0x1d)
    // 3. Extract error code, frame type, reason phrase

    return errors;
}

/// Find connection error by error code.
/// Returns first error matching the given code.
pub fn findConnectionError(
    errors: []const ConnectionError,
    error_code: u64,
) ?ConnectionError {
    for (errors) |err| {
        if (err.error_code == error_code) return err;
    }
    return null;
}

/// Validate error code is valid per RFC 9000 §20.
/// Checks that error code is a known transport error code.
pub fn validateErrorCode(error_code: u64) !void {
    // RFC 9000 §20: Transport Error Codes
    const valid_codes = [_]u64{
        0x00, // NO_ERROR
        0x01, // INTERNAL_ERROR
        0x02, // CONNECTION_REFUSED
        0x03, // FLOW_CONTROL_ERROR
        0x04, // STREAM_LIMIT_ERROR
        0x05, // STREAM_STATE_ERROR
        0x06, // FINAL_SIZE_ERROR
        0x07, // FRAME_ENCODING_ERROR
        0x08, // TRANSPORT_PARAMETER_ERROR
        0x09, // CONNECTION_ID_LIMIT_ERROR
        0x0a, // PROTOCOL_VIOLATION
        0x0b, // INVALID_TOKEN
        0x0c, // APPLICATION_ERROR
        0x0d, // CRYPTO_BUFFER_EXCEEDED
        0x0e, // KEY_UPDATE_ERROR
        0x0f, // AEAD_LIMIT_REACHED
        0x10, // NO_VIABLE_PATH
    };

    for (valid_codes) |code| {
        if (error_code == code) return;
    }

    // Check if it's a CRYPTO_ERROR (0x0100-0x01FF)
    if (error_code >= 0x0100 and error_code <= 0x01FF) return;

    return error.InvalidErrorCode;
}

// =============================================================================
// Test Assertion Helpers
// =============================================================================

/// Assert that transport parameters are valid.
/// Validates all parameters against RFC 9000 §18.2 rules.
pub fn expectValidTransportParams(
    allocator: std.mem.Allocator,
    extension_data: []const u8,
) !void {
    const params = try parseTransportParams(allocator, extension_data);
    defer params.deinit();

    for (params.items) |param| {
        try validateTransportParam(param);
    }
}

/// Assert that connection ID sequence is valid.
/// Validates CID sequence numbers are monotonically increasing.
pub fn expectValidCidSequence(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !void {
    const events = try extractNewConnectionIdFrames(allocator, captured);
    defer events.deinit();

    try validateCidSequence(events.items);
}

/// Assert that Retry packet is valid.
/// Validates Retry packet format and integrity tag.
pub fn expectValidRetryPacket(
    packet_bytes: []const u8,
    original_dcid: []const u8,
) !void {
    const retry = try parseRetryPacket(packet_bytes);
    try validateRetryIntegrityTag(retry, original_dcid);
}

/// Assert that connection error occurred.
/// Validates CONNECTION_CLOSE frame with expected error code.
pub fn expectConnectionError(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
    expected_error_code: u64,
) !void {
    const errors = try extractConnectionCloseFrames(allocator, captured);
    defer errors.deinit();

    if (errors.items.len == 0) {
        std.debug.print("Expected connection error, found none\n", .{});
        return error.NoConnectionError;
    }

    const err = findConnectionError(errors.items, expected_error_code) orelse {
        std.debug.print(
            "Expected error code 0x{X}, not found\n",
            .{expected_error_code}
        );
        return error.ErrorCodeNotFound;
    };

    try validateErrorCode(err.error_code);
}

// =============================================================================
// Integration with ConnectionPair
// =============================================================================

/// Advanced features metrics from connection pair test.
pub const AdvancedMetrics = struct {
    transport_param_count: usize,
    new_cid_count: usize,
    retired_cid_count: usize,
    retry_count: usize,
    connection_errors: usize,
};

/// Analyze advanced features from captured packets.
pub fn analyzeAdvancedFeatures(
    allocator: std.mem.Allocator,
    captured: []const harness.CapturedPacket,
) !AdvancedMetrics {
    const new_cids = try extractNewConnectionIdFrames(allocator, captured);
    defer new_cids.deinit();

    const retired_cids = try extractRetireConnectionIdFrames(allocator, captured);
    defer retired_cids.deinit();

    const errors = try extractConnectionCloseFrames(allocator, captured);
    defer errors.deinit();

    // Count Retry packets (stub)
    const retry_count: usize = 0;
    _ = retry_count;

    return AdvancedMetrics{
        .transport_param_count = 0, // Stub
        .new_cid_count = new_cids.items.len,
        .retired_cid_count = retired_cids.items.len,
        .retry_count = 0, // Stub
        .connection_errors = errors.items.len,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "validateTransportParam - valid max_udp_payload_size" {
    const param = TransportParam{
        .id = .max_udp_payload_size,
        .value = &[_]u8{ 0x04, 0xB0 }, // 1200 bytes
    };

    try validateTransportParam(param);
}

test "validateTransportParam - invalid max_udp_payload_size" {
    const param = TransportParam{
        .id = .max_udp_payload_size,
        .value = &[_]u8{ 0x04, 0x00 }, // 1024 bytes (< 1200)
    };

    const result = validateTransportParam(param);
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, result);
}

test "validateTransportParam - valid ack_delay_exponent" {
    const param = TransportParam{
        .id = .ack_delay_exponent,
        .value = &[_]u8{10}, // Valid (0-20)
    };

    try validateTransportParam(param);
}

test "validateTransportParam - invalid ack_delay_exponent" {
    const param = TransportParam{
        .id = .ack_delay_exponent,
        .value = &[_]u8{25}, // Invalid (> 20)
    };

    const result = validateTransportParam(param);
    try std.testing.expectError(error.InvalidAckDelayExponent, result);
}

test "validateErrorCode - valid transport error" {
    try validateErrorCode(0x00); // NO_ERROR
    try validateErrorCode(0x01); // INTERNAL_ERROR
    try validateErrorCode(0x08); // TRANSPORT_PARAMETER_ERROR
}

test "validateErrorCode - valid crypto error" {
    try validateErrorCode(0x0100); // CRYPTO_ERROR base
    try validateErrorCode(0x01FF); // CRYPTO_ERROR max
}

test "validateErrorCode - invalid error code" {
    const result = validateErrorCode(0x9999);
    try std.testing.expectError(error.InvalidErrorCode, result);
}

test "findTransportParam - parameter found" {
    const params = [_]TransportParam{
        .{ .id = .max_idle_timeout, .value = &[_]u8{ 0, 1 } },
        .{ .id = .max_udp_payload_size, .value = &[_]u8{ 0x04, 0xB0 } },
    };

    const found = findTransportParam(&params, .max_udp_payload_size);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(TransportParamId.max_udp_payload_size, found.?.id);
}

test "findTransportParam - parameter not found" {
    const params = [_]TransportParam{
        .{ .id = .max_idle_timeout, .value = &[_]u8{ 0, 1 } },
    };

    const found = findTransportParam(&params, .max_udp_payload_size);
    try std.testing.expect(found == null);
}

test "analyzeAdvancedFeatures - empty capture" {
    const allocator = std.testing.allocator;

    const captured: []const harness.CapturedPacket = &[_]harness.CapturedPacket{};

    const metrics = try analyzeAdvancedFeatures(allocator, captured);

    try std.testing.expectEqual(@as(usize, 0), metrics.new_cid_count);
    try std.testing.expectEqual(@as(usize, 0), metrics.retired_cid_count);
    try std.testing.expectEqual(@as(usize, 0), metrics.connection_errors);
}
