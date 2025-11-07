//! Unit tests for connection/error.zig
//!
//! RFC References:
//! - RFC 9000 §10: Connection Termination
//! - RFC 9000 §10.2: Connection Close and Draining States
//! - RFC 9000 §20: Error Codes
//! - RFC 9001 §4.8: TLS Errors (CRYPTO_ERROR)
//!
//! Coverage:
//! - Positive cases: Error code values, state transitions, timeout calculations
//! - Negative cases: Invalid states, expired timeouts
//! - Edge cases: Boundary error codes, state machine edges, zero PTO
//! - RFC compliance: All 17 transport errors, CRYPTO_ERROR mapping, draining timeout

const std = @import("std");
const testing = std.testing;

const error_mod = @import("error");

// =============================================================================
// ErrorCode Enum Tests
// =============================================================================

test "RFC 9000 §20 - ErrorCode NO_ERROR" {
    const code = error_mod.ErrorCode.NO_ERROR;

    try testing.expectEqual(@as(u64, 0x00), @intFromEnum(code));
    try testing.expectEqualStrings("NO_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode INTERNAL_ERROR" {
    const code = error_mod.ErrorCode.INTERNAL_ERROR;

    try testing.expectEqual(@as(u64, 0x01), @intFromEnum(code));
    try testing.expectEqualStrings("INTERNAL_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode CONNECTION_REFUSED" {
    const code = error_mod.ErrorCode.CONNECTION_REFUSED;

    try testing.expectEqual(@as(u64, 0x02), @intFromEnum(code));
    try testing.expectEqualStrings("CONNECTION_REFUSED", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode FLOW_CONTROL_ERROR" {
    const code = error_mod.ErrorCode.FLOW_CONTROL_ERROR;

    try testing.expectEqual(@as(u64, 0x03), @intFromEnum(code));
    try testing.expectEqualStrings("FLOW_CONTROL_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode STREAM_LIMIT_ERROR" {
    const code = error_mod.ErrorCode.STREAM_LIMIT_ERROR;

    try testing.expectEqual(@as(u64, 0x04), @intFromEnum(code));
    try testing.expectEqualStrings("STREAM_LIMIT_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode STREAM_STATE_ERROR" {
    const code = error_mod.ErrorCode.STREAM_STATE_ERROR;

    try testing.expectEqual(@as(u64, 0x05), @intFromEnum(code));
    try testing.expectEqualStrings("STREAM_STATE_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode FINAL_SIZE_ERROR" {
    const code = error_mod.ErrorCode.FINAL_SIZE_ERROR;

    try testing.expectEqual(@as(u64, 0x06), @intFromEnum(code));
    try testing.expectEqualStrings("FINAL_SIZE_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode FRAME_ENCODING_ERROR" {
    const code = error_mod.ErrorCode.FRAME_ENCODING_ERROR;

    try testing.expectEqual(@as(u64, 0x07), @intFromEnum(code));
    try testing.expectEqualStrings("FRAME_ENCODING_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode TRANSPORT_PARAMETER_ERROR" {
    const code = error_mod.ErrorCode.TRANSPORT_PARAMETER_ERROR;

    try testing.expectEqual(@as(u64, 0x08), @intFromEnum(code));
    try testing.expectEqualStrings("TRANSPORT_PARAMETER_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode CONNECTION_ID_LIMIT_ERROR" {
    const code = error_mod.ErrorCode.CONNECTION_ID_LIMIT_ERROR;

    try testing.expectEqual(@as(u64, 0x09), @intFromEnum(code));
    try testing.expectEqualStrings("CONNECTION_ID_LIMIT_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode PROTOCOL_VIOLATION" {
    const code = error_mod.ErrorCode.PROTOCOL_VIOLATION;

    try testing.expectEqual(@as(u64, 0x0A), @intFromEnum(code));
    try testing.expectEqualStrings("PROTOCOL_VIOLATION", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode INVALID_TOKEN" {
    const code = error_mod.ErrorCode.INVALID_TOKEN;

    try testing.expectEqual(@as(u64, 0x0B), @intFromEnum(code));
    try testing.expectEqualStrings("INVALID_TOKEN", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode APPLICATION_ERROR" {
    const code = error_mod.ErrorCode.APPLICATION_ERROR;

    try testing.expectEqual(@as(u64, 0x0C), @intFromEnum(code));
    try testing.expectEqualStrings("APPLICATION_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode CRYPTO_BUFFER_EXCEEDED" {
    const code = error_mod.ErrorCode.CRYPTO_BUFFER_EXCEEDED;

    try testing.expectEqual(@as(u64, 0x0D), @intFromEnum(code));
    try testing.expectEqualStrings("CRYPTO_BUFFER_EXCEEDED", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode KEY_UPDATE_ERROR" {
    const code = error_mod.ErrorCode.KEY_UPDATE_ERROR;

    try testing.expectEqual(@as(u64, 0x0E), @intFromEnum(code));
    try testing.expectEqualStrings("KEY_UPDATE_ERROR", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode AEAD_LIMIT_REACHED" {
    const code = error_mod.ErrorCode.AEAD_LIMIT_REACHED;

    try testing.expectEqual(@as(u64, 0x0F), @intFromEnum(code));
    try testing.expectEqualStrings("AEAD_LIMIT_REACHED", error_mod.errorCodeString(code));
}

test "RFC 9000 §20 - ErrorCode NO_VIABLE_PATH" {
    const code = error_mod.ErrorCode.NO_VIABLE_PATH;

    try testing.expectEqual(@as(u64, 0x10), @intFromEnum(code));
    try testing.expectEqualStrings("NO_VIABLE_PATH", error_mod.errorCodeString(code));
}

// =============================================================================
// CRYPTO_ERROR Tests
// =============================================================================

test "RFC 9001 §4.8 - cryptoError creates CRYPTO_ERROR from TLS alert" {
    const alert: u8 = 40; // handshake_failure
    const code = error_mod.ErrorCode.cryptoError(alert);

    try testing.expectEqual(@as(u64, 0x0100 + 40), @intFromEnum(code));
}

test "RFC 9001 §4.8 - cryptoError alert 0 maps to 0x0100" {
    const code = error_mod.ErrorCode.cryptoError(0);

    try testing.expectEqual(@as(u64, 0x0100), @intFromEnum(code));
}

test "RFC 9001 §4.8 - cryptoError alert 255 maps to 0x01FF" {
    const code = error_mod.ErrorCode.cryptoError(255);

    try testing.expectEqual(@as(u64, 0x01FF), @intFromEnum(code));
}

test "RFC 9001 §4.8 - isCryptoError detects CRYPTO_ERROR range" {
    const crypto_code = error_mod.ErrorCode.cryptoError(42);

    try testing.expect(error_mod.ErrorCode.isCryptoError(crypto_code));
}

test "RFC 9001 §4.8 - isCryptoError false for transport errors" {
    const transport_code = error_mod.ErrorCode.INTERNAL_ERROR;

    try testing.expect(!error_mod.ErrorCode.isCryptoError(transport_code));
}

test "RFC 9001 §4.8 - isCryptoError range boundaries" {
    const lower_bound = error_mod.ErrorCode.cryptoError(0); // 0x0100
    const upper_bound = error_mod.ErrorCode.cryptoError(255); // 0x01FF

    try testing.expect(error_mod.ErrorCode.isCryptoError(lower_bound));
    try testing.expect(error_mod.ErrorCode.isCryptoError(upper_bound));
}

test "RFC 9001 §4.8 - tlsAlert extracts TLS alert from CRYPTO_ERROR" {
    const alert: u8 = 112;
    const code = error_mod.ErrorCode.cryptoError(alert);

    const extracted = error_mod.ErrorCode.tlsAlert(code);
    try testing.expect(extracted != null);
    try testing.expectEqual(alert, extracted.?);
}

test "RFC 9001 §4.8 - tlsAlert returns null for transport errors" {
    const code = error_mod.ErrorCode.FLOW_CONTROL_ERROR;

    const result = error_mod.ErrorCode.tlsAlert(code);
    try testing.expect(result == null);
}

test "RFC 9001 §4.8 - CRYPTO_ERROR string representation" {
    const crypto_code = error_mod.ErrorCode.cryptoError(50);

    try testing.expectEqualStrings("CRYPTO_ERROR", error_mod.errorCodeString(crypto_code));
}

// =============================================================================
// CloseState Enum Tests
// =============================================================================

test "RFC 9000 §10.2 - CloseState enum values" {
    const active = error_mod.CloseState.active;
    const closing = error_mod.CloseState.closing;
    const draining = error_mod.CloseState.draining;
    const closed = error_mod.CloseState.closed;

    try testing.expectEqual(error_mod.CloseState.active, active);
    try testing.expectEqual(error_mod.CloseState.closing, closing);
    try testing.expectEqual(error_mod.CloseState.draining, draining);
    try testing.expectEqual(error_mod.CloseState.closed, closed);
}

// =============================================================================
// ErrorContext Initialization Tests
// =============================================================================

test "RFC 9000 §10 - ErrorContext init creates active state" {
    const ctx = error_mod.init();

    try testing.expectEqual(error_mod.CloseState.active, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.NO_ERROR, ctx.error_code);
    try testing.expectEqual(@as(u64, 0), ctx.frame_type);
    try testing.expectEqualStrings("", ctx.reason);
    try testing.expect(ctx.close_time_ns == null);
}

test "RFC 9000 §10 - ErrorContext default values" {
    const ctx: error_mod.ErrorContext = .{};

    try testing.expectEqual(error_mod.CloseState.active, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.NO_ERROR, ctx.error_code);
}

// =============================================================================
// State Transition Tests: enterClosing
// =============================================================================

test "RFC 9000 §10.2.1 - enterClosing from active state" {
    var ctx = error_mod.init();
    const now: u64 = 1000000;

    error_mod.enterClosing(&ctx, .INTERNAL_ERROR, 0x07, "test error", now);

    try testing.expectEqual(error_mod.CloseState.closing, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.INTERNAL_ERROR, ctx.error_code);
    try testing.expectEqual(@as(u64, 0x07), ctx.frame_type);
    try testing.expectEqualStrings("test error", ctx.reason);
    try testing.expect(ctx.close_time_ns != null);
    try testing.expectEqual(now, ctx.close_time_ns.?);
}

test "RFC 9000 §10.2.1 - enterClosing only transitions from active" {
    var ctx = error_mod.init();
    const now: u64 = 1000000;

    // Enter draining first
    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", now);

    // Try to enter closing - should not transition
    error_mod.enterClosing(&ctx, .INTERNAL_ERROR, 0, "", now + 1000);

    // Should still be draining
    try testing.expectEqual(error_mod.CloseState.draining, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.NO_ERROR, ctx.error_code);
}

test "RFC 9000 §10.2.1 - enterClosing stores error details" {
    var ctx = error_mod.init();

    error_mod.enterClosing(&ctx, .PROTOCOL_VIOLATION, 0x1C, "invalid frame", 2000000);

    try testing.expectEqual(error_mod.ErrorCode.PROTOCOL_VIOLATION, ctx.error_code);
    try testing.expectEqual(@as(u64, 0x1C), ctx.frame_type);
    try testing.expectEqualStrings("invalid frame", ctx.reason);
}

// =============================================================================
// State Transition Tests: enterDraining
// =============================================================================

test "RFC 9000 §10.2.2 - enterDraining from active state" {
    var ctx = error_mod.init();
    const now: u64 = 3000000;

    error_mod.enterDraining(&ctx, .APPLICATION_ERROR, 0, "peer closed", now);

    try testing.expectEqual(error_mod.CloseState.draining, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.APPLICATION_ERROR, ctx.error_code);
    try testing.expectEqualStrings("peer closed", ctx.reason);
    try testing.expectEqual(now, ctx.close_time_ns.?);
}

test "RFC 9000 §10.2.2 - enterDraining from closing state" {
    var ctx = error_mod.init();
    const close_time: u64 = 1000000;
    const drain_time: u64 = 1500000;

    // Enter closing
    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", close_time);

    // Then receive peer's close - enter draining
    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "peer response", drain_time);

    try testing.expectEqual(error_mod.CloseState.draining, ctx.state);
    // close_time_ns should be preserved from closing state
    try testing.expectEqual(close_time, ctx.close_time_ns.?);
}

test "RFC 9000 §10.2.2 - enterDraining preserves close_time from closing" {
    var ctx = error_mod.init();
    const initial_time: u64 = 1000000;

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", initial_time);
    const saved_time = ctx.close_time_ns.?;

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", initial_time + 5000);

    // close_time_ns should not change
    try testing.expectEqual(saved_time, ctx.close_time_ns.?);
}

test "RFC 9000 §10.2.2 - enterDraining sets close_time if null" {
    var ctx = error_mod.init();
    // Start from closing state without close_time
    ctx.state = .closing;
    ctx.close_time_ns = null;

    const now: u64 = 2000000;
    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", now);

    try testing.expect(ctx.close_time_ns != null);
    try testing.expectEqual(now, ctx.close_time_ns.?);
}

// =============================================================================
// State Transition Tests: enterClosed
// =============================================================================

test "RFC 9000 §10.2 - enterClosed marks connection closed" {
    var ctx = error_mod.init();

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);
    error_mod.enterClosed(&ctx);

    try testing.expectEqual(error_mod.CloseState.closed, ctx.state);
}

test "RFC 9000 §10.2 - enterClosed from any state" {
    var ctx1 = error_mod.init();
    var ctx2 = error_mod.init();
    var ctx3 = error_mod.init();

    // From active
    error_mod.enterClosed(&ctx1);
    try testing.expectEqual(error_mod.CloseState.closed, ctx1.state);

    // From closing
    error_mod.enterClosing(&ctx2, .NO_ERROR, 0, "", 1000000);
    error_mod.enterClosed(&ctx2);
    try testing.expectEqual(error_mod.CloseState.closed, ctx2.state);

    // From draining
    error_mod.enterDraining(&ctx3, .NO_ERROR, 0, "", 1000000);
    error_mod.enterClosed(&ctx3);
    try testing.expectEqual(error_mod.CloseState.closed, ctx3.state);
}

// =============================================================================
// State Transition Tests: immediateClose
// =============================================================================

test "RFC 9000 §10.2.3 - immediateClose bypasses closing/draining" {
    var ctx = error_mod.init();

    error_mod.immediateClose(&ctx, .INTERNAL_ERROR);

    try testing.expectEqual(error_mod.CloseState.closed, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.INTERNAL_ERROR, ctx.error_code);
}

test "RFC 9000 §10.2.3 - immediateClose from any state" {
    var ctx = error_mod.init();

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);
    error_mod.immediateClose(&ctx, .NO_VIABLE_PATH);

    try testing.expectEqual(error_mod.CloseState.closed, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.NO_VIABLE_PATH, ctx.error_code);
}

// =============================================================================
// State Query Tests
// =============================================================================

test "RFC 9000 §10.2 - isTerminating detects closing state" {
    var ctx = error_mod.init();

    try testing.expect(!error_mod.isTerminating(&ctx));

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);

    try testing.expect(error_mod.isTerminating(&ctx));
}

test "RFC 9000 §10.2 - isTerminating detects draining state" {
    var ctx = error_mod.init();

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", 1000000);

    try testing.expect(error_mod.isTerminating(&ctx));
}

test "RFC 9000 §10.2 - isTerminating false for active and closed" {
    var ctx1 = error_mod.init();
    var ctx2 = error_mod.init();

    // Active
    try testing.expect(!error_mod.isTerminating(&ctx1));

    // Closed
    error_mod.immediateClose(&ctx2, .NO_ERROR);
    try testing.expect(!error_mod.isTerminating(&ctx2));
}

test "RFC 9000 §10.2 - isClosed detects closed state" {
    var ctx = error_mod.init();

    try testing.expect(!error_mod.isClosed(&ctx));

    error_mod.immediateClose(&ctx, .NO_ERROR);

    try testing.expect(error_mod.isClosed(&ctx));
}

test "RFC 9000 §10.2.2 - canSend true for active and closing" {
    var ctx1 = error_mod.init();
    var ctx2 = error_mod.init();

    // Active
    try testing.expect(error_mod.canSend(&ctx1));

    // Closing
    error_mod.enterClosing(&ctx2, .NO_ERROR, 0, "", 1000000);
    try testing.expect(error_mod.canSend(&ctx2));
}

test "RFC 9000 §10.2.2 - canSend false for draining and closed" {
    var ctx1 = error_mod.init();
    var ctx2 = error_mod.init();

    // Draining
    error_mod.enterDraining(&ctx1, .NO_ERROR, 0, "", 1000000);
    try testing.expect(!error_mod.canSend(&ctx1));

    // Closed
    error_mod.immediateClose(&ctx2, .NO_ERROR);
    try testing.expect(!error_mod.canSend(&ctx2));
}

// =============================================================================
// Draining Timeout Tests
// =============================================================================

test "RFC 9000 §10.2 - drainingTimeoutNs is 3x PTO" {
    const pto_ns: u64 = 100_000_000; // 100ms

    const timeout = error_mod.drainingTimeoutNs(pto_ns);

    try testing.expectEqual(@as(u64, 300_000_000), timeout); // 300ms
}

test "RFC 9000 §10.2 - drainingTimeoutNs with various PTO values" {
    try testing.expectEqual(@as(u64, 3), error_mod.drainingTimeoutNs(1));
    try testing.expectEqual(@as(u64, 30), error_mod.drainingTimeoutNs(10));
    try testing.expectEqual(@as(u64, 3000), error_mod.drainingTimeoutNs(1000));
}

test "RFC 9000 §10.2.2 - isDrainingExpired false before timeout" {
    var ctx = error_mod.init();
    const close_time: u64 = 1_000_000_000;
    const pto_ns: u64 = 100_000_000;

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", close_time);

    // Check 1ms later (well before 300ms timeout)
    const check_time = close_time + 1_000_000;
    try testing.expect(!error_mod.isDrainingExpired(&ctx, check_time, pto_ns));
}

test "RFC 9000 §10.2.2 - isDrainingExpired true after timeout" {
    var ctx = error_mod.init();
    const close_time: u64 = 1_000_000_000;
    const pto_ns: u64 = 100_000_000;

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", close_time);

    // Check after 3x PTO (300ms)
    const check_time = close_time + error_mod.drainingTimeoutNs(pto_ns);
    try testing.expect(error_mod.isDrainingExpired(&ctx, check_time, pto_ns));
}

test "RFC 9000 §10.2.2 - isDrainingExpired at exact timeout boundary" {
    var ctx = error_mod.init();
    const close_time: u64 = 2_000_000_000;
    const pto_ns: u64 = 50_000_000;

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", close_time);

    const timeout = error_mod.drainingTimeoutNs(pto_ns);
    const check_time = close_time + timeout;

    try testing.expect(error_mod.isDrainingExpired(&ctx, check_time, pto_ns));
}

test "RFC 9000 §10.2.2 - isDrainingExpired false for active state" {
    var ctx = error_mod.init();

    try testing.expect(!error_mod.isDrainingExpired(&ctx, 1000000, 100000));
}

test "RFC 9000 §10.2.2 - isDrainingExpired works for closing state" {
    var ctx = error_mod.init();
    const close_time: u64 = 3_000_000_000;
    const pto_ns: u64 = 100_000_000;

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", close_time);

    // Should work for closing state too
    const check_time = close_time + error_mod.drainingTimeoutNs(pto_ns);
    try testing.expect(error_mod.isDrainingExpired(&ctx, check_time, pto_ns));
}

// =============================================================================
// Utility Function Tests
// =============================================================================

test "RFC 9000 §20 - isValidErrorCode accepts valid range" {
    try testing.expect(error_mod.isValidErrorCode(0));
    try testing.expect(error_mod.isValidErrorCode(0x10));
    try testing.expect(error_mod.isValidErrorCode(0x0100));
    try testing.expect(error_mod.isValidErrorCode(0x01FF));
    try testing.expect(error_mod.isValidErrorCode(0x1000));
}

test "RFC 9000 §20 - isValidErrorCode maximum valid value" {
    const max_valid: u64 = 0x3FFFFFFFFFFFFFFF; // 2^62 - 1

    try testing.expect(error_mod.isValidErrorCode(max_valid));
}

test "RFC 9000 §20 - errorCodeString returns correct strings" {
    try testing.expectEqualStrings("NO_ERROR", error_mod.errorCodeString(.NO_ERROR));
    try testing.expectEqualStrings("FLOW_CONTROL_ERROR", error_mod.errorCodeString(.FLOW_CONTROL_ERROR));
    try testing.expectEqualStrings("PROTOCOL_VIOLATION", error_mod.errorCodeString(.PROTOCOL_VIOLATION));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: ErrorContext with zero PTO" {
    const timeout = error_mod.drainingTimeoutNs(0);

    try testing.expectEqual(@as(u64, 0), timeout);
}

test "boundary: ErrorContext with max PTO" {
    const max_pto: u64 = std.math.maxInt(u64) / 3;
    const timeout = error_mod.drainingTimeoutNs(max_pto);

    try testing.expectEqual(max_pto * 3, timeout);
}

test "boundary: ErrorCode at CRYPTO_ERROR lower bound" {
    const code = error_mod.ErrorCode.cryptoError(0);

    try testing.expect(error_mod.ErrorCode.isCryptoError(code));
    try testing.expectEqual(@as(u64, 0x0100), @intFromEnum(code));
}

test "boundary: ErrorCode at CRYPTO_ERROR upper bound" {
    const code = error_mod.ErrorCode.cryptoError(255);

    try testing.expect(error_mod.ErrorCode.isCryptoError(code));
    try testing.expectEqual(@as(u64, 0x01FF), @intFromEnum(code));
}

test "boundary: ErrorCode just below CRYPTO_ERROR range" {
    const code: error_mod.ErrorCode = @enumFromInt(0x00FF);

    try testing.expect(!error_mod.ErrorCode.isCryptoError(code));
}

test "boundary: ErrorCode just above CRYPTO_ERROR range" {
    const code: error_mod.ErrorCode = @enumFromInt(0x0200);

    try testing.expect(!error_mod.ErrorCode.isCryptoError(code));
}

test "boundary: enterClosing with empty reason" {
    var ctx = error_mod.init();

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);

    try testing.expectEqualStrings("", ctx.reason);
}

test "boundary: enterClosing with long reason" {
    var ctx = error_mod.init();
    const long_reason = "x" ** 1000; // 1000 character reason

    error_mod.enterClosing(&ctx, .INTERNAL_ERROR, 0, long_reason, 1000000);

    try testing.expectEqualStrings(long_reason, ctx.reason);
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: Cannot transition from draining to closing" {
    var ctx = error_mod.init();

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", 1000000);
    error_mod.enterClosing(&ctx, .INTERNAL_ERROR, 0, "", 2000000);

    // Should remain in draining
    try testing.expectEqual(error_mod.CloseState.draining, ctx.state);
    try testing.expectEqual(error_mod.ErrorCode.NO_ERROR, ctx.error_code);
}

test "negative: Cannot send in draining state" {
    var ctx = error_mod.init();

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", 1000000);

    try testing.expect(!error_mod.canSend(&ctx));
}

test "negative: isDrainingExpired false without close_time" {
    var ctx = error_mod.init();
    ctx.state = .draining;
    ctx.close_time_ns = null;

    try testing.expect(!error_mod.isDrainingExpired(&ctx, 1000000, 100000));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §10 - Connection termination state machine" {
    var ctx = error_mod.init();

    // Start: active
    try testing.expectEqual(error_mod.CloseState.active, ctx.state);

    // Transition: active → closing (send CONNECTION_CLOSE)
    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);
    try testing.expectEqual(error_mod.CloseState.closing, ctx.state);

    // Transition: closing → draining (receive CONNECTION_CLOSE)
    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", 1500000);
    try testing.expectEqual(error_mod.CloseState.draining, ctx.state);

    // Transition: draining → closed (after timeout)
    error_mod.enterClosed(&ctx);
    try testing.expectEqual(error_mod.CloseState.closed, ctx.state);
}

test "RFC 9000 §10.2.1 - Closing state allows sending CONNECTION_CLOSE" {
    var ctx = error_mod.init();

    error_mod.enterClosing(&ctx, .NO_ERROR, 0, "", 1000000);

    // In closing state, can still send (for retransmitting CONNECTION_CLOSE)
    try testing.expect(error_mod.canSend(&ctx));
}

test "RFC 9000 §10.2.2 - Draining state prohibits sending" {
    var ctx = error_mod.init();

    error_mod.enterDraining(&ctx, .NO_ERROR, 0, "", 1000000);

    // In draining state, MUST NOT send any packets
    try testing.expect(!error_mod.canSend(&ctx));
}

test "RFC 9000 §10.2 - Draining timeout is 3 times PTO" {
    const pto_ns: u64 = 40_000_000; // 40ms

    const timeout = error_mod.drainingTimeoutNs(pto_ns);

    // Must be exactly 3x PTO
    try testing.expectEqual(pto_ns * 3, timeout);
}

test "RFC 9000 §20 - All transport error codes defined" {
    // Verify all 17 standard error codes exist
    _ = error_mod.ErrorCode.NO_ERROR;
    _ = error_mod.ErrorCode.INTERNAL_ERROR;
    _ = error_mod.ErrorCode.CONNECTION_REFUSED;
    _ = error_mod.ErrorCode.FLOW_CONTROL_ERROR;
    _ = error_mod.ErrorCode.STREAM_LIMIT_ERROR;
    _ = error_mod.ErrorCode.STREAM_STATE_ERROR;
    _ = error_mod.ErrorCode.FINAL_SIZE_ERROR;
    _ = error_mod.ErrorCode.FRAME_ENCODING_ERROR;
    _ = error_mod.ErrorCode.TRANSPORT_PARAMETER_ERROR;
    _ = error_mod.ErrorCode.CONNECTION_ID_LIMIT_ERROR;
    _ = error_mod.ErrorCode.PROTOCOL_VIOLATION;
    _ = error_mod.ErrorCode.INVALID_TOKEN;
    _ = error_mod.ErrorCode.APPLICATION_ERROR;
    _ = error_mod.ErrorCode.CRYPTO_BUFFER_EXCEEDED;
    _ = error_mod.ErrorCode.KEY_UPDATE_ERROR;
    _ = error_mod.ErrorCode.AEAD_LIMIT_REACHED;
    _ = error_mod.ErrorCode.NO_VIABLE_PATH;

    try testing.expect(true);
}

test "RFC 9001 §4.8 - CRYPTO_ERROR range is 0x0100 to 0x01FF" {
    const min_crypto = error_mod.ErrorCode.cryptoError(0);
    const max_crypto = error_mod.ErrorCode.cryptoError(255);

    try testing.expectEqual(@as(u64, 0x0100), @intFromEnum(min_crypto));
    try testing.expectEqual(@as(u64, 0x01FF), @intFromEnum(max_crypto));
}

test "RFC 9000 §10.2.3 - Immediate close for stateless reset" {
    var ctx = error_mod.init();

    // Stateless reset should use immediate close
    error_mod.immediateClose(&ctx, .NO_ERROR);

    try testing.expectEqual(error_mod.CloseState.closed, ctx.state);
}

test "RFC 9000 §10 - Error context preserves error details" {
    var ctx = error_mod.init();
    const frame_type: u64 = 0x08; // STREAM frame
    const reason = "stream limit exceeded";

    error_mod.enterClosing(&ctx, .STREAM_LIMIT_ERROR, frame_type, reason, 1000000);

    // Error details must be preserved for CONNECTION_CLOSE frame
    try testing.expectEqual(error_mod.ErrorCode.STREAM_LIMIT_ERROR, ctx.error_code);
    try testing.expectEqual(frame_type, ctx.frame_type);
    try testing.expectEqualStrings(reason, ctx.reason);
}

test "RFC 9000 §10.2 - Bidirectional termination sequence" {
    var local_ctx = error_mod.init();
    var peer_ctx = error_mod.init();

    const time0: u64 = 1000000;
    const time1: u64 = 1500000;
    const pto_ns: u64 = 100000000;

    // Local endpoint initiates close
    error_mod.enterClosing(&local_ctx, .NO_ERROR, 0, "done", time0);

    // Peer receives close and enters draining
    error_mod.enterDraining(&peer_ctx, .NO_ERROR, 0, "done", time1);

    // Local receives peer's close ack and enters draining
    error_mod.enterDraining(&local_ctx, .NO_ERROR, 0, "ack", time1);

    // Both wait draining timeout
    const timeout_time = time0 + error_mod.drainingTimeoutNs(pto_ns);

    try testing.expect(error_mod.isDrainingExpired(&local_ctx, timeout_time, pto_ns));

    // Both can now fully close
    error_mod.enterClosed(&local_ctx);
    error_mod.enterClosed(&peer_ctx);

    try testing.expect(error_mod.isClosed(&local_ctx));
    try testing.expect(error_mod.isClosed(&peer_ctx));
}
