// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC error handling: error codes, connection closure, and draining state.
//!
//! RFC 9000 §10: Connection Termination
//! RFC 9000 §20: Error Codes

const std = @import("std");

/// QUIC transport error codes.
/// RFC 9000 §20: All QUIC error codes standardized in the specification.
pub const ErrorCode = enum(u64) {
    /// No error (clean shutdown).
    /// RFC 9000 §20: The connection is being closed abruptly without an error.
    NO_ERROR = 0x00,

    /// Implementation-specific internal error.
    /// RFC 9000 §20: The endpoint encountered an internal error and cannot continue with the connection.
    INTERNAL_ERROR = 0x01,

    /// Server refusing connection (e.g., overloaded).
    /// RFC 9000 §20: The server is currently not accepting new connections.
    CONNECTION_REFUSED = 0x02,

    /// Flow control violation.
    /// RFC 9000 §20: An endpoint received more data than it was willing to receive (flow control limit exceeded).
    FLOW_CONTROL_ERROR = 0x03,

    /// Stream limit exceeded.
    /// RFC 9000 §20: A peer exceeded the advertised stream limit for the corresponding stream type.
    STREAM_LIMIT_ERROR = 0x04,

    /// Stream in invalid state for operation.
    /// RFC 9000 §20: An operation was attempted on a stream that was not in a state allowing that operation.
    STREAM_STATE_ERROR = 0x05,

    /// Final size mismatch.
    /// RFC 9000 §20: A RESET_STREAM or STREAM frame containing a final size that was lower than the previous final size, or a frame that would cause the final size to exceed the maximum stream data limit.
    FINAL_SIZE_ERROR = 0x06,

    /// Frame encoding error.
    /// RFC 9000 §20: A frame was received that was badly formatted or contained invalid values.
    FRAME_ENCODING_ERROR = 0x07,

    /// Transport parameter error.
    /// RFC 9000 §20: Transport parameters were invalid or contained illegal values.
    TRANSPORT_PARAMETER_ERROR = 0x08,

    /// Connection ID limit exceeded.
    /// RFC 9000 §20: The endpoint supplied more connection IDs than the peer's advertised limit.
    CONNECTION_ID_LIMIT_ERROR = 0x09,

    /// Generic protocol violation.
    /// RFC 9000 §20: A peer violated protocol requirements in a way not covered by more specific error codes.
    PROTOCOL_VIOLATION = 0x0A,

    /// Invalid token received.
    /// RFC 9000 §20: A server received a client Initial packet with an invalid token.
    INVALID_TOKEN = 0x0B,

    /// Application-specific error.
    /// RFC 9000 §20: The application requested connection closure.
    APPLICATION_ERROR = 0x0C,

    /// CRYPTO buffer size exceeded.
    /// RFC 9000 §20: The received CRYPTO data exceeded the advertised maximum or was too fragmented.
    CRYPTO_BUFFER_EXCEEDED = 0x0D,

    /// Key update error.
    /// RFC 9000 §20: A key update failed or was improperly initiated.
    KEY_UPDATE_ERROR = 0x0E,

    /// AEAD integrity limit reached.
    /// RFC 9000 §20: The AEAD algorithm's integrity limit was reached, requiring a key update or connection closure.
    AEAD_LIMIT_REACHED = 0x0F,

    /// No viable network path.
    /// RFC 9000 §20: No viable path to the peer exists (e.g., path validation failures).
    NO_VIABLE_PATH = 0x10,

    // TLS/Crypto errors: RFC 8446 alerts mapped to 0x0100-0x01FF
    // CRYPTO_ERROR(alert) = 0x0100 + alert
    // Not enumerated here as there are 256 possible values; use cryptoError() helper.

    _,

    /// Create a CRYPTO_ERROR from a TLS alert code.
    /// RFC 9000 §20, RFC 9001 §4.8: CRYPTO_ERROR(alert) = 0x0100 + alert_code.
    pub fn cryptoError(tls_alert: u8) ErrorCode {
        return @enumFromInt(0x0100 + @as(u64, tls_alert));
    }

    /// Check if an error code is a CRYPTO_ERROR (0x0100-0x01FF).
    pub fn isCryptoError(code: ErrorCode) bool {
        const val = @intFromEnum(code);
        return val >= 0x0100 and val <= 0x01FF;
    }

    /// Extract TLS alert code from a CRYPTO_ERROR.
    /// Returns null if not a CRYPTO_ERROR.
    pub fn tlsAlert(code: ErrorCode) ?u8 {
        if (!isCryptoError(code)) return null;
        const val = @intFromEnum(code);
        return @intCast(val - 0x0100);
    }
};

/// Connection termination state.
/// RFC 9000 §10.2: Connection close states (closing, draining).
pub const CloseState = enum {
    /// Connection is active.
    active,

    /// Closing state: sent CONNECTION_CLOSE, waiting for peer's close or timeout.
    /// RFC 9000 §10.2.1: An endpoint enters the closing state after sending a CONNECTION_CLOSE frame.
    closing,

    /// Draining state: received CONNECTION_CLOSE, not sending further frames.
    /// RFC 9000 §10.2.2: An endpoint enters the draining state after receiving a CONNECTION_CLOSE frame.
    draining,

    /// Connection is fully closed.
    closed,
};

/// Connection error context: state, error code, and reason.
pub const ErrorContext = struct {
    state: CloseState = .active,
    error_code: ErrorCode = .NO_ERROR,
    frame_type: u64 = 0,
    reason: []const u8 = "",
    // Timestamp when close/draining state was entered (for timeout calculation)
    close_time_ns: ?u64 = null,
};

/// Initialize error context.
pub fn init() ErrorContext {
    return .{};
}

/// Enter closing state: connection initiated closure.
/// RFC 9000 §10.2.1: After sending CONNECTION_CLOSE, enter closing state.
pub fn enterClosing(ctx: *ErrorContext, error_code: ErrorCode, frame_type: u64, reason: []const u8, now_ns: u64) void {
    if (ctx.state == .active) {
        ctx.state = .closing;
        ctx.error_code = error_code;
        ctx.frame_type = frame_type;
        ctx.reason = reason;
        ctx.close_time_ns = now_ns;
    }
}

/// Enter draining state: connection received CONNECTION_CLOSE.
/// RFC 9000 §10.2.2: After receiving CONNECTION_CLOSE, enter draining state and stop sending.
pub fn enterDraining(ctx: *ErrorContext, error_code: ErrorCode, frame_type: u64, reason: []const u8, now_ns: u64) void {
    if (ctx.state == .active or ctx.state == .closing) {
        ctx.state = .draining;
        ctx.error_code = error_code;
        ctx.frame_type = frame_type;
        ctx.reason = reason;
        if (ctx.close_time_ns == null) {
            ctx.close_time_ns = now_ns;
        }
    }
}

/// Mark connection as fully closed.
/// RFC 9000 §10.2: Transition to closed state after draining timeout or immediate close.
pub fn enterClosed(ctx: *ErrorContext) void {
    ctx.state = .closed;
}

/// Immediate close: bypass closing/draining and go straight to closed.
/// RFC 9000 §10.2.3: Immediate close can be used for fatal errors or stateless reset.
pub fn immediateClose(ctx: *ErrorContext, error_code: ErrorCode) void {
    ctx.state = .closed;
    ctx.error_code = error_code;
}

/// Check if connection is in closing or draining state.
pub fn isTerminating(ctx: *const ErrorContext) bool {
    return ctx.state == .closing or ctx.state == .draining;
}

/// Check if connection is fully closed.
pub fn isClosed(ctx: *const ErrorContext) bool {
    return ctx.state == .closed;
}

/// Check if connection can send packets.
/// RFC 9000 §10.2.2: In draining state, an endpoint MUST NOT send packets.
pub fn canSend(ctx: *const ErrorContext) bool {
    return ctx.state == .active or ctx.state == .closing;
}

/// Calculate draining timeout.
/// RFC 9000 §10.2: Draining timeout is 3x PTO (Probe Timeout).
pub fn drainingTimeoutNs(pto_ns: u64) u64 {
    return pto_ns * 3;
}

/// Check if draining timeout has expired.
/// RFC 9000 §10.2.2: After draining timeout, connection can be fully closed.
pub fn isDrainingExpired(ctx: *const ErrorContext, now_ns: u64, pto_ns: u64) bool {
    if (ctx.state != .draining and ctx.state != .closing) return false;
    const close_time = ctx.close_time_ns orelse return false;
    const timeout = drainingTimeoutNs(pto_ns);
    return now_ns >= close_time + timeout;
}

/// Generate CONNECTION_CLOSE frame payload (error code + frame type + reason).
/// RFC 9000 §19.19: CONNECTION_CLOSE format.
/// Returns a slice that can be written to a packet.
pub fn formatCloseFrame(
    error_code: ErrorCode,
    frame_type: u64,
    reason: []const u8,
    buf: []u8,
) ![]const u8 {
    // Simple format: error_code(varint) + frame_type(varint) + reason_len(varint) + reason
    // This is a helper; actual encoding uses frame module's writeConnectionClose.
    _ = buf;
    _ = error_code;
    _ = frame_type;
    _ = reason;
    // Not implementing actual encoding here as it's handled by frame/connection_mgmt.zig
    return error.NotImplemented;
}

/// Validate error code is in valid range.
/// RFC 9000 §20: Error codes up to 2^62-1 are valid.
pub fn isValidErrorCode(code: u64) bool {
    return code <= 0x3FFFFFFFFFFFFFFF; // 2^62 - 1
}

/// Convert error code to human-readable string.
pub fn errorCodeString(code: ErrorCode) []const u8 {
    return switch (code) {
        .NO_ERROR => "NO_ERROR",
        .INTERNAL_ERROR => "INTERNAL_ERROR",
        .CONNECTION_REFUSED => "CONNECTION_REFUSED",
        .FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR",
        .STREAM_LIMIT_ERROR => "STREAM_LIMIT_ERROR",
        .STREAM_STATE_ERROR => "STREAM_STATE_ERROR",
        .FINAL_SIZE_ERROR => "FINAL_SIZE_ERROR",
        .FRAME_ENCODING_ERROR => "FRAME_ENCODING_ERROR",
        .TRANSPORT_PARAMETER_ERROR => "TRANSPORT_PARAMETER_ERROR",
        .CONNECTION_ID_LIMIT_ERROR => "CONNECTION_ID_LIMIT_ERROR",
        .PROTOCOL_VIOLATION => "PROTOCOL_VIOLATION",
        .INVALID_TOKEN => "INVALID_TOKEN",
        .APPLICATION_ERROR => "APPLICATION_ERROR",
        .CRYPTO_BUFFER_EXCEEDED => "CRYPTO_BUFFER_EXCEEDED",
        .KEY_UPDATE_ERROR => "KEY_UPDATE_ERROR",
        .AEAD_LIMIT_REACHED => "AEAD_LIMIT_REACHED",
        .NO_VIABLE_PATH => "NO_VIABLE_PATH",
        _ => {
            if (ErrorCode.isCryptoError(code)) {
                return "CRYPTO_ERROR";
            }
            return "UNKNOWN_ERROR";
        },
    };
}
