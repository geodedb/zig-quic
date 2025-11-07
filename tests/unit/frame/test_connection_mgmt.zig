//! Unit tests for frame/connection_mgmt.zig
//!
//! RFC References:
//! - RFC 9000 §19.15: NEW_CONNECTION_ID Frame
//! - RFC 9000 §19.16: RETIRE_CONNECTION_ID Frame
//! - RFC 9000 §19.19: CONNECTION_CLOSE Frame
//! - RFC 9000 §19.4: RESET_STREAM Frame
//! - RFC 9000 §19.5: STOP_SENDING Frame
//! - RFC 9000 §5: Connection ID Management
//! - RFC 9000 §10: Connection Termination
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding for all 5 frame types
//! - Negative cases: Truncated buffers, wrong frame types, invalid fields
//! - Edge cases: Empty reasons, zero values, maximum values, CID lengths
//! - RFC compliance: Frame formats, CID lifecycle, connection closure, stream control

const std = @import("std");
const testing = std.testing;

const conn_mgmt = @import("connection_mgmt");
const types = @import("types");

// =============================================================================
// NEW_CONNECTION_ID Frame Tests
// =============================================================================

test "RFC 9000 §19.15 - writeNewConnectionId encodes frame" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 5;
    const retire_prior_to: u64 = 2;
    const cid = "\x01\x02\x03\x04\x05\x06\x07\x08";
    var token: [16]u8 = undefined;
    @memset(&token, 0xaa);

    const n = try conn_mgmt.writeNewConnectionId(w, sequence, retire_prior_to, cid, token);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x18), buf[0]); // NEW_CONNECTION_ID type
}

test "RFC 9000 §19.15 - decodeNewConnectionId reads frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 10;
    const retire_prior_to: u64 = 5;
    const cid = "\xaa\xbb\xcc\xdd\xee\xff\x11\x22";
    var token: [16]u8 = undefined;
    for (&token, 0..) |*t, i| {
        t.* = @intCast(i);
    }

    _ = try conn_mgmt.writeNewConnectionId(w, sequence, retire_prior_to, cid, token);

    const result = try conn_mgmt.decodeNewConnectionId(fbs.getWritten());

    try testing.expectEqual(@as(u64, 10), result.sequence);
    try testing.expectEqual(@as(u64, 5), result.retire_prior_to);
    try testing.expectEqualStrings(cid, result.connection_id);
    try testing.expectEqualSlices(u8, &token, &result.stateless_reset_token);
}

test "RFC 9000 §19.15 - NEW_CONNECTION_ID round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 7;
    const retire_prior_to: u64 = 3;
    const cid = "\x12\x34\x56\x78";
    var token: [16]u8 = undefined;
    @memset(&token, 0xde);

    const written = try conn_mgmt.writeNewConnectionId(w, sequence, retire_prior_to, cid, token);

    const result = try conn_mgmt.decodeNewConnectionId(fbs.getWritten());

    try testing.expectEqual(sequence, result.sequence);
    try testing.expectEqual(retire_prior_to, result.retire_prior_to);
    try testing.expectEqualStrings(cid, result.connection_id);
    try testing.expectEqualSlices(u8, &token, &result.stateless_reset_token);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §5.1 - NEW_CONNECTION_ID with various CID lengths" {
    var buf: [256]u8 = undefined;

    // 4-byte CID
    var fbs1 = std.io.fixedBufferStream(&buf);
    const cid1 = "\x01\x02\x03\x04";
    var token: [16]u8 = undefined;
    @memset(&token, 0xaa);
    _ = try conn_mgmt.writeNewConnectionId(fbs1.writer(), 1, 0, cid1, token);
    const r1 = try conn_mgmt.decodeNewConnectionId(fbs1.getWritten());
    try testing.expectEqual(@as(usize, 4), r1.connection_id.len);

    // 20-byte CID (maximum)
    var fbs2 = std.io.fixedBufferStream(&buf);
    const cid2 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14";
    _ = try conn_mgmt.writeNewConnectionId(fbs2.writer(), 2, 0, cid2, token);
    const r2 = try conn_mgmt.decodeNewConnectionId(fbs2.getWritten());
    try testing.expectEqual(@as(usize, 20), r2.connection_id.len);
}

test "negative: decodeNewConnectionId with truncated buffer" {
    const buf = [_]u8{ 0x18, 0x05 }; // Type + partial sequence
    try testing.expectError(error.Truncated, conn_mgmt.decodeNewConnectionId(&buf));
}

test "negative: decodeNewConnectionId with wrong frame type" {
    const buf = [_]u8{ 0x19, 0x00 }; // RETIRE_CONNECTION_ID instead
    try testing.expectError(error.InvalidFrameType, conn_mgmt.decodeNewConnectionId(&buf));
}

// =============================================================================
// RETIRE_CONNECTION_ID Frame Tests
// =============================================================================

test "RFC 9000 §19.16 - writeRetireConnectionId encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 3;
    const n = try conn_mgmt.writeRetireConnectionId(w, sequence);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x19), buf[0]); // RETIRE_CONNECTION_ID type
}

test "RFC 9000 §19.16 - decodeRetireConnectionId reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 15;
    _ = try conn_mgmt.writeRetireConnectionId(w, sequence);

    const result = try conn_mgmt.decodeRetireConnectionId(fbs.getWritten());

    try testing.expectEqual(@as(u64, 15), result.sequence);
}

test "RFC 9000 §19.16 - RETIRE_CONNECTION_ID round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 42;
    const written = try conn_mgmt.writeRetireConnectionId(w, sequence);

    const result = try conn_mgmt.decodeRetireConnectionId(fbs.getWritten());

    try testing.expectEqual(sequence, result.sequence);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §5.1 - RETIRE_CONNECTION_ID with sequence 0" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try conn_mgmt.writeRetireConnectionId(w, 0);

    const result = try conn_mgmt.decodeRetireConnectionId(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.sequence);
}

test "negative: decodeRetireConnectionId with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, conn_mgmt.decodeRetireConnectionId(buf));
}

test "negative: decodeRetireConnectionId with wrong frame type" {
    const buf = [_]u8{ 0x18, 0x00 }; // NEW_CONNECTION_ID instead
    try testing.expectError(error.InvalidFrameType, conn_mgmt.decodeRetireConnectionId(&buf));
}

// =============================================================================
// CONNECTION_CLOSE Frame Tests
// =============================================================================

test "RFC 9000 §19.19 - writeConnectionClose encodes frame" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x00; // NO_ERROR
    const frame_type: u64 = 0x00;
    const reason = "Normal closure";

    const n = try conn_mgmt.writeConnectionClose(w, error_code, frame_type, reason);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x1c), buf[0]); // CONNECTION_CLOSE type
}

test "RFC 9000 §19.19 - decodeConnectionClose reads frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x01; // INTERNAL_ERROR
    const frame_type: u64 = 0x08;
    const reason = "Internal error occurred";

    _ = try conn_mgmt.writeConnectionClose(w, error_code, frame_type, reason);

    const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0x01), result.error_code);
    try testing.expectEqual(@as(u64, 0x08), result.frame_type);
    try testing.expectEqualStrings(reason, result.reason);
}

test "RFC 9000 §19.19 - CONNECTION_CLOSE round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x0a; // PROTOCOL_VIOLATION
    const frame_type: u64 = 0x02; // ACK frame
    const reason = "ACK frame protocol violation";

    const written = try conn_mgmt.writeConnectionClose(w, error_code, frame_type, reason);

    const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());

    try testing.expectEqual(error_code, result.error_code);
    try testing.expectEqual(frame_type, result.frame_type);
    try testing.expectEqualStrings(reason, result.reason);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §19.19 - CONNECTION_CLOSE with empty reason" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x00;
    const frame_type: u64 = 0x00;
    const reason: []const u8 = "";

    _ = try conn_mgmt.writeConnectionClose(w, error_code, frame_type, reason);

    const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());

    try testing.expectEqual(@as(usize, 0), result.reason.len);
}

test "RFC 9000 §20 - CONNECTION_CLOSE with various error codes" {
    var buf: [256]u8 = undefined;

    const error_codes = [_]u64{
        0x00, // NO_ERROR
        0x01, // INTERNAL_ERROR
        0x02, // CONNECTION_REFUSED
        0x03, // FLOW_CONTROL_ERROR
        0x04, // STREAM_LIMIT_ERROR
        0x0a, // PROTOCOL_VIOLATION
    };

    for (error_codes) |code| {
        var fbs = std.io.fixedBufferStream(&buf);
        _ = try conn_mgmt.writeConnectionClose(fbs.writer(), code, 0, "Test");
        const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());
        try testing.expectEqual(code, result.error_code);
    }
}

test "negative: decodeConnectionClose with truncated buffer" {
    const buf = [_]u8{ 0x1c, 0x01 }; // Type + partial error code
    try testing.expectError(error.Truncated, conn_mgmt.decodeConnectionClose(&buf));
}

test "negative: decodeConnectionClose with wrong frame type" {
    const buf = [_]u8{ 0x04, 0x00 }; // RESET_STREAM instead
    try testing.expectError(error.InvalidFrameType, conn_mgmt.decodeConnectionClose(&buf));
}

// =============================================================================
// STOP_SENDING Frame Tests
// =============================================================================

test "RFC 9000 §19.5 - writeStopSending encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const error_code: u64 = 0x00;

    const n = try conn_mgmt.writeStopSending(w, stream_id, error_code);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x05), buf[0]); // STOP_SENDING type
}

test "RFC 9000 §19.5 - decodeStopSending reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const error_code: u64 = 0x04;

    _ = try conn_mgmt.writeStopSending(w, stream_id, error_code);

    const result = try conn_mgmt.decodeStopSending(fbs.getWritten());

    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(u64, 0x04), result.error_code);
}

test "RFC 9000 §19.5 - STOP_SENDING round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 12;
    const error_code: u64 = 0x100;

    const written = try conn_mgmt.writeStopSending(w, stream_id, error_code);

    const result = try conn_mgmt.decodeStopSending(fbs.getWritten());

    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(error_code, result.error_code);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §3.5 - STOP_SENDING with stream ID 0" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try conn_mgmt.writeStopSending(w, 0, 0x00);

    const result = try conn_mgmt.decodeStopSending(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.stream_id);
}

test "negative: decodeStopSending with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, conn_mgmt.decodeStopSending(buf));
}

test "negative: decodeStopSending with wrong frame type" {
    const buf = [_]u8{ 0x04, 0x00 }; // RESET_STREAM instead
    try testing.expectError(error.InvalidFrameType, conn_mgmt.decodeStopSending(&buf));
}

// =============================================================================
// RESET_STREAM Frame Tests
// =============================================================================

test "RFC 9000 §19.4 - writeResetStream encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const error_code: u64 = 0x00;
    const final_size: u64 = 1024;

    const n = try conn_mgmt.writeResetStream(w, stream_id, error_code, final_size);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x04), buf[0]); // RESET_STREAM type
}

test "RFC 9000 §19.4 - decodeResetStream reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const error_code: u64 = 0x100;
    const final_size: u64 = 2048;

    _ = try conn_mgmt.writeResetStream(w, stream_id, error_code, final_size);

    const result = try conn_mgmt.decodeResetStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(u64, 0x100), result.error_code);
    try testing.expectEqual(@as(u64, 2048), result.final_size);
}

test "RFC 9000 §19.4 - RESET_STREAM round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 12;
    const error_code: u64 = 0x05;
    const final_size: u64 = 4096;

    const written = try conn_mgmt.writeResetStream(w, stream_id, error_code, final_size);

    const result = try conn_mgmt.decodeResetStream(fbs.getWritten());

    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(error_code, result.error_code);
    try testing.expectEqual(final_size, result.final_size);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §3.2 - RESET_STREAM with final_size 0" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try conn_mgmt.writeResetStream(w, 4, 0x00, 0);

    const result = try conn_mgmt.decodeResetStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.final_size);
}

test "negative: decodeResetStream with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, conn_mgmt.decodeResetStream(buf));
}

test "negative: decodeResetStream with wrong frame type" {
    const buf = [_]u8{ 0x05, 0x00 }; // STOP_SENDING instead
    try testing.expectError(error.InvalidFrameType, conn_mgmt.decodeResetStream(&buf));
}

// =============================================================================
// Frame Type Verification Tests
// =============================================================================

test "RFC 9000 §19 - Frame types are distinct" {
    try testing.expectEqual(@as(u8, 0x18), @intFromEnum(types.FrameType.NEW_CONNECTION_ID));
    try testing.expectEqual(@as(u8, 0x19), @intFromEnum(types.FrameType.RETIRE_CONNECTION_ID));
    try testing.expectEqual(@as(u8, 0x1c), @intFromEnum(types.FrameType.CONNECTION_CLOSE));
    try testing.expectEqual(@as(u8, 0x05), @intFromEnum(types.FrameType.STOP_SENDING));
    try testing.expectEqual(@as(u8, 0x04), @intFromEnum(types.FrameType.RESET_STREAM));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §5.1 - NEW_CONNECTION_ID provides new CIDs for migration" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Endpoint provides new CID for peer to use
    const cid = "\x11\x22\x33\x44\x55\x66\x77\x88";
    var token: [16]u8 = undefined;
    @memset(&token, 0xde);

    _ = try conn_mgmt.writeNewConnectionId(w, 5, 2, cid, token);

    const result = try conn_mgmt.decodeNewConnectionId(fbs.getWritten());

    // Peer can now use this CID for migration
    try testing.expectEqualStrings(cid, result.connection_id);
    try testing.expectEqualSlices(u8, &token, &result.stateless_reset_token);
}

test "RFC 9000 §5.1 - NEW_CONNECTION_ID retire_prior_to indicates retirement" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 10;
    const retire_prior_to: u64 = 7; // Retire CIDs with sequence < 7
    const cid = "\xaa\xbb\xcc\xdd";
    var token: [16]u8 = undefined;
    @memset(&token, 0xff);

    _ = try conn_mgmt.writeNewConnectionId(w, sequence, retire_prior_to, cid, token);

    const result = try conn_mgmt.decodeNewConnectionId(fbs.getWritten());

    // Peer should retire CIDs with sequence 0-6
    try testing.expect(result.retire_prior_to < result.sequence);
}

test "RFC 9000 §5.1 - RETIRE_CONNECTION_ID indicates CID no longer used" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const sequence: u64 = 3; // Retire CID with sequence 3

    _ = try conn_mgmt.writeRetireConnectionId(w, sequence);

    const result = try conn_mgmt.decodeRetireConnectionId(fbs.getWritten());

    // Peer knows not to use this CID anymore
    try testing.expectEqual(@as(u64, 3), result.sequence);
}

test "RFC 9000 §10.2 - CONNECTION_CLOSE signals graceful termination" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x00; // NO_ERROR
    const reason = "Application shutdown";

    _ = try conn_mgmt.writeConnectionClose(w, error_code, 0, reason);

    const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0x00), result.error_code);
    try testing.expectEqualStrings(reason, result.reason);
}

test "RFC 9000 §10.2 - CONNECTION_CLOSE includes triggering frame type" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const error_code: u64 = 0x0a; // PROTOCOL_VIOLATION
    const frame_type: u64 = 0x0a; // STREAM frame caused error

    _ = try conn_mgmt.writeConnectionClose(w, error_code, frame_type, "Invalid stream");

    const result = try conn_mgmt.decodeConnectionClose(fbs.getWritten());

    // Frame type indicates which frame triggered closure
    try testing.expectEqual(@as(u64, 0x0a), result.frame_type);
}

test "RFC 9000 §3.5 - STOP_SENDING requests peer stop transmission" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const error_code: u64 = 0x00;

    _ = try conn_mgmt.writeStopSending(w, stream_id, error_code);

    const result = try conn_mgmt.decodeStopSending(fbs.getWritten());

    // Peer should stop sending on this stream
    try testing.expectEqual(@as(u64, 4), result.stream_id);
}

test "RFC 9000 §3.2 - RESET_STREAM aborts stream transmission" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const error_code: u64 = 0x100;
    const final_size: u64 = 1024; // Total bytes sent before reset

    _ = try conn_mgmt.writeResetStream(w, stream_id, error_code, final_size);

    const result = try conn_mgmt.decodeResetStream(fbs.getWritten());

    // Stream is aborted, final_size indicates total sent
    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(u64, 1024), result.final_size);
}

test "RFC 9000 §3.2 - RESET_STREAM final_size for flow control" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const final_size: u64 = 2048;

    _ = try conn_mgmt.writeResetStream(w, stream_id, 0, final_size);

    const result = try conn_mgmt.decodeResetStream(fbs.getWritten());

    // final_size counts toward flow control limits
    try testing.expectEqual(@as(u64, 2048), result.final_size);
}

test "RFC 9000 §5 - CID lifecycle: NEW_CONNECTION_ID then RETIRE_CONNECTION_ID" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Provide new CID
    const cid = "\x01\x02\x03\x04";
    var token: [16]u8 = undefined;
    @memset(&token, 0xaa);
    const n1 = try conn_mgmt.writeNewConnectionId(w, 5, 0, cid, token);

    // Later, retire old CID
    const n2 = try conn_mgmt.writeRetireConnectionId(w, 3);

    const written = fbs.getWritten();

    const new_cid = try conn_mgmt.decodeNewConnectionId(written);
    try testing.expectEqual(@as(u64, 5), new_cid.sequence);

    const retire = try conn_mgmt.decodeRetireConnectionId(written[n1..]);
    try testing.expectEqual(@as(u64, 3), retire.sequence);

    try testing.expect(n1 > 0 and n2 > 0);
}

test "RFC 9000 §3 - Stream lifecycle: STOP_SENDING then RESET_STREAM" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;

    // Receiver sends STOP_SENDING
    const n1 = try conn_mgmt.writeStopSending(w, stream_id, 0);

    // Sender responds with RESET_STREAM
    const n2 = try conn_mgmt.writeResetStream(w, stream_id, 0, 1024);

    const written = fbs.getWritten();

    const stop = try conn_mgmt.decodeStopSending(written);
    try testing.expectEqual(stream_id, stop.stream_id);

    const reset = try conn_mgmt.decodeResetStream(written[n1..]);
    try testing.expectEqual(stream_id, reset.stream_id);

    try testing.expect(n1 > 0 and n2 > 0);
}
