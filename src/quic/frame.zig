// MIT License
// QUIC frame codec scaffolding
const std = @import("std");

pub const FrameType = enum(u8) {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    STREAM = 0x08, // 0x08-0x0f with flags
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    NEW_CONNECTION_ID = 0x18,
    RETIRE_CONNECTION_ID = 0x19,
    PATH_CHALLENGE = 0x1a,
    PATH_RESPONSE = 0x1b,
    CONNECTION_CLOSE = 0x1c,
    HANDSHAKE_DONE = 0x1e,
    DATAGRAM = 0x30, // RFC 9221 (optional)
};

pub const AckRange = struct { gap: u64, len: u64 };

pub const Frame = union(enum) {
    padding: usize,
    ping: void,
    crypto: struct { offset: u64, data: []const u8 },
    ack: struct { largest: u64, delay: u64, ranges: []const AckRange },
    stream: struct { id: u64, offset: u64, fin: bool, data: []const u8 },
    // ... more frames as needed ...
};

pub fn encode(frame: Frame, w: anytype) !void {
    _ = frame;
    _ = w;
    return error.NotImplemented;
}

pub fn decode(r: anytype, alloc: std.mem.Allocator) !Frame {
    _ = r;
    _ = alloc;
    return error.NotImplemented;
}
