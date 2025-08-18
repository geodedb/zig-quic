// MIT License
// QUIC frame model and encoder (subset) — RFC 9000 §19
const std = @import("std");
const varint = @import("varint.zig");

pub const FrameType = enum(u8) {
    Padding = 0x00,
    Ping = 0x01,
    AckRange = 0x02,
    StreamBase = 0x08,
    HandshakeDone = 0x1e,
};

pub const Frame = union(enum) {
    padding,
    ping,
    stream: struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 },

    pub fn write(self: Frame, w: anytype) !usize {
        var total: usize = 0;
        switch (self) {
            .padding => {
                try w.writeByte(@intFromEnum(FrameType.Padding));
                total += 1;
            },
            .ping => {
                try w.writeByte(@intFromEnum(FrameType.Ping));
                total += 1;
            },
            .stream => |s| {
                var t: u8 = @intFromEnum(FrameType.StreamBase);
                t |= 0x02; // LEN
                if (s.offset != null) t |= 0x04; // OFF
                if (s.fin) t |= 0x01; // FIN
                try w.writeByte(t);
                total += 1;
                var buf: [8]u8 = undefined;
                total += try varint.encode(s.stream_id, &buf);
                if (s.offset) |off| total += try varint.encode(off, &buf);
                total += try varint.encode(s.data.len, &buf);
                try w.writeAll(s.data);
                total += s.data.len;
            },
        }
        return total;
    }
};
