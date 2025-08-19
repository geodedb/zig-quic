// MIT License
// QUIC Transport Parameters encode/decode (subset) RFC 9000 §7.4
const std = @import("std");
const varint = @import("quic_varint");

pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    disable_active_migration = 0x0c,
    active_connection_id_limit = 0x0e,
};

pub const TransportParams = struct {
    // Greasing and other fields omitted for now.
    original_destination_connection_id: ?[]u8 = null, // owned
    max_idle_timeout: ?u64 = null,
    initial_max_data: ?u64 = null,
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,
    disable_active_migration: bool = false,
    active_connection_id_limit: ?u64 = null,

    pub fn deinit(self: *TransportParams, alloc: std.mem.Allocator) void {
        if (self.original_destination_connection_id) |b| alloc.free(b);
        self.* = undefined;
    }

    pub fn encode(self: *const TransportParams, alloc: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(alloc);
        errdefer out.deinit();
        const w = out.writer();
        var tmp: [16]u8 = undefined;

        // Helper to write a TLV with raw value bytes
        const writeTlv = struct {
            fn raw(id: Id, value: []const u8, w_: anytype) !void {
                var ibuf: [16]u8 = undefined;
                var lbuf: [16]u8 = undefined;
                const id_n = try varint.encode(@intFromEnum(id), &ibuf);
                const ln = try varint.encode(value.len, &lbuf);
                try w_.writeAll(ibuf[0..id_n]);
                try w_.writeAll(lbuf[0..ln]);
                try w_.writeAll(value);
            }
        };

        // Values with u64 payloads
        if (self.max_idle_timeout) |v| try writeTlv.raw(.max_idle_timeout, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_data) |v| try writeTlv.raw(.initial_max_data, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_stream_data_bidi_local) |v| try writeTlv.raw(.initial_max_stream_data_bidi_local, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_stream_data_bidi_remote) |v| try writeTlv.raw(.initial_max_stream_data_bidi_remote, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_stream_data_uni) |v| try writeTlv.raw(.initial_max_stream_data_uni, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_streams_bidi) |v| try writeTlv.raw(.initial_max_streams_bidi, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.initial_max_streams_uni) |v| try writeTlv.raw(.initial_max_streams_uni, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.active_connection_id_limit) |v| try writeTlv.raw(.active_connection_id_limit, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);

        if (self.disable_active_migration) {
            // Length 0
            var ibuf: [16]u8 = undefined;
            const id_n = try varint.encode(@intFromEnum(Id.disable_active_migration), &ibuf);
            try w.writeAll(ibuf[0..id_n]);
            const zero: [1]u8 = .{0x00};
            try w.writeAll(&zero);
        }
        if (self.original_destination_connection_id) |v| {
            try writeTlv.raw(.original_destination_connection_id, v, w);
        }

        return out.toOwnedSlice();
    }

    pub fn decode(alloc: std.mem.Allocator, bytes: []const u8) !TransportParams {
        var tp: TransportParams = .{};
        var i: usize = 0;
        while (i < bytes.len) {
            const id_dec = varint.decode(bytes[i..]) catch return error.Malformed;
            i += id_dec.n;
            if (i > bytes.len) return error.Malformed;
            const len_dec = varint.decode(bytes[i..]) catch return error.Malformed;
            i += len_dec.n;
            const l: usize = @intCast(len_dec.value);
            if (i + l > bytes.len) return error.Malformed;
            const val = bytes[i .. i + l];
            i += l;
            const idv: u64 = id_dec.value;
            switch (idv) {
                @intFromEnum(Id.original_destination_connection_id) => {
                    if (tp.original_destination_connection_id != null) return error.Duplicate;
                    tp.original_destination_connection_id = try alloc.dupe(u8, val);
                },
                @intFromEnum(Id.max_idle_timeout) => tp.max_idle_timeout = try readVarint(val),
                @intFromEnum(Id.initial_max_data) => tp.initial_max_data = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_bidi_local) => tp.initial_max_stream_data_bidi_local = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_bidi_remote) => tp.initial_max_stream_data_bidi_remote = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_uni) => tp.initial_max_stream_data_uni = try readVarint(val),
                @intFromEnum(Id.initial_max_streams_bidi) => tp.initial_max_streams_bidi = try readVarint(val),
                @intFromEnum(Id.initial_max_streams_uni) => tp.initial_max_streams_uni = try readVarint(val),
                @intFromEnum(Id.disable_active_migration) => {
                    if (val.len != 0) return error.Malformed;
                    tp.disable_active_migration = true;
                },
                @intFromEnum(Id.active_connection_id_limit) => tp.active_connection_id_limit = try readVarint(val),
                else => {
                    // Unknown: ignore for now per RFC (MAY ignore unknown/grease)
                },
            }
        }
        return tp;
    }
};

fn readVarint(b: []const u8) !u64 {
    const dec = try varint.decode(b);
    if (dec.n != b.len) return error.Malformed;
    return dec.value;
}
