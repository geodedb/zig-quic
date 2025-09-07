// MIT License
// QUIC Transport Parameters encode/decode (subset) RFC 9000 §7.4
const std = @import("std");
const varint = @import("quic_varint");

/// Preferred address structure per RFC 9000
pub const PreferredAddress = struct {
    ipv4_addr: ?struct {
        ip: [4]u8,
        port: u16,
    } = null,
    ipv6_addr: ?struct {
        ip: [16]u8,
        port: u16,
    } = null,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
};

/// Parse preferred address from raw bytes
pub fn parsePreferredAddress(data: []const u8) !PreferredAddress {
    if (data.len < 41) return error.InvalidPreferredAddress;
    
    var result = PreferredAddress{
        .connection_id = undefined,
        .stateless_reset_token = undefined,
    };
    
    var pos: usize = 0;
    
    // IPv4 address (4 bytes) + port (2 bytes)
    const ipv4_bytes = data[pos..pos + 4];
    pos += 4;
    const ipv4_port = (@as(u16, data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Check if IPv4 is present (not all zeros)
    var has_ipv4 = false;
    for (ipv4_bytes) |b| {
        if (b != 0) {
            has_ipv4 = true;
            break;
        }
    }
    
    if (has_ipv4) {
        result.ipv4_addr = .{
            .ip = ipv4_bytes[0..4].*,
            .port = ipv4_port,
        };
    }
    
    // IPv6 address (16 bytes) + port (2 bytes)
    const ipv6_bytes = data[pos..pos + 16];
    pos += 16;
    const ipv6_port = (@as(u16, data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Check if IPv6 is present
    var has_ipv6 = false;
    for (ipv6_bytes) |b| {
        if (b != 0) {
            has_ipv6 = true;
            break;
        }
    }
    
    if (has_ipv6) {
        result.ipv6_addr = .{
            .ip = ipv6_bytes[0..16].*,
            .port = ipv6_port,
        };
    }
    
    // Connection ID length and value
    const cid_len = data[pos];
    pos += 1;
    if (pos + cid_len > data.len) return error.InvalidPreferredAddress;
    result.connection_id = data[pos..pos + cid_len];
    pos += cid_len;
    
    // Stateless reset token (16 bytes)
    if (pos + 16 > data.len) return error.InvalidPreferredAddress;
    @memcpy(&result.stateless_reset_token, data[pos..pos + 16]);
    
    return result;
}

/// Transport Parameter identifiers used in TLS QUIC handshake.
pub const Id = enum(u64) {
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
};

/// Parsed QUIC Transport Parameters (subset) with encode/decode helpers.
pub const TransportParams = struct {
    // Greasing and other fields omitted for now.
    original_destination_connection_id: ?[]u8 = null, // owned
    max_idle_timeout: ?u64 = null,
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: ?u64 = null,
    initial_max_data: ?u64 = null,
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,
    ack_delay_exponent: ?u64 = null,
    max_ack_delay: ?u64 = null,
    disable_active_migration: bool = false,
    active_connection_id_limit: ?u64 = null,
    initial_source_connection_id: ?[]u8 = null, // owned
    retry_source_connection_id: ?[]u8 = null, // owned
    preferred_address_raw: ?[]u8 = null, // owned raw bytes (structure parse deferred)

    /// Free any owned fields and poison the struct.
    pub fn deinit(self: *TransportParams, alloc: std.mem.Allocator) void {
        if (self.original_destination_connection_id) |b| alloc.free(b);
        if (self.initial_source_connection_id) |b| alloc.free(b);
        if (self.retry_source_connection_id) |b| alloc.free(b);
        if (self.preferred_address_raw) |b| alloc.free(b);
        self.* = undefined;
    }

    /// Encode to the TLS transport parameters extension format.
    pub fn encode(self: *const TransportParams, alloc: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8){};
        errdefer out.deinit(alloc);
        const w = out.writer(alloc);
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
        if (self.max_udp_payload_size) |v| try writeTlv.raw(.max_udp_payload_size, blk: {
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
        if (self.ack_delay_exponent) |v| try writeTlv.raw(.ack_delay_exponent, blk: {
            const n = try varint.encode(v, &tmp);
            break :blk tmp[0..n];
        }, w);
        if (self.max_ack_delay) |v| try writeTlv.raw(.max_ack_delay, blk: {
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
        if (self.initial_source_connection_id) |v| try writeTlv.raw(.initial_source_connection_id, v, w);
        if (self.retry_source_connection_id) |v| try writeTlv.raw(.retry_source_connection_id, v, w);
        if (self.stateless_reset_token) |tok| {
            try writeTlv.raw(.stateless_reset_token, &tok, w);
        }
        if (self.preferred_address_raw) |v| try writeTlv.raw(.preferred_address, v, w);

        return out.toOwnedSlice(alloc);
    }

    /// Decode from the TLS transport parameters extension format.
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
                @intFromEnum(Id.stateless_reset_token) => {
                    if (val.len != 16) return error.Malformed;
                    if (tp.stateless_reset_token != null) return error.Duplicate;
                    var tok: [16]u8 = undefined;
                    @memcpy(&tok, val[0..16]);
                    tp.stateless_reset_token = tok;
                },
                @intFromEnum(Id.max_udp_payload_size) => tp.max_udp_payload_size = try readVarint(val),
                @intFromEnum(Id.initial_max_data) => tp.initial_max_data = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_bidi_local) => tp.initial_max_stream_data_bidi_local = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_bidi_remote) => tp.initial_max_stream_data_bidi_remote = try readVarint(val),
                @intFromEnum(Id.initial_max_stream_data_uni) => tp.initial_max_stream_data_uni = try readVarint(val),
                @intFromEnum(Id.initial_max_streams_bidi) => tp.initial_max_streams_bidi = try readVarint(val),
                @intFromEnum(Id.initial_max_streams_uni) => tp.initial_max_streams_uni = try readVarint(val),
                @intFromEnum(Id.ack_delay_exponent) => tp.ack_delay_exponent = try readVarint(val),
                @intFromEnum(Id.max_ack_delay) => tp.max_ack_delay = try readVarint(val),
                @intFromEnum(Id.disable_active_migration) => {
                    if (val.len != 0) return error.Malformed;
                    tp.disable_active_migration = true;
                },
                @intFromEnum(Id.active_connection_id_limit) => tp.active_connection_id_limit = try readVarint(val),
                @intFromEnum(Id.initial_source_connection_id) => {
                    if (tp.initial_source_connection_id != null) return error.Duplicate;
                    tp.initial_source_connection_id = try alloc.dupe(u8, val);
                },
                @intFromEnum(Id.retry_source_connection_id) => {
                    if (tp.retry_source_connection_id != null) return error.Duplicate;
                    tp.retry_source_connection_id = try alloc.dupe(u8, val);
                },
                @intFromEnum(Id.preferred_address) => {
                    if (tp.preferred_address_raw != null) return error.Duplicate;
                    // Minimal structural check: must be at least IPv4+port+IPv6+port+cid_len+token (4+2+16+2+1+16=41)
                    if (val.len < 41) return error.Malformed;
                    tp.preferred_address_raw = try alloc.dupe(u8, val);
                },
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
