// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC packet header encoding for test/diagnostic use.
//!
//! RFC 9000 §17.2: Long Header
//! RFC 9000 §17.3: Short Header

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// Serializable Long Header structure used by helpers for tests/tools. Layout
/// matches RFC 9000 §17.2 including token length, Length varint, and packet
/// number truncation bits in the first byte.
pub const LongHeader = struct {
    ty: types.LongHeaderType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: types.PacketNumber = 1,
    token: []const u8 = &[_]u8{}, // Initial only
    payload: []const u8, // already-encoded frames

    /// Serialize this long header into the provided writer; returns bytes written.
    /// RFC 9000 §17.2: Long Header Packet Format
    pub fn encode(self: LongHeader, w: anytype) !usize {
        // First byte: Long Header (1), Fixed bit (1), Type (2 bits), PN length (2 bits)
        // Types: Initial=0, Handshake=2
        const type_bits: u8 = switch (self.ty) {
            .Initial => 0x00,
            .Handshake => 0x20,
        };
        const pn_len_bits: u8 = 0x01; // 2-byte PN (encoded as 01 -> length 2)
        const first = 0xc0 | type_bits | pn_len_bits; // 1100_0000 | type | pnlen
        try w.writeByte(first);

        // Version
        var be: [4]u8 = .{
            @as(u8, @intCast(self.version >> 24)),
            @as(u8, @intCast((self.version >> 16) & 0xff)),
            @as(u8, @intCast((self.version >> 8) & 0xff)),
            @as(u8, @intCast(self.version & 0xff)),
        };
        try w.writeAll(&be);

        // DCID Len + DCID
        try w.writeByte(@as(u8, @intCast(self.dcid.len)));
        try w.writeAll(self.dcid);

        // SCID Len + SCID
        try w.writeByte(@as(u8, @intCast(self.scid.len)));
        try w.writeAll(self.scid);

        var total: usize = 1 + 4 + 1 + self.dcid.len + 1 + self.scid.len;

        // Initial token (only for Initial)
        if (self.ty == .Initial) {
            var buf: [8]u8 = undefined;
            const tl = try varint.encode(self.token.len, &buf);
            try w.writeAll(buf[0..tl]);
            try w.writeAll(self.token);
            total += tl + self.token.len;
        }

        // Length: pn_len + payload length (ignore tag) per RFC 9000 §17.2.4.
        var buf2: [8]u8 = undefined;
        const pn_len: usize = 2; // as chosen above
        const length = pn_len + self.payload.len;
        const ll = try varint.encode(length, &buf2);
        try w.writeAll(buf2[0..ll]);
        total += ll;

        // Packet Number (2 bytes)
        const pn = @as(u16, @intCast(self.packet_number & 0xffff));
        try w.writeByte(@as(u8, @intCast((pn >> 8) & 0xff)));
        try w.writeByte(@as(u8, @intCast(pn & 0xff)));
        total += 2;

        // Payload
        try w.writeAll(self.payload);
        total += self.payload.len;

        return total;
    }
};

/// Serializable Short Header structure used by helpers for tests/tools.
/// NOTE: this helper is intentionally simplified for diagnostics—RFC 9000 §17.3
/// requires truncated packet numbers (1–4 bytes) following the destination CID,
/// whereas this helper writes a full QUIC varint for ease of use in tests.
pub const ShortHeader = struct {
    dcid: []const u8 = &[_]u8{},
    packet_number: types.PacketNumber = 1,
    payload: []const u8,

    /// Serialize this short header into the provided writer; returns bytes written.
    /// RFC 9000 §17.3: Short Header Packet Format (simplified for tests)
    pub fn encode(self: ShortHeader, w: anytype) !usize {
        // First byte short header: 0b0100_0000 (fixed bit set) per RFC 9000 §17.3.
        const first: u8 = 0x40;
        try w.writeByte(first);
        var total: usize = 1;

        // Simplified: write full PN as varint (not spec-accurate)
        var buf: [8]u8 = undefined;
        const pn = try varint.encode(self.packet_number, &buf);
        try w.writeAll(buf[0..pn]);
        total += pn;

        try w.writeAll(self.payload);
        total += self.payload.len;

        return total;
    }
};
