// MIT License
// Minimal ASN.1 DER decoder utilities used by X.509 parsing.
const std = @import("std");

pub const TagClass = enum { universal, application, context, private };

pub fn tagClass(b: u8) TagClass {
    return switch (b >> 6) {
        0 => .universal,
        1 => .application,
        2 => .context,
        else => .private,
    };
}
pub fn isConstructed(b: u8) bool {
    return (b & 0x20) != 0;
}
pub fn tagNumber(b: u8) u8 {
    return b & 0x1f;
}

pub const Decoder = struct {
    buf: []const u8,
    off: usize = 0,

    pub fn init(buf: []const u8) Decoder {
        return .{ .buf = buf, .off = 0 };
    }

    fn readByte(self: *Decoder) !u8 {
        if (self.off >= self.buf.len) return error.Truncated;
        const b = self.buf[self.off];
        self.off += 1;
        return b;
    }

    fn readLen(self: *Decoder) !usize {
        const b = try self.readByte();
        if ((b & 0x80) == 0) return b; // short form
        const n = b & 0x7f;
        if (n == 0) return error.IndefiniteLength;
        if (n > 8) return error.LengthTooLarge;
        var val: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            val = (val << 8) | try self.readByte();
        }
        return val;
    }

    pub fn nextHeader(self: *Decoder) !struct { tag: u8, len: usize, hdr_len: usize } {
        const start = self.off;
        const tag = try self.readByte();
        const len = try self.readLen();
        return .{ .tag = tag, .len = len, .hdr_len = self.off - start };
    }

    pub fn readTLV(self: *Decoder) !struct { tag: u8, val: []const u8 } {
        const h = try self.nextHeader();
        if (self.off + h.len > self.buf.len) return error.Truncated;
        const val = self.buf[self.off .. self.off + h.len];
        self.off += h.len;
        return .{ .tag = h.tag, .val = val };
    }

    pub fn readSequence(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 16 or !isConstructed(tlv.tag))
            return error.UnexpectedTag;
        return tlv.val;
    }

    pub fn readInteger(self: *Decoder) !u64 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 2)
            return error.UnexpectedTag;
        // Big-endian two's complement; support non-negative values up to 64 bits.
        var v: u64 = 0;
        for (tlv.val) |b| {
            v = (v << 8) | b;
        }
        return v;
    }

    pub fn readOctetString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 4)
            return error.UnexpectedTag;
        return tlv.val;
    }

    pub fn readBitString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 3)
            return error.UnexpectedTag;
        if (tlv.val.len == 0) return error.Truncated;
        const unused = tlv.val[0];
        if (unused > 7) return error.InvalidBitString;
        // Return payload without the initial 'unused bits' byte.
        return tlv.val[1..];
    }

    pub fn readOID(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 6)
            return error.UnexpectedTag;
        return tlv.val; // caller interprets if needed
    }

    pub fn readUtf8String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 12)
            return error.UnexpectedTag;
        return tlv.val;
    }

    pub fn readIa5String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 22)
            return error.UnexpectedTag;
        return tlv.val;
    }
};
