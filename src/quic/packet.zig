//! QUIC packet encoding helpers (simplified). RFC 9000 long/short headers.
//! MIT License
const std = @import("std");
const varint = @import("varint.zig");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");

pub const PacketNumber = u64;

pub const LongHeaderType = enum { Initial, Handshake };

pub const LongHeader = struct {
    ty: LongHeaderType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: PacketNumber = 1,
    token: []const u8 = &[_]u8{}, // Initial only
    payload: []const u8, // already-encoded frames

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
        var be: [4]u8 = .{ @as(u8, @intCast(self.version >> 24)), @as(u8, @intCast((self.version >> 16) & 0xff)), @as(u8, @intCast((self.version >> 8) & 0xff)), @as(u8, @intCast(self.version & 0xff)) };
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
        // Length: pn_len + payload length (ignore tag)
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

pub const ShortHeader = struct {
    dcid: []const u8 = &[_]u8{},
    packet_number: PacketNumber = 1,
    payload: []const u8,

    pub fn encode(self: ShortHeader, w: anytype) !usize {
        // First byte short header: 0b0100_0000 (fixed bit set)
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

/// Compute initial client/server traffic keys for QUIC v1/v2 given DCID bytes.
pub fn derive_initial_keys(version_v2: bool, dcid: []const u8) struct {
    client: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
    server: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
} {
    const initial = ks.deriveInitialSecret(version_v2, dcid);
    const pair = ks.deriveClientServerInitial(initial);
    return .{
        .client = if (version_v2) ks.deriveKeyIvHpV2(pair.client) else ks.deriveKeyIvHp(pair.client),
        .server = if (version_v2) ks.deriveKeyIvHpV2(pair.server) else ks.deriveKeyIvHp(pair.server),
    };
}

pub const InitialKeys = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };

/// Build a fully protected Initial packet (byte-exact) using AES-128-GCM.
/// Returns the serialized packet bytes in the provided allocator-backed ArrayList.
pub fn encodeInitialProtected(
    alloc: std.mem.Allocator,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    packet_number: u32,
    packet_number_len: u3, // 1..4
    payload_plaintext: []const u8,
    keys: InitialKeys,
) ![]u8 {
    if (packet_number_len < 1 or packet_number_len > 4) return error.InvalidPacketNumberLength;

    var buf = std.ArrayList(u8).init(alloc);
    errdefer buf.deinit();

    // Header first byte: Long header, Initial type, PN len bits
    const type_bits: u8 = 0x00; // Initial
    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    const first: u8 = 0xc0 | type_bits | pn_bits;

    // We'll build header_prefix first to compute AAD
    const w = buf.writer();
    try w.writeByte(first);
    var be_ver: [4]u8 = .{ @as(u8, @intCast(version >> 24)), @as(u8, @intCast((version >> 16) & 0xff)), @as(u8, @intCast((version >> 8) & 0xff)), @as(u8, @intCast(version & 0xff)) };
    try w.writeAll(&be_ver);
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);

    if (token.len > 0) {
        var tbuf: [8]u8 = undefined;
        const tl = try varint.encode(token.len, &tbuf);
        try w.writeAll(tbuf[0..tl]);
        try w.writeAll(token);
    } else {
        // zero-length token varint
        var tbuf: [1]u8 = .{0x00};
        try w.writeAll(&tbuf);
    }

    // Length varint: pn_len + ciphertext_len
    const ct_len = payload_plaintext.len + 16;
    const length_value: usize = @as(usize, packet_number_len) + ct_len;
    var lbuf: [8]u8 = undefined;
    const ll = try varint.encode(length_value, &lbuf);
    try w.writeAll(lbuf[0..ll]);

    // Remember header_prefix slice (start of buffer to end of length varint)
    const header_prefix = buf.items;

    // PN bytes big-endian truncated to packet_number_len
    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((packet_number >> 24) & 0xff)),
        @as(u8, @intCast((packet_number >> 16) & 0xff)),
        @as(u8, @intCast((packet_number >> 8) & 0xff)),
        @as(u8, @intCast(packet_number & 0xff)),
    };
    // take the last packet_number_len bytes
    const pn_slice = pn_be_full[4 - packet_number_len .. 4];
    try w.writeAll(pn_slice);

    // Prepare ciphertext buffer
    const out_cipher_idx = buf.items.len;
    try buf.ensureTotalCapacity(out_cipher_idx + ct_len);
    // Important: append zeros to reserve and then fill in place
    try buf.appendNTimes(0, ct_len);

    // Protect payload and apply header protection (mutates first byte and PN in-place)
    var header_first: u8 = first;
    // header_first is at items[0]; We'll let crypto mutate header_first then write it back.
    var pn_mut: [4]u8 = .{0} ** 4;
    @memcpy(pn_mut[0..packet_number_len], pn_slice);

    const out_cipher = buf.items[out_cipher_idx .. out_cipher_idx + ct_len];
    const suite = crypto.AeadSuite.aes_128_gcm;
    const written = try crypto.protectInitial(
        suite,
        &keys.key,
        &keys.iv,
        &keys.hp,
        packet_number,
        &header_first,
        pn_mut[0..packet_number_len],
        header_prefix,
        payload_plaintext,
        out_cipher,
    );
    std.debug.assert(written == ct_len);

    // Write back mutated header first byte and PN
    buf.items[0] = header_first;
    @memcpy(buf.items[header_prefix.len .. header_prefix.len + packet_number_len], pn_mut[0..packet_number_len]);

    return buf.toOwnedSlice();
}

pub const DecodedInitial = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u32,
    packet_number_len: u3,
    payload: []u8,
};

/// Parse and remove protection from an Initial packet using AES-128-GCM.
pub fn decodeInitialProtected(
    alloc: std.mem.Allocator,
    packet_bytes: []const u8,
    keys: InitialKeys,
) !DecodedInitial {
    if (packet_bytes.len < 7) return error.Truncated;
    var i: usize = 0;
    const first = packet_bytes[i];
    i += 1;
    if ((first & 0x80) == 0) return error.InvalidHeader; // not long header
    const pn_len: u3 = @as(u3, (first & 0x03)) + 1;

    // Version
    if (i + 4 > packet_bytes.len) return error.Truncated;
    const version: u32 = (@as(u32, packet_bytes[i]) << 24) | (@as(u32, packet_bytes[i + 1]) << 16) | (@as(u32, packet_bytes[i + 2]) << 8) | @as(u32, packet_bytes[i + 3]);
    i += 4;

    // DCID
    if (i >= packet_bytes.len) return error.Truncated;
    const dcid_len = packet_bytes[i];
    i += 1;
    if (i + dcid_len > packet_bytes.len) return error.Truncated;
    const dcid = packet_bytes[i .. i + dcid_len];
    i += dcid_len;

    // SCID
    if (i >= packet_bytes.len) return error.Truncated;
    const scid_len = packet_bytes[i];
    i += 1;
    if (i + scid_len > packet_bytes.len) return error.Truncated;
    const scid = packet_bytes[i .. i + scid_len];
    i += scid_len;

    // Token (varint length + value)
    // Decode varint length
    const rem1 = packet_bytes[i..];
    const tok_dec = try varint.decode(rem1);
    i += tok_dec.n + @as(usize, tok_dec.value);
    if (i > packet_bytes.len) return error.Truncated;

    // Length varint
    const rem2 = packet_bytes[i..];
    const len_dec = try varint.decode(rem2);
    i += len_dec.n;

    const header_prefix = packet_bytes[0..i];

    // PN bytes (masked)
    if (i + pn_len > packet_bytes.len) return error.Truncated;
    var pn_mut = [_]u8{0} ** 4;
    @memcpy(pn_mut[0..pn_len], packet_bytes[i .. i + pn_len]);
    i += pn_len;

    const ct_and_tag = packet_bytes[i .. i + (len_dec.value - pn_len)];

    // Unprotect header to recover PN and first byte
    var header_first = first;
    var aad = std.ArrayList(u8).init(alloc);
    defer aad.deinit();
    try aad.appendSlice(header_prefix);
    try aad.appendSlice(pn_mut[0..pn_len]);

    const pt = try alloc.alloc(u8, ct_and_tag.len - 16);
    errdefer alloc.free(pt);

    _ = aad.items; // not used directly; unprotectInitial rebuilds AAD; keep for clarity
    _ = try crypto.unprotectInitial(
        crypto.AeadSuite.aes_128_gcm,
        &keys.key,
        &keys.iv,
        &keys.hp,
        @as(u64, @intCast(
        // Recover pseudo-full PN from truncated; for tests, PN < 2^32 and given directly.
        (@as(u32, pn_mut[0]) << 24) | (@as(u32, pn_mut[1]) << 16) | (@as(u32, pn_mut[2]) << 8) | (@as(u32, pn_mut[3])))),
        &header_first,
        pn_mut[0..pn_len],
        header_prefix,
        ct_and_tag,
        pt,
    );

    // Compute PN value from unmasked pn_mut bytes (big-endian)
    var pn_val: u32 = 0;
    var j: usize = 0;
    while (j < pn_len) : (j += 1) pn_val = (pn_val << 8) | pn_mut[j];

    return .{ .version = version, .dcid = dcid, .scid = scid, .packet_number = pn_val, .packet_number_len = pn_len, .payload = pt };
}
