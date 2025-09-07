//! QUIC packet encoding helpers (simplified). RFC 9000 long/short headers.
//! MIT License
const std = @import("std");
const varint = @import("quic_varint");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const builtin = @import("builtin");

/// Debug helper: dump bytes when running inside tests.
fn dumpBytes(label: []const u8, bytes: []const u8) void {
    if (!builtin.is_test) return;
    var list = std.ArrayList(u8){};
    defer list.deinit(std.heap.page_allocator);
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        _ = list.writer(std.heap.page_allocator).print("{x:0>2}", .{bytes[i]}) catch break;
        if (i + 1 < bytes.len) _ = list.append(std.heap.page_allocator, ' ') catch break;
    }
    std.debug.print("{s}: {s}\n", .{ label, list.items });
}

/// Packet number type alias.
pub const PacketNumber = u64;

/// Long header type discriminator used when encoding/decoding.
pub const LongHeaderType = enum { Initial, Handshake };

/// Serializable Long Header structure used by helpers for tests/tools.
pub const LongHeader = struct {
    ty: LongHeaderType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: PacketNumber = 1,
    token: []const u8 = &[_]u8{}, // Initial only
    payload: []const u8, // already-encoded frames

    /// Serialize this long header into the provided writer; returns bytes written.
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

/// Serializable Short Header structure used by helpers for tests/tools.
pub const ShortHeader = struct {
    dcid: []const u8 = &[_]u8{},
    packet_number: PacketNumber = 1,
    payload: []const u8,

    /// Serialize this short header into the provided writer; returns bytes written.
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

/// Keys used for any protected packet (Initial/Handshake/1-RTT)
pub const AeadKeys = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };

/// Encode a protected short-header packet carrying payload with given PN length (1..4).
pub fn encodeShortProtected(
    alloc: std.mem.Allocator,
    dcid: []const u8,
    packet_number: u32,
    packet_number_len: u3,
    payload_plaintext: []const u8,
    keys: AeadKeys,
    key_phase: bool,
) ![]u8 {
    if (packet_number_len < 1 or packet_number_len > 4) return error.InvalidPacketNumberLength;

    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);

    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    var header_first: u8 = 0x40 | pn_bits; // short header with pn len bits
    if (key_phase) header_first |= 0x04; // key phase bit (bit 2)

    const w = buf.writer(alloc);
    try w.writeByte(header_first);
    // header_prefix for short = DCID (QUIC short header carries DCID)
    try w.writeAll(dcid);
    const header_prefix_len = dcid.len;

    // PN BE truncated
    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((packet_number >> 24) & 0xff)),
        @as(u8, @intCast((packet_number >> 16) & 0xff)),
        @as(u8, @intCast((packet_number >> 8) & 0xff)),
        @as(u8, @intCast(packet_number & 0xff)),
    };
    const pn_slice = pn_be_full[4 - packet_number_len .. 4];
    var pn_trunc_val: u32 = 0;
    {
        var k: usize = 0;
        while (k < packet_number_len) : (k += 1) pn_trunc_val = (pn_trunc_val << 8) | pn_slice[k];
    }
    var pn_mut: [4]u8 = .{0} ** 4;
    @memcpy(pn_mut[0..packet_number_len], pn_slice);
    try w.writeAll(pn_slice);

    // AEAD encrypt payload
    const ct_len = payload_plaintext.len + 16;
    const out_cipher_idx = buf.items.len;
    try buf.ensureTotalCapacity(alloc, out_cipher_idx + ct_len);
    try buf.appendNTimes(alloc, 0, ct_len);
    const out_cipher = buf.items[out_cipher_idx .. out_cipher_idx + ct_len];

    const suite = crypto.AeadSuite.aes_128_gcm;
    const written = try crypto.protectInitial(
        suite,
        &keys.key,
        &keys.iv,
        &keys.hp,
        @as(u64, pn_trunc_val),
        &header_first,
        pn_mut[0..packet_number_len],
        buf.items[1 .. 1 + header_prefix_len],
        payload_plaintext,
        out_cipher,
    );
    std.debug.assert(written == ct_len);

    // Write back mutated header and PN
    buf.items[0] = header_first;
    const pn_offset = 1 + header_prefix_len;
    @memcpy(buf.items[pn_offset .. pn_offset + packet_number_len], pn_mut[0..packet_number_len]);

    return buf.toOwnedSlice(alloc);
}

/// Result of decoding a protected short header packet.
pub const DecodedShort = struct {
    packet_number: u32,
    packet_number_len: u3,
    payload: []u8,
};

/// Decode and unprotect a short-header packet given dcid_len for header parsing.
pub fn decodeShortProtected(
    alloc: std.mem.Allocator,
    packet_bytes: []const u8,
    dcid_len: usize,
    keys: AeadKeys,
) !DecodedShort {
    if (packet_bytes.len < 1 + dcid_len + 1) return error.Truncated;
    var i: usize = 0;
    var header_first_masked: u8 = packet_bytes[0];
    if ((header_first_masked & 0x80) != 0) return error.InvalidHeader; // not short
    i += 1;
    const header_prefix = packet_bytes[i .. i + dcid_len];
    i += dcid_len;

    // Packet number starts here
    const pn_start = i;

    // Copy up to 4 masked PN bytes from the packet. Do NOT rely on masked PN length bits.
    var pn_masked4: [4]u8 = .{0} ** 4;
    const avail = @min(@as(usize, 4), packet_bytes.len - pn_start);
    if (avail == 0) return error.Truncated;
    @memcpy(pn_masked4[0..avail], packet_bytes[pn_start .. pn_start + avail]);

    // Sample at PN+4 (RFC 9001 §5.4.3)
    if (pn_start + 4 + 16 > packet_bytes.len) return error.Truncated;
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet_bytes[pn_start + 4 .. pn_start + 4 + 16]);

    // Determine actual PN length by unmasking header+PN on a temporary copy
    var tmp_first = header_first_masked;
    var tmp_pn: [4]u8 = pn_masked4;
    const pn_len: u3 = try crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &keys.hp, &sample16, &tmp_first, &tmp_pn);

    // Ciphertext+tag begins after PN (using actual pn_len)
    const ct = packet_bytes[pn_start + pn_len ..];
    if (ct.len < 16) return error.Truncated;

    // Decrypt while letting unprotectInitial perform the unmasking using masked header/pn
    const payload = try alloc.alloc(u8, ct.len - 16);
    errdefer alloc.free(payload);

    _ = try crypto.unprotectInitial(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        &keys.hp,
        &header_first_masked,
        pn_masked4[0..pn_len],
        header_prefix,
        &sample16,
        ct,
        payload,
        0, // No expansion for test packets
    );

    // Compute PN value from the previously unmasked temporary PN bytes
    var pn_val: u32 = 0;
    var j: usize = 0;
    while (j < pn_len) : (j += 1) pn_val = (pn_val << 8) | tmp_pn[j];

    return .{ .packet_number = pn_val, .packet_number_len = pn_len, .payload = payload };
}

/// Compute initial client/server traffic keys for QUIC v1/v2 given DCID bytes.
pub fn derive_initial_keys(version_v2: bool, dcid: []const u8) struct {
    client: InitialKeys,
    server: InitialKeys,
} {
    const initial = ks.deriveInitialSecret(version_v2, dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const client_keys: InitialKeys = if (version_v2) blk: {
        const t = ks.deriveKeyIvHpV2(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk: {
        const t = ks.deriveKeyIvHp(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };
    const server_keys: InitialKeys = if (version_v2) blk: {
        const t = ks.deriveKeyIvHpV2(pair.server);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk: {
        const t = ks.deriveKeyIvHp(pair.server);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };
    return .{ .client = client_keys, .server = server_keys };
}

/// Convenience helper returning RX/TX Initial keys oriented by endpoint role.
/// For a server, RX=client keys (decrypt Client Initial) and TX=server keys.
/// For a client, RX=server keys (decrypt Server Initials) and TX=client keys.
pub fn initialAeadKeys(version_v2: bool, is_server: bool, dcid: []const u8) struct { rx: InitialKeys, tx: InitialKeys } {
    const both = derive_initial_keys(version_v2, dcid);
    return if (is_server)
        .{ .rx = both.client, .tx = both.server }
    else
        .{ .rx = both.server, .tx = both.client };
}

/// Initial/Handshake key material used by long header helpers.
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

    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);

    // Header first byte: Long header, Initial type, PN len bits
    const type_bits: u8 = 0x00; // Initial
    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    const first: u8 = 0xc0 | type_bits | pn_bits;

    // We'll build header_prefix first to compute AAD
    const w = buf.writer(alloc);
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

    // Remember header_prefix length (after first header byte) to end of length varint
    const header_prefix_len = buf.items.len - 1; // exclude first byte

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
    try buf.ensureTotalCapacity(alloc, out_cipher_idx + ct_len);
    // Important: append zeros to reserve and then fill in place
    try buf.appendNTimes(alloc, 0, ct_len);

    // Protect payload and apply header protection (mutates first byte and PN in-place)
    var header_first: u8 = first;
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
        buf.items[1 .. 1 + header_prefix_len],
        payload_plaintext,
        out_cipher,
    );
    std.debug.assert(written == ct_len);

    // Write back mutated header first byte and PN
    buf.items[0] = header_first;
    const pn_offset = 1 + header_prefix_len; // after first + header_prefix
    @memcpy(buf.items[pn_offset .. pn_offset + packet_number_len], pn_mut[0..packet_number_len]);

    return buf.toOwnedSlice(alloc);
}

/// Result of decoding an Initial packet.
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

    const header_prefix = packet_bytes[1..i]; // after first byte up to PN

    // PN bytes (masked) begin here
    const pn_offset = i;
    if (pn_offset + 1 > packet_bytes.len) return error.Truncated;

    // Copy up to 4 masked PN bytes (may include ciphertext bytes beyond actual PN)
    var pn_masked4 = [_]u8{0} ** 4;
    const avail = @min(@as(usize, 4), packet_bytes.len - pn_offset);
    @memcpy(pn_masked4[0..avail], packet_bytes[pn_offset .. pn_offset + avail]);

    // Build AES HP sample: 16 bytes starting at PN start + 4 (RFC 9001 §5.4.3)
    const sample_start = pn_offset + 4;
    const end_total = pn_offset + @as(usize, len_dec.value);
    if (sample_start + 16 > end_total or end_total > packet_bytes.len) return error.Truncated;
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet_bytes[sample_start .. sample_start + 16]);

    // Unmask to recover header_first and actual PN bytes/length
    var header_first = first;
    const pn_len_actual: u3 = try crypto.unmaskLongHeaderAndPn(
        crypto.AeadSuite.aes_128_gcm,
        &keys.hp,
        &sample16,
        &header_first,
        &pn_masked4,
    );

    // Compute ciphertext+tag slice using actual PN length
    const ct_begin = pn_offset + pn_len_actual;
    const ct_end = end_total;
    if (ct_end < ct_begin + 16) return error.Truncated;
    const ct_and_tag = packet_bytes[ct_begin..ct_end];

    // AAD = unmasked first byte || header_prefix || unmasked PN bytes
    var aad = std.ArrayList(u8){};
    defer aad.deinit(std.heap.page_allocator);
    try aad.append(std.heap.page_allocator, header_first);
    try aad.appendSlice(std.heap.page_allocator, header_prefix);
    try aad.appendSlice(std.heap.page_allocator, pn_masked4[0..pn_len_actual]);

    // Compute PN value (big-endian truncated)
    var pn_val: u32 = 0;
    var j2: usize = 0;
    while (j2 < pn_len_actual) : (j2 += 1) pn_val = (pn_val << 8) | pn_masked4[j2];

    if (builtin.is_test) {
        dumpBytes("DEC aad", aad.items);
        var nonce: [12]u8 = undefined;
        // Compute nonce = iv XOR pn_val (big-endian in last 8 bytes)
        @memcpy(nonce[0..], &keys.iv);
        var pn_be: [12]u8 = .{0} ** 12;
        const pn64: u64 = @as(u64, pn_val);
        pn_be[4] = @as(u8, @truncate(pn64 >> 56));
        pn_be[5] = @as(u8, @truncate(pn64 >> 48));
        pn_be[6] = @as(u8, @truncate(pn64 >> 40));
        pn_be[7] = @as(u8, @truncate(pn64 >> 32));
        pn_be[8] = @as(u8, @truncate(pn64 >> 24));
        pn_be[9] = @as(u8, @truncate(pn64 >> 16));
        pn_be[10] = @as(u8, @truncate(pn64 >> 8));
        pn_be[11] = @as(u8, @truncate(pn64));
        var k: usize = 0;
        while (k < 12) : (k += 1) nonce[k] ^= pn_be[k];
        dumpBytes("DEC nonce", &nonce);
        dumpBytes("DEC pn_bytes", pn_masked4[0..pn_len_actual]);
    }

    const pt = try alloc.alloc(u8, ct_and_tag.len - 16);
    errdefer alloc.free(pt);

    _ = try crypto.aeadDecrypt(
        crypto.AeadSuite.aes_128_gcm,
        &keys.key,
        &keys.iv,
        pn_val,
        aad.items,
        ct_and_tag,
        pt,
    );

    return .{ .version = version, .dcid = dcid, .scid = scid, .packet_number = pn_val, .packet_number_len = pn_len_actual, .payload = pt };
}

/// Build a fully protected Handshake packet using AES-128-GCM.
pub fn encodeHandshakeProtected(
    alloc: std.mem.Allocator,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u32,
    packet_number_len: u3, // 1..4
    payload_plaintext: []const u8,
    keys: InitialKeys,
) ![]u8 {
    if (packet_number_len < 1 or packet_number_len > 4) return error.InvalidPacketNumberLength;

    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);

    // Header first byte: Long header, Handshake type (0x20), PN len bits
    const type_bits: u8 = 0x20; // Handshake
    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    const first: u8 = 0xc0 | type_bits | pn_bits;

    const w = buf.writer(alloc);
    try w.writeByte(first);
    var be_ver: [4]u8 = .{ @as(u8, @intCast(version >> 24)), @as(u8, @intCast((version >> 16) & 0xff)), @as(u8, @intCast((version >> 8) & 0xff)), @as(u8, @intCast(version & 0xff)) };
    try w.writeAll(&be_ver);
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);

    // Handshake packets do not carry a token

    // Length varint: pn_len + ciphertext_len
    const ct_len = payload_plaintext.len + 16;
    const length_value: usize = @as(usize, packet_number_len) + ct_len;
    var lbuf: [8]u8 = undefined;
    const ll = try varint.encode(length_value, &lbuf);
    try w.writeAll(lbuf[0..ll]);

    const header_prefix_len = buf.items.len - 1;

    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((packet_number >> 24) & 0xff)),
        @as(u8, @intCast((packet_number >> 16) & 0xff)),
        @as(u8, @intCast((packet_number >> 8) & 0xff)),
        @as(u8, @intCast(packet_number & 0xff)),
    };
    const pn_slice = pn_be_full[4 - packet_number_len .. 4];
    try w.writeAll(pn_slice);

    const out_cipher_idx = buf.items.len;
    try buf.ensureTotalCapacity(alloc, out_cipher_idx + ct_len);
    try buf.appendNTimes(alloc, 0, ct_len);

    var header_first: u8 = first;
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
        buf.items[1 .. 1 + header_prefix_len],
        payload_plaintext,
        out_cipher,
    );
    std.debug.assert(written == ct_len);

    buf.items[0] = header_first;
    const pn_offset = 1 + header_prefix_len;
    @memcpy(buf.items[pn_offset .. pn_offset + packet_number_len], pn_mut[0..packet_number_len]);

    return buf.toOwnedSlice(alloc);
}

/// Decoded representation of a Version Negotiation packet.
pub const DecodedVN = struct {
    dcid: []const u8,
    scid: []const u8,
    versions: []const u32,
};

/// Encode a Version Negotiation (VN) packet with Version=0 and provided version list.
/// Returned slice is owned by alloc.
pub fn encodeVersionNegotiation(alloc: std.mem.Allocator, dcid: []const u8, scid: []const u8, versions: []const u32) ![]u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);
    // Simplest VN first byte with Long Header bit set and fixed bit set (0x80)
    try w.writeByte(0x80);
    // Version = 0x00000000
    try w.writeAll(&[_]u8{ 0, 0, 0, 0 });
    // DCID Len + DCID
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);
    // SCID Len + SCID
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);
    // Supported versions (4-byte big-endian each)
    var i: usize = 0;
    while (i < versions.len) : (i += 1) {
        const v = versions[i];
        var be: [4]u8 = .{
            @as(u8, @intCast((v >> 24) & 0xff)),
            @as(u8, @intCast((v >> 16) & 0xff)),
            @as(u8, @intCast((v >> 8) & 0xff)),
            @as(u8, @intCast(v & 0xff)),
        };
        try w.writeAll(&be);
    }
    return buf.toOwnedSlice(alloc);
}

/// Decode a Version Negotiation (VN) packet (Version=0x00000000).
/// Returns slices into the original packet_bytes; caller must keep it alive.
pub fn decodeVersionNegotiation(alloc: std.mem.Allocator, packet_bytes: []const u8) !DecodedVN {
    if (packet_bytes.len < 7) return error.Truncated;
    var i: usize = 0;
    const first = packet_bytes[i];
    i += 1;
    if ((first & 0x80) == 0) return error.InvalidHeader; // must be long form
    // Version must be 0
    if (i + 4 > packet_bytes.len) return error.Truncated;
    const ver: u32 = (@as(u32, packet_bytes[i]) << 24) | (@as(u32, packet_bytes[i + 1]) << 16) | (@as(u32, packet_bytes[i + 2]) << 8) | @as(u32, packet_bytes[i + 3]);
    i += 4;
    if (ver != 0) return error.NotVersionNegotiation;
    // DCID
    if (i >= packet_bytes.len) return error.Truncated;
    const dcid_len: usize = packet_bytes[i];
    i += 1;
    if (i + dcid_len > packet_bytes.len) return error.Truncated;
    const dcid = packet_bytes[i .. i + dcid_len];
    i += dcid_len;
    // SCID
    if (i >= packet_bytes.len) return error.Truncated;
    const scid_len: usize = packet_bytes[i];
    i += 1;
    if (i + scid_len > packet_bytes.len) return error.Truncated;
    const scid = packet_bytes[i .. i + scid_len];
    i += scid_len;
    // Versions: 4-byte big-endian values till end
    if ((packet_bytes.len - i) % 4 != 0) return error.MalformedVersions;
    const count = (packet_bytes.len - i) / 4;
    var vers = try alloc.alloc(u32, count);
    errdefer alloc.free(vers);
    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const o = i + idx * 4;
        vers[idx] = (@as(u32, packet_bytes[o]) << 24) | (@as(u32, packet_bytes[o + 1]) << 16) | (@as(u32, packet_bytes[o + 2]) << 8) | @as(u32, packet_bytes[o + 3]);
    }
    return .{ .dcid = dcid, .scid = scid, .versions = vers };
}

/// Basic downgrade protection per RFC 9000 §6.1: ignore VN if it lists the
/// version originally attempted by the client.
pub fn shouldAcceptVersionNegotiation(original_version: u32, vn_versions: []const u32) bool {
    for (vn_versions) |v| if (v == original_version) return false;
    return true;
}

/// Common QUIC version constants
pub const QUIC_V1: u32 = 0x00000001;
/// QUIC v2 Version value per RFC 9369.
pub const QUIC_V2: u32 = 0x709a50c4;

/// Encode a 0-RTT packet (client -> server early data).
/// Uses 0-RTT keys derived from resumption secret.
pub fn encode0RTTProtected(
    alloc: std.mem.Allocator,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    pn_len: u8,
    payload: []const u8,
    keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
) ![]u8 {
    // 0-RTT uses long header type 0x01
    const ty: u2 = 0x01;
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    // First byte: long header (0x80) | fixed bit (0x40) | type (0x01 << 4) | reserved | pn_len
    const first: u8 = 0xc0 | (@as(u8, ty) << 4) | ((pn_len - 1) & 0x03);
    try w.writeByte(first);

    // Version
    var be: [4]u8 = .{ @as(u8, @intCast(version >> 24)), @as(u8, @intCast((version >> 16) & 0xff)), @as(u8, @intCast((version >> 8) & 0xff)), @as(u8, @intCast(version & 0xff)) };
    try w.writeAll(&be);

    // DCID
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);

    // SCID
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);

    // Length field (varint)
    var len_buf: [8]u8 = undefined;
    const payload_with_tag_len = payload.len + 16; // AEAD tag
    const total_len = pn_len + payload_with_tag_len;
    const len_bytes = try varint.encode(total_len, &len_buf);
    try w.writeAll(len_buf[0..len_bytes]);

    // Packet number (truncated)
    const pn_offset = buf.items.len;
    var pn_bytes: [4]u8 = undefined;
    for (0..pn_len) |i| {
        pn_bytes[i] = @as(u8, @intCast((packet_number >> @intCast(8 * (pn_len - 1 - i))) & 0xff));
    }
    try w.writeAll(pn_bytes[0..pn_len]);

    // Encrypt payload
    const header_len = buf.items.len;
    const aad = buf.items[0..header_len];

    // Nonce derived by AEAD helper from base IV and packet_number; pass base IV and pn separately.

    // Encrypt
    const ct_start = buf.items.len;
    try buf.ensureTotalCapacity(alloc, ct_start + payload.len + 16);
    buf.items.len = ct_start + payload.len + 16;

    // aeadEncrypt(suite, key, iv, packet_number, aad, plaintext, out)
    _ = try crypto.aeadEncrypt(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        packet_number,
        aad,
        payload,
        buf.items[ct_start..],
    );

    // Apply header protection
    // For long headers, use pn_offset + 4 as constant sample start (permits hp removal without knowing PN len yet)
    const sample_offset = pn_offset + 4;
    if (sample_offset + 16 <= buf.items.len) {
        // Build HP sample (16 bytes)
        var sample16: [16]u8 = undefined;
        @memcpy(&sample16, buf.items[sample_offset .. sample_offset + 16]);
        // Apply header protection in place
        const header_first_ptr = &buf.items[0];
        const pn_slice = buf.items[pn_offset .. pn_offset + pn_len];
        crypto.headerProtect(.aes_128_gcm, &keys.hp, &sample16, header_first_ptr, pn_slice) catch {};
    }

    return buf.toOwnedSlice(alloc);
}

/// Decode and decrypt a 0-RTT packet.
pub fn decode0RTTProtected(
    alloc: std.mem.Allocator,
    packet: []const u8,
    keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 },
) !struct {
    packet_number: u64,
    payload: []u8,
} {
    if (packet.len < 20) return error.PacketTooShort;

    const first_masked = packet[0];
    if ((first_masked & 0x80) == 0) return error.NotLongHeader;
    if (((first_masked >> 4) & 0x03) != 0x01) return error.Not0RTT;

    var i: usize = 5;

    const dcid_len = packet[i];
    i += 1 + dcid_len;
    if (i >= packet.len) return error.PacketTooShort;

    const scid_len = packet[i];
    i += 1 + scid_len;
    if (i >= packet.len) return error.PacketTooShort;

    const len_result = varint.decode(packet[i..]) catch return error.InvalidLength;
    i += len_result.n;

    const pn_offset = i;

    var pn_masked4: [4]u8 = .{0} ** 4;
    const avail = @min(@as(usize, 4), packet.len - pn_offset);
    if (avail == 0) return error.PacketTooShort;
    @memcpy(pn_masked4[0..avail], packet[pn_offset .. pn_offset + avail]);

    const sample_start = pn_offset + 4;
    const end_total = pn_offset + @as(usize, len_result.value);
    if (sample_start + 16 > end_total or end_total > packet.len) return error.PacketTooShort;
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet[sample_start .. sample_start + 16]);

    var header_first = first_masked;
    const pn_len_actual: u3 = try crypto.unmaskLongHeaderAndPn(
        .aes_128_gcm,
        &keys.hp,
        &sample16,
        &header_first,
        &pn_masked4,
    );

    const ct_begin = pn_offset + pn_len_actual;
    const ct_end = end_total;
    if (ct_end < ct_begin + 16) return error.CiphertextTooShort;
    const ct_and_tag = packet[ct_begin..ct_end];

    var aad = std.ArrayList(u8){};
    defer aad.deinit(std.heap.page_allocator);
    try aad.append(std.heap.page_allocator, header_first);
    try aad.appendSlice(std.heap.page_allocator, packet[1..i]);
    try aad.appendSlice(std.heap.page_allocator, pn_masked4[0..pn_len_actual]);

    var pn_val: u64 = 0;
    var j: usize = 0;
    while (j < pn_len_actual) : (j += 1) pn_val = (pn_val << 8) | pn_masked4[j];

    const plaintext = try alloc.alloc(u8, ct_and_tag.len - 16);
    errdefer alloc.free(plaintext);

    _ = crypto.aeadDecrypt(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        pn_val,
        aad.items,
        ct_and_tag,
        plaintext,
    ) catch return error.DecryptionFailed;

    return .{ .packet_number = pn_val, .payload = plaintext };
}

/// Encode a Retry packet with integrity tag per RFC 9001/9369.
/// dcid = Destination Connection ID field in Retry (must equal client's Initial SCID)
/// scid = Source Connection ID chosen by server
/// odcid = client's Original DCID (from the Initial that prompted this Retry)
pub fn encodeRetry(alloc: std.mem.Allocator, version: u32, dcid: []const u8, scid: []const u8, odcid: []const u8, token: []const u8) ![]u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);
    // First byte: Long header, Retry type (0x30); PN length bits are 0 for Retry
    try w.writeByte(0xf0 | 0x30);
    // Version
    var be_ver: [4]u8 = .{ @as(u8, @intCast(version >> 24)), @as(u8, @intCast((version >> 16) & 0xff)), @as(u8, @intCast((version >> 8) & 0xff)), @as(u8, @intCast(version & 0xff)) };
    try w.writeAll(&be_ver);
    // DCID Len + DCID (equals client's SCID)
    try w.writeByte(@as(u8, @intCast(dcid.len)));
    try w.writeAll(dcid);
    // SCID Len + SCID
    try w.writeByte(@as(u8, @intCast(scid.len)));
    try w.writeAll(scid);
    // Token
    try w.writeAll(token);

    // Build Retry Pseudo-Packet AAD: ODCID Len + ODCID + (retry_without_tag)
    const retry_without_tag = buf.items[0..];

    // Compute version-specific Retry key/iv and tag
    const version_v2 = (version == QUIC_V2);
    const tag = crypto.computeRetryIntegrityTag(version_v2, odcid, retry_without_tag);

    try w.writeAll(&tag);
    return buf.toOwnedSlice(alloc);
}

/// Verify a received Retry packet integrity tag given the client's Original DCID.
/// Returns true if tag is valid for v1/v2 based on the Version field in the packet.
pub fn verifyRetry(odcid: []const u8, retry_packet: []const u8) bool {
    if (retry_packet.len < 5 + 1 + 1 + 16) return false;
    // Parse minimal fields to get Version, DCID/SCID lengths and locate tag
    const first = retry_packet[0];
    if ((first & 0x80) == 0) return false; // must be long
    // type must be Retry (0x30 in bits 4..5)
    const ty: u2 = @intCast((first >> 4) & 0x03);
    if (ty != 3) return false;
    const version: u32 = (@as(u32, retry_packet[1]) << 24) | (@as(u32, retry_packet[2]) << 16) | (@as(u32, retry_packet[3]) << 8) | @as(u32, retry_packet[4]);
    var i: usize = 5;
    if (i >= retry_packet.len) return false;
    const dcid_len = retry_packet[i];
    i += 1;
    if (i + dcid_len > retry_packet.len) return false;
    i += dcid_len;
    if (i >= retry_packet.len) return false;
    const scid_len = retry_packet[i];
    i += 1;
    if (i + scid_len > retry_packet.len) return false;
    i += scid_len;
    if (retry_packet.len < 16 or i > retry_packet.len - 16) return false;
    const end_wo_tag = retry_packet.len - 16;
    const retry_wo_tag = retry_packet[0..end_wo_tag];
    const tag = retry_packet[end_wo_tag..];
    const version_v2 = (version == QUIC_V2);
    const calc = crypto.computeRetryIntegrityTag(version_v2, odcid, retry_wo_tag);
    return std.mem.eql(u8, &calc, tag);
}
