// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC packet encoding helpers (simplified). RFC 9000 long/short headers.

const std = @import("std");
const varint = @import("quic_varint");
const ks = @import("quic_tls");
const crypto = @import("quic_crypto");
const builtin = @import("builtin");
const logger = @import("quic_logger");

// Phase57 debug state: only active in test builds to avoid global mutable state in production.
// SEC-12: Use threadlocal to prevent data races in multi-threaded contexts.
const phase57_dump_max: u8 = 3;
threadlocal var phase57_dump_count: u8 = 0;
threadlocal var phase57_attempt_label: []const u8 = "UNSET";
pub fn phase57SetAttemptLabel(label: []const u8) void {
    if (!builtin.is_test) return;
    phase57_attempt_label = label;
}

// QUIC packet (RFC-9000):  A complete processable unit of QUIC that can be
//       encapsulated in a UDP datagram.  One or more QUIC packets can be
//       encapsulated in a single UDP datagram.

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
    logger.debugPrint("{s}: {s}\n", .{ label, list.items });
}

/// Packet number type alias.
pub const PacketNumber = u64;

/// RFC 9000 §5.1: Maximum Connection ID length (20 bytes).
/// CWE-195 mitigation: Validate before casting to u8.
pub const MAX_CID_LENGTH: usize = 20;

/// Validate CID length per RFC 9000 §5.1.
/// Returns error.InvalidCidLength if length exceeds 20 bytes.
pub fn validateCidLength(len: usize) !u8 {
    if (len > MAX_CID_LENGTH) {
        return error.InvalidCidLength;
    }
    return @as(u8, @intCast(len));
}

/// Long header type discriminator used when encoding/decoding.
pub const LongHeaderType = enum { Initial, Handshake };

/// Serializable Long Header structure used by helpers for tests/tools. Layout
/// matches RFC 9000 §17.2 including token length, Length varint, and packet
/// number truncation bits in the first byte.
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
        // DCID Len + DCID (RFC 9000 §5.1: max 20 bytes)
        try w.writeByte(try validateCidLength(self.dcid.len));
        try w.writeAll(self.dcid);
        // SCID Len + SCID (RFC 9000 §5.1: max 20 bytes)
        try w.writeByte(try validateCidLength(self.scid.len));
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
    packet_number: PacketNumber = 1,
    payload: []const u8,

    /// Serialize this short header into the provided writer; returns bytes written.
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

/// Keys used for any protected packet (Initial/Handshake/1-RTT)
pub const AeadKeys = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };

/// Encode a protected short-header packet carrying payload with given PN length (1..4).
/// Implements the authenticated encryption and header protection steps from
/// RFC 9001 §5.4.1/§5.4.3 for 1-RTT packets.
pub fn encodeShortProtectedInto(
    out: []u8,
    dcid: []const u8,
    packet_number: u32,
    packet_number_len: u3,
    payload_plaintext: []const u8,
    keys: AeadKeys,
    key_phase: bool,
) !usize {
    if (packet_number_len < 1 or packet_number_len > 4) return error.InvalidPacketNumberLength;

    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    var header_first: u8 = 0x40 | pn_bits; // short header with pn len bits
    if (key_phase) header_first |= 0x04; // key phase bit (bit 2)

    // PN BE truncated
    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((packet_number >> 24) & 0xff)),
        @as(u8, @intCast((packet_number >> 16) & 0xff)),
        @as(u8, @intCast((packet_number >> 8) & 0xff)),
        @as(u8, @intCast(packet_number & 0xff)),
    };
    const pn_slice = pn_be_full[4 - packet_number_len .. 4];
    var pn_mut: [4]u8 = .{0} ** 4;
    @memcpy(pn_mut[0..packet_number_len], pn_slice);

    // RFC 9001 §5.4.3: Ensure minimum payload size for header protection sample extraction
    // For AES with n-byte PN, need at least (4 - n) bytes offset + 16 bytes sample
    const min_plaintext_len: usize = if (packet_number_len >= 4) 0 else (4 - packet_number_len);
    var padded_payload_storage: [3]u8 = .{0} ** 3; // max padding needed when pn_len=1
    var actual_payload: []const u8 = payload_plaintext;
    if (payload_plaintext.len < min_plaintext_len) {
        @memcpy(padded_payload_storage[0..payload_plaintext.len], payload_plaintext);
        @memset(padded_payload_storage[payload_plaintext.len..min_plaintext_len], 0x00);
        actual_payload = padded_payload_storage[0..min_plaintext_len];
    }

    const ct_len = actual_payload.len + 16;
    const total_len = 1 + dcid.len + packet_number_len + ct_len;
    if (out.len < total_len) return error.BufferTooSmall;

    out[0] = header_first;
    if (dcid.len > 0) @memcpy(out[1 .. 1 + dcid.len], dcid);
    const header_prefix_len = dcid.len;
    const pn_offset = 1 + header_prefix_len;
    @memcpy(out[pn_offset .. pn_offset + packet_number_len], pn_slice);
    const out_cipher = out[pn_offset + packet_number_len .. total_len];

    const suite = crypto.AeadSuite.aes_128_gcm;
    // IMPORTANT (RFC 9001 §5.3): The AEAD nonce uses the FULL packet number, not the truncated value.
    // Previously we passed pn_trunc_val here, causing decrypt side (which expands PN) to derive a different
    // nonce -> authentication failures for 1-RTT short header packets once packet numbers exceeded the
    // truncated range. Fix: pass the original full packet_number to protectInitial/protectPacket.
    logger.debugPrint("encodeShortProtected: pn={} (0x{x}) pn_len={} dcid={s}\n", .{ packet_number, packet_number, packet_number_len, dcid });
    const written = try crypto.protectInitial(
        suite,
        &keys.key,
        &keys.iv,
        &keys.hp,
        @as(u64, packet_number), // use full packet number for nonce derivation
        &header_first,
        pn_mut[0..packet_number_len],
        out[1 .. 1 + header_prefix_len],
        actual_payload,
        out_cipher,
    );
    std.debug.assert(written == ct_len);

    // Write back mutated header and PN
    out[0] = header_first;
    @memcpy(out[pn_offset .. pn_offset + packet_number_len], pn_mut[0..packet_number_len]);

    return total_len;
}

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
    const min_plaintext_len: usize = if (packet_number_len >= 4) 0 else (4 - packet_number_len);
    const payload_len = if (payload_plaintext.len < min_plaintext_len) min_plaintext_len else payload_plaintext.len;
    const total_len = 1 + dcid.len + packet_number_len + payload_len + 16;
    const out = try alloc.alloc(u8, total_len);
    errdefer alloc.free(out);
    const written = try encodeShortProtectedInto(out, dcid, packet_number, packet_number_len, payload_plaintext, keys, key_phase);
    return out[0..written];
}

/// Result of decoding a protected short header packet.
pub const DecodedShort = struct {
    packet_number: u64, // Changed from u32 to support full QUIC packet number range
    packet_number_len: u3,
    payload: []u8,
    key_phase: bool, // PHASE 57: KEY_PHASE bit from short header (RFC 9001 §5.4)
};

/// Borrowed decode result that writes payload into caller-provided storage.
pub const DecodedShortView = struct {
    packet_number: u64,
    packet_number_len: u3,
    payload: []u8,
    key_phase: bool,
};

/// Decode and unprotect a short-header packet given dcid_len for header parsing.
/// Mirrors RFC 9001 §5.4.1/§5.4.3 using the provided largest packet number to
/// expand truncated packet numbers (Appendix A.3).
pub fn decodeShortProtected(
    alloc: std.mem.Allocator,
    packet_bytes: []const u8,
    dcid_len: usize,
    keys: AeadKeys,
    largest_pn: u64,
) !DecodedShort {
    logger.debugPrint("[SHORT-DECODE-ENTRY] bytes={} dcid_len={} largest_pn={}\n", .{ packet_bytes.len, dcid_len, largest_pn });
    return decodeShortProtectedWithHp(alloc, packet_bytes, dcid_len, keys.hp, keys, largest_pn);
}

/// Decode and unprotect a short header packet into caller-owned payload storage.
pub fn decodeShortProtectedInto(
    packet_bytes: []const u8,
    dcid_len: usize,
    keys: AeadKeys,
    largest_pn: u64,
    payload_out: []u8,
) !DecodedShortView {
    logger.debugPrint("[SHORT-DECODE-ENTRY] bytes={} dcid_len={} largest_pn={}\n", .{ packet_bytes.len, dcid_len, largest_pn });
    return decodeShortProtectedWithHpInto(packet_bytes, dcid_len, keys.hp, keys, largest_pn, payload_out);
}

/// Decode short header using a custom HP key (useful for key-update hybrids) into caller-owned storage.
pub fn decodeShortProtectedWithHpInto(
    packet_bytes: []const u8,
    dcid_len: usize,
    hp_key: [16]u8,
    keys: AeadKeys,
    largest_pn: u64,
    payload_out: []u8,
) !DecodedShortView {
    const attempt_label_snapshot = if (builtin.is_test) phase57_attempt_label else "DISABLED";
    if (packet_bytes.len < 1 + dcid_len + 1) return error.Truncated;
    var i: usize = 0;
    const header_first_masked: u8 = packet_bytes[0];
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

    // Sample at PN+4 (RFC 9001 §5.4.3) before removing header protection.
    if (pn_start + 4 + 16 > packet_bytes.len) return error.Truncated;
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet_bytes[pn_start + 4 .. pn_start + 4 + 16]);

    logger.debugPrint("SHORT HEADER HP: pn_start={}, sample_offset={}, packet_len={}\n", .{ pn_start, pn_start + 4, packet_bytes.len });
    logger.debugPrint("SHORT HEADER HP: sample16 = ", .{});
    for (sample16) |b| logger.debugPrint("{X:0>2} ", .{b});
    logger.debugPrint("\n", .{});

    // Determine actual PN length by unmasking header+PN on a temporary copy
    var tmp_first = header_first_masked;
    var tmp_pn: [4]u8 = pn_masked4;
    const pn_len: u3 = try crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &hp_key, &sample16, &tmp_first, &tmp_pn);

    // PHASE 57 FIX CRITICAL: Extract KEY_PHASE bit immediately after HP removal,
    // BEFORE AEAD decryption, so we have it available even if decryption fails.
    // This allows incoming.zig to know which key phase the packet uses and decide
    // whether to try NEXT keys.
    const key_phase = (tmp_first & 0x04) != 0;
    logger.debugPrint("decodeShortProtected: EARLY KEY_PHASE extraction = {} (header_first=0x{X:0>2})\n", .{ key_phase, tmp_first });

    // Pre-compute truncated PN (for logging) before attempting AEAD decrypt.
    var pn_val_truncated: u32 = 0;
    {
        var j_trunc: usize = 0;
        while (j_trunc < pn_len) : (j_trunc += 1) {
            pn_val_truncated = (pn_val_truncated << 8) | tmp_pn[j_trunc];
        }
    }
    const pn_val_expanded_preview = crypto.expandPacketNumber(pn_val_truncated, @intCast(pn_len), largest_pn);

    // Ciphertext+tag begins after PN (using actual pn_len)
    const ct = packet_bytes[pn_start + pn_len ..];
    if (ct.len < 16) return error.Truncated;
    const payload_len = ct.len - 16;
    if (payload_out.len < payload_len) return error.BufferTooSmall;

    // Decrypt using already-unmasked header and PN
    // CRITICAL: unprotectInitial expects unmasked values, not masked ones
    // We already unmasked into tmp_first and tmp_pn above, so use those
    const payload = payload_out[0..payload_len];

    const decrypt_result = crypto.unprotectInitialNoUnmask(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        &tmp_first,
        tmp_pn[0..pn_len],
        header_prefix,
        ct,
        payload,
        largest_pn, // Largest packet number successfully received (0 if none)
    );

    // Check decryption result
    if (decrypt_result) |_| {
        // Success - continue using precomputed PN.
    } else |err| {
        if (largest_pn >= 80 or pn_val_expanded_preview >= 80) {
            logger.debugPrint("[PHASE57-AEAD] fail pn_preview={} pn_len={} pn_trunc=0x{x} key_phase={} dcid_len={} largest={} pn_start={} err={}\n", .{
                pn_val_expanded_preview,
                pn_len,
                pn_val_truncated,
                key_phase,
                dcid_len,
                largest_pn,
                pn_start,
                err,
            });

            var aad_buf: [1 + 32 + 4]u8 = undefined;
            const aad_len = 1 + header_prefix.len + pn_len;
            aad_buf[0] = tmp_first;
            @memcpy(aad_buf[1 .. 1 + header_prefix.len], header_prefix);
            @memcpy(aad_buf[1 + header_prefix.len .. aad_len], tmp_pn[0..pn_len]);
            logger.debugPrint("[PHASE57-AEAD] expect_aad=", .{});
            var aad_idx: usize = 0;
            while (aad_idx < aad_len) : (aad_idx += 1) {
                logger.debugPrint("{X:0>2}", .{aad_buf[aad_idx]});
            }
            logger.debugPrint("\n", .{});

            maybeDumpPhase57Failure(.{
                .packet = packet_bytes,
                .header_first_masked = header_first_masked,
                .header_prefix = header_prefix,
                .pn_masked = pn_masked4[0..avail],
                .ciphertext_and_tag = ct,
                .pn_start = pn_start,
                .pn_len = pn_len,
                .pn_preview = pn_val_expanded_preview,
                .dcid_len = dcid_len,
                .key_phase = key_phase,
                .largest_pn = largest_pn,
                .key_set_label = attempt_label_snapshot,
                .dcid_candidate = @intCast(dcid_len),
            });
        }
        return err;
    }

    const pn_val_expanded = pn_val_expanded_preview;

    logger.debugPrint("decodeShortProtected: truncated PN={} -> expanded PN={} (largest_pn={})\n", .{ pn_val_truncated, pn_val_expanded, largest_pn });

    // PHASE 57: Validation logging for KEY_PHASE (already extracted at line 271)
    logger.debugPrint("decodeShortProtected: KEY_PHASE bit = {} (header_first=0x{X:0>2})\n", .{ key_phase, tmp_first });

    return .{ .packet_number = pn_val_expanded, .packet_number_len = pn_len, .payload = payload, .key_phase = key_phase };
}

/// Decode short header using a custom HP key (useful for key-update hybrids).
pub fn decodeShortProtectedWithHp(
    alloc: std.mem.Allocator,
    packet_bytes: []const u8,
    dcid_len: usize,
    hp_key: [16]u8,
    keys: AeadKeys,
    largest_pn: u64,
) !DecodedShort {
    const payload_storage = try alloc.alloc(u8, packet_bytes.len);
    errdefer alloc.free(payload_storage);
    const view = try decodeShortProtectedWithHpInto(packet_bytes, dcid_len, hp_key, keys, largest_pn, payload_storage);
    const owned_payload = if (view.payload.len == payload_storage.len)
        payload_storage
    else blk: {
        const exact = try alloc.alloc(u8, view.payload.len);
        @memcpy(exact, view.payload);
        alloc.free(payload_storage);
        break :blk exact;
    };
    return .{
        .packet_number = view.packet_number,
        .packet_number_len = view.packet_number_len,
        .payload = owned_payload,
        .key_phase = view.key_phase,
    };
}

/// Temporary legacy shim for older tests that haven't been updated to pass `largest_pn`.
/// Uses `largest_pn=0` (no previously received packets) which is correct for isolated
/// unit test scenarios that only construct a single encrypted short header packet.
/// NOTE: New tests should call `decodeShortProtected` directly.
pub fn decodeShortProtectedLegacy(
    alloc: std.mem.Allocator,
    packet_bytes: []const u8,
    dcid_len: usize,
    keys: AeadKeys,
) !DecodedShort {
    return decodeShortProtected(alloc, packet_bytes, dcid_len, keys, 0);
}

/// Compute initial client/server traffic keys for QUIC v1/v2 given DCID bytes
/// per the HKDF derivations in RFC 9001 §5.1.
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

/// Convenience helper returning RX/TX Initial keys oriented by endpoint role
/// (RFC 9001 §5.1.2).
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

    // Header first byte: Long header with fixed bit, Initial type, PN len bits
    // Per RFC 9000: Fixed bit (6) must be 1
    // Initial packet type = 00 in bits 5-4
    // 0xc0 = 11000000 (Long header + fixed bit + Initial type 00)
    const type_bits: u8 = 0x00; // Initial
    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    const first: u8 = 0xc0 | type_bits | pn_bits;

    // We'll build header_prefix first to compute AAD
    const w = buf.writer(alloc);
    try w.writeByte(first);
    var be_ver: [4]u8 = .{ @as(u8, @intCast(version >> 24)), @as(u8, @intCast((version >> 16) & 0xff)), @as(u8, @intCast((version >> 8) & 0xff)), @as(u8, @intCast(version & 0xff)) };
    try w.writeAll(&be_ver);
    // RFC 9000 §5.1: Validate CID lengths (max 20 bytes)
    try w.writeByte(try validateCidLength(dcid.len));
    try w.writeAll(dcid);
    try w.writeByte(try validateCidLength(scid.len));
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

    // Length varint: pn_len + ciphertext_len. RFC 9000 §17.2 requires the
    // sender to use the minimum-length varint encoding for this field.
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
    // Stack-allocated: 1 byte header + up to ~40 bytes prefix + 4 PN bytes = well under 256.
    var aad_buf: [256]u8 = undefined;
    var aad_stream = std.io.fixedBufferStream(&aad_buf);
    aad_stream.writer().writeByte(header_first) catch return error.Truncated;
    aad_stream.writer().writeAll(header_prefix) catch return error.Truncated;
    aad_stream.writer().writeAll(pn_masked4[0..pn_len_actual]) catch return error.Truncated;
    const aad_items = aad_buf[0..aad_stream.pos];

    // Compute PN value (big-endian truncated)
    var pn_val: u32 = 0;
    var j2: usize = 0;
    while (j2 < pn_len_actual) : (j2 += 1) pn_val = (pn_val << 8) | pn_masked4[j2];

    if (builtin.is_test) {
        dumpBytes("DEC aad", aad_items);
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
        aad_items,
        ct_and_tag,
        pt,
    );

    return .{ .version = version, .dcid = dcid, .scid = scid, .packet_number = pn_val, .packet_number_len = pn_len_actual, .payload = pt };
}

/// Build a fully protected Handshake packet using AES-128-GCM.
/// Note: Uses InitialKeys struct (same as AeadKeys structure) for Handshake protection
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
    logger.debugPrint("encodeHandshakeProtected: CALLED with packet_number={} version=0x{X:0>8}\n", .{ packet_number, version });
    logger.debugPrint("encodeHandshakeProtected: dcid.len={}, scid.len={}\n", .{ dcid.len, scid.len });
    if (dcid.len > 0) {
        logger.debugPrint("encodeHandshakeProtected: dcid bytes: ", .{});
        for (dcid) |b| logger.debugPrint("{X:0>2}\n", .{b});
        logger.debugPrint("", .{});
    }
    if (scid.len > 0) {
        logger.debugPrint("encodeHandshakeProtected: scid bytes: ", .{});
        for (scid) |b| logger.debugPrint("{X:0>2}\n", .{b});
        logger.debugPrint("", .{});
    }
    if (packet_number_len < 1 or packet_number_len > 4) return error.InvalidPacketNumberLength;

    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);

    // Header first byte: Long header with fixed bit, Handshake type, PN len bits
    // Per RFC 9000: Fixed bit (6) must be 1, Handshake packet type = 10 in bits 5-4
    // 0xe0 = 11100000 (Long header + fixed bit + Handshake type 10)
    // We don't need to OR type_bits because 0xe0 already includes Handshake type
    const pn_bits: u8 = @as(u8, packet_number_len - 1) & 0x03;
    const first: u8 = 0xe0 | pn_bits;
    logger.debugPrint("encodeHandshakeProtected: packet_number_len={}, pn_bits={}, first=0x{X:0>2}\n", .{ packet_number_len, pn_bits, first });

    const w = buf.writer(alloc);
    try w.writeByte(first);
    var be_ver: [4]u8 = .{
        @as(u8, @intCast((version >> 24) & 0xff)),
        @as(u8, @intCast((version >> 16) & 0xff)),
        @as(u8, @intCast((version >> 8) & 0xff)),
        @as(u8, @intCast(version & 0xff)),
    };
    logger.debugPrint("encodeHandshakeProtected: writing version bytes {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ be_ver[0], be_ver[1], be_ver[2], be_ver[3] });
    try w.writeAll(&be_ver);
    // RFC 9000 §5.1: Validate CID lengths (max 20 bytes)
    try w.writeByte(try validateCidLength(dcid.len));
    try w.writeAll(dcid);
    try w.writeByte(try validateCidLength(scid.len));
    try w.writeAll(scid);

    // Handshake packets do not carry a token

    // RFC 9001 §5.4.3: Ensure minimum payload size for header protection sample extraction
    // For AES with n-byte PN, need at least (4 - n) bytes offset + 16 bytes sample
    // So ciphertext must be at least max(16, 4 - n + 16) = max(16, 20 - n) bytes
    // Which means plaintext must be at least max(0, 4 - n) bytes
    const min_plaintext_len: usize = if (packet_number_len >= 4) 0 else (4 - packet_number_len);
    var actual_payload = payload_plaintext;
    var padded_payload: ?[]u8 = null;
    defer if (padded_payload) |p| alloc.free(p);

    if (payload_plaintext.len < min_plaintext_len) {
        // Need to pad the payload to meet minimum size
        padded_payload = try alloc.alloc(u8, min_plaintext_len);
        @memcpy(padded_payload.?[0..payload_plaintext.len], payload_plaintext);
        // Fill rest with PADDING frames (0x00)
        @memset(padded_payload.?[payload_plaintext.len..], 0x00);
        actual_payload = padded_payload.?;
    }

    // Length varint: pn_len + ciphertext_len, encoded with the minimal length
    // permitted by RFC 9000 §17.2.
    const ct_len = actual_payload.len + 16;
    const length_value: usize = @as(usize, packet_number_len) + ct_len;
    var lbuf: [8]u8 = undefined;
    const ll = try varint.encode(length_value, &lbuf);
    try w.writeAll(lbuf[0..ll]);

    const header_prefix_len = buf.items.len - 1;
    logger.debugPrint("encodeHandshakeProtected: payload_len={}, ct_len={}, pn_len={}, length_value={}\n", .{ payload_plaintext.len, ct_len, packet_number_len, length_value });

    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((packet_number >> 24) & 0xff)),
        @as(u8, @intCast((packet_number >> 16) & 0xff)),
        @as(u8, @intCast((packet_number >> 8) & 0xff)),
        @as(u8, @intCast(packet_number & 0xff)),
    };
    const pn_slice = pn_be_full[4 - packet_number_len .. 4];
    logger.debugPrint("encodeHandshakeProtected: PN {} encoded as bytes [", .{packet_number});
    for (pn_slice) |b| {
        logger.debugPrint("{X:0>2} ", .{b});
    }
    logger.debugPrint("]\n", .{});
    try w.writeAll(pn_slice);

    const out_cipher_idx = buf.items.len;
    try buf.ensureTotalCapacity(alloc, out_cipher_idx + ct_len);
    try buf.appendNTimes(alloc, 0, ct_len);

    var header_first: u8 = first;
    var pn_mut: [4]u8 = .{0} ** 4;
    @memcpy(pn_mut[0..packet_number_len], pn_slice);

    const out_cipher = buf.items[out_cipher_idx .. out_cipher_idx + ct_len];
    const suite = crypto.AeadSuite.aes_128_gcm;
    // Use protectPacket for Handshake packets, not protectInitial
    const written = try crypto.protectPacket(
        suite,
        &keys.key,
        &keys.iv,
        &keys.hp,
        packet_number,
        &header_first,
        pn_mut[0..packet_number_len],
        buf.items[1 .. 1 + header_prefix_len],
        actual_payload,
        out_cipher,
    );

    // CRITICAL: Verify that the actual encrypted length matches our precalculated length
    if (written != ct_len) {
        logger.debugPrint("LENGTH MISMATCH BUG DETECTED: protectPacket wrote {} bytes, but we calculated ct_len={}\n", .{ written, ct_len });
        logger.debugPrint("  payload_plaintext.len={}, packet_number_len={}, expected_tag_len=16\n", .{ payload_plaintext.len, packet_number_len });
        logger.debugPrint("  Declared length_value in header={} (pn_len + ct_len)\n", .{length_value});
        logger.debugPrint("  Actual packet will have length={} (pn_len + written)\n", .{@as(usize, packet_number_len) + written});
        logger.debugPrint("  This will cause a {} byte discrepancy!\n", .{@as(i64, @intCast(ct_len)) - @as(i64, @intCast(written))});
        // Strict length verification enabled
        return error.LengthMismatch;
    }
    std.debug.assert(written == ct_len);

    buf.items[0] = header_first;
    const pn_offset = 1 + header_prefix_len;
    @memcpy(buf.items[pn_offset .. pn_offset + packet_number_len], pn_mut[0..packet_number_len]);

    logger.debugPrint("encodeHandshakeProtected: AFTER header protection - first byte changed from 0x{X:0>2} to 0x{X:0>2}\n", .{ first, header_first });
    logger.debugPrint("encodeHandshakeProtected: Final packet first 5 bytes: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ buf.items[0], buf.items[1], buf.items[2], buf.items[3], buf.items[4] });

    // DIAGNOSTIC: Hexdump first 64 bytes of Handshake packet for analysis
    logger.debugPrint("=== HANDSHAKE PACKET HEXDUMP (first 64 bytes) ===\n", .{});
    const dump_len = @min(64, buf.items.len);
    var dump_idx: usize = 0;
    while (dump_idx < dump_len) : (dump_idx += 16) {
        const line_end = @min(dump_idx + 16, dump_len);
        logger.debugPrint("{X:0>4}: ", .{dump_idx});
        var line_idx = dump_idx;
        while (line_idx < line_end) : (line_idx += 1) {
            logger.debugPrint("{X:0>2} ", .{buf.items[line_idx]});
        }
        logger.debugPrint("", .{});
    }
    logger.debugPrint("=== END HEXDUMP (total packet size: {} bytes) ===\n", .{buf.items.len});

    // FINAL VERIFICATION: Ensure packet length matches what we declared in the header
    const expected_total_len = (1 + header_prefix_len) + packet_number_len + written;
    if (buf.items.len != expected_total_len) {
        logger.debugPrint("FINAL PACKET LENGTH MISMATCH: buf.len={}, expected={} (header={}, pn={}, payload={})\n", .{ buf.items.len, expected_total_len, 1 + header_prefix_len, packet_number_len, written });
        // Strict length verification enabled
        return error.PacketLengthMismatch;
    }

    // Log successful packet construction with length verification
    logger.debugPrint("encodeHandshakeProtected: SUCCESS - packet length verified: declared_in_header={}, actual_packet_len={}\n", .{ length_value, buf.items.len - (1 + header_prefix_len) });

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
    // DCID Len + DCID (RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(dcid.len));
    try w.writeAll(dcid);
    // SCID Len + SCID (RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(scid.len));
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

    // DCID (RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(dcid.len));
    try w.writeAll(dcid);

    // SCID (RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(scid.len));
    try w.writeAll(scid);

    // RFC 9001 §5.4.3: Calculate minimum payload size for header protection sample extraction first
    const min_plaintext_len: usize = if (pn_len >= 4) 0 else (4 - @as(usize, pn_len));
    var actual_payload = payload;
    var padded_payload: ?[]u8 = null;
    defer if (padded_payload) |p| alloc.free(p);

    if (payload.len < min_plaintext_len) {
        // Need to pad the payload to meet minimum size
        padded_payload = try alloc.alloc(u8, min_plaintext_len);
        @memcpy(padded_payload.?[0..payload.len], payload);
        // Fill rest with PADDING frames (0x00)
        @memset(padded_payload.?[payload.len..], 0x00);
        actual_payload = padded_payload.?;
    }

    // Now write the length field with the actual payload size
    var len_buf: [8]u8 = undefined;
    const payload_with_tag_len = actual_payload.len + 16; // AEAD tag
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
    try buf.ensureTotalCapacity(alloc, ct_start + actual_payload.len + 16);
    buf.items.len = ct_start + actual_payload.len + 16;

    // aeadEncrypt(suite, key, iv, packet_number, aad, plaintext, out)
    _ = try crypto.aeadEncrypt(
        .aes_128_gcm,
        &keys.key,
        &keys.iv,
        packet_number,
        aad,
        actual_payload,
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
        crypto.headerProtect(.aes_128_gcm, &keys.hp, &sample16, header_first_ptr, pn_slice) catch |err| {
            logger.err("header protection failed: {s}", .{@errorName(err)});
        };
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

    // Stack-allocated AAD: 1 byte header + header prefix + up to 4 PN bytes = well under 256.
    var aad_buf2: [256]u8 = undefined;
    var aad_stream2 = std.io.fixedBufferStream(&aad_buf2);
    aad_stream2.writer().writeByte(header_first) catch return error.CiphertextTooShort;
    aad_stream2.writer().writeAll(packet[1..i]) catch return error.CiphertextTooShort;
    aad_stream2.writer().writeAll(pn_masked4[0..pn_len_actual]) catch return error.CiphertextTooShort;
    const aad_items2 = aad_buf2[0..aad_stream2.pos];

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
        aad_items2,
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
    // DCID Len + DCID (equals client's SCID, RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(dcid.len));
    try w.writeAll(dcid);
    // SCID Len + SCID (RFC 9000 §5.1: max 20 bytes)
    try w.writeByte(try validateCidLength(scid.len));
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
    // Use constant-time comparison to prevent timing side-channel (GAP-0018/SF-018).
    return std.crypto.timing_safe.eql([16]u8, calc, tag[0..16].*);
}

const Phase57DumpContext = struct {
    packet: []const u8,
    header_first_masked: u8,
    header_prefix: []const u8,
    pn_masked: []const u8,
    ciphertext_and_tag: []const u8,
    pn_start: usize,
    pn_len: usize,
    pn_preview: u64,
    dcid_len: usize,
    key_phase: bool,
    largest_pn: u64,
    key_set_label: []const u8,
    dcid_candidate: u8,
};

fn maybeDumpPhase57Failure(ctx: Phase57DumpContext) void {
    if (!builtin.is_test) return;
    if (phase57_dump_count >= phase57_dump_max) return;
    phase57_dump_count += 1;
    const dump_id = phase57_dump_count;
    logger.debugPrint("[PHASE57-DUMP] captured failing short header #{d}: pn_preview={} key_phase={} largest_pn={} label={s}\n", .{
        dump_id,
        ctx.pn_preview,
        ctx.key_phase,
        ctx.largest_pn,
        ctx.key_set_label,
    });
    logger.debugPrint("[PHASE57-DUMP] header_first_masked=0x{X:0>2} dcid_len={} pn_len={} pn_start={}\n", .{
        ctx.header_first_masked,
        ctx.dcid_len,
        ctx.pn_len,
        ctx.pn_start,
    });
    printBytesHex("[PHASE57-DUMP] dcid", ctx.header_prefix, 64);
    printBytesHex("[PHASE57-DUMP] pn_masked", ctx.pn_masked, 16);
    printBytesHex("[PHASE57-DUMP] ciphertext+tag", ctx.ciphertext_and_tag, 256);
    printBytesHex("[PHASE57-DUMP] packet", ctx.packet, 512);
    dumpPhase57Files(ctx, dump_id);
    logger.debugPrint("[PHASE57-DUMP] ---- END ----\n", .{});
}

fn printBytesHex(label: []const u8, bytes: []const u8, limit: usize) void {
    logger.debugPrint("{s}=", .{label});
    var i: usize = 0;
    const max = @min(limit, bytes.len);
    while (i < max) : (i += 1) {
        logger.debugPrint("{X:0>2}", .{bytes[i]});
    }
    if (bytes.len > limit) {
        logger.debugPrint("...(+{} bytes)", .{bytes.len - limit});
    }
    logger.debugPrint("\n", .{});
}

fn dumpPhase57Files(ctx: Phase57DumpContext, dump_id: u8) void {
    const cwd = std.fs.cwd();
    var packet_path_buf: [64]u8 = undefined;
    var meta_path_buf: [64]u8 = undefined;
    const packet_path = std.fmt.bufPrint(&packet_path_buf, "/tmp/phase57-short-header-{d}.bin", .{dump_id}) catch return;
    const meta_path = std.fmt.bufPrint(&meta_path_buf, "/tmp/phase57-short-header-{d}.meta", .{dump_id}) catch return;

    if (cwd.createFile(packet_path, .{ .truncate = true })) |file| {
        defer file.close();
        file.writeAll(ctx.packet) catch |werr| {
            logger.debugPrint("[PHASE57-DUMP] failed to write packet data: {}\n", .{werr});
        };
    } else |err| {
        logger.debugPrint("[PHASE57-DUMP] failed to write {s}: {}\n", .{ packet_path, err });
    }

    if (cwd.createFile(meta_path, .{ .truncate = true })) |file| {
        defer file.close();
        writeLine(file, "pn_preview={}\n", .{ctx.pn_preview});
        writeLine(file, "key_phase={}\n", .{ctx.key_phase});
        writeLine(file, "largest_pn={}\n", .{ctx.largest_pn});
        writeLine(file, "header_first_masked=0x{X:0>2}\n", .{ctx.header_first_masked});
        writeLine(file, "dcid_len={}\n", .{ctx.dcid_len});
        writeLine(file, "pn_len={}\n", .{ctx.pn_len});
        writeLine(file, "pn_start={}\n", .{ctx.pn_start});
        writeLine(file, "attempt_label={s}\n", .{ctx.key_set_label});
        writeLine(file, "dcid_candidate={}\n", .{ctx.dcid_candidate});
        writeHexLine(file, "dcid_hex=", ctx.header_prefix);
        writeHexLine(file, "pn_masked_hex=", ctx.pn_masked);
    } else |err| {
        logger.debugPrint("[PHASE57-DUMP] failed to write {s}: {}\n", .{ meta_path, err });
    }

    if (dump_id == 1) {
        copyPhase57File(ctx.packet, "/tmp/phase57-short-header.bin");
        copyPhase57Meta(ctx, "/tmp/phase57-short-header.meta");
    }
}

fn copyPhase57File(data: []const u8, path: []const u8) void {
    const cwd = std.fs.cwd();
    if (cwd.createFile(path, .{ .truncate = true })) |file| {
        defer file.close();
        file.writeAll(data) catch |werr| {
            logger.debugPrint("[PHASE57-DUMP] copyPhase57File write failed: {}\n", .{werr});
        };
    } else |_| {}
}

fn copyPhase57Meta(ctx: Phase57DumpContext, path: []const u8) void {
    const cwd = std.fs.cwd();
    if (cwd.createFile(path, .{ .truncate = true })) |file| {
        defer file.close();
        writeLine(file, "pn_preview={}\n", .{ctx.pn_preview});
        writeLine(file, "key_phase={}\n", .{ctx.key_phase});
        writeLine(file, "largest_pn={}\n", .{ctx.largest_pn});
        writeLine(file, "header_first_masked=0x{X:0>2}\n", .{ctx.header_first_masked});
        writeLine(file, "dcid_len={}\n", .{ctx.dcid_len});
        writeLine(file, "pn_len={}\n", .{ctx.pn_len});
        writeLine(file, "pn_start={}\n", .{ctx.pn_start});
        writeLine(file, "attempt_label={s}\n", .{ctx.key_set_label});
        writeLine(file, "dcid_candidate={}\n", .{ctx.dcid_candidate});
        writeHexLine(file, "dcid_hex=", ctx.header_prefix);
        writeHexLine(file, "pn_masked_hex=", ctx.pn_masked);
    } else |_| {}
}

fn writeLine(file: std.fs.File, comptime fmt: []const u8, args: anytype) void {
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt, args) catch return;
    file.writeAll(line) catch |werr| {
        logger.debugPrint("[PHASE57-DUMP] writeLine failed: {}\n", .{werr});
    };
}

fn writeHexLine(file: std.fs.File, label: []const u8, bytes: []const u8) void {
    file.writeAll(label) catch return;
    var idx: usize = 0;
    var byte_buf: [2]u8 = undefined;
    while (idx < bytes.len) : (idx += 1) {
        _ = std.fmt.bufPrint(&byte_buf, "{X:0>2}", .{bytes[idx]}) catch return;
        file.writeAll(&byte_buf) catch return;
    }
    file.writeAll("\n") catch |werr| {
        logger.debugPrint("[PHASE57-DUMP] writeHexLine newline failed: {}\n", .{werr});
    };
}
