const std = @import("std");
const crypto = std.crypto;
const math = std.math;

const AuthenticationError = crypto.errors.AuthenticationError;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

/// TLS 1.3 record layer primitives (RFC 8446 §5).
/// Provides TLSPlaintext framing, TLSInnerPlaintext packing, and AEAD
/// protection helpers used by the QUIC handshake engine.
/// Legacy record protocol versions carried on the wire (RFC 8446 §5.1).
pub const LegacyVersion = enum(u16) {
    ssl_3_0 = 0x0300,
    tls_1_0 = 0x0301,
    tls_1_1 = 0x0302,
    tls_1_2 = 0x0303,
};

/// TLS 1.3 fixes the outer record version to 0x0303 (TLS 1.2).
/// Default legacy version to use in TLS 1.3 records.
pub const default_legacy_version = LegacyVersion.tls_1_2;

/// Record content types as defined in RFC 8446 §5.1.
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
};

/// Maximum TLSPlaintext fragment permitted by RFC 8446 §5.1.
pub const max_plaintext_fragment = 16384; // 2^14 bytes

/// Maximum padding we accept for TLSInnerPlaintext. RFC 8446 allows up to 2^14
/// bytes; we mirror that bound to simplify validation.
pub const max_inner_padding = max_plaintext_fragment;

/// Errors that can occur during TLS record processing.
pub const RecordError = error{
    FragmentTooLarge,
    RecordTooShort,
    LengthMismatch,
    InvalidContentType,
    MissingContentType,
    PaddingTooLarge,
    UnsupportedLegacyVersion,
    InvalidKeyLength,
    InvalidIvLength,
    CiphertextTooShort,
    AuthenticationFailed,
    AeadLimitExceeded,
    OutOfMemory,
};

/// Lightweight view over a TLSPlaintext record (RFC 8446 §5.1).
pub const PlaintextView = struct {
    content_type: ContentType,
    legacy_version: LegacyVersion,
    fragment: []const u8,
};

/// Pack content into a TLSPlaintext record. Caller owns the returned buffer.
pub fn encodePlaintext(allocator: std.mem.Allocator, content_type: ContentType, fragment: []const u8) ![]u8 {
    if (fragment.len > max_plaintext_fragment) return RecordError.FragmentTooLarge;
    const header_len: usize = 5;
    var out = try allocator.alloc(u8, header_len + fragment.len);
    out[0] = @intFromEnum(content_type);
    // RFC 8446 mandates the legacy record version 0x0303.
    out[1] = 0x03;
    out[2] = 0x03;
    const length: u16 = @intCast(fragment.len);
    out[3] = @intCast(length >> 8);
    out[4] = @intCast(length & 0xff);
    @memcpy(out[header_len..], fragment);
    return out;
}

/// Parse a TLSPlaintext record from `data`. Returned view references the
/// original slice; the caller is responsible for lifetime management.
pub fn decodePlaintext(data: []const u8) RecordError!PlaintextView {
    if (data.len < 5) return RecordError.RecordTooShort;
    const declared_len = (@as(u16, data[3]) << 8) | @as(u16, data[4]);
    const total_len: usize = 5 + declared_len;
    if (data.len != total_len) return RecordError.LengthMismatch;
    const ct = try parseContentType(data[0]);
    const version = try parseLegacyVersion(data[1], data[2]);
    const fragment = data[5..total_len];
    return PlaintextView{
        .content_type = ct,
        .legacy_version = version,
        .fragment = fragment,
    };
}

/// TLSInnerPlaintext structure (RFC 8446 §5.4) after unpacking.
pub const InnerPlaintext = struct {
    content_type: ContentType,
    content: []const u8,
    padding_len: usize,
};

/// Encode content + padding into a TLSInnerPlaintext buffer (RFC 8446 §5.4).
pub fn packInnerPlaintext(allocator: std.mem.Allocator, content_type: ContentType, content: []const u8, padding_len: usize) ![]u8 {
    if (padding_len > max_inner_padding) return RecordError.PaddingTooLarge;
    if (content.len + 1 + padding_len > max_plaintext_fragment) return RecordError.FragmentTooLarge;
    if (content_type == .invalid) return RecordError.InvalidContentType;

    const total_len = content.len + 1 + padding_len;
    var out = try allocator.alloc(u8, total_len);
    @memcpy(out[0..content.len], content);
    out[content.len] = @intFromEnum(content_type);
    if (padding_len > 0) {
        @memset(out[content.len + 1 ..], 0);
    }
    return out;
}

/// Recover content, content type, and padding count from a TLSInnerPlaintext
/// buffer. The returned slices borrow from the provided `buffer`.
pub fn unpackInnerPlaintext(buffer: []const u8) RecordError!InnerPlaintext {
    if (buffer.len == 0) return RecordError.MissingContentType;

    var idx = buffer.len;
    var pad: usize = 0;
    while (idx > 0 and buffer[idx - 1] == 0) : (idx -= 1) {
        pad += 1;
    }
    if (idx == 0) return RecordError.MissingContentType;
    const ct_byte = buffer[idx - 1];
    const ct = try parseContentType(ct_byte);
    const content = buffer[0 .. idx - 1];
    return InnerPlaintext{
        .content_type = ct,
        .content = content,
        .padding_len = pad,
    };
}

fn parseContentType(byte: u8) RecordError!ContentType {
    return switch (byte) {
        @intFromEnum(ContentType.change_cipher_spec) => .change_cipher_spec,
        @intFromEnum(ContentType.alert) => .alert,
        @intFromEnum(ContentType.handshake) => .handshake,
        @intFromEnum(ContentType.application_data) => .application_data,
        @intFromEnum(ContentType.heartbeat) => .heartbeat,
        else => RecordError.InvalidContentType,
    };
}

fn parseLegacyVersion(hi: u8, lo: u8) RecordError!LegacyVersion {
    const value: u16 = (@as(u16, hi) << 8) | @as(u16, lo);
    return switch (value) {
        @intFromEnum(LegacyVersion.ssl_3_0) => .ssl_3_0,
        @intFromEnum(LegacyVersion.tls_1_0) => .tls_1_0,
        @intFromEnum(LegacyVersion.tls_1_1) => .tls_1_1,
        @intFromEnum(LegacyVersion.tls_1_2) => .tls_1_2,
        else => RecordError.UnsupportedLegacyVersion,
    };
}

/// TLS 1.3 authenticated encryption suites supported by QUIC (RFC 8446 §5.1).
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};

const SuiteSpec = struct {
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
    default_limits: AeadUsageLimits,
};

const MaxNonceLength = @max(@max(Aes128Gcm.nonce_length, Aes256Gcm.nonce_length), ChaCha20Poly1305.nonce_length);
const MaxTagLength = @max(@max(Aes128Gcm.tag_length, Aes256Gcm.tag_length), ChaCha20Poly1305.tag_length);

/// RFC 8446 §5.5 confidentiality/integrity limits (records before rekey).
pub const AeadUsageLimits = struct {
    confidentiality: u64,
    integrity: u64,
};

/// AEAD context for TLS 1.3 records (RFC 8446 §5.2–§5.5).
pub const AeadCipher = struct {
    suite: CipherSuite,
    key_material: KeyMaterial,
    base_iv: [MaxNonceLength]u8,
    nonce_len: u8,
    tag_len: u8,
    usage: Usage,

    const Usage = struct {
        encrypted: u64,
        auth_failures: u64,
        limits: AeadUsageLimits,
    };

    const KeyMaterial = union(enum) {
        aes128: [Aes128Gcm.key_length]u8,
        aes256: [Aes256Gcm.key_length]u8,
        chacha20: [ChaCha20Poly1305.key_length]u8,
    };

    /// Initialize an AEAD context with the traffic key/IV pair for one epoch.
    pub fn init(
        suite: CipherSuite,
        key: []const u8,
        iv: []const u8,
        limits_override: ?AeadUsageLimits,
    ) RecordError!AeadCipher {
        const spec = suiteSpec(suite);
        if (key.len != spec.key_len) return RecordError.InvalidKeyLength;
        if (iv.len != spec.nonce_len or spec.nonce_len < 8 or spec.nonce_len > MaxNonceLength)
            return RecordError.InvalidIvLength;

        const limits = limits_override orelse spec.default_limits;
        const key_material = switch (suite) {
            .TLS_AES_128_GCM_SHA256 => blk: {
                var arr: [Aes128Gcm.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..Aes128Gcm.key_length]);
                break :blk KeyMaterial{ .aes128 = arr };
            },
            .TLS_AES_256_GCM_SHA384 => blk: {
                var arr: [Aes256Gcm.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..Aes256Gcm.key_length]);
                break :blk KeyMaterial{ .aes256 = arr };
            },
            .TLS_CHACHA20_POLY1305_SHA256 => blk: {
                var arr: [ChaCha20Poly1305.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..ChaCha20Poly1305.key_length]);
                break :blk KeyMaterial{ .chacha20 = arr };
            },
        };

        var cipher = AeadCipher{
            .suite = suite,
            .key_material = key_material,
            .base_iv = [_]u8{0} ** MaxNonceLength,
            .nonce_len = @intCast(spec.nonce_len),
            .tag_len = @intCast(spec.tag_len),
            .usage = .{ .encrypted = 0, .auth_failures = 0, .limits = limits },
        };
        std.mem.copyForwards(u8, cipher.base_iv[0..spec.nonce_len], iv);
        return cipher;
    }

    /// Encrypt TLSInnerPlaintext into TLSCiphertext, appending the tag.
    pub fn seal(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        plaintext: []const u8,
    ) RecordError![]u8 {
        if (limitReached(self.usage.encrypted, self.usage.limits.confidentiality))
            return RecordError.AeadLimitExceeded;
        if (self.usage.encrypted == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;

        const out = try allocator.alloc(u8, plaintext.len + self.tag_len);
        errdefer allocator.free(out);

        const ct = out[0..plaintext.len];
        const tag_slice = out[plaintext.len..];
        const tag_len: usize = @intCast(self.tag_len);
        var nonce_full = self.deriveNonce(seq);
        defer {
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
        }

        switch (self.key_material) {
            .aes128 => |key| {
                var nonce_arr: [Aes128Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes128Gcm.nonce_length]);
                var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
                Aes128Gcm.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
            .aes256 => |key| {
                var nonce_arr: [Aes256Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes256Gcm.nonce_length]);
                var tag_arr: [Aes256Gcm.tag_length]u8 = undefined;
                Aes256Gcm.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
            .chacha20 => |key| {
                var nonce_arr: [ChaCha20Poly1305.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..ChaCha20Poly1305.nonce_length]);
                var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
                ChaCha20Poly1305.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
        }

        self.usage.encrypted += 1;
        return out;
    }

    /// Decrypt and authenticate a TLSCiphertext buffer.
    pub fn open(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        ciphertext: []const u8,
    ) RecordError![]u8 {
        if (ciphertext.len < self.tag_len) return RecordError.CiphertextTooShort;

        const ct_len = ciphertext.len - self.tag_len;
        const out = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(out);

        const ct = ciphertext[0..ct_len];
        var tag_buf: [MaxTagLength]u8 = [_]u8{0} ** MaxTagLength;
        const tag_len: usize = @intCast(self.tag_len);
        std.mem.copyForwards(u8, tag_buf[0..tag_len], ciphertext[ct_len..]);
        var nonce_full = self.deriveNonce(seq);
        defer {
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
            crypto.secureZero(u8, tag_buf[0..tag_len]);
        }

        switch (self.key_material) {
            .aes128 => |key| {
                var nonce_arr: [Aes128Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes128Gcm.nonce_length]);
                var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..Aes128Gcm.tag_length]);
                Aes128Gcm.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
            .aes256 => |key| {
                var nonce_arr: [Aes256Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes256Gcm.nonce_length]);
                var tag_arr: [Aes256Gcm.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..Aes256Gcm.tag_length]);
                Aes256Gcm.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
            .chacha20 => |key| {
                var nonce_arr: [ChaCha20Poly1305.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..ChaCha20Poly1305.nonce_length]);
                var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..ChaCha20Poly1305.tag_length]);
                ChaCha20Poly1305.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
        }

        return out;
    }

    /// Zero key material and reset per-direction usage counters.
    pub fn wipe(self: *AeadCipher) void {
        switch (self.key_material) {
            .aes128 => |*key| crypto.secureZero(u8, key.*[0..]),
            .aes256 => |*key| crypto.secureZero(u8, key.*[0..]),
            .chacha20 => |*key| crypto.secureZero(u8, key.*[0..]),
        }
        const nonce_len: usize = @intCast(self.nonce_len);
        crypto.secureZero(u8, self.base_iv[0..nonce_len]);
        const limits = self.usage.limits;
        self.usage = .{ .encrypted = 0, .auth_failures = 0, .limits = limits };
    }

    fn deriveNonce(self: *const AeadCipher, seq: u64) [MaxNonceLength]u8 {
        var tmp: [MaxNonceLength]u8 = [_]u8{0} ** MaxNonceLength;
        const nonce_len: usize = @intCast(self.nonce_len);
        // Safe: xorNonce validates lengths and copies the IV prior to XOR.
        xorNonce(tmp[0..nonce_len], self.base_iv[0..nonce_len], seq) catch unreachable;
        return tmp;
    }

    fn onAuthFailure(self: *AeadCipher) RecordError {
        if (self.usage.auth_failures == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;
        self.usage.auth_failures += 1;
        if (limitExceeded(self.usage.auth_failures, self.usage.limits.integrity))
            return RecordError.AeadLimitExceeded;
        return RecordError.AuthenticationFailed;
    }
};

fn suiteSpec(suite: CipherSuite) SuiteSpec {
    return switch (suite) {
        .TLS_AES_128_GCM_SHA256 => .{
            .key_len = Aes128Gcm.key_length,
            .nonce_len = Aes128Gcm.nonce_length,
            .tag_len = Aes128Gcm.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 24,
                .integrity = @as(u64, 1) << 36,
            },
        },
        .TLS_AES_256_GCM_SHA384 => .{
            .key_len = Aes256Gcm.key_length,
            .nonce_len = Aes256Gcm.nonce_length,
            .tag_len = Aes256Gcm.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 24,
                .integrity = @as(u64, 1) << 36,
            },
        },
        .TLS_CHACHA20_POLY1305_SHA256 => .{
            .key_len = ChaCha20Poly1305.key_length,
            .nonce_len = ChaCha20Poly1305.nonce_length,
            .tag_len = ChaCha20Poly1305.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 32,
                .integrity = @as(u64, 1) << 36,
            },
        },
    };
}

fn limitReached(count: u64, limit: u64) bool {
    return limit != 0 and count >= limit;
}

fn limitExceeded(count: u64, limit: u64) bool {
    return limit != 0 and count > limit;
}

/// Derive the per-record nonce by XORing the static IV with the sequence number (RFC 8446 §5.3).
pub fn xorNonce(out: []u8, base_iv: []const u8, seq: u64) RecordError!void {
    if (out.len != base_iv.len or out.len < 8) return RecordError.InvalidIvLength;
    std.mem.copyForwards(u8, out, base_iv);
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    const offset = out.len - seq_bytes.len;
    for (seq_bytes, 0..) |byte, idx| {
        out[offset + idx] ^= byte;
    }
}
