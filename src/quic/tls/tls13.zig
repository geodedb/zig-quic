// MIT License
// Minimal TLS 1.3 handshake helpers for QUIC (no record layer)
// Scope: transcript hash, Derive-Secret helpers, handshake traffic secrets,
// and a tiny state container to consume/produce CRYPTO bytes.
const std = @import("std");
const ks = @import("quic_tls");

pub const H = ks.H; // sha256

pub const Role = enum { Client, Server };

/// TLS handshake message type codes (subset)
pub const HsType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
};

/// Small transcript helper; accumulates handshake messages as-is.
pub const Transcript = struct {
    hasher: H = H.init(.{}),

    pub fn init() Transcript {
        return .{ .hasher = H.init(.{}) };
    }
    pub fn update(self: *Transcript, msg: []const u8) void {
        self.hasher.update(msg);
    }
    pub fn finalize(self: *Transcript) [H.digest_length]u8 {
        var out: [H.digest_length]u8 = undefined;
        var tmp = self.hasher; // copy
        tmp.final(&out);
        return out;
    }
};

/// Compute TLS 1.3 handshake traffic secrets (client and server) given:
/// - ecdhe_secret: raw (EC)DHE shared secret (IKM for handshake_secret)
/// - transcript_hash: Hash(ClientHello ... ServerHello)
/// Assumes no PSK (early_secret is HKDF-Extract(0, 0)).
pub fn deriveHandshakeTraffic(ecdhe_secret: []const u8, transcript_hash: [H.digest_length]u8) struct {
    client_hs: [H.digest_length]u8,
    server_hs: [H.digest_length]u8,
} {
    // early_secret = HKDF-Extract(0, 0)
    const early_secret = ks.extract(&[_]u8{}, &[_]u8{});
    // derived = Derive-Secret(early_secret, "derived", "")
    var derived: [H.digest_length]u8 = undefined;
    ks.expandLabel(early_secret, "derived", &[_]u8{}, &derived) catch unreachable;
    // handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    const handshake_secret = ks.extract(&derived, ecdhe_secret);
    // traffic secrets
    var c_hs: [H.digest_length]u8 = undefined;
    var s_hs: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "c hs traffic", &transcript_hash, &c_hs) catch unreachable;
    ks.expandLabel(handshake_secret, "s hs traffic", &transcript_hash, &s_hs) catch unreachable;
    return .{ .client_hs = c_hs, .server_hs = s_hs };
}

/// QUIC key material derived from a TLS traffic secret.
pub const QuicKeys = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };

pub fn deriveQuicHandshakeKeys(client_or_server_hs_secret: [H.digest_length]u8, v2: bool) QuicKeys {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    if (v2) {
        const t = ks.deriveKeyIvHpV2(client_or_server_hs_secret);
        key = t.key;
        iv = t.iv;
        hp = t.hp;
    } else {
        const t = ks.deriveKeyIvHp(client_or_server_hs_secret);
        key = t.key;
        iv = t.iv;
        hp = t.hp;
    }
    return .{ .key = key, .iv = iv, .hp = hp };
}

/// Minimal, non-interoperable handshake engine stub that accumulates
/// CRYPTO bytes and allows tests to inject ServerHello pieces to drive
/// key schedule. Real message parsing/encoding will be added iteratively.
pub const Engine = struct {
    role: Role,
    transcript: Transcript = Transcript.init(),
    /// Deterministic ECDHE secret for tests or derived via X25519 in future slices.
    ecdhe_secret: ?[]const u8 = null,
    /// Buffer for producing outbound CRYPTO data (e.g., ClientHello).
    outbox: std.ArrayList(u8),

    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .transcript = Transcript.init(), .ecdhe_secret = null, .outbox = std.ArrayList(u8).init(alloc) };
    }
    pub fn deinit(self: *Engine) void {
        self.outbox.deinit();
    }

    /// Append received CRYPTO bytes into transcript (assumes complete handshake messages)
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        self.transcript.update(data);
    }

    /// Queue outbound CRYPTO bytes (e.g., initial ClientHello encoding)
    pub fn queueCrypto(self: *Engine, data: []const u8) !void {
        try self.outbox.appendSlice(data);
        self.transcript.update(data);
    }

    pub fn takeOut(self: *Engine, buf: []u8) usize {
        const n = @min(buf.len, self.outbox.items.len);
        @memcpy(buf[0..n], self.outbox.items[0..n]);
        if (n > 0) {
            _ = self.outbox.orderedRemoveRange(0, n);
        }
        return n;
    }

    /// Drives key schedule after both sides' hello are in transcript and ecdhe_secret is set.
    pub fn computeHandshakeSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        const th = self.transcript.finalize();
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }
};
