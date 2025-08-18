// MIT License
// Minimal TLS 1.3 handshake helpers for QUIC (no record layer)
// Scope: transcript hash, Derive-Secret helpers, handshake traffic secrets,
// a tiny state container to consume/produce CRYPTO bytes, and minimal
// handshake message encode/parse helpers for ClientHello/ServerHello envelopes.
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

/// Encode a single TLS Handshake message (type + 3-byte length + body).
pub fn encodeHandshake(alloc: std.mem.Allocator, typ: HsType, body: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, 4 + body.len);
    out[0] = @intFromEnum(typ);
    const L: u32 = @intCast(body.len);
    out[1] = @intCast((L >> 16) & 0xff);
    out[2] = @intCast((L >> 8) & 0xff);
    out[3] = @intCast(L & 0xff);
    @memcpy(out[4..], body);
    return out;
}

/// Attempt to parse a Handshake message from data. Returns null if not enough bytes.
pub fn parseHandshakeOne(data: []const u8) !?struct { typ: HsType, body: []const u8, n: usize } {
    if (data.len < 4) return null;
    const t_byte = data[0];
    const typ: HsType = std.meta.intToEnum(HsType, t_byte) catch return error.UnknownHandshakeType;
    const L: usize = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | @as(usize, data[3]);
    const need = 4 + L;
    if (data.len < need) return null;
    return .{ .typ = typ, .body = data[4 .. 4 + L], .n = need };
}

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
    /// Tracking flags for minimal handshake state.
    ch_sent: bool = false,
    sh_seen: bool = false,

    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .transcript = Transcript.init(), .ecdhe_secret = null, .outbox = std.ArrayList(u8).init(alloc), .ch_sent = false, .sh_seen = false };
    }
    pub fn deinit(self: *Engine) void {
        self.outbox.deinit();
    }

    /// Append received CRYPTO bytes into transcript. Attempts to parse handshake messages
    /// to update simple state, but always feeds the transcript with raw bytes.
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        // Best-effort parse to notice a ServerHello in the stream.
        var off: usize = 0;
        while (true) {
            const parsed = parseHandshakeOne(data[off..]) catch null;
            if (parsed) |p| {
                off += p.n;
                if (p.typ == .server_hello) self.sh_seen = true;
                // For completeness, mark ClientHello seen if we're in server role
                if (p.typ == .client_hello) self.ch_sent = true;
            } else break;
        }
        self.transcript.update(data);
    }

    /// Queue outbound CRYPTO bytes (e.g., initial ClientHello encoding)
    pub fn queueCrypto(self: *Engine, data: []const u8) !void {
        try self.outbox.appendSlice(data);
        self.transcript.update(data);
        // If this was a proper handshake ClientHello record, flip flag
        if (data.len >= 1 and data[0] == @intFromEnum(HsType.client_hello)) {
            self.ch_sent = true;
        }
    }

    /// Build and queue a minimal ClientHello handshake envelope with a synthetic body.
    /// This is NOT wire-compatible TLS; it's a placeholder to exercise the pipeline.
    pub fn queueMinimalClientHello(self: *Engine) !void {
        const tmp = try encodeHandshake(self.outbox.allocator, .client_hello, "CHLO");
        defer self.outbox.allocator.free(tmp);
        try self.queueCrypto(tmp);
    }

    /// Drain outbox into caller buffer. Returns number of bytes copied.
    pub fn takeOut(self: *Engine, buf: []u8) usize {
        const n = @min(buf.len, self.outbox.items.len);
        @memcpy(buf[0..n], self.outbox.items[0..n]);
        if (n > 0) {
            // Manually remove first n bytes: shift left and shrink.
            const remain = self.outbox.items.len - n;
            if (remain > 0) {
                std.mem.copyForwards(u8, self.outbox.items[0..remain], self.outbox.items[n..]);
            }
            _ = self.outbox.resize(self.outbox.items.len - n) catch {};
        }
        return n;
    }

    /// Drives key schedule after both sides' hello are in transcript and ecdhe_secret is set.
    pub fn computeHandshakeSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        // In a future slice, we could require both CH and SH presence; keep permissive for tests.
        const th = self.transcript.finalize();
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }

    /// Convenience alias for draining outbound CRYPTO intended for QUIC Handshake pkts.
    pub fn popCrypto(self: *Engine, out: []u8) usize {
        return self.takeOut(out);
    }
};
