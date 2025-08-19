// MIT License
// Minimal TLS 1.3 handshake helpers for QUIC (no record layer)
// Scope: transcript hash, Derive-Secret helpers, handshake traffic secrets,
// a tiny state container to consume/produce CRYPTO bytes, and minimal
// handshake message encode/parse helpers for ClientHello/ServerHello envelopes.
const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509.zig");

pub const H = ks.H; // sha256

pub const Role = enum { Client, Server };

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

/// Derive application traffic secrets (client and server) from handshake secret.
pub fn deriveApplicationTraffic(handshake_secret: [H.digest_length]u8, transcript_hash: [H.digest_length]u8) struct {
    client_app: [H.digest_length]u8,
    server_app: [H.digest_length]u8,
} {
    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    var derived2: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch unreachable;
    const master = ks.extract(&derived2, &[_]u8{});
    var c_app: [H.digest_length]u8 = undefined;
    var s_app: [H.digest_length]u8 = undefined;
    ks.expandLabel(master, "c ap traffic", &transcript_hash, &c_app) catch unreachable;
    ks.expandLabel(master, "s ap traffic", &transcript_hash, &s_app) catch unreachable;
    return .{ .client_app = c_app, .server_app = s_app };
}

pub fn deriveQuicAppKeys(client_or_server_app_secret: [H.digest_length]u8, v2: bool) QuicKeys {
    return if (v2) blk: {
        const t = ks.deriveKeyIvHpV2(client_or_server_app_secret);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk2: {
        const t = ks.deriveKeyIvHp(client_or_server_app_secret);
        break :blk2 .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };
}

/// Derive application traffic secrets directly from raw ECDHE secret and transcript hash.
/// This computes handshake_secret then master secret per TLS 1.3 and returns c/s app secrets.
pub fn deriveApplicationTrafficFromEcdhe(ecdhe_secret: []const u8, transcript_hash: [H.digest_length]u8) struct {
    client_app: [H.digest_length]u8,
    server_app: [H.digest_length]u8,
} {
    // early_secret = HKDF-Extract(0, 0)
    const early_secret = ks.extract(&[_]u8{}, &[_]u8{});
    // derived = Derive-Secret(early_secret, "derived", "")
    var derived: [H.digest_length]u8 = undefined;
    ks.expandLabel(early_secret, "derived", &[_]u8{}, &derived) catch unreachable;
    // handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    const handshake_secret = ks.extract(&derived, ecdhe_secret);
    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    var derived2: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch unreachable;
    const master = ks.extract(&derived2, &[_]u8{});
    var c_app: [H.digest_length]u8 = undefined;
    var s_app: [H.digest_length]u8 = undefined;
    ks.expandLabel(master, "c ap traffic", &transcript_hash, &c_app) catch unreachable;
    ks.expandLabel(master, "s ap traffic", &transcript_hash, &s_app) catch unreachable;
    return .{ .client_app = c_app, .server_app = s_app };
}

/// TLS Finished helpers (minimal): finished_key = Expand(traffic_secret, "finished");
/// verify_data = HMAC(finished_key, transcript_hash)
pub fn deriveFinishedVerifyData(traffic_secret: [H.digest_length]u8, transcript_hash: [H.digest_length]u8) [H.digest_length]u8 {
    var finished_key: [H.digest_length]u8 = undefined;
    ks.expandLabel(traffic_secret, "finished", &[_]u8{}, &finished_key) catch unreachable;
    return ks.hmacSha256(&finished_key, &transcript_hash);
}

/// Minimal, non-interoperable handshake engine stub that accumulates
/// CRYPTO bytes and allows tests to inject ServerHello pieces to drive
/// key schedule. Real message parsing/encoding will be added iteratively.
pub const Engine = struct {
    role: Role,
    transcript: Transcript = Transcript.init(),
    /// Deterministic ECDHE secret for tests or derived via X25519 in future slices.
    ecdhe_secret: ?[]const u8 = null,
    /// Buffer to hold derived ECDHE so the slice stays valid.
    ecdhe_buf: [32]u8 = undefined,
    /// Local X25519 keypair (generated on demand).
    my_priv: ?[32]u8 = null,
    my_pub: ?[32]u8 = null,
    /// Last seen peer pubkey (from CH/SH minimal envelopes).
    peer_pub: ?[32]u8 = null,
    /// Buffer for producing outbound CRYPTO data (e.g., ClientHello).
    outbox: std.ArrayList(u8),
    /// Tracking flags for minimal handshake state.
    ch_sent: bool = false,
    sh_seen: bool = false,
    /// Security / verification state (minimal)
    allow_insecure: bool = true,
    peer_cert_ok: bool = false,
    finished_sent: bool = false,
    finished_verified: bool = false,

    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .transcript = Transcript.init(), .ecdhe_secret = null, .ecdhe_buf = undefined, .my_priv = null, .my_pub = null, .peer_pub = null, .outbox = std.ArrayList(u8).init(alloc), .ch_sent = false, .sh_seen = false, .allow_insecure = true, .peer_cert_ok = false, .finished_sent = false, .finished_verified = false };
    }
    pub fn deinit(self: *Engine) void {
        self.outbox.deinit();
    }

    fn ensureKeypair(self: *Engine) void {
        if (self.my_priv == null or self.my_pub == null) {
            var sk: [32]u8 = undefined;
            std.crypto.random.bytes(&sk);
            // Derive public as sk * basepoint (0x09 || 31*0x00)
            var base: [32]u8 = .{0} ** 32;
            base[0] = 9;
            const pk = std.crypto.dh.X25519.scalarmult(sk, base) catch {
                // Fallback to deterministic non-zero pub to avoid panics in tests
                var tmp: [32]u8 = .{0} ** 32;
                tmp[0] = 1;
                self.my_priv = sk;
                self.my_pub = tmp;
                return;
            };
            self.my_priv = sk;
            self.my_pub = pk;
        }
    }

    fn tryComputeShared(self: *Engine) void {
        if (self.peer_pub) |peer| {
            if (self.my_priv) |priv| {
                const sh = std.crypto.dh.X25519.scalarmult(priv, peer) catch return;
                self.ecdhe_buf = sh;
                self.ecdhe_secret = self.ecdhe_buf[0..];
            }
        }
    }

    /// Append received CRYPTO bytes into transcript. Attempts to parse handshake messages
    /// to update simple state, but always feeds the transcript with raw bytes.
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        var off: usize = 0;
        while (true) {
            const parsed = parseHandshakeOne(data[off..]) catch null;
            if (parsed) |p| {
                // Snapshot transcript up to the start of this message for Finished verification
                var snap = self.transcript;
                snap.update(data[0..off]);
                const th_before = snap.finalize();

                off += p.n;
                if (p.typ == .server_hello) self.sh_seen = true;
                if (p.typ == .client_hello) self.ch_sent = true;
                if (parseMinimalHelloPub(p.typ, p.body)) |pk| {
                    self.peer_pub = pk;
                    // Depending on role, compute shared when appropriate.
                    switch (p.typ) {
                        .client_hello => if (self.role == .Server) self.tryComputeShared(),
                        .server_hello => if (self.role == .Client) self.tryComputeShared(),
                        else => {},
                    }
                }
                // Minimal X.509 certificate body handling (single DER cert)
                if (p.typ == .certificate) {
                    if (self.allow_insecure) {
                        self.peer_cert_ok = true;
                    } else {
                        const cert_val = x509.parseCert(self.outbox.allocator, p.body) catch null;
                        if (cert_val) |c| {
                            self.peer_cert_ok = true;
                            x509.checkValidity(std.time.timestamp(), &c) catch {
                                self.peer_cert_ok = false;
                            };
                        } else {
                            self.peer_cert_ok = false;
                        }
                    }
                }
                // Finished verification
                if (p.typ == .finished and self.ecdhe_secret != null) {
                    const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th_before);
                    const expect = switch (self.role) {
                        .Client => deriveFinishedVerifyData(hs.server_hs, th_before),
                        .Server => deriveFinishedVerifyData(hs.client_hs, th_before),
                    };
                    if (p.body.len == expect.len and std.mem.eql(u8, p.body, &expect)) {
                        self.finished_verified = true;
                    } else {
                        self.finished_verified = false;
                    }
                }
            } else break;
        }
        self.transcript.update(data);
    }

    /// Provide ECDHE shared secret directly (used in tests after X25519 exchange).
    pub fn setEcdhe(self: *Engine, shared: []const u8) void {
        self.ecdhe_secret = shared;
    }

    /// Queue outbound CRYPTO bytes (e.g., ClientHello)
    pub fn queueCrypto(self: *Engine, data: []const u8) !void {
        try self.outbox.appendSlice(data);
        self.transcript.update(data);
        // If this was a proper handshake record, flip flags
        if (data.len >= 1) {
            if (data[0] == @intFromEnum(HsType.client_hello)) {
                self.ch_sent = true;
            } else if (data[0] == @intFromEnum(HsType.server_hello)) {
                self.sh_seen = true; // mark seen on send for server gating
            }
        }
    }

    /// Build and queue a minimal ClientHello handshake envelope with a synthetic body.
    /// This is NOT wire-compatible TLS; it's a placeholder to exercise the pipeline.
    pub fn queueMinimalClientHello(self: *Engine) !void {
        const tmp = try encodeHandshake(self.outbox.allocator, .client_hello, "CHLO");
        defer self.outbox.allocator.free(tmp);
        try self.queueCrypto(tmp);
    }

    /// Build and queue a minimal ClientHello with provided X25519 pub
    pub fn queueMinimalClientHelloX25519(self: *Engine, client_pub: [32]u8) !void {
        const msg = try encodeMinimalClientHello(self.outbox.allocator, client_pub);
        defer self.outbox.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Build and queue a minimal ServerHello with provided X25519 pub
    pub fn queueMinimalServerHelloX25519(self: *Engine, server_pub: [32]u8) !void {
        const msg = try encodeMinimalServerHello(self.outbox.allocator, server_pub);
        defer self.outbox.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Auto-generate keypair (if needed) and queue minimal ClientHello carrying our pubkey.
    pub fn queueMinimalClientHelloAuto(self: *Engine) ![32]u8 {
        self.ensureKeypair();
        const pubk = self.my_pub.?;
        try self.queueMinimalClientHelloX25519(pubk);
        return pubk;
    }

    /// Auto-generate keypair (if needed) and queue minimal ServerHello carrying our pubkey.
    pub fn queueMinimalServerHelloAuto(self: *Engine) ![32]u8 {
        self.ensureKeypair();
        const pubk = self.my_pub.?;
        try self.queueMinimalServerHelloX25519(pubk);
        return pubk;
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
        // Harden: require both CH and SH observed
        if (!self.ch_sent or !self.sh_seen) return null;
        const th = self.transcript.finalize();
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }

    /// After handshakes secrets, compute application traffic secrets directly.
    pub fn computeApplicationSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        if (!self.ch_sent or !self.sh_seen) return null;
        const th = self.transcript.finalize();
        const ap = deriveApplicationTrafficFromEcdhe(self.ecdhe_secret.?, th);
        return .{ .client = ap.client_app, .server = ap.server_app };
    }

    /// Convenience alias for draining outbound CRYPTO intended for QUIC Handshake pkts.
    pub fn popCrypto(self: *Engine, out: []u8) usize {
        return self.takeOut(out);
    }

    /// Queue a minimal TLS Finished message with verify_data against current transcript.
    pub fn queueFinished(self: *Engine) !void {
        if (self.ecdhe_secret == null or !self.ch_sent or !self.sh_seen) return error.HandshakeNotReady;
        const th = self.transcript.finalize();
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        const my = if (self.role == .Client) hs.client_hs else hs.server_hs;
        const verify = deriveFinishedVerifyData(my, th);
        const msg = try encodeHandshake(self.outbox.allocator, .finished, verify[0..]);
        defer self.outbox.allocator.free(msg);
        try self.queueCrypto(msg);
        self.finished_sent = true;
    }
};

/// Generate an X25519 keypair and compute a shared secret given peer public.
/// Returns (priv, pub, shared) where shared may be null if peer_pub is null.
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) struct { priv_key: [32]u8, pub_key: [32]u8, shared: ?[32]u8 } {
    var sk: [32]u8 = undefined;
    var pk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    std.crypto.dh.X25519.scalarmultBase(&pk, sk);
    var shared: ?[32]u8 = null;
    if (peer_pub_opt) |peer_pub| {
        var sh: [32]u8 = undefined;
        if (std.crypto.dh.X25519.scalarmult(&sh, sk, peer_pub)) {
            shared = sh;
        } else shared = null;
    }
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
}

/// Encode a minimalistic ClientHello body carrying an X25519 key share only (non-interoperable placeholder).
pub fn encodeMinimalClientHello(alloc: std.mem.Allocator, client_pub: [32]u8) ![]u8 {
    // Body: "CH1" || client_pub
    var body: [3 + 32]u8 = undefined;
    body[0] = 'C';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &client_pub);
    return encodeHandshake(alloc, .client_hello, body[0..]);
}

/// Encode a minimalistic ServerHello body carrying an X25519 key share only (non-interoperable placeholder).
pub fn encodeMinimalServerHello(alloc: std.mem.Allocator, server_pub: [32]u8) ![]u8 {
    var body: [3 + 32]u8 = undefined;
    body[0] = 'S';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &server_pub);
    return encodeHandshake(alloc, .server_hello, body[0..]);
}

/// Attempt to parse minimal CH/SH and return pubkeys if present.
pub fn parseMinimalHelloPub(typ: HsType, body: []const u8) ?[32]u8 {
    if (body.len != 3 + 32) return null;
    if (typ == .client_hello and std.mem.eql(u8, body[0..3], "CH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    if (typ == .server_hello and std.mem.eql(u8, body[0..3], "SH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    return null;
}
