// MIT License
// Minimal TLS 1.3 handshake helpers for QUIC (no record layer)
// Scope: transcript hash, Derive-Secret helpers, handshake traffic secrets,
// a tiny state container to consume/produce CRYPTO bytes, and minimal
// handshake message encode/parse helpers for ClientHello/ServerHello envelopes.
const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");

/// Session ticket cache entry and store types used by the TLS 1.3 engine (minimal placeholder).
// --- Session Ticket / PSK Cache Structures (minimal placeholder) ---
/// One cached TLS 1.3 session ticket with identity, resumption secret, and lifetime.
pub const TicketEntry = struct {
    identity: []u8, // ticket bytes (owned)
    secret: [H.digest_length]u8, // resumption_secret derived from master_secret
    lifetime: u32,
};

/// Borrowed view of a ticket entry used for read-only access without copying.
pub const TicketEntryView = struct {
    identity: []const u8,
    secret: [H.digest_length]u8,
    lifetime: u32,
};

/// Fixed-size FIFO store for session tickets with helper methods to add/peek.
pub const TicketStore = struct {
    const capacity = 4; // tiny FIFO
    entries: [capacity]?TicketEntry = .{null} ** capacity,
    count: usize = 0,

    /// Free any owned ticket identities and reset the store to empty.
    pub fn deinit(self: *TicketStore, alloc: std.mem.Allocator) void {
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            if (self.entries[i]) |*e| {
                alloc.free(e.identity);
                self.entries[i] = null;
            }
        }
        self.count = 0;
    }

    fn indexNewest(self: *TicketStore) ?usize {
        if (self.count == 0) return null;
        // Newest stored at (count-1) mod capacity as FIFO append order
        return (self.count - 1) % capacity;
    }

    /// Return a borrowed view of the most recently added ticket if present.
    pub fn peek(self: *TicketStore) ?TicketEntryView {
        const idx_opt = self.indexNewest();
        if (idx_opt) |idx| {
            if (self.entries[idx]) |e| {
                return .{ .identity = e.identity, .secret = e.secret, .lifetime = e.lifetime };
            }
        }
        return null;
    }

    /// Insert a ticket, evicting the oldest when capacity is exceeded.
    pub fn add(self: *TicketStore, alloc: std.mem.Allocator, identity: []const u8, secret: [H.digest_length]u8, lifetime: u32) !void {
        // If capacity full, evict oldest (which is at index (count % capacity) before increment)
        const slot = self.count % capacity;
        if (self.entries[slot]) |*old| {
            alloc.free(old.identity);
        }
        const id_copy = try alloc.dupe(u8, identity);
        self.entries[slot] = TicketEntry{ .identity = id_copy, .secret = secret, .lifetime = lifetime };
        self.count += 1;
    }
};

/// Hash used for TLS 1.3 in this implementation (SHA-256).
pub const H = ks.H; // sha256

/// TLS handshake role.
pub const Role = enum { Client, Server };

/// TLS Handshake message types used by helpers.
pub const HsType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4, // RFC 8446
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

    /// Initialize a new transcript hash helper.
    pub fn init() Transcript {
        return .{ .hasher = H.init(.{}) };
    }
    /// Update transcript with raw bytes (handshake messages).
    pub fn update(self: *Transcript, msg: []const u8) void {
        self.hasher.update(msg);
    }
    /// Finalize and return current transcript hash without consuming internal state.
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

/// Derive QUIC handshake keys from a handshake traffic secret.
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

/// Derive QUIC 1-RTT keys from an application traffic secret.
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
    allocator: std.mem.Allocator,
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
    /// Whether EncryptedExtensions has been sent (server) or received (client) in real mode
    ee_sent: bool = false,
    /// Stored handshake traffic secrets (derived immediately after SH) for correct Finished verification
    handshake_client_secret: ?[H.digest_length]u8 = null,
    handshake_server_secret: ?[H.digest_length]u8 = null,
    /// Leaf certificate SPKI (DER) cached on Certificate message, owned by Engine
    leaf_spki: ?[]u8 = null,
    /// QUIC Transport Parameters (encoded blobs) carried in CRYPTO
    local_tp: ?[]u8 = null,
    peer_tp: ?[]u8 = null,
    /// Negotiated ALPN (opaque protocol id)
    alpn: ?[]u8 = null,
    /// Server Name Indication for certificate name checks (client-side). Owned by engine.
    server_name: ?[]u8 = null,
    /// Enable real (spec-oriented) handshake mode (currently client CH builder only)
    real_mode: bool = false,
    /// Stored server certificate (DER) and private key (for future Certificate + CertificateVerify emission)
    server_cert_der: ?[]u8 = null,
    server_priv_key: ?[]u8 = null,
    server_sig_alg: ?sig.SigAlg = null,
    /// Cached master_secret (to derive resumption/PSK secrets). Filled when application secrets computed.
    master_secret: ?[H.digest_length]u8 = null,
    /// Stored resumption tickets (very small cache FIFO). Each entry keeps identity and resumption_secret.
    tickets: TicketStore = .{},

    /// Initialize a TLS 1.3 Engine with allocator and role.
    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .allocator = alloc, .transcript = Transcript.init(), .ecdhe_secret = null, .ecdhe_buf = undefined, .my_priv = null, .my_pub = null, .peer_pub = null, .outbox = std.ArrayList(u8){}, .ch_sent = false, .sh_seen = false, .allow_insecure = true, .peer_cert_ok = false, .finished_sent = false, .finished_verified = false, .ee_sent = false, .handshake_client_secret = null, .handshake_server_secret = null, .leaf_spki = null, .local_tp = null, .peer_tp = null, .alpn = null, .server_name = null, .real_mode = false, .server_cert_der = null, .server_priv_key = null, .server_sig_alg = null, .master_secret = null, .tickets = .{} };
    }
    /// Release any owned resources and buffers.
    pub fn deinit(self: *Engine) void {
        if (self.leaf_spki) |spki| self.allocator.free(spki);
        if (self.local_tp) |b| self.allocator.free(b);
        if (self.peer_tp) |b| self.allocator.free(b);
        if (self.alpn) |a| self.allocator.free(a);
        if (self.server_name) |s| self.allocator.free(s);
        if (self.server_cert_der) |c| self.allocator.free(c);
        if (self.server_priv_key) |k| self.allocator.free(k);
        self.tickets.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
    }

    /// Queue a minimal NewSessionTicket (placeholder). Not yet used for PSK resumption.
    pub fn queueNewSessionTicket(self: *Engine) !void {
        try self.queueNewSessionTicketWithParams(3600, "test_ticket");
    }
    
    /// Queue a NewSessionTicket with specific parameters.
    pub fn queueNewSessionTicketWithParams(self: *Engine, lifetime: u32, ticket: []const u8) !void {
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        // struct {
        //   uint32 ticket_lifetime;
        //   uint32 ticket_age_add;
        //   opaque ticket_nonce<0..255>; (len=0)
        //   opaque ticket<1..2^16-1>;
        //   Extension extensions<0..2^16-2> (len=0)
        // }
        var be4: [4]u8 = undefined; // big-endian scratch
        var be2: [2]u8 = undefined; // big-endian scratch
        std.mem.writeInt(u32, &be4, lifetime, .big);
        try body.appendSlice(self.allocator, &be4);
        std.mem.writeInt(u32, &be4, 0, .big); // age_add placeholder
        try body.appendSlice(self.allocator, &be4);
        try body.append(self.allocator, 0); // nonce length 0
        std.mem.writeInt(u16, &be2, @intCast(ticket.len), .big);
        try body.appendSlice(self.allocator, &be2);
        try body.appendSlice(self.allocator, ticket);
        std.mem.writeInt(u16, &be2, 0, .big); // extensions length 0
        try body.appendSlice(self.allocator, &be2);
        const msg = try encodeHandshake(self.allocator, .new_session_ticket, body.items);
        defer self.allocator.free(msg);
        self.transcript.update(msg);
        try self.outbox.appendSlice(self.allocator, msg);
    }

    /// Access first cached ticket (if any) for simple resumption offering.
    pub fn peekTicket(self: *Engine) ?TicketEntryView {
        return self.tickets.peek();
    }

    /// Flush and return the outbox contents, transferring ownership to caller.
    pub fn flushCrypto(self: *Engine, alloc: std.mem.Allocator) ![]u8 {
        const result = try alloc.alloc(u8, self.outbox.items.len);
        @memcpy(result, self.outbox.items);
        self.outbox.clearRetainingCapacity();
        return result;
    }

    /// Ingest CRYPTO data from peer and parse handshake messages.
    pub fn ingestCrypto(self: *Engine, data: []const u8) !void {
        self.onCryptoRecv(data);
    }

    /// Activate real handshake mode (experimental). Currently only affects ClientHello generation.
    pub fn enableReal(self: *Engine) void {
        self.real_mode = true;
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
                std.debug.print("{s}: Computed ECDHE secret\n", .{if (self.role == .Server) "Server" else "Client"});
            } else {
                std.debug.print("{s}: No my_priv for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
            }
        } else {
            std.debug.print("{s}: No peer_pub for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
        }
    }

    /// Append received CRYPTO bytes into transcript. Attempts to parse handshake messages
    /// to update simple state, but always feeds the transcript with raw bytes.
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        var off: usize = 0;
        while (true) {
            const parsed = parseHandshakeOne(data[off..]) catch null;
            if (parsed) |p| {
                std.debug.print("TLS: Parsed handshake message type={} len={}\n", .{ p.typ, p.body.len });

                // For Finished verification, we need the transcript BEFORE the Finished message
                // So take a snapshot of the current transcript state
                var snap = self.transcript;
                const th_before = snap.finalize();

                // Update the transcript with this message UNLESS it's a Finished message
                // Finished messages are added to the transcript AFTER verification
                const msg_data = data[off .. off + p.n];
                if (p.typ != .finished) {
                    self.transcript.update(msg_data);
                    std.debug.print("TLS: Added {} bytes to transcript (recv): ", .{msg_data.len});
                    for (msg_data[0..@min(8, msg_data.len)]) |b| std.debug.print("{X:0>2} ", .{b});
                    std.debug.print("...\n", .{});
                }

                off += p.n;
                if (p.typ == .server_hello) self.sh_seen = true;
                if (p.typ == .client_hello) self.ch_sent = true;
                // If we just processed a real ServerHello, derive handshake secrets immediately (spec: hash includes CH+SH)
                if (self.real_mode and p.typ == .server_hello and self.handshake_client_secret == null and self.ecdhe_secret != null) {
                    var th_tr = Transcript.init();
                    th_tr.update(data[0..off]);
                    const th_hash = th_tr.finalize();
                    const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th_hash);
                    self.handshake_client_secret = hs.client_hs;
                    self.handshake_server_secret = hs.server_hs;
                    _ = self.computeApplicationSecrets();
                }

                // Only try to extract public keys from ClientHello and ServerHello
                if (p.typ == .client_hello or p.typ == .server_hello) {
                    var extracted: ?[32]u8 = null;
                    if (self.real_mode) {
                        switch (p.typ) {
                            .client_hello => extracted = parseRealClientHello(p.body),
                            .server_hello => extracted = parseRealServerHello(p.body),
                            else => {},
                        }
                    }
                    if (extracted == null) {
                        if (parseMinimalHelloPub(p.typ, p.body)) |pk_min| {
                            extracted = pk_min;
                        } else {
                            std.debug.print("{s}: Failed to parse hello pub (typ={}, body_len={})\n", .{ if (self.role == .Server) "Server" else "Client", p.typ, p.body.len });
                        }
                    }
                    if (extracted) |pk| {
                        self.peer_pub = pk;
                        // Compute shared secret after receiving peer's public key
                        switch (p.typ) {
                            .server_hello => if (self.role == .Client) self.tryComputeShared(),
                            // For server, shared secret is computed after generating own keypair in queueMinimalServerHelloAuto
                            else => {},
                        }
                    }
                }

                // Parse EncryptedExtensions (real or legacy placeholder)
                if (p.typ == .encrypted_extensions) {
                    if (self.real_mode) {
                        self.ee_sent = true; // mark seen (client)
                        if (p.body.len >= 2) {
                            const total = readU16(p.body[0..2]);
                            if (2 + total <= p.body.len) {
                                var pos2: usize = 2;
                                while (pos2 + 4 <= 2 + total) : (pos2 += 4 + readU16(p.body[pos2 + 2 .. pos2 + 4])) {
                                    const etype = readU16(p.body[pos2 .. pos2 + 2]);
                                    const elen = readU16(p.body[pos2 + 2 .. pos2 + 4]);
                                    if (pos2 + 4 + elen > 2 + total) break;
                                    const edata = p.body[pos2 + 4 .. pos2 + 4 + elen];
                                    switch (etype) {
                                        0x0010 => { // ALPN
                                            if (elen >= 3) {
                                                if (elen >= 2) {
                                                    const list_len = readU16(edata[0..2]);
                                                    if (2 + list_len <= edata.len and list_len > 0) {
                                                        const name_len = edata[2];
                                                        if (3 + name_len <= edata.len and name_len > 0) {
                                                            if (self.alpn) |old| self.allocator.free(old);
                                                            self.alpn = self.allocator.dupe(u8, edata[3 .. 3 + name_len]) catch null;
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        0x0039 => { // QUIC TP
                                            if (self.peer_tp) |old| self.allocator.free(old);
                                            self.peer_tp = self.allocator.dupe(u8, edata) catch null;
                                        },
                                        else => {},
                                    }
                                }
                            }
                        }
                    } else {
                        var i: usize = 0;
                        if (p.body.len >= 5 and std.mem.eql(u8, p.body[0..4], "ALPN")) {
                            i = 4;
                            const n: usize = p.body[i];
                            i += 1;
                            if (i + n <= p.body.len) {
                                if (self.alpn) |old| self.allocator.free(old);
                                self.alpn = self.allocator.dupe(u8, p.body[i .. i + n]) catch null;
                                i += n;
                            }
                        }
                        if (i + 2 <= p.body.len and p.body[i] == 'T' and p.body[i + 1] == 'P') {
                            const tp_bytes = p.body[i + 2 ..];
                            if (self.peer_tp) |old| self.allocator.free(old);
                            self.peer_tp = self.allocator.dupe(u8, tp_bytes) catch null;
                        }
                    }
                }
                // Minimal X.509 certificate body handling (single DER cert)
                if (p.typ == .certificate) {
                    if (self.allow_insecure) {
                        self.peer_cert_ok = true;
                    } else {
                        const cert_val = x509.parseCert(self.allocator, p.body) catch null;
                        if (cert_val) |c| {
                            self.peer_cert_ok = true;
                            if (self.leaf_spki) |old| self.allocator.free(old);
                            self.leaf_spki = self.allocator.dupe(u8, c.spki) catch null;
                            x509.checkValidity(std.time.timestamp(), &c) catch {
                                self.peer_cert_ok = false;
                            };
                            if (self.peer_cert_ok) {
                                if (self.server_name) |sni| {
                                    x509.validateChain(self.allocator, &[_][]const u8{p.body}, std.time.timestamp(), sni, self.allow_insecure) catch {
                                        self.peer_cert_ok = false;
                                    };
                                }
                            }
                            if (self.peer_cert_ok) {
                                if (c.eku) |eku| {
                                    if (!eku.server_auth) {
                                        self.peer_cert_ok = false;
                                    }
                                }
                            }
                        } else {
                            self.peer_cert_ok = false;
                        }
                    }
                }
                // CertificateVerify: toy format for now -> first byte = alg id, rest = signature
                if (p.typ == .certificate_verify and !self.allow_insecure) {
                    if (!self.peer_cert_ok or self.leaf_spki == null) {
                        self.peer_cert_ok = false;
                    } else {
                        if (p.body.len > 1) {
                            const alg_id: u8 = p.body[0];
                            const signature = p.body[1..];
                            const th = th_before; // transcript up to CertificateVerify
                            const alg: sig.SigAlg = switch (alg_id) {
                                0x40 => .ecdsa_secp256r1_sha256,
                                0x41 => .ecdsa_secp384r1_sha384,
                                0x50 => .rsa_pss_sha256,
                                else => blk: {
                                    self.peer_cert_ok = false;
                                    break :blk .rsa_pss_sha256;
                                },
                            };
                            const ok = sig.verifyCertificateVerify(alg, self.leaf_spki.?, signature, "TLS 1.3, server CertificateVerify", &th) catch false;
                            self.peer_cert_ok = ok;
                        } else self.peer_cert_ok = false;
                    }
                }
                // Finished verification
                if (p.typ == .finished and self.ecdhe_secret != null) {
                    std.debug.print("TLS: Processing Finished message\n", .{});
                    var peer_secret_opt: ?[H.digest_length]u8 = null;
                    if (self.handshake_client_secret != null and self.handshake_server_secret != null) {
                        peer_secret_opt = switch (self.role) {
                            .Client => self.handshake_server_secret.?,
                            .Server => self.handshake_client_secret.?,
                        };
                        std.debug.print("TLS: Using stored handshake secrets for verification\n", .{});
                    }
                    const ok = if (peer_secret_opt) |ps| self.verifyPeerFinished(ps, p.body) else blk: {
                        std.debug.print("TLS: Using fallback for Finished verification\n", .{});
                        // Fallback (should not happen in real mode past this point)
                        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th_before);
                        break :blk switch (self.role) {
                            .Client => self.verifyPeerFinished(hs.server_hs, p.body),
                            .Server => self.verifyPeerFinished(hs.client_hs, p.body),
                        };
                    };
                    std.debug.print("TLS: Finished verification result: {}\n", .{ok});
                    self.finished_verified = ok;

                    // Add the Finished message to the transcript AFTER verification
                    if (ok) {
                        const finished_msg = data[off - p.n .. off];
                        self.transcript.update(finished_msg);
                        std.debug.print("TLS: Added {} bytes to transcript (recv-finished): ", .{finished_msg.len});
                        for (finished_msg[0..@min(8, finished_msg.len)]) |b| std.debug.print("{X:0>2} ", .{b});
                        std.debug.print("...\n", .{});
                    }
                }
                // NewSessionTicket parsing (client side only for now)
                if (p.typ == .new_session_ticket and self.role == .Client) {
                    const b = p.body;
                    var pos: usize = 0;
                    if (b.len >= 4) {
                        if (b.len < 4 + 4) continue; // need lifetime + age_add
                        const lifetime: u32 = (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | @as(u32, b[3]);
                        pos = 4 + 4; // skip age_add as well
                        if (pos >= b.len) continue;
                        if (pos >= b.len) continue;
                        const nonce_len: usize = b[pos];
                        pos += 1;
                        if (pos + nonce_len > b.len) continue; // skip nonce
                        pos += nonce_len;
                        if (pos + 2 > b.len) continue;
                        const ticket_len: usize = (@as(usize, b[pos]) << 8) | b[pos + 1];
                        pos += 2;
                        if (pos + ticket_len > b.len) continue;
                        const ticket_bytes = b[pos .. pos + ticket_len];
                        pos += ticket_len;
                        if (pos + 2 > b.len) continue; // extensions length
                        const ext_len: usize = (@as(usize, b[pos]) << 8) | b[pos + 1];
                        pos += 2;
                        if (pos + ext_len > b.len) continue;
                        // Compute resumption_secret if we have master_secret stored
                        if (self.master_secret) |ms| {
                            var resumption_secret: [H.digest_length]u8 = undefined;
                            // RFC 8446: resumption_master_secret = HKDF-Expand-Label(master_secret, "res master", Hash("") )
                            var empty_hash: [H.digest_length]u8 = .{0} ** H.digest_length;
                            // For now use zero hash as placeholder (transcript hash of empty string)
                            ks.expandLabel(ms, "res master", &empty_hash, &resumption_secret) catch continue;
                            self.tickets.add(self.allocator, ticket_bytes, resumption_secret, lifetime) catch {};
                            std.debug.print("TLS: Stored session ticket (len={}, lifetime={})\n", .{ ticket_bytes.len, lifetime });
                        } else {
                            std.debug.print("TLS: Received ticket before master_secret ready; ignoring\n", .{});
                        }
                    }
                }
            } else break;
        }
        // Transcript is now updated message-by-message in the loop above
        self.maybeAutoProgress();
    }

    /// Provide ECDHE shared secret directly (used in tests after X25519 exchange).
    pub fn setEcdhe(self: *Engine, shared: []const u8) void {
        self.ecdhe_secret = shared;
        if (self.ch_sent and self.sh_seen) {
            const th = self.transcript.finalize();
            const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
            self.handshake_client_secret = hs.client_hs;
            self.handshake_server_secret = hs.server_hs;
            _ = self.computeApplicationSecrets();
        }
    }

    /// Queue outbound CRYPTO bytes (e.g., ClientHello)
    pub fn queueCrypto(self: *Engine, data: []const u8) !void {
        try self.outbox.appendSlice(self.allocator, data);
        self.transcript.update(data);
        std.debug.print("TLS: Added {} bytes to transcript (queue): ", .{data.len});
        for (data[0..@min(8, data.len)]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("...\n", .{});
        // If this was a proper handshake record, flip flags
        if (data.len >= 1) {
            if (data[0] == @intFromEnum(HsType.client_hello)) {
                self.ch_sent = true;
            } else if (data[0] == @intFromEnum(HsType.server_hello)) {
                self.sh_seen = true; // mark seen on send for server gating
            }
        }
    }

    /// Attach local Transport Parameters to be sent in next handshake message.
    /// The Engine will prefix with a simple marker "TP" and include bytes as-is.
    pub fn setLocalTransportParameters(self: *Engine, tp_encoded: []const u8) !void {
        if (self.local_tp) |old| self.allocator.free(old);
        self.local_tp = try self.allocator.dupe(u8, tp_encoded);
    }

    /// Set the expected server name (SNI) for certificate validation on client.
    pub fn setServerName(self: *Engine, name: []const u8) !void {
        if (self.server_name) |old| self.allocator.free(old);
        self.server_name = try self.allocator.dupe(u8, name);
    }

    /// Build and queue a minimal ClientHello handshake envelope with optional TP.
    pub fn queueMinimalClientHello(self: *Engine) !void {
        if (self.real_mode) return self.queueRealClientHello();
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        // Base CH body
        try body.appendSlice(self.allocator, "CHLO");
        // Optionally append TP marker and bytes
        if (self.local_tp) |tp| {
            try body.appendSlice(self.allocator, "TP");
            try body.appendSlice(self.allocator, tp);
        }
        const tmp = try encodeHandshake(self.allocator, .client_hello, body.items);
        defer self.allocator.free(tmp);
        try self.queueCrypto(tmp);
    }

    /// Build a minimally spec-compliant TLS 1.3 ClientHello (QUIC) with:
    /// - cipher_suites: TLS_AES_128_GCM_SHA256 only
    /// - groups: x25519
    /// - key_share: x25519
    /// - supported_versions: TLS 1.3
    /// - signature_algorithms: a small set
    /// - alpn (if set via setServerName?) / local alpn not yet; will be extended
    /// - quic transport parameters extension (0x0039) if local_tp present
    fn queueRealClientHello(self: *Engine) !void {
        self.ensureKeypair();
        const pubkey = self.my_pub orelse return error.Internal;
        // Buffers
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        // legacy_version 0x0303
        try body.appendSlice(self.allocator, &.{ 0x03, 0x03 });
        // random 32 bytes
        var rnd: [32]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        try body.appendSlice(self.allocator, &rnd);
        // session id (empty vector length 0)
        try body.append(self.allocator, 0); // length
        // cipher_suites vector (length 2, then suite 0x1301)
        try body.appendSlice(self.allocator, &.{ 0x00, 0x02, 0x13, 0x01 });
        // legacy_compression_methods (length=1 then 0)
        try body.appendSlice(self.allocator, &.{ 0x01, 0x00 });
        // Build extensions into temp buffer
        var ext_buf = std.ArrayList(u8){};
        defer ext_buf.deinit(self.allocator);
        // supported_versions (43 / 0x002b)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 }); // len=3(0x0003), list length=2, version 0x0304
        // supported_groups (10 / 0x000a) -> length 2 list containing x25519 (0x001d)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
        // signature_algorithms (13 / 0x000d) list length 6 (3 algorithms)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x07 });
        // key_share (51 / 0x0033) group x25519(0x001d) key length 32
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x33 });
        const key_share_len: u16 = 2 + 2 + 32; // group(2)+key_len(2)+key(32)
        const total_key_share_len: u16 = @intCast(key_share_len + 2); // plus vector length field (u16)
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(total_key_share_len >> 8), @intCast(total_key_share_len & 0xff) });
        // inner vector length
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
        // group
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x1d });
        // key length (32)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 32 });
        try ext_buf.appendSlice(self.allocator, pubkey[0..]);
        // ALPN if configured (reuse self.alpn if already set via test harness) - ALPN ext type 16
        if (self.alpn) |alpn_vec| {
            // Extension type 0x0010
            // Format: type(2)|len(2)|list_len(2)|proto_len(1)|proto
            const list_len: usize = 1 + alpn_vec.len; // one entry
            const ext_len: usize = 2 + list_len; // list length field + list
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_len >> 8), @intCast(ext_len & 0xff), @intCast(list_len >> 8), @intCast(list_len & 0xff), @intCast(alpn_vec.len) });
            try ext_buf.appendSlice(self.allocator, alpn_vec);
        }
        // QUIC Transport Parameters extension (0x0039) if local_tp present
        if (self.local_tp) |tp| {
            const tp_len: usize = tp.len;
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tp);
        }
        // Pre-Shared Key (PSK) offer if we have cached tickets. Minimal implementation:
        // - Offer single identity (first ticket). Binder is zero-filled placeholder (not validated yet).
        if (self.peekTicket()) |tkt| {
            // psk_key_exchange_modes (ext 0x002d) offering mode 0 (psk_ke) only
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2d, 0x00, 0x02, 0x01, 0x00 });
            // pre_shared_key (0x0029)
            const id_len: u16 = @intCast(tkt.identity.len);
            // identities vector: length(2) + identity + obfuscated_ticket_age(4)
            const one_identity_len: usize = 2 + id_len + 4;
            const identities_vec_len: u16 = @intCast(one_identity_len);
            const binders_len: u16 = @intCast(1 + H.digest_length); // vector length(1) + binder (digest length)
            const total_psk_len: u16 = @intCast(2 + identities_vec_len + 2 + binders_len);
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x29, @intCast(total_psk_len >> 8), @intCast(total_psk_len & 0xff) });
            // identities vector length
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(identities_vec_len >> 8), @intCast(identities_vec_len & 0xff) });
            // identity length
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(id_len >> 8), @intCast(id_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tkt.identity);
            // obfuscated_ticket_age (placeholder 0)
            try ext_buf.appendSlice(self.allocator, &.{ 0, 0, 0, 0 });
            // binders vector length
            const binders_vec_len: u16 = @intCast(1 + H.digest_length);
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(binders_vec_len >> 8), @intCast(binders_vec_len & 0xff) });
            // single binder length (H.digest_length)
            try ext_buf.append(self.allocator, @as(u8, @intCast(H.digest_length)));
            // zero-filled binder placeholder
            var zeros: [H.digest_length]u8 = .{0} ** H.digest_length;
            try ext_buf.appendSlice(self.allocator, &zeros);
        }
        // Now write extensions length
        const exts = ext_buf.items;
        const exts_len: u16 = @intCast(exts.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, exts);
        const msg = try encodeHandshake(self.allocator, .client_hello, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Build and queue a minimal ServerHello with optional TP.
    pub fn queueMinimalServerHello(self: *Engine) !void {
        if (self.real_mode) {
            try self.queueRealServerHello();
            return;
        }
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "SHLO");
        if (self.local_tp) |tp| {
            try body.appendSlice(self.allocator, "TP");
            try body.appendSlice(self.allocator, tp);
        }
        const msg = try encodeHandshake(self.allocator, .server_hello, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Accessor for peer transport parameters (encoded), if any.
    pub fn getPeerTransportParameters(self: *Engine) ?[]const u8 {
        return self.peer_tp;
    }

    /// Build and queue a Finished message for this endpoint using provided traffic secret.
    /// This computes verify_data = HMAC(FinishedKey(secret), Transcript-Hash(before-Finished)).
    pub fn queueFinished(self: *Engine, traffic_secret: [H.digest_length]u8) !void {
        var snap = self.transcript;
        const th = snap.finalize();
        std.debug.print("TLS: Queueing Finished with transcript hash: ", .{});
        for (th[0..8]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("...\n", .{});
        const verify = deriveFinishedVerifyData(traffic_secret, th);
        const msg = try encodeHandshake(self.allocator, .finished, verify[0..]);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        self.finished_sent = true;
    }

    /// Verify peer Finished given peer traffic secret.
    pub fn verifyPeerFinished(self: *Engine, peer_secret: [H.digest_length]u8, finished_body: []const u8) bool {
        // finished_body is the verify_data sent by the peer
        var snap = self.transcript;
        const th = snap.finalize();
        std.debug.print("TLS: Verifying Finished with transcript hash: ", .{});
        for (th[0..8]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("...\n", .{});
        const expect = deriveFinishedVerifyData(peer_secret, th);
        const match = finished_body.len == expect.len and std.mem.eql(u8, finished_body, &expect);
        if (!match) {
            std.debug.print("TLS: Finished verification failed. Expected len={}, got len={}\n", .{ expect.len, finished_body.len });
            if (finished_body.len == expect.len) {
                std.debug.print("TLS: MAC mismatch\n", .{});
            }
        }
        return match;
    }

    /// Build and queue EncryptedExtensions carrying ALPN and Transport Parameters.
    pub fn queueEncryptedExtensions(self: *Engine, alpn: []const u8, tp_bytes: []const u8) !void {
        if (self.real_mode) {
            // Encode standard TLS EncryptedExtensions extension vector
            var ext_list = std.ArrayList(u8){};
            defer ext_list.deinit(self.allocator);
            if (alpn.len > 0) {
                // ALPN extension (0x0010)
                const proto_list_len: u16 = @intCast(1 + alpn.len); // one entry
                const ext_data_len: u16 = @intCast(2 + proto_list_len);
                try ext_list.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_data_len >> 8), @intCast(ext_data_len & 0xff), @intCast(proto_list_len >> 8), @intCast(proto_list_len & 0xff), @intCast(alpn.len) });
                try ext_list.appendSlice(self.allocator, alpn);
            }
            if (tp_bytes.len > 0) {
                const tp_len: u16 = @intCast(tp_bytes.len);
                try ext_list.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
                try ext_list.appendSlice(self.allocator, tp_bytes);
            }
            const all_ext = ext_list.items;
            const total_len: u16 = @intCast(all_ext.len);
            var body = std.ArrayList(u8){};
            defer body.deinit(self.allocator);
            try body.appendSlice(self.allocator, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
            try body.appendSlice(self.allocator, all_ext);
            const msg = try encodeHandshake(self.allocator, .encrypted_extensions, body.items);
            defer self.allocator.free(msg);
            try self.queueCrypto(msg);
            self.ee_sent = true; // mark sent (server)
            self.maybeAutoProgress();
            return;
        }
        // Legacy minimal placeholder encoding
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        if (alpn.len > 0) {
            try body.appendSlice(self.allocator, "ALPN");
            try body.append(self.allocator, @as(u8, @intCast(alpn.len)));
            try body.appendSlice(self.allocator, alpn);
        }
        if (tp_bytes.len > 0) {
            try body.appendSlice(self.allocator, "TP");
            try body.appendSlice(self.allocator, tp_bytes);
        }
        const msg = try encodeHandshake(self.allocator, .encrypted_extensions, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Queue a raw Certificate handshake message body (DER) for interop; in secure mode,
    /// the peer will validate this using x509 helpers.
    pub fn queueCertificate(self: *Engine, cert_der: []const u8) !void {
        const msg = try encodeHandshake(self.allocator, .certificate, cert_der);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    // --- New helper methods used by tests ---

    /// Compute handshake traffic secrets if ECDHE and both CH/SH are present.
    pub fn computeHandshakeSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        if (!(self.ch_sent and self.sh_seen)) return null;
        const th = self.transcript.finalize();
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        // Store the secrets in the engine for later use
        self.handshake_client_secret = hs.client_hs;
        self.handshake_server_secret = hs.server_hs;
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }

    /// Compute application traffic secrets from current transcript and ECDHE.
    pub fn computeApplicationSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        if (!(self.ch_sent and self.sh_seen)) return null;
        const th = self.transcript.finalize();
        // Recompute master_secret path locally to retain master
        const early_secret = ks.extract(&[_]u8{}, &[_]u8{});
        var derived: [H.digest_length]u8 = undefined;
        ks.expandLabel(early_secret, "derived", &[_]u8{}, &derived) catch return null;
        const handshake_secret = ks.extract(&derived, self.ecdhe_secret.?);
        var derived2: [H.digest_length]u8 = undefined;
        ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch return null;
        const master = ks.extract(&derived2, &[_]u8{});
        self.master_secret = master; // cache for tickets
        var c_app: [H.digest_length]u8 = undefined;
        var s_app: [H.digest_length]u8 = undefined;
        ks.expandLabel(master, "c ap traffic", &th, &c_app) catch return null;
        ks.expandLabel(master, "s ap traffic", &th, &s_app) catch return null;
        return .{ .client = c_app, .server = s_app };
    }

    /// Queue a minimalistic ClientHello with an auto-generated X25519 key share.
    pub fn queueMinimalClientHelloAuto(self: *Engine) !usize {
        self.ensureKeypair();
        // For client, we'll compute shared secret when we receive ServerHello
        const pubkey = self.my_pub orelse return error.Internal;
        const msg = try encodeMinimalClientHello(self.allocator, pubkey);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        return msg.len;
    }

    /// Queue a minimalistic ServerHello with an auto-generated X25519 key share.
    pub fn queueMinimalServerHelloAuto(self: *Engine) !usize {
        if (self.real_mode) {
            try self.queueRealServerHello();
            return 0;
        }
        self.ensureKeypair();
        // Now that we have our keypair, try to compute shared secret if we have peer's public key
        if (self.role == .Server) self.tryComputeShared();
        const pubkey = self.my_pub orelse return error.Internal;
        const msg = try encodeMinimalServerHello(self.allocator, pubkey);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        return msg.len;
    }

    /// Pop CRYPTO bytes up to a specified limit, preserving remaining bytes.
    pub fn popCryptoPartial(self: *Engine, out: []u8, max_bytes: usize) usize {
        const available = self.outbox.items.len;
        const n = @min(@min(out.len, max_bytes), available);
        if (n > 0) {
            @memcpy(out[0..n], self.outbox.items[0..n]);
            // Remove only the consumed bytes
            _ = self.outbox.orderedRemove(0);
            var i: usize = 1;
            while (i < n) : (i += 1) {
                _ = self.outbox.orderedRemove(0);
            }
        }
        return n;
    }

    /// Pop all queued CRYPTO bytes into caller-provided buffer, returning bytes copied.
    pub fn popCrypto(self: *Engine, out: []u8) usize {
        const n = @min(out.len, self.outbox.items.len);
        if (n > 0) @memcpy(out[0..n], self.outbox.items[0..n]);
        // Clear the outbox after pop
        self.outbox.clearRetainingCapacity();
        return n;
    }

    /// Get the size of the next handshake message without consuming it.
    pub fn peekNextMessageSize(self: *Engine) usize {
        if (self.outbox.items.len < 4) return 0;
        // TLS handshake message format: type(1) + length(3)
        const len = (@as(usize, self.outbox.items[1]) << 16) |
            (@as(usize, self.outbox.items[2]) << 8) |
            self.outbox.items[3];
        return 4 + len; // Include header
    }

    /// Build a minimally spec-compliant TLS 1.3 ServerHello (real mode)
    pub fn queueRealServerHello(self: *Engine) !void {
        self.ensureKeypair();
        const pubkey = self.my_pub orelse return error.Internal;
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, &.{ 0x03, 0x03 }); // legacy_version
        var rnd: [32]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        try body.appendSlice(self.allocator, &rnd);
        try body.append(self.allocator, 0); // session id length
        try body.appendSlice(self.allocator, &.{ 0x13, 0x01 }); // cipher suite
        try body.append(self.allocator, 0); // compression method
        var ext = std.ArrayList(u8){};
        defer ext.deinit(self.allocator);
        // supported_versions
        try ext.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 });
        // key_share
        try ext.appendSlice(self.allocator, &.{ 0x00, 0x33 });
        const ks_len: u16 = 2 + 2 + 32; // group + key_len + key
        try ext.appendSlice(self.allocator, &.{ @intCast(ks_len >> 8), @intCast(ks_len & 0xff) });
        try ext.appendSlice(self.allocator, &.{ 0x00, 0x1d }); // group x25519
        try ext.appendSlice(self.allocator, &.{ 0x00, 32 });
        try ext.appendSlice(self.allocator, pubkey[0..]);
        const exts_bytes = ext.items;
        const exts_len: u16 = @intCast(exts_bytes.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, exts_bytes);
        const msg = try encodeHandshake(self.allocator, .server_hello, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        self.tryComputeShared();
        if (self.ecdhe_secret != null and self.handshake_client_secret == null) {
            var snap = self.transcript;
            const th = snap.finalize();
            const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
            self.handshake_client_secret = hs.client_hs;
            self.handshake_server_secret = hs.server_hs;
            _ = self.computeApplicationSecrets();
        }
    }
    /// Internal: auto-send Finished when conditions satisfied
    fn maybeAutoProgress(self: *Engine) void {
        if (self.finished_sent) return;
        if (self.ecdhe_secret == null) return;

        // In minimal mode, handle Finished generation for both client and server
        if (!self.real_mode) {
            if (self.role == .Client) {
                // Client: send Finished after verifying server's Finished
                if (self.finished_verified and self.handshake_client_secret != null) {
                    std.debug.print("Client: Queueing Finished message in minimal mode\n", .{});
                    self.queueFinished(self.handshake_client_secret.?) catch {};
                } else {
                    std.debug.print("Client: Not ready to send Finished (verified={}, has_secret={})\n", .{ self.finished_verified, self.handshake_client_secret != null });
                }
            }
            // Server in minimal mode doesn't use this path
            return;
        }

        // Real mode handling
        if (self.role == .Server) {
            // Authenticated path: if a server certificate is configured and not yet sent, emit Certificate + CertificateVerify
            if (self.ee_sent and self.handshake_server_secret != null) {
                if (self.server_cert_der != null and self.server_priv_key != null and !self.allow_insecure) {
                    // Check if Certificate already in transcript by scanning for finished_sent flag only; use finished_sent as barrier.
                    // If Finished not yet sent, we can still add cert flight.
                    // Queue Certificate
                    self.queueCertificate(self.server_cert_der.?) catch {};
                    // Build CertificateVerify signature
                    var snap = self.transcript; // includes cert now
                    const th = snap.finalize();
                    const alg = self.server_sig_alg orelse .ecdsa_secp256r1_sha256;
                    const sig_bytes = sig.signCertificateVerify(alg, self.server_priv_key.?, "TLS 1.3, server CertificateVerify", &th, self.allocator) catch null;
                    if (sig_bytes) |sb| {
                        // toy encoding: alg id byte + DER signature
                        var body = std.ArrayList(u8){};
                        defer body.deinit(self.allocator);
                        const alg_id: u8 = switch (alg) {
                            .ecdsa_secp256r1_sha256 => 0x40,
                            .ecdsa_secp384r1_sha384 => 0x41,
                            .rsa_pss_sha256 => 0x50,
                            .ed25519 => 0x87, // 0x0807 in TLS, single byte in CertificateVerify
                        };
                        body.append(self.allocator, alg_id) catch {};
                        body.appendSlice(self.allocator, sb) catch {};
                        const msg = encodeHandshake(self.allocator, .certificate_verify, body.items) catch null;
                        if (msg) |m| {
                            self.queueCrypto(m) catch {};
                            self.allocator.free(m);
                        }
                        self.allocator.free(sb);
                    }
                }
                // After (optionally) sending certificate flight, send Finished
                self.queueFinished(self.handshake_server_secret.?) catch {};
            }
            return;
        } else { // Client
            // Client waits for Finished verification; in authenticated mode also ensures peer_cert_ok
            if (self.finished_verified and self.handshake_client_secret != null) {
                if (!self.allow_insecure and !self.peer_cert_ok) return; // wait for cert validation
                self.queueFinished(self.handshake_client_secret.?) catch {};
            }
        }
    }
    /// Public: handshake complete when both sides' Finished exchanged.
    pub fn handshakeComplete(self: *Engine) bool {
        return self.finished_sent and self.finished_verified;
    }
    /// Install server certificate and private key (ECDSA P-256 for now). Stored for future emission.
    pub fn setServerCertificate(self: *Engine, cert_der: []const u8, priv_key: []const u8, alg: sig.SigAlg) !void {
        if (self.role != .Server) return error.WrongRole;
        if (self.server_cert_der) |c| self.allocator.free(c);
        if (self.server_priv_key) |k| self.allocator.free(k);
        self.server_cert_der = try self.allocator.dupe(u8, cert_der);
        self.server_priv_key = try self.allocator.dupe(u8, priv_key);
        self.server_sig_alg = alg;
    }

    /// Force queue of remaining server handshake flight (EncryptedExtensions already queued externally).
    pub fn queueServerHandshakeFlight(self: *Engine) void {
        if (self.role != .Server) return;
        if (self.finished_sent) return; // already done

        // In minimal mode, just queue the Finished message
        if (!self.real_mode) {
            if (self.handshake_server_secret) |secret| {
                self.queueFinished(secret) catch {};
            }
            return;
        }

        // Real mode: full handshake flight
        // Require that handshake_server_secret be present (after SH) and EE queued.
        if (self.handshake_server_secret == null) return;
        // If we have a certificate configured, send Certificate + CertificateVerify.
        if (self.server_cert_der != null and self.server_priv_key != null and !self.allow_insecure) {
            self.queueCertificate(self.server_cert_der.?) catch {};
            var snap = self.transcript;
            const th = snap.finalize();
            const alg = self.server_sig_alg orelse .ecdsa_secp256r1_sha256;
            const sig_bytes = sig.signCertificateVerify(alg, self.server_priv_key.?, "TLS 1.3, server CertificateVerify", &th, self.allocator) catch null;
            if (sig_bytes) |sb| {
                var body = std.ArrayList(u8){};
                defer body.deinit(self.allocator);
                const alg_id: u8 = switch (alg) {
                    .ecdsa_secp256r1_sha256 => 0x40,
                    .ecdsa_secp384r1_sha384 => 0x41,
                    .rsa_pss_sha256 => 0x50,
                    .ed25519 => 0x87, // 0x0807 in TLS, single byte in CertificateVerify
                };
                body.append(self.allocator, alg_id) catch {};
                body.appendSlice(self.allocator, sb) catch {};
                const msg = encodeHandshake(self.allocator, .certificate_verify, body.items) catch null;
                if (msg) |m| {
                    self.queueCrypto(m) catch {};
                    self.allocator.free(m);
                }
                self.allocator.free(sb);
            }
        } else if (self.allow_insecure and !self.finished_sent) {
            // In insecure mode, no real certificate; queue an empty Certificate message
            self.queueCertificate(&[_]u8{}) catch {};
        }
        // Always queue Finished last
        if (!self.finished_sent and self.handshake_server_secret != null) {
            self.queueFinished(self.handshake_server_secret.?) catch {};
        }
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

// --- Real TLS 1.3 ClientHello / ServerHello parsing helpers (minimal) ---

fn readU16(be: []const u8) u16 {
    return (@as(u16, be[0]) << 8) | be[1];
}

/// Attempt to parse a real (spec-like) TLS 1.3 ClientHello and extract the first X25519 key share.
/// Returns pubkey if successful; otherwise null. Does not perform deep validation beyond bounds.
fn parseRealClientHello(body: []const u8) ?[32]u8 {
    if (body.len < 2 + 32 + 1) return null; // version + random + session id len
    var pos: usize = 0;
    // legacy_version
    pos += 2;
    // random
    pos += 32;
    if (pos >= body.len) return null;
    // session id
    const sid_len: usize = body[pos];
    pos += 1;
    if (pos + sid_len > body.len) return null;
    pos += sid_len;
    if (pos + 2 > body.len) return null;
    const cs_len = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + cs_len > body.len) return null;
    pos += cs_len; // skip cipher_suites
    if (pos >= body.len) return null;
    const comp_len: usize = body[pos];
    pos += 1;
    if (pos + comp_len > body.len) return null;
    pos += comp_len;
    if (pos + 2 > body.len) return null;
    const exts_len = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return null;
    const exts_end = pos + exts_len;
    var pk: ?[32]u8 = null;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return null;
        if (etype == 0x0033) { // key_share
            if (elen < 2) return null;
            if (pos + 2 > exts_end) return null;
            const list_len = readU16(body[pos .. pos + 2]);
            pos += 2;
            if (pos + list_len > exts_end) return null;
            var lp: usize = pos;
            const list_end = pos + list_len;
            while (lp + 4 <= list_end) {
                const group = readU16(body[lp .. lp + 2]);
                const klen = readU16(body[lp + 2 .. lp + 4]);
                lp += 4;
                if (lp + klen > list_end) return null;
                if (group == 0x001d and klen == 32) {
                    var out: [32]u8 = undefined;
                    @memcpy(&out, body[lp .. lp + 32]);
                    pk = out;
                    break;
                }
                lp += klen;
            }
            // We don't parse further extensions once key_share found.
        }
        pos += elen; // advance to next extension
    }
    return pk;
}

/// Attempt to parse a real (spec-like) TLS 1.3 ServerHello and extract the X25519 key share.
fn parseRealServerHello(body: []const u8) ?[32]u8 {
    if (body.len < 2 + 32 + 1 + 2 + 1 + 2) return null; // minimal size
    var pos: usize = 0;
    pos += 2; // legacy version
    pos += 32; // random
    if (pos >= body.len) return null;
    const sid_len: usize = body[pos];
    pos += 1;
    if (pos + sid_len > body.len) return null;
    pos += sid_len; // session id
    if (pos + 3 > body.len) return null;
    pos += 2; // cipher suite
    pos += 1; // compression method
    if (pos + 2 > body.len) return null;
    const exts_len = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return null;
    const exts_end = pos + exts_len;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return null;
        if (etype == 0x0033) { // key_share (server format)
            if (elen < 4 + 32) return null;
            const group = readU16(body[pos .. pos + 2]);
            const klen = readU16(body[pos + 2 .. pos + 4]);
            if (group == 0x001d and klen == 32 and pos + 4 + 32 <= pos + elen) {
                var out: [32]u8 = undefined;
                @memcpy(&out, body[pos + 4 .. pos + 4 + 32]);
                return out;
            }
        }
        pos += elen;
    }
    return null;
}

// Build a minimally spec-compliant TLS 1.3 ServerHello with:
// - cipher_suite TLS_AES_128_GCM_SHA256
// - supported_versions (selected 1.3)
// - key_share (x25519)
