const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");
const transport_params = @import("quic_transport_params");
const test_certs = @import("test_certs");

const default_signature_schemes = [_]u16{ 0x0807, 0x0403 };

var metadata_callback_count: usize = 0;
var metadata_alpn_seen: bool = false;
var metadata_tp_seen: bool = false;
var peer_finished_callback_count: usize = 0;
var handshake_complete_callback_count: usize = 0;

fn testOnMetadata(ctx: *tls13.Context, meta: tls13.HandshakeMetadata) anyerror!void {
    _ = ctx;
    metadata_callback_count += 1;
    metadata_alpn_seen = meta.alpn != null;
    metadata_tp_seen = meta.local_transport_parameters != null;
}

fn testOnPeerFinished(ctx: *tls13.Context) anyerror!void {
    _ = ctx;
    peer_finished_callback_count += 1;
}

fn testOnHandshakeComplete(ctx: *tls13.Context) anyerror!void {
    _ = ctx;
    handshake_complete_callback_count += 1;
}

fn buildServerTransportParams(alloc: std.mem.Allocator) ![]u8 {
    var params = transport_params.TransportParams{
        .max_idle_timeout = 30,
        .max_udp_payload_size = 1350,
        .initial_max_data = 65536,
        .initial_max_stream_data_bidi_local = 32768,
        .initial_max_stream_data_bidi_remote = 32768,
        .initial_max_stream_data_uni = 32768,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 4,
        .active_connection_id_limit = 4,
        .disable_active_migration = true,
    };
    return try params.encode(alloc);
}

fn buildClientHelloWithKeyShare(
    alloc: std.mem.Allocator,
    alpn: ?[]const []const u8,
    signature_schemes: []const u16,
    psk_identity: ?[]const u8,
    key_share_group: u16,
    key_share_bytes: []const u8,
) ![]u8 {
    var body = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer body.deinit(alloc);

    try body.appendSlice(alloc, &.{ 0x03, 0x03 });

    var rnd: [32]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    try body.appendSlice(alloc, &rnd);

    try body.append(alloc, 0);

    try body.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    try body.appendSlice(alloc, &.{ 0x01, 0x00 });

    var ext_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer ext_buf.deinit(alloc);

    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    var groups = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer groups.deinit(alloc);
    try groups.appendSlice(alloc, &.{ @intCast(key_share_group >> 8), @intCast(key_share_group & 0xff) });
    if (key_share_group != 0x001d) {
        // Include x25519 as a fallback to exercise HRR upgrade paths.
        try groups.appendSlice(alloc, &.{ 0x00, 0x1d });
    }
    const groups_len: u16 = @intCast(groups.items.len);
    const groups_ext_len: u16 = groups_len + 2;
    try ext_buf.appendSlice(alloc, &.{
        0x00,
        0x0a,
        @intCast(groups_ext_len >> 8),
        @intCast(groups_ext_len & 0xff),
        @intCast(groups_len >> 8),
        @intCast(groups_len & 0xff),
    });
    try ext_buf.appendSlice(alloc, groups.items);

    if (signature_schemes.len != 0) {
        const count_bytes = signature_schemes.len * 2;
        const list_len = std.math.cast(u16, count_bytes) orelse return error.SignatureListTooLong;
        const ext_len = std.math.cast(u16, @as(usize, list_len) + 2) orelse return error.SignatureListTooLong;

        var header: [6]u8 = undefined;
        header[0] = 0x00;
        header[1] = 0x0d;
        header[2] = @as(u8, @intCast(ext_len >> 8));
        header[3] = @as(u8, @intCast(ext_len & 0xff));
        header[4] = @as(u8, @intCast(list_len >> 8));
        header[5] = @as(u8, @intCast(list_len & 0xff));
        try ext_buf.appendSlice(alloc, header[0..]);

        for (signature_schemes) |scheme| {
            try ext_buf.appendSlice(alloc, &.{
                @as(u8, @intCast((scheme >> 8) & 0xff)),
                @as(u8, @intCast(scheme & 0xff)),
            });
        }
    }

    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 });
    const key_share_len: u16 = @intCast(2 + 2 + key_share_bytes.len);
    const total_len: u16 = key_share_len + 2;
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_group >> 8), @intCast(key_share_group & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_bytes.len >> 8), @intCast(key_share_bytes.len & 0xff) });
    try ext_buf.appendSlice(alloc, key_share_bytes);

    if (alpn) |list| {
        if (list.len != 0) {
            var names_len: usize = 0;
            for (list) |proto| {
                std.debug.assert(proto.len != 0 and proto.len <= std.math.maxInt(u8));
                names_len += 1 + proto.len;
            }
            const list_len = std.math.cast(u16, names_len) orelse return error.AlpnListTooLong;
            const ext_len = std.math.cast(u16, names_len + 2) orelse return error.AlpnListTooLong;
            try ext_buf.appendSlice(alloc, &.{
                0x00,                            0x10,
                @as(u8, @intCast(ext_len >> 8)), @as(u8, @intCast(ext_len & 0xff)),
            });
            try ext_buf.appendSlice(alloc, &.{
                @as(u8, @intCast(list_len >> 8)),
                @as(u8, @intCast(list_len & 0xff)),
            });
            for (list) |proto| {
                try ext_buf.append(alloc, @as(u8, @intCast(proto.len)));
                try ext_buf.appendSlice(alloc, proto);
            }
        }
    }

    if (psk_identity) |identity| {
        // psk_key_exchange_modes (0x002d) offering psk_dhe_ke (0x01)
        try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 });

        const identity_len: u16 = @intCast(identity.len);
        const identities_vec_len: u16 = @intCast(2 + identity_len + 4);
        const binders_vec_len: u16 = @intCast(1 + ks.H.digest_length);
        const total_psk_len: u16 = @intCast(2 + identities_vec_len + 2 + binders_vec_len);

        try ext_buf.appendSlice(alloc, &.{ 0x00, 0x29, @intCast(total_psk_len >> 8), @intCast(total_psk_len & 0xff) });
        try ext_buf.appendSlice(alloc, &.{ @intCast(identities_vec_len >> 8), @intCast(identities_vec_len & 0xff) });
        try ext_buf.appendSlice(alloc, &.{ @intCast(identity_len >> 8), @intCast(identity_len & 0xff) });
        try ext_buf.appendSlice(alloc, identity);
        try ext_buf.appendSlice(alloc, &.{ 0, 0, 0, 0 });
        try ext_buf.appendSlice(alloc, &.{ @intCast(binders_vec_len >> 8), @intCast(binders_vec_len & 0xff) });
        try ext_buf.append(alloc, @as(u8, @intCast(ks.H.digest_length)));
        var binder: [ks.H.digest_length]u8 = .{0} ** ks.H.digest_length;
        try ext_buf.appendSlice(alloc, &binder);
    }

    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(alloc, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(alloc, ext_buf.items);

    const body_len: u32 = @intCast(body.items.len);
    const result = try alloc.alloc(u8, 4 + body.items.len);
    result[0] = 0x01;
    result[1] = @intCast((body_len >> 16) & 0xff);
    result[2] = @intCast((body_len >> 8) & 0xff);
    result[3] = @intCast(body_len & 0xff);
    @memcpy(result[4..], body.items);

    return result;
}

fn buildStandardClientHello(
    alloc: std.mem.Allocator,
    alpn: ?[]const []const u8,
    signature_schemes: []const u16,
    psk_identity: ?[]const u8,
) ![]u8 {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);
    return buildClientHelloWithKeyShare(
        alloc,
        alpn,
        signature_schemes,
        psk_identity,
        0x001d,
        pk[0..],
    );
}

fn computeTranscriptHash(data: []const u8) [ks.H.digest_length]u8 {
    var out: [ks.H.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

test "context parses ClientHello and stores handshake view" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    try std.testing.expectEqual(tls13.HandshakePhase.keys_installed, ctx.phase);

    const view_opt = ctx.clientHello();
    try std.testing.expect(view_opt != null);
    const view = view_opt.?;

    try std.testing.expectEqual(@as(usize, 0), view.session_id.len);
    try std.testing.expect(view.cipher_suites.len != 0);
    try std.testing.expectEqual(@as(usize, 32), view.key_share.key.len);
    try std.testing.expectEqual(@as(u16, 0x001d), @intFromEnum(view.key_share.group));
    try std.testing.expect(!view.early_data);
    try std.testing.expectEqual(@as(usize, ch.len - 4), view.raw.len);

    const expected_hash = computeTranscriptHash(ch);
    const stored_ch_hash = ctx.transcripts.client_hello_hash.get(.sha256) orelse unreachable;
    try std.testing.expectEqualSlices(u8, expected_hash[0..], stored_ch_hash.slice());
    try std.testing.expect(ctx.secrets.handshake.send.valid);

    try std.testing.expectError(tls13.HandshakeError.DuplicateClientHello, ctx.processCrypto(.Initial, ch));
}

test "context captures ClientHello ALPN list" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const client_alpn = [_][]const u8{ "h3", "hq-interop" };
    const ch = try buildStandardClientHello(alloc, client_alpn[0..], default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const view_opt = ctx.clientHello();
    try std.testing.expect(view_opt != null);
    const view = view_opt.?;
    try std.testing.expect(view.alpn_list != null);
    const alpn_view = view.alpn_list.?;
    try std.testing.expectEqual(@as(usize, client_alpn.len), alpn_view.len);
    for (client_alpn, alpn_view) |expected, got| {
        try std.testing.expectEqualSlices(u8, expected, got);
    }
}

test "context accepts second ClientHello after HelloRetryRequest" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .quic_transport_parameters = server_tp,
        .server_cert_der = test_certs.server_cert_der,
        .server_key_der = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    // First ClientHello uses P-256 key_share, forcing server HRR for x25519.
    var p256_key: [65]u8 = undefined;
    std.crypto.random.bytes(&p256_key);
    p256_key[0] = 0x04; // Uncompressed EC point prefix.
    const ch1 = try buildClientHelloWithKeyShare(
        alloc,
        null,
        default_signature_schemes[0..],
        null,
        0x0017,
        p256_key[0..],
    );
    defer alloc.free(ch1);

    try ctx.processCrypto(.Initial, ch1);

    const hrr_initial = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(hrr_initial);
    const hrr_msg = (try tls13.parseHandshakeOne(hrr_initial)).?;
    try std.testing.expectEqual(tls13.HsType.server_hello, hrr_msg.typ);
    try std.testing.expectError(error.Unimplemented, ctx.pollCrypto(alloc, .Handshake));

    // Second ClientHello (x25519) must replace CH1 state instead of DuplicateClientHello.
    const ch2 = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], null);
    defer alloc.free(ch2);
    try ctx.processCrypto(.Initial, ch2);

    const view = ctx.clientHello().?;
    try std.testing.expectEqual(@as(u16, 0x001d), @intFromEnum(view.key_share.group));

    const sh_initial = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(sh_initial);
    const sh_msg = (try tls13.parseHandshakeOne(sh_initial)).?;
    try std.testing.expectEqual(tls13.HsType.server_hello, sh_msg.typ);

    const hs_flight = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(hs_flight);
    try std.testing.expect(hs_flight.len > 0);
}

test "context captures pre_shared_key offer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const psk_identity = "ticket-123";
    const ch = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], psk_identity);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const view_opt = ctx.clientHello();
    try std.testing.expect(view_opt != null);
    const view = view_opt.?;

    try std.testing.expect(view.pre_shared_key != null);
    const psk = view.pre_shared_key.?;
    try std.testing.expectEqual(@as(usize, 1), psk.identities.len);
    try std.testing.expectEqualSlices(u8, psk_identity, psk.identities[0].identity);
    try std.testing.expectEqual(@as(u32, 0), psk.identities[0].obfuscated_ticket_age);
    try std.testing.expectEqual(@as(usize, 1), psk.binders.len);
    try std.testing.expectEqual(@as(usize, ks.H.digest_length), psk.binders[0].len);
    try std.testing.expect(std.mem.allEqual(u8, psk.binders[0], 0));
}

test "server emits ServerHello flight with Finished" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const initial_bytes = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(initial_bytes);
    const sh_msg = (try tls13.parseHandshakeOne(initial_bytes)).?;
    try std.testing.expectEqual(tls13.HsType.server_hello, sh_msg.typ);

    const handshake_bytes = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(handshake_bytes);
    var remaining = handshake_bytes;

    const ee_msg = (try tls13.parseHandshakeOne(remaining)).?;
    try std.testing.expectEqual(tls13.HsType.encrypted_extensions, ee_msg.typ);
    remaining = remaining[ee_msg.n..];

    try std.testing.expect(ee_msg.body.len >= 2);
    const ext_total_len = (@as(u16, ee_msg.body[0]) << 8) | @as(u16, ee_msg.body[1]);
    try std.testing.expectEqual(@as(usize, ext_total_len), ee_msg.body.len - 2);
    const exts = ee_msg.body[2 .. 2 + ext_total_len];
    var cursor: usize = 0;
    var found_tp = false;
    while (cursor + 4 <= exts.len) {
        const etype = (@as(u16, exts[cursor]) << 8) | @as(u16, exts[cursor + 1]);
        const elen = (@as(u16, exts[cursor + 2]) << 8) | @as(u16, exts[cursor + 3]);
        cursor += 4;
        try std.testing.expect(cursor + elen <= exts.len);
        if (etype == 0x0039) {
            found_tp = true;
            try std.testing.expectEqualSlices(u8, server_tp, exts[cursor .. cursor + elen]);
        }
        cursor += elen;
    }
    try std.testing.expectEqual(cursor, exts.len);
    try std.testing.expect(found_tp);

    // With real certs the server sends Certificate + CertificateVerify before Finished.
    // Skip any non-Finished messages until we reach Finished.
    while (remaining.len > 0) {
        const msg = (try tls13.parseHandshakeOne(remaining)).?;
        remaining = remaining[msg.n..];
        if (msg.typ == tls13.HsType.finished) {
            try std.testing.expectEqual(@as(usize, ks.H.digest_length), msg.body.len);
            break;
        }
    }

    try std.testing.expectEqual(@as(usize, 0), remaining.len);

    try std.testing.expect(ctx.flags.local_finished_sent);
    try std.testing.expect(ctx.transcripts.finished_hash.get(.sha256) != null);
}

test "server verifies client Finished and derives application secrets" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    metadata_callback_count = 0;
    metadata_alpn_seen = false;
    metadata_tp_seen = false;
    peer_finished_callback_count = 0;
    handshake_complete_callback_count = 0;

    const callbacks = tls13.Callbacks{
        .on_handshake_metadata = testOnMetadata,
        .on_peer_finished = testOnPeerFinished,
        .on_handshake_complete = testOnHandshakeComplete,
    };
    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const server_alpn = [_][]const u8{"hq-interop"};
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .quic_transport_parameters = server_tp,
        .alpn_protocols = server_alpn[0..],
        .server_cert_der = test_certs.server_cert_der,
        .server_key_der = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var ctx = try tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, server_alpn[0..], default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const initial_bytes = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(initial_bytes);

    const handshake_bytes = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(handshake_bytes);

    const recv_slot = ctx.secrets.slot(.Handshake, .recv);
    try std.testing.expect(recv_slot.valid);

    var transcript_snapshot = ctx.transcripts.handshake;
    const transcript_hash = transcript_snapshot.finalize(.sha256);
    const verify_data = tls13.deriveFinishedVerifyData(.sha256, &recv_slot.value, transcript_hash);

    const client_finished = try tls13.encodeHandshake(alloc, .finished, verify_data.slice());
    defer alloc.free(client_finished);

    try ctx.processCrypto(.Handshake, client_finished);

    try std.testing.expect(ctx.handshakeComplete());
    try std.testing.expectEqual(tls13.HandshakePhase.application_ready, ctx.phase);
    try std.testing.expect(ctx.secrets.slot(.Application, .send).valid);
    try std.testing.expect(ctx.secrets.slot(.Application, .recv).valid);
    try std.testing.expectEqual(@as(usize, 1), metadata_callback_count);
    try std.testing.expect(metadata_alpn_seen);
    try std.testing.expect(metadata_tp_seen);
    try std.testing.expectEqual(@as(usize, 1), peer_finished_callback_count);
    try std.testing.expectEqual(@as(usize, 1), handshake_complete_callback_count);

    const meta = ctx.metadataView();
    try std.testing.expect(meta.alpn != null);
    try std.testing.expect(meta.local_transport_parameters != null);
}

test "server rejects tampered client Finished" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const server_alpn = [_][]const u8{"hq-interop"};
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .quic_transport_parameters = server_tp,
        .alpn_protocols = server_alpn[0..],
        .server_cert_der = test_certs.server_cert_der,
        .server_key_der = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, server_alpn[0..], default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const initial_bytes = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(initial_bytes);

    const handshake_bytes = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(handshake_bytes);

    const recv_slot = ctx.secrets.slot(.Handshake, .recv);
    try std.testing.expect(recv_slot.valid);

    var transcript_snapshot = ctx.transcripts.handshake;
    const transcript_hash = transcript_snapshot.finalize(.sha256);
    var verify_data = tls13.deriveFinishedVerifyData(.sha256, &recv_slot.value, transcript_hash);
    // Corrupt the verify data by flipping a bit (verify_data is Secret, need to get mutable slice)
    var verify_data_bytes = verify_data.sliceMut();
    verify_data_bytes[0] ^= 0x01;

    const client_finished = try tls13.encodeHandshake(alloc, .finished, verify_data.slice());
    defer alloc.free(client_finished);

    try std.testing.expectError(tls13.HandshakeError.FinishedVerifyFailed, ctx.processCrypto(.Handshake, client_finished));
    try std.testing.expect(!ctx.handshakeComplete());
    try std.testing.expectEqual(tls13.HandshakePhase.keys_installed, ctx.phase);
    try std.testing.expect(!ctx.secrets.slot(.Application, .send).valid);
    try std.testing.expect(!ctx.secrets.slot(.Application, .recv).valid);
}

test "server records negotiated signature algorithm" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);
    const scheme_opt = ctx.negotiatedSignatureScheme();
    try std.testing.expect(scheme_opt != null);
    try std.testing.expectEqual(tls13.SignatureScheme.ed25519, scheme_opt.?);
}

test "server rejects client without compatible signature algorithm" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp, .server_cert_der = test_certs.server_cert_der, .server_key_der = test_certs.server_key_der, .allow_insecure = true };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const incompatible_schemes = [_]u16{0x0403};
    const ch = try buildStandardClientHello(alloc, null, incompatible_schemes[0..], null);
    defer alloc.free(ch);

    try std.testing.expectError(tls13.HandshakeError.NoSignatureScheme, ctx.processCrypto(.Initial, ch));
    try std.testing.expect(ctx.negotiatedSignatureScheme() == null);
}

test "server negotiates ALPN when offered" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const server_alpn = [_][]const u8{ "hq-interop", "h3" };
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .quic_transport_parameters = server_tp,
        .alpn_protocols = server_alpn[0..],
        .server_cert_der = test_certs.server_cert_der,
        .server_key_der = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const client_alpn = [_][]const u8{ "h3", "hq-interop" };
    const ch = try buildStandardClientHello(alloc, client_alpn[0..], default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try ctx.processCrypto(.Initial, ch);

    const initial_bytes = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(initial_bytes);
    const sh_msg = (try tls13.parseHandshakeOne(initial_bytes)).?;
    try std.testing.expectEqual(tls13.HsType.server_hello, sh_msg.typ);

    const handshake_bytes = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(handshake_bytes);
    var remaining = handshake_bytes;

    const ee_msg = (try tls13.parseHandshakeOne(remaining)).?;
    try std.testing.expectEqual(tls13.HsType.encrypted_extensions, ee_msg.typ);
    remaining = remaining[ee_msg.n..];

    const exts = blk: {
        try std.testing.expect(ee_msg.body.len >= 2);
        const ext_total_len = (@as(u16, ee_msg.body[0]) << 8) | @as(u16, ee_msg.body[1]);
        try std.testing.expectEqual(@as(usize, ext_total_len), ee_msg.body.len - 2);
        break :blk ee_msg.body[2 .. 2 + ext_total_len];
    };

    var cursor: usize = 0;
    var found_tp = false;
    var found_alpn = false;
    while (cursor + 4 <= exts.len) {
        const etype = (@as(u16, exts[cursor]) << 8) | @as(u16, exts[cursor + 1]);
        const elen = (@as(u16, exts[cursor + 2]) << 8) | @as(u16, exts[cursor + 3]);
        cursor += 4;
        try std.testing.expect(cursor + elen <= exts.len);
        const edata = exts[cursor .. cursor + elen];
        switch (etype) {
            0x0039 => {
                found_tp = true;
                try std.testing.expectEqualSlices(u8, server_tp, edata);
            },
            0x0010 => {
                try std.testing.expect(elen >= 3);
                const list_len = (@as(u16, edata[0]) << 8) | @as(u16, edata[1]);
                try std.testing.expectEqual(@as(usize, list_len + 2), edata.len);
                const name_len = edata[2];
                try std.testing.expectEqual(@as(usize, name_len + 1), list_len);
                const proto = edata[3 .. 3 + name_len];
                try std.testing.expectEqualSlices(u8, server_alpn[0], proto);
                found_alpn = true;
            },
            else => {},
        }
        cursor += elen;
    }
    try std.testing.expectEqual(cursor, exts.len);
    try std.testing.expect(found_tp);
    try std.testing.expect(found_alpn);

    try std.testing.expect(ctx.negotiatedAlpn() != null);
    const negotiated = ctx.negotiatedAlpn().?;
    try std.testing.expectEqualSlices(u8, server_alpn[0], negotiated);

    // With real certs the server sends Certificate + CertificateVerify before Finished.
    // Skip any non-Finished messages until we reach Finished.
    while (remaining.len > 0) {
        const msg = (try tls13.parseHandshakeOne(remaining)).?;
        remaining = remaining[msg.n..];
        if (msg.typ == tls13.HsType.finished) {
            try std.testing.expectEqual(@as(usize, ks.H.digest_length), msg.body.len);
            break;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.len);
}

test "server errors when ALPN required but absent" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const server_alpn = [_][]const u8{"hq-interop"};
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .quic_transport_parameters = server_tp,
        .alpn_protocols = server_alpn[0..],
        .server_cert_der = test_certs.server_cert_der,
        .server_key_der = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc, null, default_signature_schemes[0..], null);
    defer alloc.free(ch);

    try std.testing.expectError(tls13.HandshakeError.AlpnNegotiationFailed, ctx.processCrypto(.Initial, ch));
    try std.testing.expect(ctx.negotiatedAlpn() == null);
}
