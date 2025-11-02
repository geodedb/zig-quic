const std = @import("std");
const tls13 = @import("quic_tls13");
const transport_params = @import("quic_transport_params");

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

fn buildStandardClientHello(alloc: std.mem.Allocator) ![]u8 {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

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

    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 });

    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 });
    const key_share_len: u16 = 2 + 2 + 32;
    const total_len: u16 = key_share_len + 2;
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x1d });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 32 });
    try ext_buf.appendSlice(alloc, &pk);

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

fn computeTranscriptHash(data: []const u8) [tls13.H.digest_length]u8 {
    var hasher = tls13.H.init(.{});
    hasher.update(data);
    var out: [tls13.H.digest_length]u8 = undefined;
    hasher.final(&out);
    return out;
}

test "context parses ClientHello and stores handshake view" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp };
    var ctx = tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc);
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
    const stored_ch_hash = ctx.transcripts.client_hello_hash orelse unreachable;
    try std.testing.expectEqualSlices(u8, expected_hash[0..], stored_ch_hash[0..]);
    try std.testing.expect(ctx.secrets.handshake.send.valid);

    try std.testing.expectError(tls13.HandshakeError.DuplicateClientHello, ctx.processCrypto(.Initial, ch));
}

test "server emits ServerHello flight with Finished" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const server_tp = try buildServerTransportParams(alloc);
    defer alloc.free(server_tp);

    const config = tls13.Config{ .allocator = alloc, .role = .Server, .quic_transport_parameters = server_tp };
    var ctx = tls13.Context.init(config, .{});
    defer ctx.deinit();

    const ch = try buildStandardClientHello(alloc);
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

    const fin_msg = (try tls13.parseHandshakeOne(remaining)).?;
    try std.testing.expectEqual(tls13.HsType.finished, fin_msg.typ);
    try std.testing.expectEqual(@as(usize, tls13.H.digest_length), fin_msg.body.len);
    remaining = remaining[fin_msg.n..];
    try std.testing.expectEqual(@as(usize, 0), remaining.len);

    try std.testing.expect(ctx.flags.local_finished_sent);
    try std.testing.expect(ctx.transcripts.finished_hash != null);
}
