const std = @import("std");
const tls13 = @import("quic_tls13");
const transport_params = @import("quic_transport_params");
const tls13_full = @import("tls13_full.zig");

fn buildClientTp(alloc: std.mem.Allocator) ![]u8 {
    var params = transport_params.TransportParams{ .max_idle_timeout = 10, .max_udp_payload_size = 1350 };
    return try params.encode(alloc);
}

fn buildServerHello(alloc: std.mem.Allocator, client_pub: []const u8) ![]u8 {
    var server_random: [32]u8 = undefined; std.crypto.random.bytes(&server_random);
    // normal (non-downgrade) random, ensure last 8 bytes not sentinel
    if (std.mem.eql(u8, server_random[24..32], "DOWNGRD\x01")) server_random[31] ^= 0xFF;
    const body = try tls13_full.buildServerHello(alloc, server_random, .TLS_AES_128_GCM_SHA256, .x25519, client_pub, null, null);
    defer alloc.free(body);
    return try tls13.encodeHandshake(alloc, .server_hello, body);
}

fn buildDowngradeServerHello(alloc: std.mem.Allocator, client_pub: []const u8) ![]u8 {
    var rnd: [32]u8 = undefined; std.crypto.random.bytes(&rnd);
    // Inject TLS 1.2 downgrade sentinel ("DOWNGRD" + 0x01)
    const sentinel = "DOWNGRD\x01"; @memcpy(rnd[24..32], sentinel);
    const body = try tls13_full.buildServerHello(alloc, rnd, .TLS_AES_128_GCM_SHA256, .x25519, client_pub, null, null);
    defer alloc.free(body);
    return try tls13.encodeHandshake(alloc, .server_hello, body);
}

test "client derives handshake secrets after ServerHello and sends Finished" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const tp = try buildClientTp(alloc); defer alloc.free(tp);
    var ctx = tls13.Context.init(.{ .allocator = alloc, .role = .Client, .quic_transport_parameters = tp }, .{});
    defer ctx.deinit();

    try ctx.startClientHandshake();
    const ch_bytes = try ctx.pollCrypto(alloc, .Initial); defer alloc.free(ch_bytes);
    try std.testing.expectEqual(@as(u8, 1), ch_bytes[0]); // ClientHello

    // Extract client key share public (from message body) to craft ServerHello
    // Skip header (4 bytes). Find key_share extension (0x0033)
    const body = ch_bytes[4..];
    // Simple search for pattern 0x00 0x33
    var i: usize = 0; var client_pub: ?[]const u8 = null;
    while (i + 4 <= body.len) : (i += 1) {
        if (body[i] == 0x00 and i + 1 < body.len and body[i+1] == 0x33) {
            // Next two bytes: ext len
            if (i + 4 <= body.len) {
                const ks_vec_len = (@as(u16, body[i+2]) << 8) | @as(u16, body[i+3]);
                // inner vector length at i+4,i+5
                if (i + 6 <= body.len) {
                    const inner = (@as(u16, body[i+4]) << 8) | @as(u16, body[i+5]);
                    // group (2) + key_len(2) + key(32)
                    if (inner == 36 and i + 6 + 36 <= body.len) {
                        const key_len = (@as(u16, body[i+8]) << 8) | @as(u16, body[i+9]);
                        if (key_len == 32) {
                            client_pub = body[i+10 .. i+10+32]; break;
                        }
                    }
                }
            }
        }
    }
    const cp = client_pub orelse unreachable;
    const sh = try buildServerHello(alloc, cp); defer alloc.free(sh);
    try ctx.processCrypto(.Initial, sh);
    try std.testing.expect(ctx.secrets.slot(.Handshake, .send).valid);
    try std.testing.expect(ctx.secrets.slot(.Handshake, .recv).valid);
    try std.testing.expect(ctx.phase == .keys_installed);

    // Simulate receiving server Finished (use server_hs secret)
    const server_hs = ctx.secrets.slot(.Handshake, .recv).value; // server handshake secret
    var snap = ctx.transcripts.handshake; const th = snap.finalize();
    const verify = tls13.deriveFinishedVerifyData(server_hs, th);
    const fin = try tls13.encodeHandshake(alloc, .finished, verify[0..]); defer alloc.free(fin);
    try ctx.processCrypto(.Handshake, fin);
    try std.testing.expect(ctx.handshakeComplete());
}

test "client detects downgrade attempt via random sentinel" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const tp = try buildClientTp(alloc); defer alloc.free(tp);
    var ctx = tls13.Context.init(.{ .allocator = alloc, .role = .Client, .quic_transport_parameters = tp }, .{});
    defer ctx.deinit();
    try ctx.startClientHandshake();
    const ch_bytes = try ctx.pollCrypto(alloc, .Initial); defer alloc.free(ch_bytes);
    const body = ch_bytes[4..];
    var i: usize = 0; var client_pub: ?[]const u8 = null;
    while (i + 4 <= body.len) : (i += 1) {
        if (body[i] == 0x00 and i + 1 < body.len and body[i+1] == 0x33) {
            if (i + 10 + 32 <= body.len) {
                client_pub = body[i+10 .. i+10+32]; break;
            }
        }
    }
    const cp = client_pub orelse unreachable;
    const sh = try buildDowngradeServerHello(alloc, cp); defer alloc.free(sh);
    try std.testing.expectError(tls13.HandshakeError.DowngradeAttempt, ctx.processCrypto(.Initial, sh));
}
