const std = @import("std");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");

test "server processes Initial and queues response" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Create endpoint
    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
    };
    var ep = try endpoint.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();

    // Build a minimal Initial packet from client
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    
    // Derive Initial keys
    const initial = ks.deriveInitialSecret(false, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const client_keys = ks.deriveKeyIvHp(pair.client);

    // Create minimal ClientHello CRYPTO frame
    var crypto_payload = std.ArrayList(u8){};
    defer crypto_payload.deinit(alloc);
    const w = crypto_payload.writer(alloc);
    
    // Minimal TLS ClientHello
    const ch_bytes = [_]u8{
        0x01, 0x00, 0x00, 0x20, // Handshake header: ClientHello, length 32
        0x03, 0x03, // TLS 1.2 (for compatibility)
    } ++ ([_]u8{0x00} ** 32) ++ // Random
        [_]u8{
        0x00, // Session ID length
        0x00, 0x02, 0x13, 0x01, // Cipher suites: TLS_AES_128_GCM_SHA256
        0x01, 0x00, // Compression methods
        0x00, 0x00, // Extensions length (none for now)
    };
    
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = &ch_bytes } }).write(w);

    // Encode Initial packet
    const initial_pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &dcid,
        &scid,
        &[_]u8{}, // no token
        0, // packet number
        2, // packet number length
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp }
    );
    defer alloc.free(initial_pkt);

    // Send the Initial packet to the endpoint via UDP
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);
    
    // Get server address
    var server_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var addr_len: std.posix.socklen_t = server_addr.getOsSockLen();
    try std.posix.getsockname(ep.sock_fd, &server_addr.any, &addr_len);
    
    // Send Initial packet
    _ = try std.posix.sendto(sock, initial_pkt, 0, &server_addr.any, server_addr.getOsSockLen());
    
    // Poll the endpoint to process the packet
    try ep.poll(10);

    // Check if a connection was created and queued for accept
    try std.testing.expect(ep.accepted.items.len > 0);
    
    // Get the connection
    const conn = ep.accepted.items[0];
    
    // Verify the connection is a server
    try std.testing.expectEqual(conn_mod.Role.Server, conn.role);
    
    // Verify ServerHello was queued
    try std.testing.expect(conn.tls.sh_seen);
    
    std.debug.print("Test passed: Server processed Initial and queued ServerHello\n", .{});
}