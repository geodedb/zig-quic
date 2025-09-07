const std = @import("std");
const api = @import("quic_api");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const ks = @import("quic_tls");

test "server responds to client Initial" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Start server on a random port
    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
    };
    const server_ep = try api.endpointInit(&alloc, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(server_ep);

    // Get the actual port the server is listening on
    var server_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var addr_len: std.posix.socklen_t = server_addr.getOsSockLen();
    try std.posix.getsockname(server_ep.sock_fd, &server_addr.any, &addr_len);

    // Create a raw UDP socket to send Initial packet
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    // Build a minimal Initial packet
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
    
    // Minimal TLS ClientHello (just enough to trigger response)
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

    // Send Initial packet to server
    _ = try std.posix.sendto(sock, initial_pkt, 0, &server_addr.any, server_addr.getOsSockLen());

    // Poll server to process the packet
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        try api.poll(server_ep, 10);
        
        // Check if server has a connection ready to accept
        if (server_ep.popAccepted()) |_| {
            // Server accepted a connection, which means it processed the Initial
            break;
        }
    }

    // Try to receive response from server with a few attempts to reduce flakiness
    var recv_buf: [2048]u8 = undefined;
    const recv_flags: u32 = if (@import("builtin").target.os.tag == .windows) 0 else std.posix.MSG.DONTWAIT;
    var got: usize = 0;
    var tries: usize = 0;
    while (tries < 20 and got == 0) : (tries += 1) {
        const n = std.posix.recv(sock, &recv_buf, recv_flags) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n > 0) {
            got = n;
            break;
        }
        // Drive server once more and wait briefly
        try api.poll(server_ep, 5);
        std.Thread.sleep(1_000_000); // 1ms
    }

    if (got == 0) {
        std.debug.print("No response received from server\n", .{});
        return error.NoServerResponse;
    }

    const response = recv_buf[0..got];
    const first_byte = response[0];
    const is_long = (first_byte & 0x80) != 0;
    try std.testing.expect(is_long);
    const packet_type = (first_byte >> 4) & 0x03;
    try std.testing.expect(packet_type == 0 or packet_type == 3);
    std.debug.print("Server responded with packet type: {}\n", .{packet_type});
}