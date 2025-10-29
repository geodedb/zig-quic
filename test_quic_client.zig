const std = @import("std");
const net = std.net;
const crypto = std.crypto;
const crypto_quic = @import("src/quic/crypto_quic.zig");

// QUIC v1 Initial salt from RFC 9001
const INITIAL_SALT_V1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Connection IDs
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    // Derive Initial keys using DCID
    const initial_secret = crypto_quic.hkdfExtract(.sha256, &INITIAL_SALT_V1, &dcid);
    const client_initial = crypto_quic.hkdfExpandLabel(allocator, .sha256, initial_secret[0..32], "client in", "", 32) catch |err| {
        std.debug.print("Failed to derive client initial: {}\n", .{err});
        return err;
    };
    defer allocator.free(client_initial);

    // Derive client key and IV
    const client_key = crypto_quic.hkdfExpandLabel(allocator, .sha256, client_initial, "quic key", "", 16) catch |err| {
        std.debug.print("Failed to derive client key: {}\n", .{err});
        return err;
    };
    defer allocator.free(client_key);

    const client_iv = crypto_quic.hkdfExpandLabel(allocator, .sha256, client_initial, "quic iv", "", 12) catch |err| {
        std.debug.print("Failed to derive client IV: {}\n", .{err});
        return err;
    };
    defer allocator.free(client_iv);

    const client_hp = crypto_quic.hkdfExpandLabel(allocator, .sha256, client_initial, "quic hp", "", 16) catch |err| {
        std.debug.print("Failed to derive client HP: {}\n", .{err});
        return err;
    };
    defer allocator.free(client_hp);

    std.debug.print("Derived keys:\n", .{});
    std.debug.print("  Client key: ", .{});
    for (client_key) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\n", .{});
    std.debug.print("  Client IV: ", .{});
    for (client_iv) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\n", .{});

    // Build CRYPTO frame with minimal ClientHello
    var crypto_frame = std.ArrayList(u8).init(allocator);
    defer crypto_frame.deinit();

    // CRYPTO frame type
    try crypto_frame.append(0x06);
    // Offset (0)
    try crypto_frame.append(0x00);

    // Build minimal TLS ClientHello
    var client_hello = std.ArrayList(u8).init(allocator);
    defer client_hello.deinit();

    try client_hello.append(0x01); // HandshakeType: ClientHello
    try client_hello.appendSlice(&[_]u8{ 0x00, 0x00, 0x00 }); // Length placeholder
    try client_hello.appendSlice(&[_]u8{ 0x03, 0x03 }); // TLS 1.2
    try client_hello.appendSlice(&([_]u8{0} ** 32)); // Random
    try client_hello.append(0x00); // Session ID length
    try client_hello.appendSlice(&[_]u8{ 0x00, 0x02 }); // Cipher suites length
    try client_hello.appendSlice(&[_]u8{ 0x13, 0x01 }); // TLS_AES_128_GCM_SHA256
    try client_hello.append(0x01); // Compression methods length
    try client_hello.append(0x00); // No compression

    // ALPN extension
    var extensions = std.ArrayList(u8).init(allocator);
    defer extensions.deinit();

    try extensions.appendSlice(&[_]u8{ 0x00, 0x10 }); // ALPN extension type
    try extensions.appendSlice(&[_]u8{ 0x00, 0x0e }); // Extension length
    try extensions.appendSlice(&[_]u8{ 0x00, 0x0c }); // ALPN list length
    try extensions.append(0x0b); // Protocol name length
    try extensions.appendSlice("hq-interop"); // 10 bytes
    try extensions.append(0); // padding to make 11

    // QUIC transport params (minimal)
    try extensions.appendSlice(&[_]u8{ 0xff, 0xa5 }); // QUIC transport params
    try extensions.appendSlice(&[_]u8{ 0x00, 0x06 }); // Length
    try extensions.appendSlice(&[_]u8{ 0x01, 0x04, 0x80, 0x00, 0x75, 0x30 }); // max_idle_timeout

    // Add extensions length
    const ext_len_bytes = std.mem.toBytes(@as(u16, @intCast(extensions.items.len)));
    try client_hello.append(ext_len_bytes[1]);
    try client_hello.append(ext_len_bytes[0]);
    try client_hello.appendSlice(extensions.items);

    // Fix ClientHello length (3-byte)
    const ch_len = client_hello.items.len - 4;
    client_hello.items[1] = @as(u8, @intCast((ch_len >> 16) & 0xFF));
    client_hello.items[2] = @as(u8, @intCast((ch_len >> 8) & 0xFF));
    client_hello.items[3] = @as(u8, @intCast(ch_len & 0xFF));

    // Add ClientHello to CRYPTO frame
    try crypto_frame.append(@as(u8, @intCast(client_hello.items.len)));
    try crypto_frame.appendSlice(client_hello.items);

    // Add padding to reach minimum Initial packet size (1200 bytes)
    const min_packet_size = 1200;
    const header_size = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2 + 1; // Estimated header size
    const tag_size = 16;
    const padding_needed = min_packet_size - header_size - crypto_frame.items.len - tag_size;

    if (padding_needed > 0) {
        var i: usize = 0;
        while (i < padding_needed) : (i += 1) {
            try crypto_frame.append(0x00); // PADDING frames
        }
    }

    // Build Initial packet header
    var header = std.ArrayList(u8).init(allocator);
    defer header.deinit();

    try header.append(0xC0); // Long header, Initial packet, 1-byte PN
    try header.appendSlice(&std.mem.toBytes(@as(u32, 0x00000001))); // Version QUIC v1
    try header.append(@as(u8, dcid.len));
    try header.appendSlice(&dcid);
    try header.append(@as(u8, scid.len));
    try header.appendSlice(&scid);
    try header.append(0x00); // Token length

    // Packet number
    const packet_number: u64 = 0;
    const pn_bytes = [_]u8{@as(u8, @intCast(packet_number & 0xFF))};

    // Length (payload + PN + tag)
    const packet_length = crypto_frame.items.len + pn_bytes.len + 16;
    const length_varint = (@as(u16, @intCast(packet_length)) | 0x4000); // 2-byte encoding
    const len_bytes = std.mem.toBytes(length_varint);
    try header.append(len_bytes[1]);
    try header.append(len_bytes[0]);
    try header.appendSlice(&pn_bytes);

    // Create AAD for AEAD
    const aad = header.items;

    // Encrypt payload
    var ciphertext_buf: [2048]u8 = undefined;
    const ct_len = crypto_quic.aeadEncrypt(
        .aes_128_gcm,
        client_key,
        client_iv,
        packet_number,
        aad,
        crypto_frame.items,
        &ciphertext_buf,
    ) catch |err| {
        std.debug.print("AEAD encryption failed: {}\n", .{err});
        return err;
    };

    // Build complete packet
    var packet = std.ArrayList(u8).init(allocator);
    defer packet.deinit();
    try packet.appendSlice(header.items);
    try packet.appendSlice(ciphertext_buf[0..ct_len]);

    // Apply header protection
    const sample = ciphertext_buf[0..16];
    const mask = crypto_quic.headerProtectionMask(.aes_128, client_hp, sample) catch |err| {
        std.debug.print("Header protection failed: {}\n", .{err});
        return err;
    };

    // Mask first byte and packet number
    packet.items[0] ^= (mask[0] & 0x0F);
    const pn_offset = header.items.len - pn_bytes.len;
    var i: usize = 0;
    while (i < pn_bytes.len) : (i += 1) {
        packet.items[pn_offset + i] ^= mask[1 + i];
    }

    std.debug.print("\nBuilt Initial packet ({} bytes)\n", .{packet.items.len});
    std.debug.print("First 64 bytes (hex): ", .{});
    const show_len = @min(64, packet.items.len);
    for (packet.items[0..show_len]) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\n", .{});

    // Send packet to server
    const address = try net.Address.parseIp("127.0.0.1", 7567);
    const sock = try std.posix.socket(address.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    std.debug.print("\nSending Initial packet to localhost:7567...\n", .{});
    _ = try std.posix.sendto(sock, packet.items, 0, &address.any, address.getOsSockLen());

    // Wait for response
    var recv_buf: [4096]u8 = undefined;

    // Set timeout
    const timeout = std.posix.timeval{
        .tv_sec = 2,
        .tv_usec = 0,
    };
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    std.debug.print("Waiting for response...\n", .{});

    const recv_len = std.posix.recv(sock, &recv_buf, 0) catch |err| {
        if (err == error.WouldBlock) {
            std.debug.print("No response received (timeout)\n", .{});
            return;
        }
        return err;
    };

    std.debug.print("Received {} bytes response!\n", .{recv_len});
    std.debug.print("First 64 bytes (hex): ", .{});
    const resp_show = @min(64, recv_len);
    for (recv_buf[0..resp_show]) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
}