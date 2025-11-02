const std = @import("std");
const ks = @import("src/quic/tls/key_schedule.zig");

pub fn main() !void {
    // Test vector from RFC 9001 Appendix A and quic-go tests
    // Connection ID: 0x8394c8f03e515708
    const dcid = [_]u8{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

    std.debug.print("Testing Initial Secret Derivation\n", .{});
    std.debug.print("DCID: ", .{});
    for (dcid) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n\n", .{});

    // Derive initial secret
    const initial_secret = ks.deriveInitialSecretV1(&dcid);
    std.debug.print("Initial Secret: ", .{});
    for (initial_secret) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n\n", .{});

    // Derive client and server secrets
    const pair = ks.deriveClientServerInitial(initial_secret);

    std.debug.print("Client Secret: ", .{});
    for (pair.client) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected from quic-go test:
    // c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
    const expected_client = [_]u8{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
        0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
        0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };

    if (std.mem.eql(u8, &pair.client, &expected_client)) {
        std.debug.print("✓ Client secret matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Client secret MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_client) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }

    std.debug.print("Server Secret: ", .{});
    for (pair.server) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected from quic-go test:
    // 3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b
    const expected_server = [_]u8{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
        0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
        0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    };

    if (std.mem.eql(u8, &pair.server, &expected_server)) {
        std.debug.print("✓ Server secret matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Server secret MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_server) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }

    // Derive client key and IV
    const client_mat = ks.deriveKeyIvHp(pair.client);
    std.debug.print("Client Key: ", .{});
    for (client_mat.key) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected: 1f369613dd76d5467730efcbe3b1a22d
    const expected_client_key = [_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };

    if (std.mem.eql(u8, &client_mat.key, &expected_client_key)) {
        std.debug.print("✓ Client key matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Client key MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_client_key) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }

    std.debug.print("Client IV: ", .{});
    for (client_mat.iv) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected: fa044b2f42a3fd3b46fb255c
    const expected_client_iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    };

    if (std.mem.eql(u8, &client_mat.iv, &expected_client_iv)) {
        std.debug.print("✓ Client IV matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Client IV MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_client_iv) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }

    // Derive server key and IV
    const server_mat = ks.deriveKeyIvHp(pair.server);
    std.debug.print("Server Key: ", .{});
    for (server_mat.key) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected: cf3a5331653c364c88f0f379b6067e37
    const expected_server_key = [_]u8{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    };

    if (std.mem.eql(u8, &server_mat.key, &expected_server_key)) {
        std.debug.print("✓ Server key matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Server key MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_server_key) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }

    std.debug.print("Server IV: ", .{});
    for (server_mat.iv) |b| std.debug.print("{X:0>2}\n", .{b});
    std.debug.print("\n", .{});

    // Expected: 0ac1493ca1905853b0bba03e
    const expected_server_iv = [_]u8{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
        0xb0, 0xbb, 0xa0, 0x3e,
    };

    if (std.mem.eql(u8, &server_mat.iv, &expected_server_iv)) {
        std.debug.print("✓ Server IV matches expected\n\n", .{});
    } else {
        std.debug.print("✗ Server IV MISMATCH\n", .{});
        std.debug.print("Expected: ", .{});
        for (expected_server_iv) |b| std.debug.print("{X:0>2}\n", .{b});
        std.debug.print("\n\n", .{});
    }
}
