const std = @import("std");
const ks = @import("src/quic/tls/key_schedule.zig");

pub fn main() !void {
    // QUIC v2 DCID from the logs: D9 66 EF 01 E0 5A 92 B7 36 B6 8E 73 46 19
    const dcid = [_]u8{ 0xD9, 0x66, 0xEF, 0x01, 0xE0, 0x5A, 0x92, 0xB7, 0x36, 0xB6, 0x8E, 0x73, 0x46, 0x19 };

    std.debug.print("Testing key derivation with DCID:\n", .{});
    for (dcid) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n\n", .{});

    // Step 1: Derive initial secret
    const initial_secret = ks.deriveInitialSecretV2(&dcid);
    std.debug.print("Initial secret: ", .{});
    for (initial_secret) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n\n", .{});

    // Step 2: Derive client/server initial secrets
    const pair = ks.deriveClientServerInitial(initial_secret);
    std.debug.print("Client secret: ", .{});
    for (pair.client) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n\n", .{});

    std.debug.print("Server secret: ", .{});
    for (pair.server) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n\n", .{});

    // Step 3: Derive keys from server secret (since we're the server receiving client Initial)
    std.debug.print("Calling deriveKeyIvHpV2 for client (RX) keys...\n", .{});
    const client_keys = ks.deriveKeyIvHpV2(pair.client);

    std.debug.print("\nClient (RX) Key: ", .{});
    for (client_keys.key) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    std.debug.print("Client (RX) IV: ", .{});
    for (client_keys.iv) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    std.debug.print("Client (RX) HP: ", .{});
    for (client_keys.hp) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});
}
