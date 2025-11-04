const std = @import("std");
const ks = @import("src/quic/tls/key_schedule.zig");

pub fn main() !void {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Test Initial secret derivation (RFC 9001 A.1)
    const initial_secret = ks.deriveInitialSecretV1(&dcid);
    std.debug.print("initial_secret:        ", .{});
    for (initial_secret) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("expected (RFC 9001):   7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44\n", .{});

    // Test client/server initial secret derivation
    const cs = ks.deriveClientServerInitial(initial_secret);
    std.debug.print("\nclient_initial_secret: ", .{});
    for (cs.client) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("expected (RFC 9001):   c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea\n", .{});

    // Test key/iv/hp derivation
    const kih = ks.deriveKeyIvHp(cs.client);
    std.debug.print("\nclient key:            ", .{});
    for (kih.key) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("expected (RFC 9001):   1f369613dd76d5467730efcbe3b1a22d\n", .{});

    std.debug.print("\nclient iv:             ", .{});
    for (kih.iv) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("expected (RFC 9001):   fa044b2f42a3fd3b46fb255c\n", .{});

    std.debug.print("\nclient hp:             ", .{});
    for (kih.hp) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("expected (RFC 9001):   9f50449e04a0e810283a1e9933adedd2\n", .{});
}
