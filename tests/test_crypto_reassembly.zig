const std = @import("std");
const conn_mod = @import("quic_conn");

// These exercise the production Connection reassembly path. TLS is absent so
// the receive offset records exactly how many contiguous bytes it was fed.
test "buffered Handshake overlap preserves its unconsumed tail" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    try std.testing.expect(try conn.handleHandshakeCrypto(&allocator, 4, "EFGH"));
    try std.testing.expect(try conn.handleHandshakeCrypto(&allocator, 0, "ABCDEF"));
    try std.testing.expectEqual(@as(u64, 8), conn.crypto_rx_off_handshake);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_buffer_handshake.count);
}

test "buffered duplicate Handshake fragments release all consumed storage" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    for (0..8) |_| try std.testing.expect(try conn.handleHandshakeCrypto(&allocator, 4, "EFGH"));
    try std.testing.expect(try conn.handleHandshakeCrypto(&allocator, 0, "ABCD"));
    try std.testing.expectEqual(@as(u64, 8), conn.crypto_rx_off_handshake);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_buffer_handshake.count);
}

test "Initial reassembly handles a duplicate before the next contiguous fragment" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    try std.testing.expect(try conn.handleInitialCrypto(&allocator, 4, "EFGH"));
    try std.testing.expect(try conn.handleInitialCrypto(&allocator, 4, "EFGH"));
    try std.testing.expect(try conn.handleInitialCrypto(&allocator, 8, "IJKL"));
    try std.testing.expect(try conn.handleInitialCrypto(&allocator, 0, "ABCD"));
    try std.testing.expectEqual(@as(u64, 12), conn.crypto_rx_off_initial);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_buffer_initial.count);
}

test "reassembly emits each overlapping byte once and removes its exact queue prefix" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    var buffer = &conn.crypto_buffer_handshake;
    try buffer.add(3, "DEFGHI", allocator);
    try buffer.add(1, "BCDE", allocator);
    try buffer.add(8, "IJKL", allocator);
    try buffer.add(20, "U", allocator);
    const fragments = buffer.getContiguous(3).?;
    var bytes: [9]u8 = undefined;
    var count: usize = 0;
    for (fragments) |fragment| {
        try std.testing.expectEqual(@as(u64, 3 + count), fragment.offset);
        @memcpy(bytes[count..][0..fragment.data.len], fragment.data);
        count += fragment.data.len;
    }
    try std.testing.expectEqualStrings("DEFGHIJKL", bytes[0..count]);
    buffer.removeProcessed(fragments.len, allocator);
    try std.testing.expectEqual(@as(usize, 1), buffer.count);
    try std.testing.expectEqual(@as(u64, 20), buffer.fragments[0].?.offset);
    try std.testing.expect(buffer.getContiguous(12) == null);
}

test "CRYPTO range overflow is rejected before allocating or mutating the queue" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    try std.testing.expectError(error.InvalidCryptoOffset, conn.crypto_buffer_handshake.add(std.math.maxInt(u64), "X", allocator));
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_buffer_handshake.count);
}
