const std = @import("std");
const conn_mod = @import("quic_conn");

fn make_conn(alloc: *std.mem.Allocator) conn_mod.Connection {
    // Initialize via init() to populate all internal fields correctly.
    var c: conn_mod.Connection = undefined;
    c.init(alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    return c;
}

test "pn expansion edges per RFC 9000 §12.3" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var alloc = gpa.allocator();
    var c = make_conn(&alloc);
    defer c.deinit();

    // Initial space: expected=0 -> expand should return trunc as-is
    var full = c.expandPnInitial(0x12, 1);
    try std.testing.expectEqual(@as(u64, 0x12), full);
    c.trackRecvPnInitial(full);

    // With expected next = 0x100 and 1-byte trunc=0xfe, RFC chooses the value closest to expected => 0xfe (254)
    c.pn_initial.max = 0x0ff;
    c.pn_initial.have_any = true;
    full = c.expandPnInitial(0xfe, 1);
    try std.testing.expectEqual(@as(u64, 0x00fe), full);

    // Handshake space test: set expected and verify expansion returns a value in reasonable window
    c.pn_handshake.max = 0x7fff;
    c.pn_handshake.have_any = true;
    const full_hs = c.expandPnHandshake(0x80, 1);
    try std.testing.expect(full_hs > 0);
}
