const std = @import("std");
const conn_mod = @import("quic_conn");

fn initConn(alloc: *std.mem.Allocator) conn_mod.Connection {
    var c: conn_mod.Connection = undefined;
    c.init(alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    return c;
}

test "connection caches negotiated ALPN independently" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn = initConn(&alloc);
    defer conn.deinit();

    var dynamic = try alloc.dupe(u8, "h3");
    defer alloc.free(dynamic);

    try conn.cacheNegotiatedAlpn(dynamic);

    const alpn = conn.getNegotiatedAlpn() orelse return error.ExpectedAlpn;
    try std.testing.expect(std.mem.eql(u8, alpn, "h3"));

    dynamic[0] = 'x';
    // Cached copy must remain unchanged even if source buffer is mutated.
    const cached = conn.getNegotiatedAlpn() orelse return error.ExpectedAlpnAfterMutation;
    try std.testing.expect(std.mem.eql(u8, cached, "h3"));
}

test "connection caches peer transport parameters copy" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn = initConn(&alloc);
    defer conn.deinit();

    var encoded = [_]u8{ 0x00, 0x39, 0x00, 0x02, 0xaa, 0xbb };
    try conn.cachePeerTransportParams(encoded[0..]);

    // Mutate original buffer to ensure cache retains original values
    encoded[4] = 0;
    encoded[5] = 0;

    const cached = conn.getPeerTransportParams() orelse return error.ExpectedParams;
    try std.testing.expect(cached.len == 6);
    try std.testing.expect(cached[4] == 0xaa and cached[5] == 0xbb);
}

test "connection setLocalTransportParameters caches encoded bytes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn = initConn(&alloc);
    defer conn.deinit();

    const local_tp = [_]u8{ 0x40, 0x0e, 0, 2, 0x12, 0x34 };
    try conn.setLocalTransportParameters(local_tp[0..]);

    const cached = conn.getLocalTransportParams() orelse return error.ExpectedLocalParams;
    try std.testing.expect(std.mem.eql(u8, cached, local_tp[0..]));
    try std.testing.expect(conn.local_transport_params_raw != null);
}
