const std = @import("std");
const conn_mod = @import("quic_conn");
const tls13 = @import("quic_tls13");

test "Connection.setServerName wires TLS SNI config" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    defer ctx.deinit();

    var conn: conn_mod.Connection = undefined;
    conn.allocator = &alloc;
    conn.server_name = null;
    conn.tls_context = &ctx;

    try conn.setServerName("example.test");

    try std.testing.expect(conn.server_name != null);
    try std.testing.expectEqualStrings("example.test", conn.server_name.?);
    try std.testing.expect(ctx.config.server_name != null);
    try std.testing.expectEqualStrings("example.test", ctx.config.server_name.?);

    if (conn.server_name) |name| {
        ctx.config.server_name = null;
        alloc.free(name);
        conn.server_name = null;
    }
    conn.tls_context = null;
}
