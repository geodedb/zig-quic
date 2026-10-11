const std = @import("std");
const conn_mod = @import("quic_conn");
const tp = @import("quic_transport_params");

fn apply(conn: *conn_mod.Connection, params: *const tp.TransportParams) !void {
    const encoded = try params.encode(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    try conn.applyPeerTransportParameters(encoded);
}

fn acceptOptionalToken(retry: bool) !void {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    var scid = [_]u8{ 1, 2, 3, 4 };
    var odcid = [_]u8{ 5, 6, 7, 8 };
    conn.setPeerInitialCids(&odcid, &scid);
    conn.retry_received = retry;
    const params = tp.TransportParams{
        .initial_source_connection_id = &scid,
        .original_destination_connection_id = &odcid,
        .retry_source_connection_id = if (retry) &scid else null,
        .initial_max_data = 8192,
    };
    try apply(&conn, &params);
    try std.testing.expect(conn.transport_params_applied);
    try std.testing.expectEqual(@as(u64, 8192), conn.peer_max_data);
}

test "server transport parameters may omit the optional reset token without Retry" {
    try acceptOptionalToken(false);
}

test "server transport parameters may omit the optional reset token after Retry" {
    try acceptOptionalToken(true);
}

test "omitting the reset token does not bypass required connection IDs" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    try std.testing.expectError(error.InvalidTransportParams, apply(&conn, &.{}));
    try std.testing.expect(!conn.transport_params_applied);
    var scid = [_]u8{ 1, 2, 3, 4 };
    conn.retry_received = true;
    try std.testing.expectError(error.InvalidTransportParams, apply(&conn, &.{ .initial_source_connection_id = &scid }));
    try std.testing.expect(!conn.transport_params_applied);
}

test "omitting the reset token preserves connection ID authentication" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    var scid = [_]u8{ 1, 2, 3, 4 };
    var odcid = [_]u8{ 5, 6, 7, 8 };
    var other = [_]u8{ 9, 10, 11, 12 };
    conn.setPeerInitialCids(&odcid, &scid);
    try std.testing.expectError(error.TransportParameterCidMismatch, apply(&conn, &.{ .initial_source_connection_id = &other }));
    try std.testing.expect(!conn.transport_params_applied);
    try std.testing.expectError(error.TransportParameterCidMismatch, apply(&conn, &.{
        .initial_source_connection_id = &scid,
        .original_destination_connection_id = &other,
    }));
    try std.testing.expect(!conn.transport_params_applied);
}

test "a supplied reset token still requires exactly sixteen bytes" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    // Parameter ID 2, length 15, followed by an invalid short token.
    const malformed = [_]u8{ 2, 15 } ++ ([_]u8{0x42} ** 15);
    try std.testing.expectError(error.MalformedTransportParams, conn.applyPeerTransportParameters(&malformed));
    try std.testing.expect(!conn.transport_params_applied);
}
