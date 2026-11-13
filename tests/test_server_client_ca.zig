// SPDX-License-Identifier: Apache-2.0
//! SONNY-6457: a server that requires client certificates tells TLS which
//! CAs it trusts for them.
//!
//! `QuicConfig.inline_client_ca_der` (DER CA certificates) reaches the TLS
//! context of every server connection as `trusted_ca_der`, so TLS trusts only
//! those CAs for client certificates and can complete a client chain sent
//! without its CA. The server used to pass null, leaving client-certificate
//! validation to the process-global trust store with no chain completion.

const std = @import("std");
const testing = std.testing;
const server = @import("server");
const quic_conn = @import("quic_conn");
const packet = @import("quic_packet");
const config = @import("quic_config");

const SockAddr = quic_conn.SockAddr;

fn testSocket(fd: usize) std.posix.socket_t {
    if (comptime @import("builtin").os.tag == .windows) return @ptrFromInt(fd);
    return @intCast(fd);
}

const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const scid = [_]u8{ 9, 10, 11, 12 };

test "SONNY-6457: QuicConfig carries the server's client CA list" {
    const anchors = [_][]const u8{&[_]u8{ 0x30, 0x82 }};
    const cfg = config.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .require_client_cert = true,
        .inline_client_ca_der = &anchors,
    };
    try testing.expectEqual(@as(usize, 1), cfg.inline_client_ca_der.?.len);
    try testing.expectEqual(@as(?[]const []const u8, null), (config.QuicConfig{ .alpn = &.{} }).inline_client_ca_der);
}

test "SONNY-6457: createServerConnection hands the client CA list to the server TLS context" {
    const anchors = [_][]const u8{ &[_]u8{ 0x30, 0x03, 0x01, 0x01, 0xff }, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 } };
    var alloc = testing.allocator;
    const conn = try server.createServerConnection(&alloc, testSocket(1), SockAddr.ipv4(127, 0, 0, 1, 4433), .{
        .version = packet.QUIC_V1,
        .client_dcid = &dcid,
        .client_scid = &scid,
        .require_client_cert = true,
        .client_ca_der = &anchors,
    });
    defer {
        conn.deinit();
        alloc.destroy(conn);
    }
    const tls_ctx = conn.tls_context orelse return error.NoTlsContext;
    try testing.expect(tls_ctx.config.request_client_cert);
    const got = tls_ctx.config.trusted_ca_der orelse return error.ClientCaListNotPassed;
    try testing.expectEqual(anchors.len, got.len);
    for (anchors, got) |want, have| try testing.expectEqualSlices(u8, want, have);
}

test "SONNY-6457: without a client CA list the server TLS context has no anchors" {
    var alloc = testing.allocator;
    const conn = try server.createServerConnection(&alloc, testSocket(1), SockAddr.ipv4(127, 0, 0, 1, 4433), .{
        .version = packet.QUIC_V1,
        .client_dcid = &dcid,
        .client_scid = &scid,
    });
    defer {
        conn.deinit();
        alloc.destroy(conn);
    }
    const tls_ctx = conn.tls_context orelse return error.NoTlsContext;
    try testing.expectEqual(@as(?[]const []const u8, null), tls_ctx.config.trusted_ca_der);
}
