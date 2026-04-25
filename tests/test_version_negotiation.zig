const std = @import("std");
const pkt = @import("quic_packet");
const conn_mod = @import("quic_conn");
const incoming = @import("incoming");
const endpoint_types = @import("endpoint/types");
const cfg_mod = @import("config");

var probe_count: usize = 0;

fn fakePeer() conn_mod.SockAddr {
    return conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);
}

fn sendFn(_: conn_mod.SockAddr, data: []const u8) anyerror!usize {
    return data.len;
}

fn scheduleTimer(_: *conn_mod.Connection, _: endpoint_types.TimerKind, _: u32) anyerror!u64 {
    return 1;
}

fn sendInitialProbe(conn: *conn_mod.Connection) anyerror!void {
    _ = conn;
    probe_count += 1;
}

fn setupSender(_: *conn_mod.Connection) void {}

test "vn_decode_and_downgrade_protection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = "abcdef";
    const scid = "1234";
    const versions = [_]u32{ pkt.QUIC_V1, pkt.QUIC_V2 };
    const buf = try pkt.encodeVersionNegotiation(alloc, dcid, scid, &versions);
    defer alloc.free(buf);

    const vn = try pkt.decodeVersionNegotiation(alloc, buf);
    defer alloc.free(vn.versions);

    try std.testing.expectEqualStrings(dcid, vn.dcid);
    try std.testing.expectEqualStrings(scid, vn.scid);
    try std.testing.expectEqual(@as(usize, 2), vn.versions.len);
    try std.testing.expect(vn.versions[0] == pkt.QUIC_V1 or vn.versions[0] == pkt.QUIC_V2);
    try std.testing.expect(vn.versions[1] == pkt.QUIC_V1 or vn.versions[1] == pkt.QUIC_V2);

    // Downgrade protection: if VN lists our attempted version, ignore VN
    try std.testing.expect(!pkt.shouldAcceptVersionNegotiation(pkt.QUIC_V1, vn.versions));
    // If original version is not present, accept VN
    try std.testing.expect(pkt.shouldAcceptVersionNegotiation(0x0a0a0a0a, vn.versions));
}

test "vn_malformed_versions_length" {
    // Build a bogus VN with versions length not multiple of 4
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try buf.append(std.testing.allocator, 0x80);
    try buf.appendSlice(std.testing.allocator, &[_]u8{ 0, 0, 0, 0 });
    try buf.append(std.testing.allocator, 2); // dcid len
    try buf.appendSlice(std.testing.allocator, "aa");
    try buf.append(std.testing.allocator, 2); // scid len
    try buf.appendSlice(std.testing.allocator, "bb");
    try buf.append(std.testing.allocator, 0x12); // one extra byte -> not multiple of 4
    const res = pkt.decodeVersionNegotiation(std.testing.allocator, buf.items);
    try std.testing.expectError(error.MalformedVersions, res);
}

test "endpoint compatible VN switches version and sends a fresh Initial probe" {
    var allocator = std.testing.allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .empty;
    defer accepted.deinit(allocator);

    var cfg = cfg_mod.QuicConfig{ .alpn = &[_][]const u8{}, .compatible_vn = true };
    const peer = fakePeer();

    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, peer);
    defer conn.deinit();
    conn.initial_version = 0x0a0a0a0a;
    conn.version = conn.initial_version;

    const client_scid = "VNCS";
    const client_dcid = "VNDC";
    const versions = [_]u32{ pkt.QUIC_V2, pkt.QUIC_V1 };
    const vn_packet = try pkt.encodeVersionNegotiation(allocator, client_scid, client_dcid, &versions);
    defer allocator.free(vn_packet);

    const peer_hash = endpoint_types.hashSockaddr(&peer.storage, peer.len);
    try conns.put(.{ .peer_hash = peer_hash, .dcid_hash = endpoint_types.hashBytes(client_scid) }, &conn);
    try conns.put(.{ .peer_hash = peer_hash, .dcid_hash = endpoint_types.hashBytes(client_dcid) }, &conn);

    var secret = [_]u8{0} ** 32;
    var ctx = incoming.RxContext{
        .allocator = &allocator,
        .conns = &conns,
        .accepted = &accepted,
        .cfg = &cfg,
        .send_fn = sendFn,
        .schedule_timer_fn = scheduleTimer,
        .send_initial_probe_fn = sendInitialProbe,
        .setup_sender_fn = setupSender,
        .test_capture_enabled = false,
        .endpoint_role = .Client,
        .generated_token_secret = &secret,
    };

    probe_count = 0;
    incoming.processVersionNegotiation(&ctx, peer, vn_packet);

    try std.testing.expectEqual(pkt.QUIC_V2, conn.version);
    try std.testing.expect(conn.version_v2);
    try std.testing.expectEqual(@as(usize, 1), probe_count);
}

test "endpoint VN rejects downgrade and disabled compatible VN" {
    var allocator = std.testing.allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .empty;
    defer accepted.deinit(allocator);

    var cfg = cfg_mod.QuicConfig{ .alpn = &[_][]const u8{}, .compatible_vn = true };
    const peer = fakePeer();

    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, peer);
    defer conn.deinit();
    conn.initial_version = pkt.QUIC_V1;
    conn.version = pkt.QUIC_V1;

    const client_scid = "VNDS";
    const client_dcid = "VNDD";
    const versions = [_]u32{ pkt.QUIC_V1, pkt.QUIC_V2 };
    const vn_packet = try pkt.encodeVersionNegotiation(allocator, client_scid, client_dcid, &versions);
    defer allocator.free(vn_packet);

    const peer_hash = endpoint_types.hashSockaddr(&peer.storage, peer.len);
    try conns.put(.{ .peer_hash = peer_hash, .dcid_hash = endpoint_types.hashBytes(client_scid) }, &conn);

    var secret = [_]u8{0} ** 32;
    var ctx = incoming.RxContext{
        .allocator = &allocator,
        .conns = &conns,
        .accepted = &accepted,
        .cfg = &cfg,
        .send_fn = sendFn,
        .schedule_timer_fn = scheduleTimer,
        .send_initial_probe_fn = sendInitialProbe,
        .setup_sender_fn = setupSender,
        .test_capture_enabled = false,
        .endpoint_role = .Client,
        .generated_token_secret = &secret,
    };

    probe_count = 0;
    incoming.processVersionNegotiation(&ctx, peer, vn_packet);
    try std.testing.expectEqual(pkt.QUIC_V1, conn.version);
    try std.testing.expect(!conn.version_v2);
    try std.testing.expectEqual(@as(usize, 0), probe_count);

    conn.initial_version = 0x0a0a0a0a;
    conn.version = conn.initial_version;
    cfg.compatible_vn = false;
    incoming.processVersionNegotiation(&ctx, peer, vn_packet);
    try std.testing.expectEqual(@as(u32, 0x0a0a0a0a), conn.version);
    try std.testing.expectEqual(@as(usize, 0), probe_count);
}
