// Expanded migration tests: varied rebind patterns, concurrent paths, and timeout/failure.
const std = @import("std");
const api = @import("quic_api");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");

// RFC 9000 §9.3–§9.6 cover path validation, preferred address migration, and
// the anti-amplification rule (§8.1). The following scenarios exercise those
// requirements across rebinding, timeouts, preferred addresses, and PTO loops.
fn fake_peer(ip_last_octet: u8, port: u16) conn_mod.SockAddr {
    return conn_mod.SockAddr.ipv4(127, 0, 0, ip_last_octet, port);
}

// Helper: encode a PATH_RESPONSE echoing the server's challenge for short header
fn encode_path_response(a: std.mem.Allocator, c: *conn_mod.Connection) !?[]u8 {
    if (c.app_rx_keys == null) return null;
    var fb = std.ArrayList(u8){};
    defer fb.deinit(a);
    const w = fb.writer(a);
    _ = (frame.Frame{ .path_response = c.path_challenge_data }).write(w) catch {};
    return packet.encodeShortProtected(a, c.our_scid.bytes[0..c.our_scid.len], @as(u32, @truncate(c.pn_app_tx)), 2, fb.items, .{ .key = c.app_rx_keys.?.key, .iv = c.app_rx_keys.?.iv, .hp = c.app_rx_keys.?.hp }, c.tx_key_phase) catch null;
}

test "migration: back-to-back rebinds then validate latest only (older stays gated)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:7777");
    // Seed minimal 1-RTT keys and DCID to allow short header
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "CID1");

    // Trigger first rebinding (A)
    const peer_a = fake_peer(20, 7777);
    var probe_a: [8]u8 = .{0} ** 8;
    probe_a[0] = 0x40; // short header first byte
    std.mem.copyForwards(u8, probe_a[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(peer_a, &probe_a);

    // Immediately trigger second rebinding (B)
    const peer_b = fake_peer(21, 7777);
    var probe_b: [8]u8 = .{0} ** 8;
    probe_b[0] = 0x40;
    std.mem.copyForwards(u8, probe_b[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(peer_b, &probe_b);

    // Drain any PATH_CHALLENGE sends; count per-peer pre-validation bytes
    var sent_a: usize = 0;
    var sent_b: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            if (conn_mod.SockAddr.eq(&cap.peer, &peer_a)) sent_a += cap.bytes.len else if (conn_mod.SockAddr.eq(&cap.peer, &peer_b)) sent_b += cap.bytes.len;
            A.free(cap.bytes);
        } else break;
    }
    // Each unvalidated path must be <= 3x amplification individually
    try std.testing.expect(sent_a <= 3 * probe_a.len);
    try std.testing.expect(sent_b <= 3 * probe_b.len);

    // Validate only latest path (B)
    if (try encode_path_response(A, &c)) |resp| {
        defer A.free(resp);
        ep.testInject(peer_b, resp);
    }

    // After validation, server can send more to B; A should remain gated or quiet
    var more_a: usize = 0;
    var more_b: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            if (conn_mod.SockAddr.eq(&cap.peer, &peer_a)) more_a += cap.bytes.len else if (conn_mod.SockAddr.eq(&cap.peer, &peer_b)) more_b += cap.bytes.len;
            A.free(cap.bytes);
        } else break;
    }
    try std.testing.expect(more_b > 0);
    try std.testing.expect(more_a <= 3 * probe_a.len);
}

test "migration: validation timeout keeps 3x gating on new path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:7778");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.app_rx_keys = c.app_tx_keys;
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "CID2");

    const new_peer = fake_peer(30, 7778);
    var probe: [8]u8 = .{0} ** 8;
    probe[0] = 0x40;
    std.mem.copyForwards(u8, probe[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(new_peer, &probe);

    // Let timers expire to simulate PATH validation timeout
    ep.forceExpireAllTimers();

    var sent: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            if (conn_mod.SockAddr.eq(&cap.peer, &new_peer)) sent += cap.bytes.len;
            A.free(cap.bytes);
        } else break;
    }
    // Still must not exceed 3x amplification on the unvalidated path
    try std.testing.expect(sent <= 3 * probe.len);
}

test "migration: server-initiated migration to preferred address with validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:8080");
    // Seed app keys for short header
    const zero16 = [_]u8{0} ** 16;
    const zero12 = [_]u8{0} ** 12;
    c.app_tx_keys = .{ .key = zero16, .iv = zero12, .hp = zero16 };
    c.app_rx_keys = c.app_tx_keys;
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "SVR1");

    // Simulate server advertising a preferred address; client migrates by sending from new address
    const pref_peer = fake_peer(40, 8080);
    var trigger: [8]u8 = .{0} ** 8;
    trigger[0] = 0x40;
    std.mem.copyForwards(u8, trigger[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(pref_peer, &trigger);

    // Server should PATH_CHALLENGE; validate by sending PATH_RESPONSE
    if (try encode_path_response(A, &c)) |resp| {
        defer A.free(resp);
        ep.testInject(pref_peer, resp);
    }

    // After validation, traffic to preferred address should no longer be 3x-gated
    var sent_pref: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            if (conn_mod.SockAddr.eq(&cap.peer, &pref_peer)) sent_pref += cap.bytes.len;
            A.free(cap.bytes);
        } else break;
    }
    try std.testing.expect(sent_pref > 0);
}

test "migration: blackholed new path enforces <=3x across PTO retries" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:9090");
    const z16 = [_]u8{0} ** 16;
    const z12 = [_]u8{0} ** 12;
    c.app_tx_keys = .{ .key = z16, .iv = z12, .hp = z16 };
    c.app_rx_keys = c.app_tx_keys;
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "PTO1");

    const new_peer = fake_peer(50, 9090);
    var probe: [8]u8 = .{0} ** 8;
    probe[0] = 0x40;
    std.mem.copyForwards(u8, probe[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(new_peer, &probe);

    // Do not send PATH_RESPONSE (blackhole). Force PTO expirations to trigger re-sends of PATH_CHALLENGE.
    const recv_bytes: usize = probe.len;
    var sent_bytes: usize = 0;
    var rounds: usize = 0;
    while (rounds < 3) : (rounds += 1) {
        ep.forceExpireAllTimers();
        while (ep.captureLen() > 0) {
            if (ep.capturePop()) |cap| {
                if (conn_mod.SockAddr.eq(&cap.peer, &new_peer)) sent_bytes += cap.bytes.len;
                A.free(cap.bytes);
            } else break;
        }
        // Still must not exceed 3x per unvalidated path impulse
        try std.testing.expect(sent_bytes <= 3 * recv_bytes);
    }
}

test "migration: rebind after PATH_RESPONSE reordered before another rebind" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:7070");
    const z16 = [_]u8{0} ** 16;
    const z12 = [_]u8{0} ** 12;
    c.app_tx_keys = .{ .key = z16, .iv = z12, .hp = z16 };
    c.app_rx_keys = c.app_tx_keys;
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "RB1!");

    const peer1 = fake_peer(60, 7070);
    const peer2 = fake_peer(61, 7070);
    var h1: [8]u8 = .{0} ** 8;
    h1[0] = 0x40;
    std.mem.copyForwards(u8, h1[1..5], c.our_scid.bytes[0..4]);
    var h2: [8]u8 = .{0} ** 8;
    h2[0] = 0x40;
    std.mem.copyForwards(u8, h2[1..5], c.our_scid.bytes[0..4]);
    ep.testInject(peer1, &h1);
    // Immediately validate peer1 (send PATH_RESPONSE)
    if (try encode_path_response(A, &c)) |resp| {
        defer A.free(resp);
        ep.testInject(peer1, resp);
    }
    // Now inject another rebinding (peer2)
    ep.testInject(peer2, &h2);

    // Drain and ensure helper leaves peer2 gated and allows traffic to validated peer1
    var to1: usize = 0;
    var to2: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            if (conn_mod.SockAddr.eq(&cap.peer, &peer1)) to1 += cap.bytes.len else if (conn_mod.SockAddr.eq(&cap.peer, &peer2)) to2 += cap.bytes.len;
            A.free(cap.bytes);
        } else break;
    }
    try std.testing.expect(to1 > 0);
    try std.testing.expect(to2 <= 3 * h2.len);
}
