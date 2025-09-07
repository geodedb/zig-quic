// MIT License
// Tests NAT rebinding path-validation gating across repeated rebindings.
const std = @import("std");
const api = @import("quic_api");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");

fn build_client_initial(alloc: std.mem.Allocator, c: *conn_mod.Connection) ![]u8 {
    const initial = ks.deriveInitialSecret(false, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    const pair = ks.deriveClientServerInitial(initial);
    const tx_keys: packet.InitialKeys = blk: {
        const t = ks.deriveKeyIvHp(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(frames.writer(alloc)) catch {};
    return packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
        c.our_scid.bytes[0..c.our_scid.len],
        &[_]u8{},
        1,
        4,
        frames.items,
        tx_keys,
    );
}

// Helper to fabricate a different peer sockaddr (simulating NAT rebinding)
fn fake_peer(ip_last_octet: u8, port: u16) conn_mod.SockAddr {
    return conn_mod.SockAddr.ipv4(127, 0, 0, ip_last_octet, port);
}

// This test simulates: client sends an Initial; server responds within 3x. Then path changes
// (NAT rebinding) multiple times; each time, server must gate sends until PATH_RESPONSE validates.
// We inject PATH_CHALLENGE to client and craft PATH_RESPONSE back to validate, repeating twice.
test "nat rebinding enforces 3x before validation across repeated rebindings" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    const c = try ep.connectClient("127.0.0.1:9");
    // Build and inject a client Initial to create server conn and trigger Initial ACK
    const init_pkt = try build_client_initial(alloc, c);
    defer alloc.free(init_pkt);
    const original_peer = c.peer;
    ep.testInject(original_peer, init_pkt);

    // Drain captures and compute total bytes sent so far by server (should be within 3x)
    var sent_total: usize = 0;
    while (ep.captureLen() > 0) {
        if (ep.capturePop()) |cap| {
            sent_total += cap.bytes.len;
            alloc.free(cap.bytes);
        } else break;
    }
    try std.testing.expect(sent_total <= 3 * init_pkt.len);

    // Fetch server connection from endpoint map via peer hash + dcid
    var srv_opt: ?*conn_mod.Connection = null;
    var it = ep.conns.iterator();
    while (it.next()) |e| {
        const cand = e.value_ptr.*;
        if (cand.role == .Server) {
            srv_opt = cand;
            break;
        }
    }
    const srv = srv_opt orelse return error.TestUnexpected;

    // Seed 1-RTT keys and DCID so PATH_CHALLENGE/RESPONSE works on short header
    srv.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    srv.app_rx_keys = srv.app_tx_keys;
    srv.our_scid.len = 4;
    std.mem.copyForwards(u8, srv.our_scid.bytes[0..4], "SRV1");

    inline for (.{ 10, 11 }) |oct| {
        // Simulate NAT rebinding by changing peer address
        const new_peer = fake_peer(oct, 9);
        // Craft a short-header with server DCID to trigger mapping and onPathAddressChanged
        var probe: [8]u8 = .{0} ** 8;
        probe[0] = 0x40; // short header
        std.mem.copyForwards(u8, probe[1..5], srv.our_scid.bytes[0..srv.our_scid.len]);
        ep.testInject(new_peer, &probe);
        // After path change, address_validated must be false and 3x applies; server will send PATH_CHALLENGE
        // Count received bytes on new path (our probe plus our PATH_RESPONSE later)
        var recv_bytes: usize = probe.len;
        var sent_bytes_on_new: usize = 0;
        // Server will have generated srv.path_challenge_data; respond with PATH_RESPONSE now.
        {
            var fb = std.ArrayList(u8){};
            defer fb.deinit(alloc);
            const w = fb.writer(alloc);
            _ = (frame.Frame{ .path_response = srv.path_challenge_data }).write(w) catch {};
            const out = packet.encodeShortProtected(alloc, srv.our_scid.bytes[0..srv.our_scid.len], @as(u32, @truncate(srv.pn_app_tx)), 2, fb.items, .{ .key = srv.app_rx_keys.?.key, .iv = srv.app_rx_keys.?.iv, .hp = srv.app_rx_keys.?.hp }, srv.tx_key_phase) catch null;
            if (out) |bytes_out| {
                defer alloc.free(bytes_out);
                ep.testInject(new_peer, bytes_out);
                recv_bytes += bytes_out.len;
            }
        }
        // Drain captures and sum bytes the server sent to new path before validation
        while (ep.captureLen() > 0) {
            if (ep.capturePop()) |cap| {
                if (conn_mod.SockAddr.eq(&cap.peer, &new_peer)) {
                    sent_bytes_on_new += cap.bytes.len;
                }
                alloc.free(cap.bytes);
            } else break;
        }
        // After validation, counters reset and further sends are not 3x constrained. At least ensure not exceeding 3x before validation impulse
        try std.testing.expect(sent_bytes_on_new <= 3 * recv_bytes);
    }
}
