// MIT License
// Tests for minimal DPLPMTUD probe building and validation
const std = @import("std");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const endpoint_mod = @import("quic_endpoint");

test "pmtud probe builds PING+PADDING to exact UDP payload size" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Build a connection with app keys ready
    var c = conn_mod.Connection{
        .id = 1,
        .role = .Client,
        .sock_fd = 0,
        .peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 5555),
        .tls_inbox = std.ArrayList(u8).init(alloc),
        .tls = @import("quic_tls13").Engine.init(alloc, .Client),
        .allocator = &alloc,
    };
    defer c.deinit();
    c.init(&alloc, .Client, 0, c.peer);
    // Seed minimal 1-RTT TX keys (zeros suffice for encode in tests)
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    // Set a DCID for short header
    c.our_scid.len = 8;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..8], "ABCDEFGH");

    const target: u16 = 1250;
    const sent_bytes = try c.sendPmtudProbe(target);
    try std.testing.expectEqual(@as(usize, target), sent_bytes);
}

test "pmtud validation raises path_mtu on ACK of probe PN" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = conn_mod.Connection{
        .id = 1,
        .role = .Client,
        .sock_fd = 0,
        .peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 5555),
        .tls_inbox = std.ArrayList(u8).init(alloc),
        .tls = @import("quic_tls13").Engine.init(alloc, .Client),
        .allocator = &alloc,
    };
    defer c.deinit();
    c.init(&alloc, .Client, 0, c.peer);
    // Seed minimal 1-RTT TX keys
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "ABCD");

    const target: u16 = 1300;
    const old_mtu = c.path_mtu;
    _ = try c.sendPmtudProbe(target);
    // Build an ACK for that PN in Application space
    const pn = c.probe_pending_pn.?;
    var ranges = [_]frame.AckRange{};
    c.onAckReceivedSpace(.Application, pn, 0, ranges[0..0], null);
    try std.testing.expectEqual(@as(u16, target), c.path_mtu);
    try std.testing.expect(c.path_mtu >= old_mtu);
}

test "icmp packet too big clamps path_mtu and clears oversize pending" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = conn_mod.Connection{
        .id = 1,
        .role = .Client,
        .sock_fd = 0,
        .peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 5555),
        .tls_inbox = std.ArrayList(u8).init(alloc),
        .tls = @import("quic_tls13").Engine.init(alloc, .Client),
        .allocator = &alloc,
    };
    defer c.deinit();
    c.init(&alloc, .Client, 0, c.peer);
    c.path_mtu = 1350;
    c.probe_pending_pn = 42;
    c.probe_pending_size = 1400;
    c.onIcmpPacketTooBig(1280);
    try std.testing.expectEqual(@as(u16, 1280), c.path_mtu);
    try std.testing.expect(c.probe_pending_pn == null);
}

test "icmp ptb spoof-check: only applies when DCID matches known connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    // Build endpoint and a client connection mapping
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:9");
    // Seed minimal 1-RTT TX keys and DCID for short header
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "DCID");
    c.path_mtu = 1400;
    // Craft a quoted UDP payload resembling a short-header QUIC with our DCID at offset 0
    var quote_ok: [16]u8 = .{0} ** 16;
    quote_ok[0] = 0x40; // short header first byte with key phase 0
    std.mem.copyForwards(u8, quote_ok[1..5], "DCID");
    ep.testInjectIcmpPtb(c.peer, &quote_ok, 1280);
    try std.testing.expectEqual(@as(u16, 1280), c.path_mtu);
    // Now inject a quote with a different DCID; MTU should remain unchanged
    var quote_bad: [16]u8 = .{0} ** 16;
    quote_bad[0] = 0x40;
    std.mem.copyForwards(u8, quote_bad[1..5], "XXXX");
    c.path_mtu = 1400;
    ep.testInjectIcmpPtb(c.peer, &quote_bad, 1250);
    try std.testing.expectEqual(@as(u16, 1400), c.path_mtu);
}

test "pmtud state machine sends probes and raises mtu upon ack progression" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    // Use endpoint to drive timers; attach one connection with TX keys
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:9");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "ABCD");
    // Start PMTUD and force timers to fire
    c.pmtudStart(&ep);
    ep.forceExpireAllTimers(); // should send 1280 probe and arm next
    // Simulate ACK progress to accelerate probing
    c.pmtudOnAckProgress(&ep);
    ep.forceExpireAllTimers(); // should send next step probe (e.g., 1400)
    // Now pretend the probe PN was acked so path_mtu increases to at least 1280
    if (c.probe_pending_pn) |pn| {
        var empty = [_]frame.AckRange{};
        c.onAckReceivedSpace(.Application, pn, 0, empty[0..0], null);
    }
    try std.testing.expect(c.path_mtu >= 1280);
}
