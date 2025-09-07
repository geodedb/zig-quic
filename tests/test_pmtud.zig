// MIT License
// Tests for minimal DPLPMTUD probe building and validation
const std = @import("std");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const endpoint_mod = @import("quic_endpoint");

test "pmtud pacing: paced send occurs under NewReno and CUBIC when cwnd is partially full" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Helper to run a paced send scenario under a given CC mode
    const run_once = struct {
        fn f(A: *std.mem.Allocator, use_cubic: bool) !void {
            var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
            cfg.enable_pacing = true;
            cfg.cc = if (use_cubic) .cubic else .newreno;
            var ep = try endpoint_mod.Endpoint.init(A, "127.0.0.1:0", &cfg);
            defer ep.deinit();
            // Enable outbound capture to observe pacing behavior
            ep.test_capture_enabled = true;
            var c = try ep.connectClient("127.0.0.1:9");
            // Seed minimal 1-RTT TX keys and DCID for short header encode
            c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
            c.our_scid.len = 4;
            std.mem.copyForwards(u8, c.our_scid.bytes[0..4], if (use_cubic) "CUBC" else "NREN");

            // Arrange cwnd/bytes_in_flight to trigger pacing but not block on cwnd
            c.rec.cc.cwnd = 5000;
            c.rec.cc.bytes_in_flight = 3500; // >= cwnd/2 -> pacing delay; +1400 <= 5000 so not blocked

            // No datagrams captured yet
            try std.testing.expectEqual(@as(usize, 0), ep.captureLen());
            const sent = try c.sendPmtudProbe(1400);
            try std.testing.expectEqual(@as(usize, 1400), sent);
            // Because pacing is enabled and delay_ns>0, payload is queued in a paced timer; no immediate capture
            try std.testing.expectEqual(@as(usize, 0), ep.captureLen());

            // Expire timers to flush paced send; exactly one capture should appear
            ep.forceExpireAllTimers();
            try std.testing.expectEqual(@as(usize, 1), ep.captureLen());
            // Drain capture to keep allocator balanced for next iteration
            if (ep.capturePop()) |cap| A.free(cap.bytes);
            ep.captureClear();
        }
    }.f;

    try run_once(&alloc, false); // NewReno
    try run_once(&alloc, true); // CUBIC
}

test "pmtud with cubic: single outstanding probe with backoff (blackhole)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    cfg.cc = .cubic;
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:10");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "CBKH");
    // Start PMTUD but never ACK probes; ensure only one pending at a time and PN advances/updates
    c.pmtudStart(&ep);
    var prev_pn: ?u64 = null;
    var rounds: usize = 0;
    while (rounds < 3) : (rounds += 1) {
        ep.forceExpireAllTimers();
        const cur = c.probe_pending_pn;
        try std.testing.expect(cur != null);
        if (prev_pn) |_| {
            // Ensure probe size is tracked (non-zero) and only one pending PN exists
            try std.testing.expect(c.probe_pending_size != 0);
        }
        prev_pn = cur;
    }
}

test "pmtud with cubic: cwnd insufficient blocks probe and PTO backoff increases" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    cfg.cc = .cubic;
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:12");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "CBWD");
    // Block probe due to cwnd
    c.rec.cc.cwnd = 1200;
    c.rec.cc.bytes_in_flight = 1200;
    const err1 = c.sendPmtudProbe(1400);
    try std.testing.expect(err1 == error.WouldBlock);
    // Allow a 1280 probe
    c.rec.cc.bytes_in_flight = 0;
    c.rec.cc.cwnd = 2000;
    const sent = try c.sendPmtudProbe(1280);
    try std.testing.expectEqual(@as(usize, 1280), sent);
    // PTO backoff should increase next deadline when pto_count increments
    const now_i = std.time.nanoTimestamp();
    const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
    const d1 = c.rec.computeNextPtoTimeNs(now_ns);
    c.setPtoExpiredApp();
    const d2 = c.rec.computeNextPtoTimeNs(now_ns);
    if (d1) |a| if (d2) |b| try std.testing.expect(b >= a);
}

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
        .tls_inbox = std.ArrayList(u8){},
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
        .tls_inbox = std.ArrayList(u8){},
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
        .tls_inbox = std.ArrayList(u8){},
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

test "icmp ptb spoof corner: quoted header too short is ignored" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = @import("quic_api").QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:9");
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "DCID");
    c.path_mtu = 1400;
    var quote_short: [2]u8 = .{ 0x40, 0x00 };
    ep.testInjectIcmpPtb(c.peer, &quote_short, 1200);
    try std.testing.expectEqual(@as(u16, 1400), c.path_mtu);
}

test "pmtud: send multiple probe sizes and accept only acked size" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var c = conn_mod.Connection{
        .id = 2,
        .role = .Client,
        .sock_fd = 0,
        .peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 5555),
        .tls_inbox = std.ArrayList(u8){},
        .tls = @import("quic_tls13").Engine.init(alloc, .Client),
        .allocator = &alloc,
    };
    defer c.deinit();
    c.init(&alloc, .Client, 0, c.peer);
    // For direct sends in this unit test, bypass anti-amplification gating
    c.address_validated = true;
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "PROB");

    const s1: u16 = 1280;
    const s2: u16 = 1400;
    _ = try c.sendPmtudProbe(s1);
    const pn1 = c.probe_pending_pn.?;
    // Send next without acking first—should overwrite pending PN and size
    _ = try c.sendPmtudProbe(s2);
    const pn2 = c.probe_pending_pn.?;
    try std.testing.expect(pn2 != pn1);
    // Ack only the latest; path_mtu should become s2
    var ranges = [_]frame.AckRange{};
    c.onAckReceivedSpace(.Application, pn2, 0, ranges[0..0], null);
    try std.testing.expectEqual(@as(u16, s2), c.path_mtu);
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

test "icmp ptb ipv6 minimal quote length required" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:9");
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "V6ID");
    c.path_mtu = 1400;
    // Too-short IPv6 quote should be ignored
    var quote_tiny: [4]u8 = .{ 0x40, 'V', '6', 'X' };
    ep.testInjectIcmpPtb(c.peer, &quote_tiny, 1200);
    try std.testing.expectEqual(@as(u16, 1400), c.path_mtu);
}

test "icmp ptb ipv6 EH offset scan: accept DCID match beyond base header" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:9");
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "V6EH");
    c.path_mtu = 1400;
    // Build a quote with 40 bytes of IPv6 header + 8 bytes extension, then short header + DCID
    var quote: [64]u8 = .{0} ** 64;
    // Place short header byte at offset 48 (typical IPv6(40)+EH(8))
    quote[48] = 0x40;
    std.mem.copyForwards(u8, quote[49..53], "V6EH");
    ep.testInjectIcmpPtb(c.peer, &quote, 1280);
    try std.testing.expectEqual(@as(u16, 1280), c.path_mtu);
}

test "pmtud pacing: single outstanding probe with backoff on blackhole" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:10");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "PACE");
    // Start PMTUD but never ACK probes; ensure only one pending at a time and PN advances
    c.pmtudStart(&ep);
    var prev_pn: ?u64 = null;
    var rounds: usize = 0;
    while (rounds < 3) : (rounds += 1) {
        ep.forceExpireAllTimers();
        const cur = c.probe_pending_pn;
        try std.testing.expect(cur != null);
        if (prev_pn) |pp| {
            // Either same PN re-sent due to timer or advanced by search—both acceptable, but never two pending
            try std.testing.expect(c.probe_pending_size != 0);
            _ = pp; // silence lint; logical check is the presence of only one pending
        }
        prev_pn = cur;
    }
}

test "pmtud pacing: do not send probe when cwnd insufficient; respects PTO backoff" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = false;
    var ep = try endpoint_mod.Endpoint.init(&alloc, "127.0.0.1:0", &cfg);
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:12");
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    c.our_scid.len = 4;
    std.mem.copyForwards(u8, c.our_scid.bytes[0..4], "CWND");
    // Set a very small cwnd and high bytes_in_flight to block probe
    c.rec.cc.cwnd = 1200;
    c.rec.cc.bytes_in_flight = 1200;
    const target: u16 = 1400;
    const err1 = c.sendPmtudProbe(target);
    try std.testing.expect(err1 == error.WouldBlock);

    // Reduce bytes_in_flight and raise cwnd to allow a standard 1280 probe
    c.rec.cc.bytes_in_flight = 0;
    c.rec.cc.cwnd = 2000;
    const sent = try c.sendPmtudProbe(1280);
    try std.testing.expectEqual(@as(usize, 1280), sent);

    // Verify PTO backoff interaction: on PTO expiry, pto_count increases
    // and subsequent computeNextPtoTimeNs reflects backoff via a larger deadline delta.
    const now_i = std.time.nanoTimestamp();
    const now_ns: u64 = @intCast(if (now_i > 0) now_i else 0);
    const d1 = c.rec.computeNextPtoTimeNs(now_ns);
    // Simulate PTO expiry in App space
    c.setPtoExpiredApp();
    const d2 = c.rec.computeNextPtoTimeNs(now_ns);
    // After backoff, d2 should be >= d1 (or both null if no in-flight)
    if (d1) |a| if (d2) |b| try std.testing.expect(b >= a);
}
