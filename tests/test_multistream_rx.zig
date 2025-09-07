const std = @import("std");
const conn_mod = @import("quic_conn");
const fr = @import("quic_frame");
const pkt = @import("quic_packet");
const endpoint = @import("quic_endpoint");

// Helper: build and inject a short 1-RTT packet carrying provided frames with zero keys.
fn injectShort(a: std.mem.Allocator, ep: *endpoint.Endpoint, c: *conn_mod.Connection, frames_bytes: []const u8) !void {
    const keys = c.app_rx_keys.?; // installed by test
    const pkt_bytes = try pkt.encodeShortProtected(a, c.our_scid.bytes[0..c.our_scid.len], 1, 2, frames_bytes, keys, c.rx_key_phase);
    defer a.free(pkt_bytes);
    ep.testInject(c.peer, pkt_bytes);
}

test "multi-stream RX: independent FIN completion" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();
    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:1");
    // Install deterministic keys
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    // Simulate two inbound streams (0 and 4). Push partial data + FIN for stream 0 only.
    var fb = std.ArrayList(u8){};
    defer fb.deinit(alloc);
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = 0, .fin = true, .data = "hello" } }).write(fb.writer(alloc)) catch 0;
    _ = (fr.Frame{ .stream = .{ .stream_id = 4, .offset = 0, .fin = false, .data = "abc" } }).write(fb.writer(alloc)) catch 0;
    try injectShort(A, &ep, &c, fb.items);
    // Stream 0 should mark fin; stream 4 should not.
    const s0 = c.streams_rx.getPtr(0).?;
    try std.testing.expect(s0.fin_off.? == 5);
    const s4 = c.streams_rx.getPtr(4).?;
    try std.testing.expect(s4.fin_off == null);
}

test "multi-stream RX: RESET_STREAM aborts only target stream" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();
    var c: conn_mod.Connection = undefined;
    c.init(&A, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer c.deinit();
    // Install zero keys (not used since we call handler directly)
    c.app_rx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    // Build RX state for two streams
    try c.pushStreamFrame(0, 0, "hello", false);
    try c.pushStreamFrame(4, 0, "abcdef", false);
    // Apply RESET to stream 4 only
    c.handleResetStream(4, 42, 6);
    // Validate: stream 4 fin, stream 0 unaffected
    const s4 = c.streams_rx.getPtr(4).?;
    try std.testing.expect(s4.fin_off.? == 6);
    const s0 = c.streams_rx.getPtr(0).?;
    try std.testing.expect(s0.fin_off == null);
}
