const std = @import("std");
const api = @import("quic_api");

// Basic timing tests for endpoint timers.

test "endpoint_timer_fire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 20);
    const t0 = std.time.milliTimestamp();
    try api.poll(ep, 200);
    const dt = std.time.milliTimestamp() - t0;

    // Should have waited at least a few milliseconds, but much less than the full poll timeout.
    try std.testing.expect(dt >= 5);
    try std.testing.expect(dt < 500);

    // Timer should be consumed.
    try std.testing.expect(ep.timers.items.len == 0);
}

test "endpoint_timer_cancel" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 200);
    const id2 = try api.scheduleTimer(ep, 200);
    try std.testing.expect(ep.timers.items.len == 2);

    try std.testing.expect(api.cancelTimer(ep, id2));
    try std.testing.expect(ep.timers.items.len == 1);

    // Poll briefly to let the remaining timer not fire yet; count stays 1.
    try api.poll(ep, 10);
    try std.testing.expect(ep.timers.items.len == 1);

    // Now poll long enough for it to expire and be removed.
    try api.poll(ep, 300);
    try std.testing.expect(ep.timers.items.len == 0);
}
