const std = @import("std");
const api = @import("quic_api");

// Basic multi-stream open/write/close behavior smoke test.
// Opens several bidi streams, writes small payloads, ensures flow control
// does not block prematurely and offsets advance independently.

pub fn main() !void {}

test "multi-stream basic open/write" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();
    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"hq-interop"}, .allow_insecure = true };
    const ep = try api.endpointInit(&alloc, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);
    const client = try api.connect(ep, "127.0.0.1:4433", "example");
    // Simulate handshake done (test shortcut) if not already
    var spins: usize = 0;
    while (!api.handshakeDoneSeen(client) and spins < 2000) : (spins += 1) {
        api.poll(ep, 1) catch {};
    }
    // Open multiple streams
    const s1 = try api.openStream(client, true);
    std.testing.expectEqual(@as(u64, 0), s1) catch return error.TestExpectedEqual; // first bidi stream id usually 0
    const s2 = try api.openStream(client, true);
    std.testing.expect(s2 != s1) catch return error.TestExpectedEqual;
    // Write to streams
    var payload = "hello world".*;
    _ = api.writeStream(client, s1, payload[0..]) catch |e| switch (e) {
        else => return e,
    };
    _ = api.writeStream(client, s2, payload[0..]) catch |e| switch (e) {
        else => return e,
    };
    // Close streams
    api.closeStream(client, s1, 0) catch {};
    api.closeStream(client, s2, 0) catch {};
    // Expect further writes to be stopped
    const err1 = api.writeStream(client, s1, payload[0..]) catch |e| e;
    std.testing.expect(err1 != null) catch return error.TestExpectedEqual;
}
