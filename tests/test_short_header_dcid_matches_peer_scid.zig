const std = @import("std");
const api = @import("quic_api");
const packet = @import("quic_packet");

extern fn __test_export_peer_initial_scid(ptr: *anyopaque, buf: [*]u8, max: usize) callconv(.C) usize;
extern fn __test_export_our_scid(ptr: *anyopaque, buf: [*]u8, max: usize) callconv(.C) usize;

fn getPeerInitialScid(c: *anyopaque) []const u8 {
    var tmp: [32]u8 = undefined;
    const n = __test_export_peer_initial_scid(c, &tmp, tmp.len);
    return tmp[0..n];
}

// Capture structure for intercepted short-header packets.
const Capture = struct {
    buf: []u8,
};

// Simple ring to collect a handful of captured DCIDs.
const CaptureRing = struct {
    items: [16]Capture = undefined,
    count: usize = 0,

    fn add(self: *CaptureRing, alloc: std.mem.Allocator, pkt: []const u8) void {
        if (self.count == self.items.len) return; // drop if full
        const owned = alloc.alloc(u8, pkt.len) catch return;
        std.mem.copy(u8, owned, pkt);
        self.items[self.count] = .{ .buf = owned };
        self.count += 1;
    }

    fn deinit(self: *CaptureRing, alloc: std.mem.Allocator) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) alloc.free(self.items[i].buf);
        self.count = 0;
    }
};

// Sender shim that records outgoing short-header packets for the client connection only.
fn captureSender(ctx: *anyopaque, c: *api.Connection, data: []const u8) anyerror!usize {
    _ = c; // unused (we only capture raw packet bytes)
    const cap: *CaptureRing = @ptrCast(@alignCast(ctx));
    // Heuristic: short-header first byte has 0b0100_0000 with fixed bit set and bit 7 clear.
    if (data.len > 5 and (data[0] & 0x80) == 0 and (data[0] & 0x40) != 0) {
        // DCID length in our encoder equals peer SCID length; we just store entire packet.
        cap.add(std.heap.page_allocator, data);
    }
    // Pretend packet was "sent" (tests run in-process without network).
    return data.len;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"}, .allow_insecure = true };
    const ep = try api.endpointInit(&alloc, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    const conn = try api.connect(ep, "127.0.0.1:55556", "test.local");

    // Install capture sender on client connection (after connect returns conn*).
    var ring: CaptureRing = .{ .items = undefined, .count = 0 };
    api.setSender(conn, &ring, captureSender);

    // Drive until handshake done.
    var spins: usize = 0;
    while (spins < 10_000 and !api.handshakeDoneSeen(conn)) : (spins += 1) {
        api.poll(ep, 5) catch break;
    }
    try std.testing.expect(api.handshakeDoneSeen(conn));

    const peer_scid = getPeerInitialScid(@ptrCast(conn));
    try std.testing.expect(peer_scid.len > 0);

    // Send some STREAM data to force short-header packets.
    const stream_id = try api.openStream(conn, true);
    var sent_total: usize = 0;
    while (sent_total < 200) {
        var chunk: [32]u8 = undefined;
        for (chunk, 0..) |*b, i| b.* = @intCast(i);
        const n = api.writeStream(conn, stream_id, chunk[0..]) catch |e| switch (e) {
            error.FlowControlBlocked => break,
            else => return e,
        };
        sent_total += n;
        api.poll(ep, 5) catch {};
    }

    // We should have captured at least one short-header packet now.
    try std.testing.expect(ring.count > 0);

    // Validate that each captured packet starts with a short header carrying the peer SCID as DCID.
    var i: usize = 0;
    while (i < ring.count) : (i += 1) {
        const pkt_bytes = ring.items[i].buf;
        // Short header format we emit: first byte + DCID (peer_scid) + PN (1-4) + ciphertext
        try std.testing.expect(pkt_bytes.len >= 1 + peer_scid.len + 1 + 16);
        // First byte short, fixed bit set (0x40) and bit 7 clear
        try std.testing.expect((pkt_bytes[0] & 0x80) == 0);
        try std.testing.expect((pkt_bytes[0] & 0x40) != 0);
        // Compare DCID bytes
        const dcid_bytes = pkt_bytes[1 .. 1 + peer_scid.len];
        try std.testing.expect(std.mem.eql(u8, dcid_bytes, peer_scid));
    }

    ring.deinit(std.heap.page_allocator);
}
