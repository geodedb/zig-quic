const std = @import("std");
const testing = std.testing;

const transport_mod = @import("transport.zig");
const udp_transport_mod = @import("udp_transport.zig");

test "udp transport batch API round-trip smoke" {
    var recv_transport_impl = try udp_transport_mod.UdpTransport.init("127.0.0.1:0");
    defer recv_transport_impl.deinit();
    var send_transport_impl = try udp_transport_mod.UdpTransport.init("127.0.0.1:0");
    defer send_transport_impl.deinit();

    var recv_transport = recv_transport_impl.asTransport();
    var send_transport = send_transport_impl.asTransport();
    const recv_addr = try recv_transport.getLocalAddr();

    var payloads: [4][32]u8 = undefined;
    var items: [4]transport_mod.SendBatchItem = undefined;
    for (&payloads, 0..) |*payload, idx| {
        @memset(payload, 0);
        payload[0] = @as(u8, @intCast(idx));
        payload[1] = 0x42;
        items[idx] = .{
            .peer = recv_addr,
            .data = payload[0..],
        };
    }

    const sent = try send_transport.sendBatch(items[0..]);
    try testing.expectEqual(items.len, sent);

    var recv_bufs: [8][64]u8 = undefined;
    var recv_slots: [8]transport_mod.RecvBatchSlot = undefined;
    for (&recv_slots, 0..) |*slot, idx| {
        slot.* = .{
            .buf = recv_bufs[idx][0..],
            .n = 0,
            .peer = .{},
            .ecn = null,
        };
    }

    var seen = [_]bool{ false, false, false, false };
    var received_total: usize = 0;
    var attempts: usize = 0;
    while (received_total < items.len and attempts < 200) : (attempts += 1) {
        const got = recv_transport.recvBatch(recv_slots[0..]) catch |err| {
            if (err == error.WouldBlock) {
                std.Thread.sleep(1 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        if (got == 0) continue;

        var i: usize = 0;
        while (i < got) : (i += 1) {
            const slot = recv_slots[i];
            try testing.expect(slot.n >= 2);
            const marker = slot.buf[0];
            try testing.expect(marker < seen.len);
            seen[marker] = true;
            try testing.expectEqual(@as(u8, 0x42), slot.buf[1]);
            received_total += 1;
        }
    }

    try testing.expectEqual(items.len, received_total);
    for (seen) |ok| {
        try testing.expect(ok);
    }
}
