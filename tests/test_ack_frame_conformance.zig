// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6486 items 3 and 4).
//
// Item 3: STREAM_DATA_BLOCKED is ack-eliciting (RFC 9002 §2: every frame
// but ACK, PADDING and CONNECTION_CLOSE). It was neither acknowledged nor
// acted on, so a blocked sender's only packets were never acknowledged: if
// its last data packets were lost, nothing ever triggered their
// retransmission and the stream stalled.
//
// Item 4: the ACK Delay field is encoded with the exponent this endpoint
// advertises (RFC 9000 §18.2, §19.3); it used the peer's exponent.

const std = @import("std");
const testing = std.testing;
const conn_mod = @import("quic_conn");
const frame = @import("quic_frame");
const packet = @import("quic_packet");
const frame_handler = @import("frame_handler");
const cfg = @import("quic_config");
const handshake = @import("handshake_integration");
const transport_params = @import("quic_transport_params");

const keys = packet.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

const Capture = struct {
    alloc: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) !usize {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        try self.sent.append(self.alloc, try self.alloc.dupe(u8, bytes));
        return bytes.len;
    }

    fn deinit(self: *Capture) void {
        for (self.sent.items) |p| self.alloc.free(p);
        self.sent.deinit(self.alloc);
    }

    /// Latest MAX_STREAM_DATA for `sid` sent from packet index `from`.
    fn maxStreamData(self: *Capture, from: usize, sid: u64) ?u64 {
        var found: ?u64 = null;
        for (self.sent.items[from..]) |p| {
            const dec = packet.decodeShortProtected(self.alloc, p, 4, keys, 0) catch continue;
            defer self.alloc.free(dec.payload);
            var off: usize = 0;
            while (off < dec.payload.len) {
                const fr = frame.decodeOne(dec.payload[off..]) catch break;
                off += fr.n;
                if (fr.f == .max_stream_data and fr.f.max_stream_data.stream_id == sid) found = fr.f.max_stream_data.max;
            }
        }
        return found;
    }
};

fn serverConn(alloc: *std.mem.Allocator, capture: *Capture) !*conn_mod.Connection {
    const c = try alloc.create(conn_mod.Connection);
    c.init(alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    c.app_tx_keys = keys;
    c.peer_finished_verified = true;
    c.address_validated = true;
    c.peer_initial_scid.len = 4;
    @memcpy(c.peer_initial_scid.bytes[0..4], "PEER");
    c.setSender(@ptrCast(capture), Capture.send);
    return c;
}

test "SONNY-6486 STREAM_DATA_BLOCKED is ack-eliciting and answered with the current MAX_STREAM_DATA" {
    var alloc = testing.allocator;
    var capture = Capture{ .alloc = alloc };
    defer capture.deinit();
    const c = try serverConn(&alloc, &capture);
    defer {
        c.deinit();
        alloc.destroy(c);
    }

    try c.pushStreamFrame(4, 0, "hello", false);
    const rx = c.streams_rx.getPtr(4).?;
    const advertised = capture.maxStreamData(0, 4).?;
    // The application consumed more; the larger limit is below the
    // 32 KiB update threshold, so it was not sent on its own.
    rx.local_max_stream_data += 1000;

    const mark = capture.sent.items.len;
    const test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{} };
    var ctx = frame_handler.FrameContext{
        .conn = c,
        .allocator = &alloc,
        .send_fn = struct {
            fn s(_: conn_mod.SockAddr, d: []const u8) anyerror!usize {
                return d.len;
            }
        }.s,
        .peer = .{},
        .space = .Application,
        .cfg = &test_cfg,
    };
    const r = try frame_handler.processFrame(&ctx, .{ .stream_data_blocked = .{ .stream_id = 4, .limit = advertised } });
    try testing.expect(r.saw_ack_eliciting);
    try testing.expectEqual(@as(?u64, rx.local_max_stream_data), capture.maxStreamData(mark, 4));
}

test "SONNY-6486 ACK delay is encoded with our exponent, not the peer's" {
    var alloc = testing.allocator;
    var capture = Capture{ .alloc = alloc };
    defer capture.deinit();
    const c = try serverConn(&alloc, &capture);
    defer {
        c.deinit();
        alloc.destroy(c);
    }
    // Non-default on both sides: the peer advertised 10, we use 5.
    c.ack_delay_exponent = 10;
    c.local_ack_delay_exponent = 5;
    const now: u64 = 10_000_000_000;
    c.last_ack_eliciting_rx_app_ns = now - 8 * std.time.ns_per_ms;
    // 8000 us at 2^5 per unit (the peer decodes with our advertised 5).
    try testing.expectEqual(@as(u64, 8000 >> 5), c.getAckDelayEncoded(.Application, now));

    // Our exponent is advertised, so the peer decodes with it.
    const server_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{} };
    try handshake.setupServerTransportParams(c, &server_cfg, alloc);
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const tp = try transport_params.TransportParams.decode(arena.allocator(), c.getLocalTransportParams().?);
    try testing.expectEqual(@as(?u64, 5), tp.ack_delay_exponent);
}

test "SONNY-6486 the default exponent is not advertised and encodes as before" {
    var alloc = testing.allocator;
    var capture = Capture{ .alloc = alloc };
    defer capture.deinit();
    const c = try serverConn(&alloc, &capture);
    defer {
        c.deinit();
        alloc.destroy(c);
    }
    c.ack_delay_exponent = 10; // the peer's choice does not change ours
    const now: u64 = 10_000_000_000;
    c.last_ack_eliciting_rx_app_ns = now - 8 * std.time.ns_per_ms;
    try testing.expectEqual(@as(u64, 8000 >> 3), c.getAckDelayEncoded(.Application, now));
}
