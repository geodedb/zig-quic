// SONNY-6737: every paced datagram is sent exactly once when a batched send
// is only partly accepted.
//
// The endpoint queues paced datagrams in timers and, when they expire, hands
// up to 16 of them to `Transport.sendBatch` at once (`processExpiredTimers`).
// `sendBatch` returns how many it sent. The endpoint ignored that count: the
// datagrams past it were freed unsent although their packet numbers were
// used, and when `sendBatch` failed after sending some, the endpoint's
// per-packet fallback sent the whole batch again. `UdpTransport.sendBatch`
// failed outright when a later `sendmmsg` chunk failed after earlier chunks
// went out, so its caller could not tell which ones had.
//
// The datagrams below go through the real paced-send path: a client
// connection's `send` -> `senderPaced` -> `schedulePaced` timer ->
// `processExpiredTimers` -> `Transport.sendBatch`.
const std = @import("std");
const compat = @import("compat");
const cfg_mod = @import("quic_config");
const conn_mod = @import("quic_conn");
const endpoint_mod = @import("quic_endpoint");
const transport_mod = @import("quic_endpoint_transport");
const udp_mod = @import("quic_udp_transport");

const Endpoint = endpoint_mod.Endpoint;
const Transport = transport_mod.Transport;
const SendBatchItem = transport_mod.SendBatchItem;
const SockAddr = conn_mod.SockAddr;
const RecvResult = transport_mod.RecvResult;

const magic: u8 = 0xA5;
const datagram_len: usize = 64;
const max_datagrams: usize = 32;

/// Datagram `idx` of a test: `magic`, its index, then filler.
fn fillDatagram(buf: []u8, idx: usize) void {
    @memset(buf, 0x5A);
    buf[0] = magic;
    buf[1] = @intCast(idx);
}

/// Records which test datagrams a transport sent, and in what order.
const Ledger = struct {
    counts: [max_datagrams]usize = [_]usize{0} ** max_datagrams,
    order: [4 * max_datagrams]u8 = undefined,
    order_len: usize = 0,

    fn record(self: *Ledger, data: []const u8) void {
        if (data.len != datagram_len or data[0] != magic) return; // not a test datagram
        const idx = data[1];
        self.counts[idx] += 1;
        if (self.order_len < self.order.len) {
            self.order[self.order_len] = idx;
            self.order_len += 1;
        }
    }

    fn expectEachOnceInOrder(self: *const Ledger, n: usize) !void {
        for (self.counts[0..n], 0..) |count, idx| {
            if (count != 1) {
                std.debug.print("datagram {d} sent {d} times (want exactly 1); order={any}\n", .{ idx, count, self.order[0..self.order_len] });
                return error.DatagramNotSentExactlyOnce;
            }
        }
        try std.testing.expectEqual(n, self.order_len);
        for (self.order[0..self.order_len], 0..) |idx, pos| {
            try std.testing.expectEqual(@as(u8, @intCast(pos)), idx);
        }
    }
};

fn recvNothing(_: *anyopaque, _: []u8) anyerror!RecvResult {
    return error.WouldBlock;
}
fn pollNothing(_: *anyopaque, _: i32) anyerror!void {}
fn closeNothing(_: *anyopaque) void {}
fn noLocalAddr(_: *anyopaque) anyerror!SockAddr {
    return error.Unsupported;
}

/// A transport whose batched send accepts the first `accept_first` datagrams
/// of the first batch only, as `sendmmsg` does when the socket buffer fills
/// mid-batch (EAGAIN after some messages went out). Later batches go out
/// whole.
const PartialBatchTransport = struct {
    ledger: Ledger = .{},
    accept_first: usize,
    batch_calls: usize = 0,

    fn sendFn(ctx: *anyopaque, _: SockAddr, data: []const u8) anyerror!usize {
        const self: *PartialBatchTransport = @ptrCast(@alignCast(ctx));
        self.ledger.record(data);
        return data.len;
    }

    fn sendBatchFn(ctx: *anyopaque, items: []const SendBatchItem) anyerror!usize {
        const self: *PartialBatchTransport = @ptrCast(@alignCast(ctx));
        self.batch_calls += 1;
        const accepted = if (self.batch_calls == 1) @min(self.accept_first, items.len) else items.len;
        for (items[0..accepted]) |it| self.ledger.record(it.data);
        return accepted;
    }

    fn transport(self: *PartialBatchTransport) Transport {
        return .{
            .sendFn = sendFn,
            .sendBatchFn = sendBatchFn,
            .recvFn = recvNothing,
            .pollFn = pollNothing,
            .closeFn = closeNothing,
            .getLocalAddrFn = noLocalAddr,
            .context = @ptrCast(self),
        };
    }
};

/// A transport with no batched send of its own, so `Transport.sendBatch`
/// sends the batch one datagram at a time. The second test datagram it is
/// handed fails once with WouldBlock (a full socket buffer); everything else
/// goes out.
const SecondSendBlocksTransport = struct {
    ledger: Ledger = .{},
    test_sends: usize = 0,

    fn sendFn(ctx: *anyopaque, _: SockAddr, data: []const u8) anyerror!usize {
        const self: *SecondSendBlocksTransport = @ptrCast(@alignCast(ctx));
        if (data.len == datagram_len and data[0] == magic) {
            self.test_sends += 1;
            if (self.test_sends == 2) return error.WouldBlock;
        }
        self.ledger.record(data);
        return data.len;
    }

    fn transport(self: *SecondSendBlocksTransport) Transport {
        return .{
            .sendFn = sendFn,
            .recvFn = recvNothing,
            .pollFn = pollNothing,
            .closeFn = closeNothing,
            .getLocalAddrFn = noLocalAddr,
            .context = @ptrCast(self),
        };
    }
};

fn pacingConfig() cfg_mod.QuicConfig {
    var cfg = cfg_mod.QuicConfig{ .alpn = &[_][]const u8{} };
    cfg.enable_pacing = true;
    return cfg;
}

/// A client connection whose sends are all paced: cwnd more than half full
/// with a 50 ms smoothed RTT gives a pacing delay well above the 10 us
/// inline-send threshold of `senderPaced`.
fn pacedClient(ep: *Endpoint, peer: ?SockAddr) !*conn_mod.Connection {
    const c = try ep.connectClient("127.0.0.1:9");
    if (peer) |p| c.peer = p;
    c.address_validated = true;
    c.rec.cc.cwnd = 1_000_000;
    c.rec.cc.bytes_in_flight = 900_000;
    c.rec.rtt.smoothed_rtt_ns = 50 * std.time.ns_per_ms;
    c.rec.refreshAtomicMirrors();
    return c;
}

fn pacedTimerCount(ep: *Endpoint) usize {
    var n: usize = 0;
    for (ep.timers.items) |t| {
        if (t.paced) n += 1;
    }
    return n;
}

/// Expire the endpoint's timers until no paced datagram is left queued.
fn drainPaced(ep: *Endpoint) !void {
    var rounds: usize = 0;
    while (pacedTimerCount(ep) > 0) : (rounds += 1) {
        if (rounds == 16) return error.PacedDatagramsNeverSent;
        ep.forceExpireAllTimers();
    }
}

fn queueTestDatagrams(c: *conn_mod.Connection, ep: *Endpoint, n: usize) !void {
    var buf: [datagram_len]u8 = undefined;
    for (0..n) |idx| {
        fillDatagram(&buf, idx);
        try std.testing.expectEqual(buf.len, try c.send(&buf));
    }
    // All of them are waiting in paced timers, none sent yet.
    try std.testing.expectEqual(n, pacedTimerCount(ep));
}

test "paced datagrams past a partial sendBatch stay queued and go out once" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    var alloc = gpa.allocator();
    const cfg = pacingConfig();

    var backend = PartialBatchTransport{ .accept_first = 3 };
    var ep = try Endpoint.initWithTransport(&alloc, backend.transport(), &cfg, .Client);
    defer ep.deinit();
    const c = try pacedClient(&ep, null);

    const n: usize = 8;
    try queueTestDatagrams(c, &ep, n);

    ep.forceExpireAllTimers();
    // The first batch took 3 of the 8. The other 5 are still queued.
    try std.testing.expectEqual(@as(usize, 1), backend.batch_calls);
    try std.testing.expectEqual(n - 3, pacedTimerCount(&ep));

    try drainPaced(&ep);
    try backend.ledger.expectEachOnceInOrder(n);
}

test "a send failing mid-batch does not make the endpoint send the batch again" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    var alloc = gpa.allocator();
    const cfg = pacingConfig();

    var backend = SecondSendBlocksTransport{};
    var ep = try Endpoint.initWithTransport(&alloc, backend.transport(), &cfg, .Client);
    defer ep.deinit();
    const c = try pacedClient(&ep, null);

    const n: usize = 8;
    try queueTestDatagrams(c, &ep, n);

    ep.forceExpireAllTimers();
    // Datagram 0 went out, datagram 1 hit a full buffer: 1..7 stay queued.
    try std.testing.expectEqual(n - 1, pacedTimerCount(&ep));

    try drainPaced(&ep);
    try backend.ledger.expectEachOnceInOrder(n);
}

/// Receive test datagrams on `rx` until `quiet_ms` pass with nothing new.
fn receiveTestDatagrams(rx: *Transport, ledger: *Ledger, quiet_ms: i64) !void {
    var bufs: [16][datagram_len + 16]u8 = undefined;
    var slots: [16]transport_mod.RecvBatchSlot = undefined;
    for (&slots, 0..) |*slot, i| slot.* = .{ .buf = bufs[i][0..], .n = 0, .peer = .{}, .ecn = null };
    var last_rx = compat.milliTimestamp();
    while (compat.milliTimestamp() - last_rx < quiet_ms) {
        const got = rx.recvBatch(slots[0..]) catch |err| switch (err) {
            error.WouldBlock => {
                compat.threadSleep(std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        for (slots[0..got]) |slot| ledger.record(slot.buf[0..slot.n]);
        if (got > 0) last_rx = compat.milliTimestamp();
    }
}

test "UdpTransport.sendBatch returns the count sent when a later sendmmsg chunk fails" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var rx_impl = try udp_mod.UdpTransport.init("127.0.0.1:0");
    defer rx_impl.deinit();
    var tx_impl = try udp_mod.UdpTransport.init("127.0.0.1:0");
    defer tx_impl.deinit();
    var rx = rx_impl.asTransport();
    var tx = tx_impl.asTransport();
    const rx_addr = try rx.getLocalAddr();

    // The first sendmmsg chunk is UdpBatchCap datagrams. The first datagram
    // of the second chunk is larger than any UDP datagram, so that sendmmsg
    // fails (EMSGSIZE) with nothing of its chunk sent.
    const chunk = udp_mod.UdpBatchCap;
    const total = chunk + 6;
    const good = try alloc.alloc([datagram_len]u8, total);
    defer alloc.free(good);
    const oversized = try alloc.alloc(u8, 70_000);
    defer alloc.free(oversized);
    @memset(oversized, 0);
    const items = try alloc.alloc(SendBatchItem, total);
    defer alloc.free(items);
    for (items, 0..) |*it, idx| {
        // Index wraps at max_datagrams; only the first chunk is checked by index.
        fillDatagram(&good[idx], idx % max_datagrams);
        it.* = .{ .peer = rx_addr, .data = if (idx == chunk) oversized else good[idx][0..] };
    }

    const sent = try tx.sendBatch(items);
    try std.testing.expectEqual(chunk, sent);

    // Exactly the first chunk arrived: 64 datagrams, each index 0..31 twice.
    var ledger = Ledger{};
    try receiveTestDatagrams(&rx, &ledger, 200);
    for (ledger.counts) |count| try std.testing.expectEqual(chunk / max_datagrams, count);
}

test "paced datagrams over a real UDP socket survive a partial sendmmsg" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    var alloc = gpa.allocator();
    const cfg = pacingConfig();

    var rx_impl = try udp_mod.UdpTransport.init("127.0.0.1:0");
    defer rx_impl.deinit();
    var tx_impl = try udp_mod.UdpTransport.init("127.0.0.1:0");
    defer tx_impl.deinit();
    var rx = rx_impl.asTransport();
    const rx_addr = try rx.getLocalAddr();

    var ep = try Endpoint.initWithTransport(&alloc, tx_impl.asTransport(), &cfg, .Client);
    defer ep.deinit();
    const c = try pacedClient(&ep, rx_addr);

    // Datagrams 0..2, then one larger than any UDP datagram, then 3..7. The
    // kernel's sendmmsg sends 0..2 and stops at the oversized one (EMSGSIZE),
    // returning 3: a real partial batch. The oversized datagram can never be
    // sent; 3..7 must still go out, once each.
    var buf: [datagram_len]u8 = undefined;
    const oversized = try alloc.alloc(u8, 70_000);
    defer alloc.free(oversized);
    @memset(oversized, 0);
    for (0..3) |idx| {
        fillDatagram(&buf, idx);
        _ = try c.send(&buf);
    }
    _ = try c.send(oversized);
    for (3..8) |idx| {
        fillDatagram(&buf, idx);
        _ = try c.send(&buf);
    }
    try std.testing.expectEqual(@as(usize, 9), pacedTimerCount(&ep));

    try drainPaced(&ep);

    var ledger = Ledger{};
    try receiveTestDatagrams(&rx, &ledger, 200);
    try ledger.expectEachOnceInOrder(8);
}
