//! Loopback Transport for Integration Testing
//!
//! Provides in-memory packet delivery between endpoints without using real UDP sockets.
//! Supports:
//! - Queue-based packet exchange
//! - Configurable packet loss
//! - Configurable packet reordering
//! - Configurable packet delay
//! - MTU simulation
//! - ECN marking support
//!
//! RFC References:
//! - RFC 9000 §14: Datagram Size
//! - RFC 9000 §13.4: Explicit Congestion Notification

const std = @import("std");

/// Loopback transport for testing
pub const LoopbackTransport = struct {
    /// Allocator for packet buffers
    allocator: std.mem.Allocator,

    /// Queue of packets from A to B
    queue_a_to_b: PacketQueue,

    /// Queue of packets from B to A
    queue_b_to_a: PacketQueue,

    /// Transport configuration
    config: Config,

    /// Random number generator for loss/corruption
    prng: std.Random.DefaultPrng,

    /// Statistics
    stats: Stats,

    /// Optional capture callback for packets sent by SideA (client)
    capture_a_send_fn: ?*const fn (data: []const u8, timestamp_ms: i64, user_data: ?*anyopaque) void = null,

    /// Optional capture callback for packets sent by SideB (server)
    capture_b_send_fn: ?*const fn (data: []const u8, timestamp_ms: i64, user_data: ?*anyopaque) void = null,

    /// User data for capture callbacks
    capture_user_data: ?*anyopaque = null,

    /// Configuration for loopback transport
    pub const Config = struct {
        /// Packet loss rate (0.0 to 1.0)
        loss_rate: f64 = 0.0,

        /// Packet corruption rate (0.0 to 1.0)
        corruption_rate: f64 = 0.0,

        /// Packet reordering probability (0.0 to 1.0)
        reordering_rate: f64 = 0.0,

        /// Base delay in milliseconds
        delay_ms: u32 = 0,

        /// Delay jitter in milliseconds
        jitter_ms: u32 = 0,

        /// Maximum transmission unit
        mtu: u16 = 1500,

        /// Enable ECN marking
        enable_ecn: bool = false,
    };

    /// Transport statistics
    pub const Stats = struct {
        packets_sent: u64 = 0,
        packets_received: u64 = 0,
        packets_lost: u64 = 0,
        packets_corrupted: u64 = 0,
        packets_reordered: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
    };

    /// Initialize loopback transport
    pub fn init(allocator: std.mem.Allocator, config: Config) !*LoopbackTransport {
        const self = try allocator.create(LoopbackTransport);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .queue_a_to_b = try PacketQueue.init(allocator),
            .queue_b_to_a = try PacketQueue.init(allocator),
            .config = config,
            .prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
            .stats = .{},
            .capture_a_send_fn = null,
            .capture_b_send_fn = null,
            .capture_user_data = null,
        };

        return self;
    }

    /// Clean up loopback transport
    pub fn deinit(self: *LoopbackTransport) void {
        self.queue_a_to_b.deinit();
        self.queue_b_to_a.deinit();
        self.allocator.destroy(self);
    }

    /// Send packet from endpoint A to endpoint B
    pub fn sendAtoB(self: *LoopbackTransport, data: []const u8) !void {
        // Capture if callback is registered
        if (self.capture_a_send_fn) |capture_fn| {
            capture_fn(data, std.time.milliTimestamp(), self.capture_user_data);
        }
        try self.send(&self.queue_a_to_b, data);
    }

    /// Send packet from endpoint B to endpoint A
    pub fn sendBtoA(self: *LoopbackTransport, data: []const u8) !void {
        // Capture if callback is registered
        if (self.capture_b_send_fn) |capture_fn| {
            capture_fn(data, std.time.milliTimestamp(), self.capture_user_data);
        }
        try self.send(&self.queue_b_to_a, data);
    }

    /// Receive packet at endpoint A (from B)
    pub fn recvAtA(self: *LoopbackTransport, buffer: []u8) !?usize {
        return self.recv(&self.queue_b_to_a, buffer);
    }

    /// Receive packet at endpoint B (from A)
    pub fn recvAtB(self: *LoopbackTransport, buffer: []u8) !?usize {
        return self.recv(&self.queue_a_to_b, buffer);
    }

    /// Internal send implementation
    fn send(self: *LoopbackTransport, queue: *PacketQueue, data: []const u8) !void {
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += data.len;

        // Check MTU
        if (data.len > self.config.mtu) {
            return error.PacketTooLarge;
        }

        // Simulate packet loss
        if (self.config.loss_rate > 0.0) {
            const rand_val = self.prng.random().float(f64);
            if (rand_val < self.config.loss_rate) {
                self.stats.packets_lost += 1;
                return; // Packet lost
            }
        }

        // Simulate packet corruption
        var corrupted = false;
        if (self.config.corruption_rate > 0.0) {
            const rand_val = self.prng.random().float(f64);
            if (rand_val < self.config.corruption_rate) {
                corrupted = true;
                self.stats.packets_corrupted += 1;
            }
        }

        // Calculate delivery time
        const base_delay = self.config.delay_ms;
        const jitter = if (self.config.jitter_ms > 0)
            self.prng.random().uintLessThan(u32, self.config.jitter_ms)
        else
            0;
        const delivery_time_ms = std.time.milliTimestamp() + base_delay + jitter;

        // Create packet
        var pkt_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(pkt_data);

        // Apply corruption if selected
        if (corrupted and pkt_data.len > 0) {
            const corrupt_idx = self.prng.random().uintLessThan(usize, pkt_data.len);
            pkt_data[corrupt_idx] ^= 0xFF; // Flip all bits in one byte
        }

        const packet = Packet{
            .data = pkt_data,
            .delivery_time_ms = delivery_time_ms,
            .ecn = if (self.config.enable_ecn) .Ect0 else .NotEct,
        };

        try queue.enqueue(packet);
    }

    /// Internal receive implementation
    fn recv(self: *LoopbackTransport, queue: *PacketQueue, buffer: []u8) !?usize {
        const now = std.time.milliTimestamp();

        // Check if packet is ready for delivery
        const packet = queue.peek() orelse return null;
        if (packet.delivery_time_ms > now) {
            return null; // Not ready yet
        }

        // Dequeue and deliver
        const pkt = try queue.dequeue() orelse return null;
        defer self.allocator.free(pkt.data);

        if (pkt.data.len > buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(buffer[0..pkt.data.len], pkt.data);

        self.stats.packets_received += 1;
        self.stats.bytes_received += pkt.data.len;

        return pkt.data.len;
    }

    /// Get number of packets in flight from A to B
    pub fn getAtoBQueueLen(self: *const LoopbackTransport) usize {
        return self.queue_a_to_b.len();
    }

    /// Get number of packets in flight from B to A
    pub fn getBtoAQueueLen(self: *const LoopbackTransport) usize {
        return self.queue_b_to_a.len();
    }

    /// Clear all packets in flight (for cleanup)
    pub fn clearAll(self: *LoopbackTransport) void {
        self.queue_a_to_b.clear();
        self.queue_b_to_a.clear();
    }
};

/// Packet in the queue
const Packet = struct {
    /// Packet data
    data: []u8,

    /// When packet should be delivered (simulated delay)
    delivery_time_ms: i64,

    /// ECN marking
    ecn: EcnCodepoint,
};

/// ECN codepoints (RFC 3168)
pub const EcnCodepoint = enum(u2) {
    NotEct = 0b00,
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
};

/// Packet queue with FIFO semantics
pub const PacketQueue = struct {
    /// Queue of packets
    packets: std.ArrayList(Packet),

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize packet queue
    pub fn init(allocator: std.mem.Allocator) !PacketQueue {
        return .{
            .packets = std.ArrayList(Packet){},
            .allocator = allocator,
        };
    }

    /// Clean up packet queue
    pub fn deinit(self: *PacketQueue) void {
        for (self.packets.items) |pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.deinit(self.allocator);
    }

    /// Add packet to queue
    pub fn enqueue(self: *PacketQueue, packet: Packet) !void {
        try self.packets.append(self.allocator, packet);
    }

    /// Remove and return next packet (if delivery time has passed)
    pub fn dequeue(self: *PacketQueue) !?Packet {
        if (self.packets.items.len == 0) {
            return null;
        }

        const pkt = self.packets.orderedRemove(0);
        return pkt;
    }

    /// Peek at next packet without removing
    pub fn peek(self: *const PacketQueue) ?*const Packet {
        if (self.packets.items.len == 0) {
            return null;
        }
        return &self.packets.items[0];
    }

    /// Get number of packets in queue
    pub fn len(self: *const PacketQueue) usize {
        return self.packets.items.len;
    }

    /// Clear all packets
    pub fn clear(self: *PacketQueue) void {
        for (self.packets.items) |pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.clearRetainingCapacity();
    }
};

// Tests

test "LoopbackTransport - basic send/receive" {
    const allocator = std.testing.allocator;

    const config = LoopbackTransport.Config{};
    var transport = try LoopbackTransport.init(allocator, config);
    defer transport.deinit();

    // Send packet from A to B
    const send_data = "Hello, QUIC!";
    try transport.sendAtoB(send_data);

    // Receive at B
    var recv_buf: [256]u8 = undefined;
    const recv_len = try transport.recvAtB(&recv_buf);

    try std.testing.expect(recv_len != null);
    try std.testing.expectEqualSlices(u8, send_data, recv_buf[0..recv_len.?]);
}

test "LoopbackTransport - bidirectional communication" {
    const allocator = std.testing.allocator;

    const config = LoopbackTransport.Config{};
    var transport = try LoopbackTransport.init(allocator, config);
    defer transport.deinit();

    // A -> B
    try transport.sendAtoB("A to B");
    // B -> A
    try transport.sendBtoA("B to A");

    // Receive at B
    var recv_buf: [256]u8 = undefined;
    const b_recv = try transport.recvAtB(&recv_buf);
    try std.testing.expect(b_recv != null);
    try std.testing.expectEqualSlices(u8, "A to B", recv_buf[0..b_recv.?]);

    // Receive at A
    const a_recv = try transport.recvAtA(&recv_buf);
    try std.testing.expect(a_recv != null);
    try std.testing.expectEqualSlices(u8, "B to A", recv_buf[0..a_recv.?]);
}

test "LoopbackTransport - packet loss simulation" {
    const allocator = std.testing.allocator;

    const config = LoopbackTransport.Config{
        .loss_rate = 1.0, // 100% loss
    };
    var transport = try LoopbackTransport.init(allocator, config);
    defer transport.deinit();

    // Send packet (should be lost)
    try transport.sendAtoB("Lost packet");

    // Try to receive (should get nothing)
    var recv_buf: [256]u8 = undefined;
    const recv_len = try transport.recvAtB(&recv_buf);

    try std.testing.expect(recv_len == null);
    try std.testing.expectEqual(@as(u64, 1), transport.stats.packets_lost);
}

test "LoopbackTransport - MTU enforcement" {
    const allocator = std.testing.allocator;

    const config = LoopbackTransport.Config{
        .mtu = 100, // Small MTU
    };
    var transport = try LoopbackTransport.init(allocator, config);
    defer transport.deinit();

    // Try to send packet larger than MTU
    const large_data = try allocator.alloc(u8, 200);
    defer allocator.free(large_data);

    const result = transport.sendAtoB(large_data);
    try std.testing.expectError(error.PacketTooLarge, result);
}

test "LoopbackTransport - statistics tracking" {
    const allocator = std.testing.allocator;

    const config = LoopbackTransport.Config{};
    var transport = try LoopbackTransport.init(allocator, config);
    defer transport.deinit();

    // Send and receive some packets
    try transport.sendAtoB("packet1");
    try transport.sendAtoB("packet2");

    var recv_buf: [256]u8 = undefined;
    _ = try transport.recvAtB(&recv_buf);
    _ = try transport.recvAtB(&recv_buf);

    try std.testing.expectEqual(@as(u64, 2), transport.stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 2), transport.stats.packets_received);
    try std.testing.expectEqual(@as(u64, 14), transport.stats.bytes_sent); // "packet1" + "packet2"
}

test "PacketQueue - FIFO ordering" {
    const allocator = std.testing.allocator;

    var queue = try PacketQueue.init(allocator);
    defer queue.deinit();

    // Enqueue packets
    const data1 = try allocator.dupe(u8, "first");
    const data2 = try allocator.dupe(u8, "second");
    const data3 = try allocator.dupe(u8, "third");

    try queue.enqueue(.{ .data = data1, .delivery_time_ms = 0, .ecn = .NotEct });
    try queue.enqueue(.{ .data = data2, .delivery_time_ms = 0, .ecn = .NotEct });
    try queue.enqueue(.{ .data = data3, .delivery_time_ms = 0, .ecn = .NotEct });

    try std.testing.expectEqual(@as(usize, 3), queue.len());

    // Dequeue in FIFO order
    const pkt1 = try queue.dequeue();
    try std.testing.expectEqualSlices(u8, "first", pkt1.?.data);
    allocator.free(pkt1.?.data);

    const pkt2 = try queue.dequeue();
    try std.testing.expectEqualSlices(u8, "second", pkt2.?.data);
    allocator.free(pkt2.?.data);

    const pkt3 = try queue.dequeue();
    try std.testing.expectEqualSlices(u8, "third", pkt3.?.data);
    allocator.free(pkt3.?.data);

    try std.testing.expectEqual(@as(usize, 0), queue.len());
}
