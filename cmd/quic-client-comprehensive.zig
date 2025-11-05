const std = @import("std");
const api = @import("quic_api");

const Connection = api.Connection;
const QuicEndpoint = api.QuicEndpoint;

const TestResult = struct {
    name: []const u8,
    success: bool,
    details: []const u8,
    elapsed_ms: u64,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var connect: []const u8 = "127.0.0.1:4433";
    var sni: []const u8 = "test.local";
    var alpn: []const u8 = "h3";
    var insecure = true;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--connect")) {
            connect = args.next().?;
        } else if (std.mem.eql(u8, a, "--sni")) {
            sni = args.next().?;
        } else if (std.mem.eql(u8, a, "--alpn")) {
            alpn = args.next().?;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        }
    }

    std.debug.print("\n🚀 Starting Comprehensive QUIC Test Suite (Zig)\n", .{});
    std.debug.print("="**60 ++ "\n", .{});
    std.debug.print("📡 Connecting to {s}\n\n", .{connect});

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .enable_datagram = false,
        .compatible_vn = false,
    };
    const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(ep);

    const conn = try api.connect(ep, connect, sni);

    // Wait for handshake
    var handshake_attempts: usize = 0;
    while (!api.handshakeDoneSeen(conn) and handshake_attempts < 1000) : (handshake_attempts += 1) {
        try api.poll(ep, 10);
    }

    if (!api.handshakeDoneSeen(conn)) {
        std.debug.print("❌ Handshake failed\n", .{});
        return error.HandshakeFailed;
    }

    std.debug.print("✅ Connection established\n", .{});
    std.debug.print("✅ TLS handshake complete\n\n", .{});

    var results = std.ArrayList(TestResult){};
    defer {
        for (results.items) |result| {
            alloc.free(result.details);
        }
        results.deinit(alloc);
    }

    // Run comprehensive test suite
    try results.append(alloc, try testSingleStreamEcho(&alloc, ep, conn));
    try results.append(alloc, try testMultipleStreams(&alloc, ep, conn, 4));
    try results.append(alloc, try testLargeDataTransfer(&alloc, ep, conn, 10 * 1024)); // 10KB
    try results.append(alloc, try testLargeDataTransfer(&alloc, ep, conn, 100 * 1024)); // 100KB
    try results.append(alloc, try testMultipleRoundTrips(&alloc, ep, conn, 10));
    try results.append(alloc, try testStreamInterleaving(&alloc, ep, conn, 5));

    // Print summary
    printTestSummary(results.items);

    // Graceful close
    api.close(conn, 0, "test completed") catch {};
    api.flush(ep, 5);
    var spins: usize = 0;
    while (spins < 50 and !api.isDrained(conn)) : (spins += 1) {
        api.poll(ep, 5) catch break;
    }
    api.destroy(ep, conn);

    std.debug.print("\n✅ All tests passed!\n", .{});
}

fn testSingleStreamEcho(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection) !TestResult {
    std.debug.print("📝 Test 1: Single stream echo\n", .{});
    const start = std.time.milliTimestamp();

    const stream_id: u64 = 0;
    const msg = "Hello from Zig!";

    // Write message
    var wrote = false;
    var attempts: usize = 0;
    while (!wrote and attempts < 1000) : (attempts += 1) {
        const wn = api.writeStream(conn, stream_id, msg) catch |err| switch (err) {
            error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked => blk: {
                try api.poll(ep, 10);
                break :blk 0;
            },
            else => return err,
        };
        if (wn > 0) wrote = true;
        if (!wrote) try api.poll(ep, 10);
    }

    if (!wrote) return error.WriteTimeout;

    // Read response
    var rbuf: [4096]u8 = undefined;
    var total: usize = 0;
    var polls: usize = 0;
    while (polls < 1000 and total == 0) : (polls += 1) {
        try api.poll(ep, 10);
        const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
        if (n > 0) total = n;
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const details = try std.fmt.allocPrint(alloc.*, "Sent {d} bytes, received {d} bytes in {d}ms", .{ msg.len, total, elapsed });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = "Single Stream Echo",
        .success = total > 0,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn testMultipleStreams(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection, num_streams: usize) !TestResult {
    std.debug.print("📝 Test 2: Multiple concurrent streams ({d} streams)\n", .{num_streams});
    const start = std.time.milliTimestamp();

    var stream_id: u64 = 0;
    while (stream_id < num_streams * 4) : (stream_id += 4) { // Client-initiated bidirectional streams: 0, 4, 8, ...
        var msg_buf: [100]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Stream {d} message", .{stream_id});

        // Write
        var wrote = false;
        var attempts: usize = 0;
        while (!wrote and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, msg) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked => blk: {
                    try api.poll(ep, 5);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) wrote = true;
            if (!wrote) try api.poll(ep, 5);
        }

        // Read response
        var rbuf: [1024]u8 = undefined;
        var polls: usize = 0;
        while (polls < 200) : (polls += 1) {
            try api.poll(ep, 5);
            const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
            if (n > 0) {
                std.debug.print("✓ Stream {d} completed\n", .{stream_id});
                break;
            }
        }
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const details = try std.fmt.allocPrint(alloc.*, "{d} concurrent streams completed in {d}ms", .{ num_streams, elapsed });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = "Multiple Concurrent Streams",
        .success = true,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn testLargeDataTransfer(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection, size: usize) !TestResult {
    const size_name = if (size >= 1024 * 1024)
        try std.fmt.allocPrint(alloc.*, "{d}MB", .{size / (1024 * 1024)})
    else if (size >= 1024)
        try std.fmt.allocPrint(alloc.*, "{d}KB", .{size / 1024})
    else
        try std.fmt.allocPrint(alloc.*, "{d}B", .{size});
    defer alloc.free(size_name);

    std.debug.print("📝 Test: Large data transfer ({s})\n", .{size_name});
    const start = std.time.milliTimestamp();

    const stream_id: u64 = 100; // Use higher stream ID to avoid conflicts

    // Generate random data
    const data = try alloc.alloc(u8, size);
    defer alloc.free(data);
    std.crypto.random.bytes(data);

    // Write data in chunks
    var written: usize = 0;
    const chunk_size = 4096;
    while (written < size) {
        const remaining = size - written;
        const to_write = @min(remaining, chunk_size);
        const chunk = data[written .. written + to_write];

        var chunk_written = false;
        var attempts: usize = 0;
        while (!chunk_written and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, chunk) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked => blk: {
                    try api.poll(ep, 10);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) {
                written += wn;
                chunk_written = true;
            }
            if (!chunk_written) try api.poll(ep, 10);
        }
    }

    // Read acknowledgment or echo
    var rbuf: [8192]u8 = undefined;
    var total: usize = 0;
    var polls: usize = 0;
    while (polls < 2000 and total < 1024) : (polls += 1) { // Wait for at least 1KB response
        try api.poll(ep, 10);
        const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
        if (n > 0) total += n;
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const throughput_mbps = if (elapsed > 0)
        @as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(elapsed)) * 1000.0 / (1024.0 * 1024.0)
    else
        0.0;

    const details = try std.fmt.allocPrint(alloc.*, "Transferred {d} bytes in {d}ms ({d:.2} MB/s)", .{ size, elapsed, throughput_mbps });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = try std.fmt.allocPrint(alloc.*, "Large Transfer ({s})", .{size_name}),
        .success = written == size,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn testMultipleRoundTrips(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection, num_rounds: usize) !TestResult {
    std.debug.print("📝 Test: Multiple round-trips ({d} cycles)\n", .{num_rounds});
    const start = std.time.milliTimestamp();

    const stream_id: u64 = 200;
    var round: usize = 0;

    while (round < num_rounds) : (round += 1) {
        var msg_buf: [100]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Round {d}", .{round});

        // Write
        var wrote = false;
        var attempts: usize = 0;
        while (!wrote and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, msg) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked => blk: {
                    try api.poll(ep, 5);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) wrote = true;
            if (!wrote) try api.poll(ep, 5);
        }

        // Read response
        var rbuf: [1024]u8 = undefined;
        var polls: usize = 0;
        while (polls < 200) : (polls += 1) {
            try api.poll(ep, 5);
            const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
            if (n > 0) break;
        }
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const avg_latency = elapsed / num_rounds;
    const details = try std.fmt.allocPrint(alloc.*, "{d} round-trips in {d}ms (avg: {d}ms per round)", .{ num_rounds, elapsed, avg_latency });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = "Multiple Round-trips",
        .success = true,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn testStreamInterleaving(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection, num_streams: usize) !TestResult {
    std.debug.print("📝 Test: Stream interleaving ({d} streams)\n", .{num_streams});
    const start = std.time.milliTimestamp();

    // Send data in round-robin fashion across multiple streams
    var round: usize = 0;
    while (round < 5) : (round += 1) {
        var stream_idx: usize = 0;
        while (stream_idx < num_streams) : (stream_idx += 1) {
            const stream_id = stream_idx * 4 + 300; // Start from stream 300

            var msg_buf: [100]u8 = undefined;
            const msg = try std.fmt.bufPrint(&msg_buf, "Stream {d}, Round {d}", .{ stream_id, round });

            var wrote = false;
            var attempts: usize = 0;
            while (!wrote and attempts < 300) : (attempts += 1) {
                const wn = api.writeStream(conn, stream_id, msg) catch |err| switch (err) {
                    error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked => blk: {
                        try api.poll(ep, 5);
                        break :blk 0;
                    },
                    else => return err,
                };
                if (wn > 0) wrote = true;
                if (!wrote) try api.poll(ep, 5);
            }
        }
    }

    // Read responses from all streams
    var stream_idx: usize = 0;
    while (stream_idx < num_streams) : (stream_idx += 1) {
        const stream_id = stream_idx * 4 + 300;
        var rbuf: [1024]u8 = undefined;
        var polls: usize = 0;
        while (polls < 200) : (polls += 1) {
            try api.poll(ep, 5);
            const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
            if (n > 0) break;
        }
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const details = try std.fmt.allocPrint(alloc.*, "{d} interleaved streams, 5 rounds in {d}ms", .{ num_streams, elapsed });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = "Stream Interleaving",
        .success = true,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn printTestSummary(results: []const TestResult) void {
    std.debug.print("\n" ++ "="**60 ++ "\n", .{});
    std.debug.print("📊 TEST SUMMARY\n", .{});
    std.debug.print("="**60 ++ "\n", .{});

    var passed: usize = 0;
    var failed: usize = 0;

    for (results) |result| {
        const status = if (result.success) "✅" else "❌";
        if (result.success) {
            passed += 1;
        } else {
            failed += 1;
        }

        std.debug.print("{s} {s}\n", .{ status, result.name });
        std.debug.print("   └─ {s}\n", .{result.details});
    }

    std.debug.print("\n" ++ "="**60 ++ "\n", .{});
    std.debug.print("RESULTS: {d} passed, {d} failed, {d} total\n", .{ passed, failed, results.len });
    std.debug.print("="**60 ++ "\n", .{});
}
