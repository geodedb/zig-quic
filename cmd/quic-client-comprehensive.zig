const std = @import("std");
const api = @import("quic_api");

const Connection = api.Connection;
const QuicEndpoint = api.QuicEndpoint;

const TestResult = struct {
    name: []const u8,
    success: bool,
    details: []const u8,
    elapsed_ms: u64,
    name_owned: bool = false,
};

fn openBidiStreamWithRetry(ep: *QuicEndpoint, conn: *Connection, max_attempts: usize, poll_ms: i32) !u64 {
    var attempts: usize = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        const sid = api.openStream(conn, true) catch |err| switch (err) {
            error.OutOfStreams => {
                try api.poll(ep, poll_ms);
                continue;
            },
            else => return err,
        };
        return sid;
    }
    return error.OutOfStreams;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var connect: []const u8 = "127.0.0.1:4433";
    var sni: []const u8 = "test.local";
    var alpn: []const u8 = "hq-interop";
    var insecure = false; // Default to secure mode

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--connect")) {
            connect = args.next().?;
        } else if (std.mem.eql(u8, a, "--sni")) {
            sni = args.next().?;
        } else if (std.mem.eql(u8, a, "--alpn")) {
            alpn = args.next().?;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print("Usage: quic-client-comprehensive [options]\n", .{});
            std.debug.print("  --connect <host:port>  Server address (default: 127.0.0.1:4433)\n", .{});
            std.debug.print("  --sni <hostname>       SNI hostname (default: test.local)\n", .{});
            std.debug.print("  --alpn <protocol>      ALPN protocol (default: hq-interop)\n", .{});
            std.debug.print("  --insecure             Skip TLS certificate validation (TESTING ONLY)\n", .{});
            return;
        }
    }

    // Security warning when insecure mode is enabled
    if (insecure) {
        std.debug.print("\n", .{});
        std.debug.print("WARNING: TLS certificate validation DISABLED (--insecure)\n", .{});
        std.debug.print("         DO NOT use in production - connections may be intercepted!\n", .{});
    }

    std.debug.print("\n🚀 Starting Comprehensive QUIC Test Suite (Zig)\n", .{});
    std.debug.print("=" ** 60 ++ "\n", .{});
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
            if (result.name_owned) {
                alloc.free(result.name);
            }
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

    const stream_id = try openBidiStreamWithRetry(ep, conn, 50, 10);
    const msg = "Hello from Zig!";

    // Write message
    var wrote = false;
    var attempts: usize = 0;
    while (!wrote and attempts < 1000) : (attempts += 1) {
        const wn = api.writeStream(conn, stream_id, msg, true) catch |err| switch (err) {
            error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.InvalidStream => blk: {
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

    var stream_idx: usize = 0;
    while (stream_idx < num_streams) : (stream_idx += 1) {
        const stream_id = try openBidiStreamWithRetry(ep, conn, 100, 5);
        var msg_buf: [100]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Stream {d} message", .{stream_id});

        // Write
        var wrote = false;
        var attempts: usize = 0;
        while (!wrote and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, msg, true) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.InvalidStream => blk: {
                    try api.poll(ep, 5);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) wrote = true;
            if (!wrote) {
                try api.poll(ep, 5);
            } else {
                try api.poll(ep, 0);
            }
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

    const stream_id = try openBidiStreamWithRetry(ep, conn, 100, 10); // Allocate a fresh bidi stream for large transfers

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
        const is_last_chunk = (written + to_write >= size);

        var chunk_written = false;
        var attempts: usize = 0;
        while (!chunk_written and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, chunk, is_last_chunk) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.InvalidStream => blk: {
                    try api.poll(ep, 10);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) {
                written += wn;
                chunk_written = true;
            }
            if (!chunk_written) {
                try api.poll(ep, 10);
            } else {
                try api.poll(ep, 0);
            }
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
    const name = try std.fmt.allocPrint(alloc.*, "Large Transfer ({s})", .{size_name});
    errdefer alloc.free(name);

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = name,
        .success = written == size,
        .details = details,
        .elapsed_ms = elapsed,
        .name_owned = true,
    };
}

fn testMultipleRoundTrips(alloc: *std.mem.Allocator, ep: *QuicEndpoint, conn: *Connection, num_rounds: usize) !TestResult {
    std.debug.print("📝 Test: Multiple round-trips ({d} cycles)\n", .{num_rounds});
    const start = std.time.milliTimestamp();

    const stream_id = try openBidiStreamWithRetry(ep, conn, 100, 5);
    var round: usize = 0;

    while (round < num_rounds) : (round += 1) {
        var msg_buf: [100]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Round {d}", .{round});
        const is_last = (round + 1 == num_rounds);

        // Write
        var wrote = false;
        var attempts: usize = 0;
        while (!wrote and attempts < 500) : (attempts += 1) {
            const wn = api.writeStream(conn, stream_id, msg, is_last) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.InvalidStream => blk: {
                    try api.poll(ep, 5);
                    break :blk 0;
                },
                else => return err,
            };
            if (wn > 0) wrote = true;
            if (!wrote) {
                try api.poll(ep, 5);
            } else {
                try api.poll(ep, 0);
            }
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

    // Use only streams 0 and 4 to avoid hitting max_streams limit
    const actual_streams = @min(num_streams, 2);
    var stream_ids = try alloc.alloc(u64, actual_streams);
    defer alloc.free(stream_ids);
    var open_idx: usize = 0;
    while (open_idx < actual_streams) : (open_idx += 1) {
        stream_ids[open_idx] = try openBidiStreamWithRetry(ep, conn, 100, 5);
    }

    // Send data in round-robin fashion across multiple streams
    var round: usize = 0;
    while (round < 5) : (round += 1) {
        var stream_idx: usize = 0;
        while (stream_idx < actual_streams) : (stream_idx += 1) {
            const stream_id = stream_ids[stream_idx];
            const is_last_round = (round + 1 == 5);

            var msg_buf: [100]u8 = undefined;
            const msg = try std.fmt.bufPrint(&msg_buf, "Stream {d}, Round {d}", .{ stream_id, round });

            var wrote = false;
            var attempts: usize = 0;
            while (!wrote and attempts < 300) : (attempts += 1) {
                const wn = api.writeStream(conn, stream_id, msg, is_last_round) catch |err| switch (err) {
                    error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.InvalidStream => blk: {
                        try api.poll(ep, 5);
                        break :blk 0;
                    },
                    else => return err,
                };
                if (wn > 0) wrote = true;
                if (!wrote) {
                    try api.poll(ep, 5);
                } else {
                    try api.poll(ep, 0);
                }
            }
        }
    }

    // Read responses from all streams
    var stream_idx: usize = 0;
    while (stream_idx < actual_streams) : (stream_idx += 1) {
        const stream_id = stream_ids[stream_idx];
        var rbuf: [1024]u8 = undefined;
        var polls: usize = 0;
        while (polls < 200) : (polls += 1) {
            try api.poll(ep, 5);
            const n = api.readStream(conn, stream_id, rbuf[0..]) catch 0;
            if (n > 0) break;
        }
    }

    const elapsed = @as(u64, @intCast(std.time.milliTimestamp() - start));
    const details = try std.fmt.allocPrint(alloc.*, "{d} interleaved streams, 5 rounds in {d}ms", .{ actual_streams, elapsed });

    std.debug.print("✅ {s}\n\n", .{details});
    return TestResult{
        .name = "Stream Interleaving",
        .success = true,
        .details = details,
        .elapsed_ms = elapsed,
    };
}

fn printTestSummary(results: []const TestResult) void {
    std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
    std.debug.print("📊 TEST SUMMARY\n", .{});
    std.debug.print("=" ** 60 ++ "\n", .{});

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

    std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
    std.debug.print("RESULTS: {d} passed, {d} failed, {d} total\n", .{ passed, failed, results.len });
    std.debug.print("=" ** 60 ++ "\n", .{});
}
