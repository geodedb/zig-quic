const std = @import("std");
const quic = @import("quic");

// Multi-stream echo server for testing
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var port: u16 = 4433;
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = try std.fmt.parseInt(u16, port_str, 10);
            }
        }
    }

    // Create config with proper flow control limits
    var config = quic.Config{
        .max_streams_bidi = 128,
        .max_stream_data_bidi_local = 10485760,  // 10MB per stream
        .max_stream_data_bidi_remote = 10485760,  // 10MB per stream
        .max_stream_data_uni = 10485760,  // 10MB per stream
        .max_data = 104857600,  // 100MB total connection limit
        .idle_timeout_ms = 30000,
        .max_udp_payload_size = 1472,
        .initial_max_streams_uni = 10,
        .disable_active_migration = false,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
        .grease_quic_bit = false,
        .client_hello_pad = 0,
        .flexible_server_cid_len = true,
        .trust_client_dcid_len = false,
        .reject_new_connections = false,
        .retry = false,
        .server_name = "localhost",
        .root_certs = null,
        .client_cert = null,
        .client_key = null,
        .alpn = &[_][]const u8{"hq-interop"},
        .rtt_target_ms = 100,
        .max_ack_delay_ms = 25,
        .min_ack_delay_us = 1000,
        .time_threshold_numerator = 9,
        .time_threshold_denominator = 8,
        .packet_threshold = 3,
        .pmtud_probe_delay_ms = 200,
        .use_spin_bit = false,
        .skip_server_cert_verify = true,
        .key_log_file = null,
        .session_tickets = false,
        .zero_rtt = false,
        .compatible_vn = false,
        .test_ack_frequency = 2,
        .test_disable_gso = false,
        .test_disable_ecn = false,
        .test_disable_pacing = false,
        .test_random_drops_percent = 0,
        .test_capture_transmitted = false,
        .server_test_0rtt_accept = false,
        .server_test_0rtt_reject = false,
    };

    // Bind to address
    const bind_addr = try std.fmt.allocPrint(allocator, "0.0.0.0:{}", .{port});
    defer allocator.free(bind_addr);

    std.debug.print("Creating multi-stream QUIC server on {s}...\n", .{bind_addr});

    // Initialize endpoint
    var endpoint = try quic.Endpoint.init(&allocator, bind_addr, &config);
    defer endpoint.deinit();

    std.debug.print("Multi-stream QUIC server listening on {s}\n", .{bind_addr});

    // Main server loop - properly handle multiple streams
    while (true) {
        endpoint.poll(20) catch {};
        endpoint.processTimers() catch |err| std.debug.print("Timer processing error: {}\n", .{err});

        while (endpoint.tryAccept()) |conn| {
            std.debug.print("Accepted new QUIC connection!\n", .{});

            // Handle multiple streams on this connection
            var active_streams = std.ArrayList(u64).init(allocator);
            defer active_streams.deinit();

            var buf: [65536]u8 = undefined;  // 64KB buffer
            var loops: usize = 0;

            while (loops < 10000 and !conn.closed) : (loops += 1) {
                endpoint.poll(0) catch {};

                // Try to read from all possible client-initiated bidirectional streams
                // Stream IDs: 0, 4, 8, 12, 16, 20, 24, 28...
                var stream_id: u64 = 0;
                while (stream_id < 256) : (stream_id += 4) {
                    const n = conn.readStream(stream_id, buf[0..]) catch 0;
                    if (n > 0) {
                        // Track this stream as active
                        var found = false;
                        for (active_streams.items) |id| {
                            if (id == stream_id) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            try active_streams.append(stream_id);
                            std.debug.print("Stream {} opened, echoing {} bytes\n", .{stream_id, n});
                        }

                        // Echo back the data immediately
                        const written = conn.writeStream(stream_id, buf[0..n]) catch 0;
                        if (written < n) {
                            std.debug.print("Stream {} partial write: {} of {} bytes\n", .{stream_id, written, n});
                        }
                    }
                }

                std.time.sleep(100_000);  // 0.1ms
            }

            std.debug.print("Connection closed, handled {} streams\n", .{active_streams.items.len});
        }

        std.time.sleep(500_000); // 0.5ms throttle
    }
}