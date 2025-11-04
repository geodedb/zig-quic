const std = @import("std");
const quic = @import("quic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== DIAGNOSTIC QUIC SERVER ===\n", .{});
    std.debug.print("Purpose: Debug 1-RTT bi-directional communication failure\n", .{});
    std.debug.print("Expected: Server receives STREAM frames and echoes them back\n\n", .{});

    // Create config
    var config = quic.Config{
        .max_streams_bidi = 128,
        .max_stream_data_bidi_local = 1048576,
        .max_stream_data_bidi_remote = 1048576,
        .max_stream_data_uni = 1048576,
        .max_data = 10485760,
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

    const bind_addr = "0.0.0.0:4433";
    std.debug.print("Creating QUIC endpoint on {s}...\n", .{bind_addr});

    var endpoint = try quic.Endpoint.init(&allocator, bind_addr, &config);
    defer endpoint.deinit();

    std.debug.print("Server listening. Waiting for connections...\n\n", .{});

    var connection_count: usize = 0;

    while (true) {
        // Poll with short timeout
        endpoint.poll(10) catch |err| {
            std.debug.print("Poll error: {}\n", .{err});
        };

        endpoint.processTimers() catch |err| {
            std.debug.print("Timer error: {}\n", .{err});
        };

        // Try to accept new connections
        while (endpoint.tryAccept()) |conn| {
            connection_count += 1;
            std.debug.print("\n========================================\n", .{});
            std.debug.print("ACCEPTED CONNECTION #{}\n", .{connection_count});
            std.debug.print("========================================\n", .{});
            std.debug.print("Connection details:\n", .{});
            std.debug.print("  - Role: {}\n", .{conn.role});
            std.debug.print("  - Has app_rx_keys: {}\n", .{conn.app_rx_keys != null});
            std.debug.print("  - Has app_tx_keys: {}\n", .{conn.app_tx_keys != null});
            std.debug.print("  - Handshake complete: {}\n", .{conn.handshake_complete});
            std.debug.print("\n", .{});

            // Echo loop
            var buf: [4096]u8 = undefined;
            var total_echoed: usize = 0;
            var loops: usize = 0;
            const max_loops = 5000;

            std.debug.print("Entering echo loop (max {} iterations)...\n", .{max_loops});

            while (loops < max_loops) : (loops += 1) {
                // Poll to receive packets
                endpoint.poll(0) catch {};

                // Try to read from stream 0
                const n = conn.readStream(0, buf[0..]) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    error.InvalidStream => blk: {
                        if (loops % 500 == 0) {
                            std.debug.print("[Loop {}] Stream 0 not yet available\n", .{loops});
                        }
                        break :blk 0;
                    },
                    else => |e| {
                        std.debug.print("readStream error: {}\n", .{e});
                        break :blk 0;
                    },
                };

                if (n > 0) {
                    std.debug.print("\n>>> RECEIVED {} BYTES from stream 0:\n", .{n});
                    std.debug.print("    Data: {s}\n", .{buf[0..n]});
                    std.debug.print("    Hex: ", .{});
                    for (buf[0..n]) |byte| {
                        std.debug.print("{x:0>2} ", .{byte});
                    }
                    std.debug.print("\n", .{});

                    // Echo back
                    std.debug.print(">>> ECHOING {} bytes back...\n", .{n});
                    const written = conn.writeStream(0, buf[0..n]) catch |err| {
                        std.debug.print("    writeStream FAILED: {}\n", .{err});
                        0
                    };

                    if (written > 0) {
                        std.debug.print("    writeStream SUCCESS: {} bytes queued\n", .{written});
                        total_echoed += written;

                        // Force a poll to flush
                        endpoint.poll(0) catch {};
                    } else if (written == 0) {
                        std.debug.print("    writeStream returned 0 (keys not ready or flow control)\n", .{});
                    }
                }

                // Check connection state
                if (conn.closed) {
                    std.debug.print("\n>>> Connection CLOSED at loop {}\n", .{loops});
                    std.debug.print("    Total echoed: {} bytes\n", .{total_echoed});
                    break;
                }

                // Periodic status
                if (loops % 1000 == 0 and loops > 0) {
                    std.debug.print("[Loop {}] Still alive. Total echoed: {} bytes\n", .{ loops, total_echoed });
                }

                // Small sleep to avoid busy loop
                std.time.sleep(100_000); // 0.1ms
            }

            std.debug.print("\nConnection processing complete after {} loops\n", .{loops});
            std.debug.print("Total data echoed: {} bytes\n", .{total_echoed});
        }

        std.time.sleep(1_000_000); // 1ms between accept attempts
    }
}
