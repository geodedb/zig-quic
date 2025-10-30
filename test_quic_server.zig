const std = @import("std");
const quic = @import("quic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var port: u16 = 7567;
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = try std.fmt.parseInt(u16, port_str, 10);
            }
        }
    }

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

    // Bind to address
    const bind_addr = try std.fmt.allocPrint(allocator, "0.0.0.0:{}", .{port});
    defer allocator.free(bind_addr);

    std.debug.print("Creating QUIC endpoint on {s}...\n", .{bind_addr});

    // Initialize endpoint
    var endpoint = try quic.Endpoint.init(&allocator, bind_addr, &config);
    defer endpoint.deinit();

    std.debug.print("QUIC server listening on {s}\n", .{bind_addr});
    std.debug.print("Entering poll loop...\n", .{});

    // Main server loop (non-blocking accept + echo)
    while (true) {
        endpoint.poll(20) catch {};
        endpoint.processTimers() catch |err| std.debug.print("Timer processing error: {}\n", .{err});
        while (endpoint.tryAccept()) |conn| {
            std.debug.print("Accepted new QUIC connection!\n", .{});
            var buf: [1024]u8 = undefined;
            var opened = false;
            var loops: usize = 0;
            while (loops < 2000) : (loops += 1) {
                endpoint.poll(0) catch {};
                const n = conn.readStream(0, buf[0..]) catch 0;
                if (n > 0) {
                    if (!opened) { opened = true; std.debug.print("stream0 opened rx {d}\n", .{n}); }
                    _ = conn.writeStream(0, buf[0..n]) catch 0;
                }
                if (conn.closed) break;
            }
        }
        std.time.sleep(500_000); // 0.5ms throttle
    }
}