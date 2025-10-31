const std = @import("std");
const api = @import("quic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Parse command-line arguments
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.skip(); // Skip program name

    var bind_addr: []const u8 = "0.0.0.0:4433";
    var cert_path: []const u8 = "certs/server.crt";
    var key_path: []const u8 = "certs/server.key";
    var insecure = false;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--bind")) {
            bind_addr = args.next() orelse bind_addr;
        } else if (std.mem.eql(u8, a, "--cert")) {
            cert_path = args.next() orelse cert_path;
        } else if (std.mem.eql(u8, a, "--key")) {
            key_path = args.next() orelse key_path;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        }
    }

    // Generate self-signed certificates if they don't exist
    if (!insecure) {
        std.fs.cwd().access(cert_path, .{}) catch {
            try generateSelfSignedCert(cert_path, key_path);
            std.debug.print("Generated self-signed certificate at {s}\n", .{cert_path});
        };
    }

    // Configure the QUIC endpoint
    const cfg = api.QuicConfig{
        .version = .v1,
        .allow_insecure = insecure,
        .alpn = &[_][]const u8{"quic-zig/1", "h3", "http/0.9"},
        .cc = .newreno,
        .enable_datagram = false,
        .enable_spin_bit = false,
        .grease = true,
        .compatible_vn = false,
        .enable_retry = false,
        .token_secret = null,
        .token_expiry_ms = 60000,
        .enable_pacing = false,
        .max_datagram_size = 1200,
        .max_idle_timeout_ms = 30000,
        .max_udp_payload = 1350,
        .cert_path = if (insecure) null else cert_path,
        .key_path = if (insecure) null else key_path,
        .ca_path = null,
        .aead_confidentiality_limit_override = null,
        .aead_integrity_limit_override = null,
        .inline_server_cert_der = null,
        .inline_server_priv_p256 = null,
    };

    std.debug.print("Starting QUIC server on {s} (insecure={}, cert={s})\n",
        .{bind_addr, insecure, cert_path});

    // Initialize endpoint
    const ep = try api.endpointInit(&alloc, bind_addr, &cfg);
    defer api.endpointDeinit(ep);

    std.debug.print("Server listening...\n", .{});

    // Main server loop
    while (true) {
        // Poll for events
        api.poll(ep, 10) catch |err| {
            std.debug.print("Poll error: {}\n", .{err});
            continue;
        };

        // Try to accept a connection
        if (api.tryAccept(ep)) |conn| {
            std.debug.print("Accepted new connection\n", .{});

            // Handle connection in a separate thread (simplified for testing)
            handleConnection(conn, &alloc) catch |err| {
                std.debug.print("Connection handling error: {}\n", .{err});
            };
        }
    }
}

fn handleConnection(conn: *api.QuicConnection, _: *std.mem.Allocator) !void {
    defer api.closeConnectionSimple(conn) catch {};

    std.debug.print("Handling connection...\n", .{});

    // Check negotiated ALPN
    if (api.getNegotiatedAlpn(conn)) |alpn| {
        std.debug.print("Negotiated ALPN: {s}\n", .{alpn});
    }

    // Simple echo server - accept incoming streams and echo back
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        // Try to accept an incoming stream
        const stream_id = api.acceptStream(conn) catch |err| switch (err) {
            error.WouldBlock => {
                // No stream available yet, wait and try again
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };

        std.debug.print("Accepted stream {d}\n", .{stream_id});

        // Read from the accepted stream
        var buf: [4096]u8 = undefined;
        const n = api.readStream(conn, stream_id, &buf) catch |err| switch (err) {
            error.KeysNotReady => 0,
            error.StreamNotFound => 0,
            error.NoDataAvailable => 0,
            else => return err,
        };

        if (n > 0) {
            std.debug.print("Received {d} bytes: {s}\n", .{n, buf[0..n]});

            // Echo back
            const written = api.writeStream(conn, stream_id, buf[0..n]) catch |err| {
                std.debug.print("Write error: {}\n", .{err});
                return;
            };

            std.debug.print("Echoed {d} bytes\n", .{written});

            // For simple test, close after echo
            return;
        }

        // Wait a bit
        std.time.sleep(10 * std.time.ns_per_ms);
    }
}

fn generateSelfSignedCert(cert_path: []const u8, key_path: []const u8) !void {
    // Create certs directory if it doesn't exist
    std.fs.cwd().makeDir("certs") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Generate using openssl (simplified for testing)
    var cmd = std.ArrayList(u8).init(std.heap.page_allocator);
    defer cmd.deinit(std.heap.page_allocator);

    try cmd.writer().print(
        "openssl req -x509 -newkey rsa:2048 -keyout {s} -out {s} -days 365 -nodes -subj '/CN=localhost'",
        .{key_path, cert_path}
    );

    const result = try std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{"sh", "-c", cmd.items},
    });
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        std.debug.print("Failed to generate certificate: {s}\n", .{result.stderr});
        return error.CertificateGenerationFailed;
    }
}