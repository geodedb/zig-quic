const std = @import("std");
const api = @import("quic_api");
const pem = @import("quic_api").pem;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(alloc);
    defer args_it.deinit();

    // Skip program name
    _ = args_it.next();

    var bind_addr: []const u8 = "127.0.0.1:4433";
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var alpn_str: []const u8 = "hq-interop";
    var insecure = false;
    var datagram = false;

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--bind")) {
            bind_addr = args_it.next() orelse "127.0.0.1:4433";
        } else if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args_it.next();
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args_it.next();
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            alpn_str = args_it.next() orelse "hq-interop";
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            insecure = true;
        } else if (std.mem.eql(u8, arg, "--datagram")) {
            datagram = true;
        }
    }

    // Load certificate and key if provided
    var cert_der: ?[]const u8 = null;
    var key_p256: ?[]const u8 = null;

    if (cert_path) |cp| {
        if (std.fs.cwd().openFile(cp, .{})) |cert_file| {
            defer cert_file.close();
            const cert_pem_data = try cert_file.readToEndAlloc(alloc, 1024 * 1024);
            defer alloc.free(cert_pem_data);

            // Parse PEM to DER
            cert_der = pem.parseCertificate(alloc, cert_pem_data) catch |err| blk: {
                std.debug.print("Warning: Failed to parse certificate '{s}': {}\n", .{cp, err});
                std.debug.print("Continuing without certificate (insecure mode)\n", .{});
                break :blk null;
            };
            if (cert_der) |cd| {
                std.debug.print("Loaded and parsed certificate from '{s}' (DER: {} bytes)\n", .{cp, cd.len});
            }
        } else |err| {
            std.debug.print("Warning: Could not open certificate file '{s}': {}\n", .{cp, err});
            std.debug.print("Continuing without certificate (insecure mode)\n", .{});
        }
    }

    if (key_path) |kp| {
        if (std.fs.cwd().openFile(kp, .{})) |key_file| {
            defer key_file.close();
            const key_pem_data = try key_file.readToEndAlloc(alloc, 1024 * 1024);
            defer alloc.free(key_pem_data);

            // Parse PEM private key (EC or RSA)
            key_p256 = pem.parsePrivateKey(alloc, key_pem_data) catch |err| blk: {
                std.debug.print("Warning: Failed to parse private key '{s}': {}\n", .{kp, err});
                std.debug.print("Continuing without private key (insecure mode)\n", .{});
                break :blk null;
            };
            if (key_p256) |kd| {
                std.debug.print("Loaded and parsed private key from '{s}' ({} bytes)\n", .{kp, kd.len});
            }
        } else |err| {
            std.debug.print("Warning: Could not open key file '{s}': {}\n", .{kp, err});
            std.debug.print("Continuing without private key (insecure mode)\n", .{});
        }
    }

    // Create ALPN slice
    var alpn_list = [_][]const u8{alpn_str};

    var config = api.QuicConfig{
        .inline_server_cert_der = cert_der,
        .inline_server_priv_p256 = key_p256,
        .alpn = &alpn_list,
        .allow_insecure = insecure,
        .max_idle_timeout_ms = 30000,
        .max_udp_payload = 1350,
        .enable_datagram = datagram,
    };

    const ep = try api.endpointInit(&alloc, bind_addr, &config);
    defer api.endpointDeinit(ep);

    std.debug.print("listening on {s}\n", .{bind_addr});

    // Keep track of active connections
    var active_conns = std.ArrayListUnmanaged(*api.QuicConnection){};
    defer active_conns.deinit(alloc);
    defer {
        for (active_conns.items) |conn| {
            api.destroy(ep, conn);
        }
        active_conns.deinit();
    }

    while (true) {
        // Drive I/O with a reasonable timeout to allow proper event-driven I/O
        // This replaces the busy-wait pattern with proper blocking I/O
        api.poll(ep, 20) catch {};

        // Accept all newly-ready connections
        while (api.tryAccept(ep)) |conn| {
            std.debug.print("accepted connection\n", .{});
            active_conns.append(alloc, conn) catch {};
        }

        // Process all active connections
        var i: usize = 0;
        while (i < active_conns.items.len) {
            const conn = active_conns.items[i];

            // Check if connection is drained (closed)
            if (api.isDrained(conn)) {
                std.debug.print("connection closed\n", .{});
                api.destroy(ep, conn);
                _ = active_conns.swapRemove(i);
                continue; // Don't increment i, check the swapped element
            }

            // Handle datagrams if enabled
            if (datagram) {
                var dgram_buf: [2048]u8 = undefined;
                const dn = api.recvDatagram(conn, &dgram_buf) catch 0;
                if (dn > 0) {
                    _ = api.sendDatagram(conn, dgram_buf[0..dn]) catch 0;
                }
            }

            // Handle stream data (echo server)
            // Accept and process ALL pending streams (not just one!)
            while (true) {
                const stream_id = api.acceptStream(conn) catch break; // Break when no more streams available
                std.debug.print("DEBUG: Accepted stream {d}\n", .{stream_id});

                // Read from the accepted stream
                var buf: [4096]u8 = undefined;
                const n = api.readStream(conn, stream_id, buf[0..]) catch |err| blk: {
                    std.debug.print("DEBUG: readStream error: {}\n", .{err});
                    break :blk 0;
                };
                if (n > 0) {
                    std.debug.print("stream {d} received {d} bytes: ", .{stream_id, n});
                    for (buf[0..@min(n, 32)]) |b| std.debug.print("{x:0>2} ", .{b});
                    if (n > 32) std.debug.print("...", .{});
                    std.debug.print("\n", .{});

                    const written = api.writeStream(conn, stream_id, buf[0..n]) catch |err| blk: {
                        std.debug.print("DEBUG: writeStream error: {}\n", .{err});
                        break :blk 0;
                    };
                    std.debug.print("DEBUG: Wrote {d} bytes to stream {d}\n", .{written, stream_id});
                } else {
                    std.debug.print("DEBUG: No data read from stream {d}\n", .{stream_id});
                }
            }

            i += 1;
        }
    } // main event loop

}