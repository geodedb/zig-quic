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

    // PHASE 42 PART 12: Per-stream state tracking for flow control resilience
    const StreamState = struct {
        pending_write: std.ArrayListUnmanaged(u8) = .{},  // Data waiting to be written
        got_fin: bool = false,             // Received FIN from peer
        sent_fin: bool = false,            // Sent FIN to peer

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.pending_write.deinit(allocator);
        }
    };

    const ConnState = struct {
        conn: *api.QuicConnection,
        streams: std.AutoHashMap(u64, StreamState),
        allocator: std.mem.Allocator,

        fn init(allocator: std.mem.Allocator, connection: *api.QuicConnection) @This() {
            return .{
                .conn = connection,
                .streams = std.AutoHashMap(u64, StreamState).init(allocator),
                .allocator = allocator,
            };
        }

        fn deinit(self: *@This()) void {
            var iter = self.streams.iterator();
            while (iter.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
            }
            self.streams.deinit();
        }
    };

    // Keep track of active connections
    var active_conns = std.ArrayListUnmanaged(ConnState){};
    defer {
        for (active_conns.items) |*conn_state| {
            api.destroy(ep, conn_state.conn);
            conn_state.deinit();
        }
        active_conns.deinit(alloc);
    }

    while (true) {
        // Drive I/O with a reasonable timeout to allow proper event-driven I/O
        // This replaces the busy-wait pattern with proper blocking I/O
        api.poll(ep, 20) catch {};

        // Accept all newly-ready connections
        while (api.tryAccept(ep)) |conn| {
            std.debug.print("accepted connection\n", .{});
            const conn_state = ConnState.init(alloc, conn);
            active_conns.append(alloc, conn_state) catch {};
        }

        // Process all active connections
        var i: usize = 0;
        while (i < active_conns.items.len) {
            var conn_state = &active_conns.items[i];
            const conn = conn_state.conn;

            // Check if connection is drained (closed)
            if (api.isDrained(conn)) {
                std.debug.print("connection closed\n", .{});
                api.destroy(ep, conn);
                conn_state.deinit();
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

            // PHASE 42 PART 12: Flow-control-resilient stream echo
            // Accept all newly available streams
            while (api.acceptStream(conn)) |stream_id| {
                std.debug.print("[P42-12] Accepted stream {}\n", .{stream_id});
                conn_state.streams.put(stream_id, .{}) catch {};
            } else |_| {}

            // Process all active streams in round-robin fashion
            var stream_iter = conn_state.streams.iterator();
            while (stream_iter.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                var stream = entry.value_ptr;

                // Skip if already completed
                if (stream.sent_fin) continue;

                // Step 1: Try to flush pending writes first (flow control may have unblocked)
                if (stream.pending_write.items.len > 0) {
                    const written: usize = api.writeStream(conn, stream_id, stream.pending_write.items, false) catch |err| blk: {
                        if (err == error.FlowControlBlocked) {
                            std.debug.print("[P42-12] Stream {} still blocked, {} bytes pending\n", .{stream_id, stream.pending_write.items.len});
                            continue; // Try next stream, will retry this one next iteration
                        }
                        std.debug.print("[P42-12] Stream {} write error: {}\n", .{stream_id, err});
                        break :blk 0;
                    };

                    if (written > 0) {
                        std.debug.print("[P42-12] Stream {} flushed {} of {} pending bytes\n", .{stream_id, written, stream.pending_write.items.len});
                        // Remove written bytes from pending buffer
                        const remaining = stream.pending_write.items.len - written;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, stream.pending_write.items[0..remaining], stream.pending_write.items[written..]);
                        }
                        stream.pending_write.shrinkRetainingCapacity(remaining);
                    }

                    // If still have pending data, skip reading more until we flush
                    if (stream.pending_write.items.len > 0) {
                        continue;
                    }
                }

                // Step 2: Read new data from stream
                if (!stream.got_fin) {
                    var chunk: [4096]u8 = undefined;
                    const n: usize = api.readStream(conn, stream_id, chunk[0..]) catch |err| blk: {
                        std.debug.print("[P42-12] Stream {} read error: {}\n", .{stream_id, err});
                        break :blk 0;
                    };

                    if (n > 0) {
                        std.debug.print("[P42-12] Stream {} read {} bytes\n", .{stream_id, n});

                        // Try to echo immediately
                        const written: usize = api.writeStream(conn, stream_id, chunk[0..n], false) catch |err| blk: {
                            if (err == error.FlowControlBlocked) {
                                std.debug.print("[P42-12] Stream {} flow control blocked, buffering {} bytes\n", .{stream_id, n});
                                // Buffer the data for later retry
                                stream.pending_write.appendSlice(conn_state.allocator, chunk[0..n]) catch {};
                                break :blk 0;
                            }
                            std.debug.print("[P42-12] Stream {} write error: {}\n", .{stream_id, err});
                            break :blk 0;
                        };

                        if (written > 0) {
                            std.debug.print("[P42-12] Stream {} echoed {} bytes\n", .{stream_id, written});

                            // If partial write, buffer remainder
                            if (written < n) {
                                stream.pending_write.appendSlice(conn_state.allocator, chunk[written..n]) catch {};
                                std.debug.print("[P42-12] Stream {} partial write, buffered {} bytes\n", .{stream_id, n - written});
                            }
                        }
                    } else {
                        // readStream returned 0, likely got FIN
                        stream.got_fin = true;
                        std.debug.print("[P42-12] Stream {} received FIN\n", .{stream_id});
                    }
                }

                // Step 3: If got FIN and no pending data, send FIN back
                if (stream.got_fin and stream.pending_write.items.len == 0 and !stream.sent_fin) {
                    _ = api.writeStream(conn, stream_id, &[_]u8{}, true) catch {};
                    stream.sent_fin = true;
                    std.debug.print("[P42-12] Stream {} sent FIN, complete\n", .{stream_id});
                }
            }

            i += 1;
        }
    } // main event loop

}