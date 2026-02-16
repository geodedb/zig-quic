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
                std.debug.print("Warning: Failed to parse certificate '{s}': {}\n", .{ cp, err });
                std.debug.print("Continuing without certificate (insecure mode)\n", .{});
                break :blk null;
            };
            if (cert_der) |cd| {
                std.debug.print("Loaded and parsed certificate from '{s}' (DER: {} bytes)\n", .{ cp, cd.len });
            }
        } else |err| {
            std.debug.print("Warning: Could not open certificate file '{s}': {}\n", .{ cp, err });
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
                std.debug.print("Warning: Failed to parse private key '{s}': {}\n", .{ kp, err });
                std.debug.print("Continuing without private key (insecure mode)\n", .{});
                break :blk null;
            };
            if (key_p256) |kd| {
                std.debug.print("Loaded and parsed private key from '{s}' ({} bytes)\n", .{ kp, kd.len });
            }
        } else |err| {
            std.debug.print("Warning: Could not open key file '{s}': {}\n", .{ kp, err });
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
        pending_write: std.ArrayListUnmanaged(u8) = .{}, // Data waiting to be written
        got_fin: bool = false, // Received FIN from peer
        sent_fin: bool = false, // Sent FIN to peer
        total_read: u64 = 0, // PHASE 42 PART 13: Total bytes read from peer
        total_written: u64 = 0, // PHASE 42 PART 13: Total bytes written to peer

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

    // PHASE 42 PART 13: Deep debug logging for event loop analysis
    var loop_count: u64 = 0;
    var last_debug_time = std.time.milliTimestamp();

    // Server push is disabled for now; keep knobs in place for future experiments.
    const enable_server_push = false;
    var push_active: bool = false;
    const push_stream_id: u64 = 1; // server-initiated bidi stream id (odd => server-initiated)
    const push_target: usize = 1048576;
    var push_sent: usize = 0;
    var push_buf: ?[]u8 = null;
    while (true) {
        loop_count += 1;
        const now = std.time.milliTimestamp();

        // Log event loop iterations every 100ms during active processing
        if (active_conns.items.len > 0 and (now - last_debug_time) >= 100) {
            std.debug.print("[P42-13-LOOP] Iteration {}, {} active connections\n", .{ loop_count, active_conns.items.len });
            last_debug_time = now;
        }

        // Drive I/O with a reasonable timeout to allow proper event-driven I/O
        // This replaces the busy-wait pattern with proper blocking I/O
        api.poll(ep, if (active_conns.items.len > 0) 5 else 20) catch {}; // adaptive shorter poll for active transfers

        // Accept all newly-ready connections
        while (api.tryAccept(ep)) |conn| {
            std.debug.print("accepted connection\n", .{});
            const conn_state = ConnState.init(alloc, conn);
            active_conns.append(alloc, conn_state) catch {};
            if (enable_server_push and !push_active) {
                push_active = true;
                if (push_buf == null) {
                    const tmp = try alloc.alloc(u8, push_target);
                    @memset(tmp, '\xAB');
                    push_buf = tmp;
                }
                const initial_burst = @min(push_target - push_sent, 64 * 1024);
                if (initial_burst > 0) {
                    const written = api.writeStream(conn, push_stream_id, push_buf.?[push_sent .. push_sent + initial_burst], false) catch 0;
                    push_sent += written;
                    std.debug.print("[SERVER-PUSH] initial wrote={} total={} target={}\n", .{ written, push_sent, push_target });
                }
            }
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
            // PHASE 42 PART 14: Only create NEW state for streams we haven't seen before
            while (api.acceptStream(conn)) |stream_id| {
                std.debug.print("[P42-14-ACCEPT] Accepted stream {}\n", .{stream_id});
                // Only create state if this is a genuinely new stream
                if (conn_state.streams.getPtr(stream_id) == null) {
                    conn_state.streams.put(stream_id, .{}) catch {};
                    std.debug.print("[P42-14-NEW] Created new state for stream {}\n", .{stream_id});
                } else {
                    std.debug.print("[P42-14-EXISTS] Stream {} already has state (re-queued for more data)\n", .{stream_id});
                }
            } else |_| {}

            // Process all active streams in round-robin fashion
            var stream_iter = conn_state.streams.iterator();
            var streams_processed: usize = 0;
            while (stream_iter.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                var stream = entry.value_ptr;

                // Skip if already completed
                if (stream.sent_fin) continue;

                streams_processed += 1;

                // Step 1: Try to flush pending writes first (flow control may have unblocked)
                if (stream.pending_write.items.len > 0) {
                    while (stream.pending_write.items.len > 0) {
                        std.debug.print("[P42-13] Stream {} flushing {} pending bytes (loop {})\n", .{ stream_id, stream.pending_write.items.len, loop_count });
                        const written: usize = api.writeStream(conn, stream_id, stream.pending_write.items, false) catch |err| blk: {
                            if (err == error.FlowControlBlocked) {
                                std.debug.print("[P42-13-FC-BLOCKED] Stream {} still blocked, {} bytes pending (loop {})\n", .{ stream_id, stream.pending_write.items.len, loop_count });
                                break;
                            }
                            std.debug.print("[P42-13-ERROR] Stream {} write error: {} (loop {})\n", .{ stream_id, err, loop_count });
                            break :blk 0;
                        };

                        if (written == 0) break;

                        stream.total_written += written;
                        const remaining = stream.pending_write.items.len - written;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, stream.pending_write.items[0..remaining], stream.pending_write.items[written..]);
                        }
                        stream.pending_write.shrinkRetainingCapacity(remaining);
                        std.debug.print("[P42-13-FLUSH] Stream {} flushed {} bytes ({} total written, {} still pending)\n", .{ stream_id, written, stream.total_written, stream.pending_write.items.len });
                    }
                }

                // Server push progression
                if (enable_server_push and push_active and push_sent < push_target) {
                    const chunk = @min(push_target - push_sent, 64 * 1024);
                    const wrote = api.writeStream(conn, push_stream_id, push_buf.?[push_sent .. push_sent + chunk], false) catch 0;
                    if (wrote > 0) {
                        push_sent += wrote;
                        std.debug.print("[SERVER-PUSH] wrote={} total={} target={}\n", .{ wrote, push_sent, push_target });
                        if (push_sent == push_target) {
                            _ = api.writeStream(conn, push_stream_id, &[_]u8{}, true) catch {};
                            std.debug.print("[SERVER-PUSH] FIN sent total={}\n", .{push_sent});
                        }
                    }
                }

                // Step 2: Read new data from stream (drain aggressively each iteration)
                // PHASE 57 PART 12: Decouple reading from writing to fix bidirectional deadlock
                // Reference: @forks/quic-go/send_stream.go:93-211 and receive_stream.go:84-237
                // quic-go NEVER blocks reads based on pending writes - they are independent!
                if (!stream.got_fin) {
                    var chunk: [64 * 1024]u8 = undefined; // 64KB buffer similar to quinn/quiche examples
                    // PHASE 57 PART 17: Restore baseline (no read limiting) for flush rate investigation
                    const max_reads_per_iter: usize = 64;
                    var reads_this_iter: usize = 0;

                    // REMOVED: pending_write.items.len == 0 check that caused deadlock
                    while (!stream.got_fin and reads_this_iter < max_reads_per_iter) {
                        // PHASE 55 FIX: Don't confuse WouldBlock with FIN
                        const read_result = api.readStream(conn, stream_id, chunk[0..]);

                        if (read_result) |n| {
                            if (n > 0) {
                                reads_this_iter += 1;
                                stream.total_read += n;
                                std.debug.print("[P57-14-READ] Stream {} read {} bytes ({} total read, loop {}, reads_iter={}, pending_write={})\n", .{ stream_id, n, stream.total_read, loop_count, reads_this_iter, stream.pending_write.items.len });

                                // PHASE 57 PART 12: Only try immediate echo if no pending writes
                                // If we're already blocked, buffer ALL new reads to prevent unbounded growth
                                if (stream.pending_write.items.len == 0) {
                                    // Try to echo immediately
                                    // Loop to write entire read buffer (may exceed single packet max)
                                    var write_off: usize = 0;
                                    while (write_off < n) {
                                        const slice_len = n - write_off;
                                        const written: usize = api.writeStream(conn, stream_id, chunk[write_off..n], false) catch |err| blk: {
                                            if (err == error.FlowControlBlocked or err == error.CongestionControlBlocked) {
                                                std.debug.print("[P42-13-FC/CC-BLOCKED] Stream {} blocked mid-chunk, buffering {} bytes (loop {})\n", .{ stream_id, n - write_off, loop_count });
                                                stream.pending_write.appendSlice(conn_state.allocator, chunk[write_off..n]) catch {};
                                                break :blk 0;
                                            }
                                            std.debug.print("[P42-13-ERROR] Stream {} write error: {} (loop {})\n", .{ stream_id, err, loop_count });
                                            break :blk 0;
                                        };
                                        if (written == 0) break; // blocked or error
                                        stream.total_written += written;
                                        write_off += written;
                                        if (written < slice_len) {
                                            // Partial: buffer remainder
                                            stream.pending_write.appendSlice(conn_state.allocator, chunk[write_off..n]) catch {};
                                            std.debug.print("[P42-13-PARTIAL] Stream {} partial echo, buffered {} bytes (loop {})\n", .{ stream_id, n - write_off, loop_count });
                                            break;
                                        }
                                    }
                                    const fully_echoed = write_off == n;
                                    if (fully_echoed) {
                                        std.debug.print("[P42-13-ECHO] Stream {} echoed {} bytes ({} total written, loop {})\n", .{ stream_id, n, stream.total_written, loop_count });
                                    }
                                } else {
                                    // Already blocked, buffer this read instead of trying to echo
                                    stream.pending_write.appendSlice(conn_state.allocator, chunk[0..n]) catch {};
                                    std.debug.print("[P57-12-BUFFER] Stream {} buffered {} bytes (already blocked, pending={}, loop {})\n", .{ stream_id, n, stream.pending_write.items.len, loop_count });
                                }
                            } else {
                                // readStream returned 0 successfully - this is a real FIN
                                stream.got_fin = true;
                                std.debug.print("[P42-13-FIN] Stream {} received FIN (total read: {}, total written: {}, pending: {})\n", .{ stream_id, stream.total_read, stream.total_written, stream.pending_write.items.len });
                                break;
                            }
                        } else |err| {
                            // Error reading - WouldBlock just means no data available yet, continue
                            if (err != error.WouldBlock) {
                                std.debug.print("[P42-13-ERROR] Stream {} read error: {} (loop {})\n", .{ stream_id, err, loop_count });
                            }
                            break;
                        }
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
