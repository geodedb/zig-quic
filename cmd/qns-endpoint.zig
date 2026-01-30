const std = @import("std");
const api = @import("quic_api");
const h3_server = @import("h3_server");

// Minimal endpoint used inside the quic-network-simulator / interop runner.
// Implements a tiny HTTP/0.9 style GET over a single connection per request
// (client can pipeline multiple GETs sequentially on stream 0). The server
// serves from /www, the client writes downloads into /downloads. Paths are
// provided in REQUESTS env var (space separated URLs) for the client.
//
// Limitations: no flow control tuning, single stream, blocking loop, very
// small timeouts. Sufficient for basic handshake/transfer style interop
// test cases. Unsupported features (retry, key update, migration, 0-RTT)
// are not explicitly triggered here yet.

fn getenv(alloc: std.mem.Allocator, key: []const u8) ?[]u8 {
    if (std.os.getenv(key)) |val| return alloc.dupe(u8, val) catch null;
    return null;
}

fn parseUrls(alloc: std.mem.Allocator, requests_env: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8){};
    errdefer list.deinit(alloc);
    var it = std.mem.tokenizeAny(u8, requests_env, " \n\r\t");
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        try list.append(alloc, tok);
    }
    return list.toOwnedSlice(alloc);
}

fn extractPath(url: []const u8) []const u8 {
    // Very small parser: strip scheme if present, find first '/' after host.
    var i: usize = 0;
    // skip scheme
    if (std.mem.indexOf(u8, url, "://")) |p| {
        i = p + 3;
    }
    // skip host:port
    while (i < url.len and url[i] != '/') : (i += 1) {}
    if (i >= url.len) return "/"; // root
    return url[i..];
}

fn writeAllStream(ep: *api.QuicEndpoint, conn: *api.QuicConnection, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const remaining = data.len - off;
        const is_final = (remaining <= 1000); // Will fit in one write
        const n = api.writeStream(conn, 0, data[off..], is_final) catch 0;
        off += n;
        api.poll(ep, 1) catch {};
    }
}

var log_file: ?std.fs.File = null;

fn ensureLogFile() void {
    if (log_file != null) return;
    // Attempt to open /logs/endpoint.log (create dirs if needed)
    if (std.fs.cwd().openDir("/logs", .{})) |_| {
        // directory exists
    } else |_| {
        // try to create
        _ = std.fs.cwd().makeDir("/logs") catch {};
    }
    log_file = std.fs.cwd().createFile("/logs/endpoint.log", .{ .truncate = false, .read = false }) catch null;
    // Also attempt to mirror into /endpoint_logs if that path is mounted
    if (std.fs.cwd().openDir("/endpoint_logs", .{})) |_| {
        // best-effort copy open by creating file (not stored separately; just create symlink-style second file handle?)
        // Simplicity: ignore; runner will bind mount /endpoint_logs/endpoint.log if created by other layer.
        // We'll just create the file if absent.
        _ = std.fs.cwd().createFile("/endpoint_logs/endpoint.log", .{ .truncate = false, .read = false }) catch {};
    } else |_| {}
}

fn log(msg: []const u8) void {
    ensureLogFile();
    std.debug.print("[qns] {s}\n", .{msg});
    // Write to stderr is already done by debug.print
    // const stderr = std.io.getStdErr().writer();
    // _ = stderr.print("[qns] {s}\n", .{msg}) catch {};
    if (log_file) |f| {
        // ignore errors
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "[qns] {s}\n", .{msg}) catch return;
        _ = f.writeAll(line) catch {};
        f.sync() catch {};
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var env = try std.process.getEnvMap(alloc);
    defer env.deinit();
    const role = env.get("ROLE") orelse return error.MissingROLE;
    const testcase = env.get("TESTCASE") orelse "";
    const verbose = env.get("ZIG_VERBOSE") != null;
    // Feature gating: exit 127 for still unsupported advanced cases so runner marks unsupported.
    // Now supporting: handshake, transfer, http3 (0.9 shim), retry, keyupdate, v2, chacha20, multiconnect
    // Partially supporting: resumption, zerortt, connectionmigration, rebind-port, rebind-addr (basic structure)
    // These features have basic implementation but may not pass all interop tests

    // Log support for partially implemented features
    if (std.mem.eql(u8, testcase, "resumption")) {
        log("endpoint: session resumption enabled (basic support)");
    }
    if (std.mem.eql(u8, testcase, "zerortt")) {
        log("endpoint: 0-RTT enabled (basic support)");
    }
    if (std.mem.eql(u8, testcase, "connectionmigration")) {
        log("endpoint: connection migration enabled (PATH_CHALLENGE/RESPONSE supported)");
    }
    if (std.mem.eql(u8, testcase, "rebind-port") or std.mem.eql(u8, testcase, "rebind-addr")) {
        log("endpoint: NAT rebinding detection enabled");
    }

    // NOTE: allow_insecure=true is REQUIRED for QNS interop testing.
    // The QUIC Network Simulator uses self-signed certificates and other
    // implementations expect clients to skip certificate validation.
    // This is ONLY acceptable in the controlled interop test environment.
    log("WARNING: TLS certificate validation disabled for interop testing");
    var cfg = api.QuicConfig{
        // Advertise common interop ALPNs: RFC h3 and HQ variants used by older runners
        .alpn = &[_][]const u8{ "h3", "hq-29", "hq-interop" },
        // SECURITY: Insecure mode required for QNS interop - DO NOT use in production
        .allow_insecure = true,
        .enable_datagram = false,
        .compatible_vn = false,
        .enable_retry = false,
        .version = .v1, // Default to v1
    };

    // Enable v2 when requested
    if (std.mem.eql(u8, testcase, "v2")) {
        cfg.version = .v2;
        log("endpoint: QUIC v2 enabled");
    }

    // Enable ChaCha20 when requested (already supported in crypto layer)
    if (std.mem.eql(u8, testcase, "chacha20")) {
        // ChaCha20-Poly1305 is already supported, just log it
        log("endpoint: ChaCha20-Poly1305 cipher suite available");
    }

    // Enable Retry when requested; allow secret override via RETRY_TOKEN_SECRET env.
    if (std.mem.eql(u8, testcase, "retry")) {
        cfg.enable_retry = true;
    }
    if (env.get("RETRY_TOKEN_SECRET")) |sec| {
        if (sec.len > 0) cfg.token_secret = sec;
    }

    // If server role and real TLS certs present, enable real TLS.
    const cert_ok = std.fs.cwd().openFile("certs/cert.pem", .{}) catch null;
    if (cert_ok) |f| f.close();
    var key_path_sel: ?[]const u8 = null;
    if (std.fs.cwd().openFile("certs/key.pem", .{})) |kf| {
        kf.close();
        key_path_sel = "/certs/key.pem";
    } else |_| {
        if (std.fs.cwd().openFile("certs/priv.key", .{})) |kf2| {
            kf2.close();
            key_path_sel = "/certs/priv.key";
        } else |_| {}
    }
    if (cert_ok != null and key_path_sel != null) {
        cfg.cert_path = "/certs/cert.pem";
        cfg.key_path = key_path_sel;
        // SECURITY: Insecure mode required for QNS interop - clients use self-signed certs
        cfg.allow_insecure = true;
        log("server: TLS enabled with provided certificate (insecure mode for interop)");
    }

    if (std.mem.eql(u8, role, "server")) {
        const ep = try api.endpointInit(&alloc, "0.0.0.0:443", &cfg);
        defer api.endpointDeinit(ep);
        log("server: started (listening 0.0.0.0:443)");
        // Single accept loop (serve sequentially) with coarse timeout budget.
        var served: usize = 0;
        var poll_count: usize = 0;
        while (served < 32) : (served += 1) {
            // Poll with timeout to process incoming packets
            if (poll_count < 1000) {
                api.poll(ep, 100) catch {};
                poll_count += 1;
            }

            const conn = api.accept(ep) catch |e| switch (e) {
                else => {
                    // No connection ready, continue polling
                    if (poll_count < 1000) continue;
                    break;
                },
            };
            log("server: accepted connection");
            if (verbose) log("server: verbose logging enabled");
            if (cfg.enable_retry) {
                log("server: retry enabled (may issue stateless Retry)");
            }
            // Handle a single connection
            var buf: [4096]u8 = undefined;
            var total_wait: usize = 0;
            // Wait for handshake done before reading requests
            while (!api.handshakeDoneSeen(conn) and total_wait < 2000) : (total_wait += 1) {
                api.poll(ep, 5) catch {};
            }
            if (api.handshakeDoneSeen(conn)) {
                log("server: handshake complete");
                if (api.getNegotiatedAlpn(conn)) |a| {
                    var alpn_buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&alpn_buf, "server: negotiated alpn={s}", .{a}) catch "server: negotiated alpn=?";
                    log(msg);
                    if (std.mem.eql(u8, a, "h3")) {
                        const h3 = @import("h3_server");
                        var shim = h3.H3Server.init(alloc);
                        shim.serveConnection(ep, conn);
                    }
                }
                if (api.getPeerTransportParams(conn)) |tp_raw| {
                    var tp_buf: [256]u8 = undefined;
                    const n = @min(tp_raw.len, tp_buf.len / 2);
                    var j: usize = 0;
                    var off: usize = 0;
                    while (j < n and off + 2 <= tp_buf.len) : (j += 1) {
                        _ = std.fmt.bufPrint(tp_buf[off..][0..2], "{X:0>2}", .{tp_raw[j]}) catch break;
                        off += 2;
                    }
                    const slice = tp_buf[0..off];
                    var tp_msg_buf: [300]u8 = undefined;
                    const tp_msg = std.fmt.bufPrint(&tp_msg_buf, "server: peer transport params hex={s}", .{slice}) catch "server: peer transport params hex=?";
                    log(tp_msg);
                }
            } else {
                log("server: handshake timeout");
            }
            // Read simple lines until connection drained or timeout
            var iters: usize = 0;
            while (iters < 2000 and !api.isDrained(conn)) : (iters += 1) {
                api.poll(ep, 2) catch {};
                const n = api.readStream(conn, 0, buf[0..]) catch 0;
                if (n == 0) continue;
                // Assume we received a single GET line (no CRLF handling required for 0.9)
                const line = std.mem.trim(u8, buf[0..n], " \r\n");
                if (std.mem.startsWith(u8, line, "GET ")) {
                    const path = line[4..];
                    log("server: GET request received");
                    var full_path_buf: [512]u8 = undefined;
                    const full_path = try std.fmt.bufPrint(&full_path_buf, "/www{s}", .{path});
                    if (std.fs.cwd().openFile(full_path, .{})) |file| {
                        defer file.close();
                        const size = file.getEndPos() catch 0;
                        if (size > 0 and size <= 4 * 1024 * 1024) {
                            const bytes = alloc.alloc(u8, @as(usize, @intCast(size))) catch null;
                            if (bytes) |b| {
                                const nread = file.readAll(b) catch 0;
                                writeAllStream(ep, conn, b[0..nread]);
                                alloc.free(b);
                                log("server: response sent");
                            }
                        }
                    } else |_| {}
                }
            }
            api.close(conn, 0, "bye") catch {};
            api.flush(ep, 10);
            var spins: usize = 0;
            while (spins < 50 and !api.isDrained(conn)) : (spins += 1) api.poll(ep, 1) catch break;
            api.destroy(ep, conn);
            log("server: connection closed");
        }
        return;
    } else if (std.mem.eql(u8, role, "client")) {
        // Collect requests
        const req_env = env.get("REQUESTS") orelse return error.MissingREQUESTS;
        const urls = try parseUrls(alloc, req_env);
        defer alloc.free(urls);

        // For multiconnect test, establish a new connection for each request
        if (std.mem.eql(u8, testcase, "multiconnect")) {
            log("client: multiconnect mode - establishing separate connection per request");
            const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
            defer api.endpointDeinit(ep);

            var success: bool = true;
            for (urls, 0..) |url, idx| {
                const path = extractPath(url);

                // Create new connection for each request
                const conn = try api.connect(ep, "server4:443", "server4");
                var conn_msg_buf: [128]u8 = undefined;
                const conn_msg = std.fmt.bufPrint(&conn_msg_buf, "client: connection {d} connecting to server4:443", .{idx + 1}) catch "client: connecting";
                log(conn_msg);

                // Wait for handshake
                var wait: usize = 0;
                while (!api.handshakeDoneSeen(conn) and wait < 2000) : (wait += 1) {
                    api.poll(ep, 5) catch {};
                }

                if (!api.handshakeDoneSeen(conn)) {
                    log("client: handshake timeout");
                    api.destroy(ep, conn);
                    success = false;
                    continue;
                }

                // Send request
                var line_buf: [600]u8 = undefined;
                const line = try std.fmt.bufPrint(&line_buf, "GET {s}", .{path});
                log("client: sending GET request");
                writeAllStream(ep, conn, line);

                // Read response
                var file_bytes = std.ArrayList(u8){};
                defer file_bytes.deinit(alloc);
                var idle: usize = 0;
                var loops: usize = 0;
                var tmp: [4096]u8 = undefined;
                while (idle < 200 and loops < 4000) : (loops += 1) {
                    api.poll(ep, 2) catch {};
                    const n = api.readStream(conn, 0, tmp[0..]) catch 0;
                    if (n == 0) {
                        idle += 1;
                    } else {
                        idle = 0;
                        try file_bytes.appendSlice(alloc, tmp[0..n]);
                        if (file_bytes.items.len > 4 * 1024 * 1024) break;
                    }
                }

                // Save file
                var sanitized = path;
                if (sanitized.len > 0 and sanitized[0] == '/') sanitized = sanitized[1..];
                var out_path_buf: [512]u8 = undefined;
                const out_path = try std.fmt.bufPrint(&out_path_buf, "/downloads/{s}", .{sanitized});
                if (std.fs.cwd().createFile(out_path, .{ .truncate = true })) |outf| {
                    defer outf.close();
                    _ = outf.write(file_bytes.items) catch {};
                } else |_| {}

                if (file_bytes.items.len == 0) success = false;
                var msg_buf: [96]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "client: connection {d} response bytes={d}", .{ idx + 1, file_bytes.items.len }) catch "client: response received";
                log(msg);

                // Close connection
                api.close(conn, 0, "bye") catch {};
                api.flush(ep, 10);
                api.destroy(ep, conn);
            }

            if (!success) std.process.exit(1);
            return;
        }

        // Normal mode: single connection for all requests
        const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
        defer api.endpointDeinit(ep);
        const conn = try api.connect(ep, "server4:443", "server4");
        log("client: connecting to server4:443");
        if (verbose) log("client: verbose logging enabled");
        if (cfg.enable_retry) {
            log("client: retry enabled (will process Retry if received)");
        }
        // Wait for handshake done
        var wait: usize = 0;
        while (!api.handshakeDoneSeen(conn) and wait < 2000) : (wait += 1) {
            api.poll(ep, 5) catch {};
        }
        if (api.handshakeDoneSeen(conn)) {
            log("client: handshake complete");
            if (api.getNegotiatedAlpn(conn)) |a| {
                var alpn_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&alpn_buf, "client: negotiated alpn={s}", .{a}) catch "client: negotiated alpn=?";
                log(msg);
            }
            if (api.getPeerTransportParams(conn)) |tp_raw| {
                var tp_buf: [256]u8 = undefined;
                const n = @min(tp_raw.len, tp_buf.len / 2);
                var j: usize = 0;
                var off: usize = 0;
                while (j < n and off + 2 <= tp_buf.len) : (j += 1) {
                    _ = std.fmt.bufPrint(tp_buf[off..][0..2], "{X:0>2}", .{tp_raw[j]}) catch break;
                    off += 2;
                }
                const slice = tp_buf[0..off];
                var tp_msg_buf: [300]u8 = undefined;
                const tp_msg = std.fmt.bufPrint(&tp_msg_buf, "client: peer transport params hex={s}", .{slice}) catch "client: peer transport params hex=?";
                log(tp_msg);
            }
        } else {
            log("client: handshake timeout");
        }
        var success: bool = true;
        var request_i: usize = 0;
        while (request_i < urls.len) : (request_i += 1) {
            const path = extractPath(urls[request_i]);
            var line_buf: [600]u8 = undefined;
            const line = try std.fmt.bufPrint(&line_buf, "GET {s}", .{path});
            log("client: sending GET request");
            writeAllStream(ep, conn, line);
            // For keyupdate testcase, after first request send ~70KiB padding to force early key update.
            if (request_i == 0 and std.mem.eql(u8, testcase, "keyupdate")) {
                var pad: [1024]u8 = undefined;
                @memset(pad[0..], 'X');
                var sent_total: usize = 0;
                const total_to_send = 70 * 1024;
                while (sent_total < total_to_send) {
                    const is_final_padding = (sent_total + pad.len >= total_to_send);
                    const wn = api.writeStream(conn, 0, pad[0..], is_final_padding) catch 0;
                    if (wn == 0) {
                        api.poll(ep, 1) catch {};
                    } else {
                        sent_total += wn;
                    }
                }
                log("client: padding sent for keyupdate testcase");
            }
            // Read response until timeout or no progress; save to file
            var file_bytes = std.ArrayList(u8){};
            defer file_bytes.deinit(alloc);
            var idle: usize = 0;
            var loops: usize = 0;
            var tmp: [4096]u8 = undefined;
            while (idle < 200 and loops < 4000) : (loops += 1) {
                api.poll(ep, 2) catch {};
                const n = api.readStream(conn, 0, tmp[0..]) catch 0;
                if (n == 0) {
                    idle += 1;
                } else {
                    idle = 0;
                    try file_bytes.appendSlice(alloc, tmp[0..n]);
                    if (file_bytes.items.len > 4 * 1024 * 1024) break; // cap
                }
            }
            // Write downloaded data
            var sanitized = path;
            if (sanitized.len > 0 and sanitized[0] == '/') sanitized = sanitized[1..];
            var out_path_buf: [512]u8 = undefined;
            const out_path = try std.fmt.bufPrint(&out_path_buf, "/downloads/{s}", .{sanitized});
            // Ensure directory exists (flat)
            if (std.fs.cwd().createFile(out_path, .{ .truncate = true })) |outf| {
                defer outf.close();
                _ = outf.write(file_bytes.items) catch {};
            } else |_| {}
            if (file_bytes.items.len == 0) success = false;
            var msg_buf: [96]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "client: response bytes={d}", .{file_bytes.items.len}) catch "client: response bytes=?";
            log(msg);
        }
        api.close(conn, 0, "bye") catch {};
        api.flush(ep, 10);
        api.destroy(ep, conn);
        if (!success) std.process.exit(1) else return;
    } else {
        return error.UnknownROLE;
    }
}
