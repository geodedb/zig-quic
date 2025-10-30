const std = @import("std");
const api = @import("quic_api");
// Import connection module for alignment checking of opaque pointers
const quic_conn = @import("quic_conn");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var bind: []const u8 = "127.0.0.1:4433";
    var host: ?[]const u8 = null;
    var port: ?[]const u8 = null;
    var alpn: []const u8 = "h3";
    var insecure = false;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var datagram = false;
    var compat_vn = false;
    var enable_retry = false;
    var token_secret: ?[]const u8 = null;
    var token_expiry_ms: u32 = 60000;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--bind")) {
            bind = args.next().?;
        } else if (std.mem.eql(u8, a, "--host")) {
            host = args.next().?;
        } else if (std.mem.eql(u8, a, "--port")) {
            port = args.next().?;
        } else if (std.mem.eql(u8, a, "--alpn")) {
            alpn = args.next().?;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "--cert")) {
            cert_path = args.next().?;
        } else if (std.mem.eql(u8, a, "--key")) {
            key_path = args.next().?;
        } else if (std.mem.eql(u8, a, "--datagram")) {
            const v = args.next().?;
            datagram = std.mem.eql(u8, v, "true");
        } else if (std.mem.eql(u8, a, "--compatible-vn")) {
            compat_vn = true;
        } else if (std.mem.eql(u8, a, "--retry")) {
            const v = args.next().?;
            enable_retry = std.mem.eql(u8, v, "true");
        } else if (std.mem.eql(u8, a, "--token-secret")) {
            token_secret = args.next().?;
        } else if (std.mem.eql(u8, a, "--token-expiry-ms")) {
            const v = args.next().?;
            token_expiry_ms = std.fmt.parseInt(u32, v, 10) catch token_expiry_ms;
        }
    }

    // If --host and --port are provided, construct bind address
    var bind_buf: [256]u8 = undefined;
    if (host != null and port != null) {
        bind = try std.fmt.bufPrint(&bind_buf, "{s}:{s}", .{ host.?, port.? });
    }

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .cert_path = cert_path,
        .key_path = key_path,
        .enable_datagram = datagram,
        .compatible_vn = compat_vn,
        .enable_retry = enable_retry,
        .token_secret = token_secret,
        .token_expiry_ms = token_expiry_ms,
    };
    // If file-based cert/key provided, load them and stash as inline for endpoint connections.
    var loaded_cert: ?[]u8 = null;
    var loaded_key: ?[]u8 = null;
    defer {
        if (loaded_cert) |cbytes| alloc.free(cbytes);
        if (loaded_key) |kbytes| alloc.free(kbytes);
    }
    if (cert_path != null and key_path != null) {
        // Simple PEM -> DER loader (single object) for CERTIFICATE / (EC) PRIVATE KEY
        const PemLoad = struct {
            fn loadPem(allocator: std.mem.Allocator, path: []const u8, markers: []const []const u8) ![]u8 {
                const data = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024);
                errdefer allocator.free(data);
                var chosen_begin: ?[]const u8 = null;
                var chosen_end: ?[]const u8 = null;
                for (markers) |m| {
                    var buf_begin: [64]u8 = undefined;
                    var buf_end: [64]u8 = undefined;
                    const begin_marker = try std.fmt.bufPrint(&buf_begin, "-----BEGIN {s}-----", .{m});
                    const end_marker = try std.fmt.bufPrint(&buf_end, "-----END {s}-----", .{m});
                    if (std.mem.indexOf(u8, data, begin_marker)) |_| {
                        chosen_begin = try allocator.dupe(u8, begin_marker);
                        chosen_end = try allocator.dupe(u8, end_marker);
                        break;
                    }
                }
                if (chosen_begin == null or chosen_end == null) return error.PemMarkerNotFound;
                defer allocator.free(chosen_begin.?);
                defer allocator.free(chosen_end.?);
                const start = std.mem.indexOf(u8, data, chosen_begin.?) orelse return error.PemMarkerNotFound;
                const rest = data[start + chosen_begin.?.len ..];
                const end_rel = std.mem.indexOf(u8, rest, chosen_end.?) orelse return error.PemMarkerNotFound;
                const b64_region = rest[0..end_rel];
                // Collect base64 characters (skip newlines)
                var tmp = try allocator.alloc(u8, b64_region.len);
                defer allocator.free(tmp);
                var n: usize = 0;
                for (b64_region) |ch| {
                    if (ch == '\n' or ch == '\r') continue;
                    if (ch == ' ') continue;
                    tmp[n] = ch;
                    n += 1;
                }
                // Decode
                const out_buf = try allocator.alloc(u8, (n * 3) / 4 + 8);
                // Compute decoded length manually: every 4 chars -> 3 bytes, minus padding '='.
                var pad: usize = 0;
                if (n >= 2 and tmp[n - 1] == '=') pad += 1;
                if (n >= 2 and tmp[n - 2] == '=') pad += 1;
                const need: usize = (n / 4) * 3 - pad;
                allocator.free(out_buf);
                const exact = try allocator.alloc(u8, need);
                // std.base64 Decoder.decode writes into exact; assume well-formed input.
                std.base64.standard.Decoder.decode(exact, tmp[0..n]) catch |e| {
                    allocator.free(exact);
                    return e;
                };
                return exact;
            }
        };
        loaded_cert = PemLoad.loadPem(alloc, cert_path.?, &[_][]const u8{"CERTIFICATE"}) catch null;
        // Try PKCS#8 first (PRIVATE KEY) then EC PRIVATE KEY as fallback
        loaded_key = PemLoad.loadPem(alloc, key_path.?, &[_][]const u8{ "PRIVATE KEY", "EC PRIVATE KEY" }) catch null;
        if (loaded_cert != null and loaded_key != null) {
            cfg.inline_server_cert_der = loaded_cert;
            cfg.inline_server_priv_p256 = loaded_key;
        }
    }
    const ep = try api.endpointInit(&alloc, bind, &cfg);
    defer api.endpointDeinit(ep);

    std.debug.print("listening on {s}\n", .{bind});

    // Track active connections to avoid storing them in a separate data structure
    // The connections are managed internally by the endpoint
    var active_conns = std.ArrayList(*api.QuicConnection).initCapacity(alloc, 0) catch unreachable;
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
            var buf: [4096]u8 = undefined;
            const n = api.readStream(conn, 0, buf[0..]) catch 0;
            if (n > 0) {
                std.debug.print("stream 0 received {d} bytes\n", .{n});
                _ = api.writeStream(conn, 0, buf[0..n]) catch 0;
            }

            i += 1;
        }
    } // main event loop

}
