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
    var alpn: []const u8 = "h3";
    var insecure = false;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var datagram = false;
    var compat_vn = false;
    var enable_retry = false;
    var token_secret: ?[]const u8 = null;
    var token_expiry_ms: u32 = 60000;
    var real_tls = false;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--bind")) {
            bind = args.next().?;
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
        } else if (std.mem.eql(u8, a, "--real-tls")) {
            real_tls = true;
        }
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
        .real_tls = real_tls,
    };
    // If real TLS requested and file-based cert/key provided, load them and stash as inline for endpoint connections.
    var loaded_cert: ?[]u8 = null;
    var loaded_key: ?[]u8 = null;
    defer {
        if (loaded_cert) |cbytes| alloc.free(cbytes);
        if (loaded_key) |kbytes| alloc.free(kbytes);
    }
    if (real_tls and cert_path != null and key_path != null) {
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

    while (true) {
        // Accept is blocking, so we don't need to poll before it
        const conn = try api.accept(ep);
        std.debug.print("accepted connection\n", .{});

        // Handle the connection
        // Track whether the handshake has been logged.  In previous iterations we
        // attempted to query handshake confirmation via api.isHandshakeConfirmed(),
        // but use‑after‑free issues in the underlying library caused occasional
        // segmentation faults.  To avoid dereferencing stale connection
        // pointers, we no longer call isHandshakeConfirmed() here.
        var stream_opened = false;
        var dgram_buf: [2048]u8 = undefined;
        var buf: [4096]u8 = undefined;
        var iter: usize = 0;
        while (iter < 10000) : (iter += 1) {
            // Drive I/O and timers. Ignore errors from polling.
            api.poll(ep, 5) catch {};

            // If the connection has been marked as closed by the transport or peer, stop
            // processing it. Destroying a drained connection removes it from internal
            // maps and frees its resources, which prevents use‑after‑free in
            // subsequent API calls. Without this check the server could retain a
            // pointer to a retired connection and later dereference invalid memory.
            if (api.isDrained(conn)) {
                api.destroy(ep, conn);
                break;
            }

            // Previously we logged handshake confirmation when 1‑RTT keys became
            // available via api.isHandshakeConfirmed().  However, calling into
            // isHandshakeConfirmed() after a connection has been closed or
            // destroyed could dereference invalid memory.  As a defensive
            // measure we skip this check entirely.  If needed, application code
            // can infer handshake progress by observing successful read/write
            // operations on streams.

            // Echo datagrams back to the peer when datagram support is enabled.
            if (datagram) {
                const dn = api.recvDatagram(conn, &dgram_buf) catch 0;
                if (dn > 0) {
                    _ = api.sendDatagram(conn, dgram_buf[0..dn]) catch 0;
                }
            }

            // Echo stream 0 data back to the client. The first read also
            // indicates that the stream has been opened. Subsequent reads
            // simply echo any received data.
            if (!stream_opened) {
                const n = api.readStream(conn, 0, buf[0..]) catch 0;
                if (n > 0) {
                    stream_opened = true;
                    std.debug.print("stream 0 opened (rx {d} bytes)\n", .{n});
                    _ = api.writeStream(conn, 0, buf[0..n]) catch 0;
                }
            } else {
                const n = api.readStream(conn, 0, buf[0..]) catch 0;
                if (n > 0) {
                    _ = api.writeStream(conn, 0, buf[0..n]) catch 0;
                }
            }
        }
    }
}
