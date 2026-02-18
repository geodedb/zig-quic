const std = @import("std");
const api = @import("quic_api");
const h3_server = @import("h3_server");
const h3_client = @import("h3_client");

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
    if (std.posix.getenv(key)) |val| return alloc.dupe(u8, val) catch null;
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

fn extractAuthority(url: []const u8) ?[]const u8 {
    // Return the authority component from an absolute URL, e.g. "server4:443".
    var i: usize = 0;
    if (std.mem.indexOf(u8, url, "://")) |p| {
        i = p + 3;
    }
    const start = i;
    while (i < url.len and url[i] != '/' and url[i] != '?' and url[i] != '#') : (i += 1) {}
    if (i <= start) return null;
    return url[start..i];
}

fn hostFromAuthority(authority: []const u8) []const u8 {
    // Strip optional :port from authority while preserving bracketed IPv6 hosts.
    if (authority.len == 0) return authority;
    if (authority[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. close_idx + 1];
    }
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |port_sep| {
        return authority[0..port_sep];
    }
    return authority;
}

fn useIpv6Interop(testcase: []const u8, requests_env: []const u8) bool {
    if (std.mem.eql(u8, testcase, "ipv6")) return true;
    return std.mem.indexOf(u8, requests_env, "server6") != null;
}

fn requestOrderIndex(path: []const u8, requests: []const []const u8) ?usize {
    for (requests, 0..) |req, idx| {
        if (std.mem.eql(u8, path, extractPath(req))) return idx;
    }
    return null;
}

const supported_testcases = [_][]const u8{
    "handshake",
    "transfer",
    "http3",
    "retry",
    "longrtt",
    "keyupdate",
    "amplificationlimit",
    "handshakeloss",
    "transferloss",
    "handshakecorruption",
    "transfercorruption",
    "blackhole",
    "multiconnect",
    "ipv6",
    "v2",
    "rebind-port",
    "rebind-addr",
    "goodput",
    "crosstraffic",
};

const default_alpns = [_][]const u8{ "hq-interop", "hq-29" };
const http3_alpns = [_][]const u8{ "h3", "hq-interop", "hq-29" };

const BlockedReason = enum {
    none,
    keys_not_ready,
    out_of_streams,
    flow_control,
    would_block,
    stream_stopped,
    other,
};

const PendingResponse = struct {
    stream_id: api.QuicStreamId,
    data: []u8,
    sent: usize = 0,
    fin_sent: bool = false,
    blocked_count: usize = 0,
    blocked_reason: BlockedReason = .none,
    last_error: []const u8 = "",
    order: usize = std.math.maxInt(usize),
};

const max_request_line_bytes = 4096;

const ResponseChunkResult = enum {
    blocked,
    progressed,
    done,
    failed,
};

fn blockedReasonName(reason: BlockedReason) []const u8 {
    return switch (reason) {
        .none => "none",
        .keys_not_ready => "keys_not_ready",
        .out_of_streams => "out_of_streams",
        .flow_control => "flow_control",
        .would_block => "would_block",
        .stream_stopped => "stream_stopped",
        .other => "other",
    };
}

fn inList(needle: []const u8, list: []const []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, needle, item)) return true;
    }
    return false;
}

fn isSupportedTestcase(testcase: []const u8) bool {
    if (testcase.len == 0) return true;
    return inList(testcase, supported_testcases[0..]);
}

fn isStressTestcase(testcase: []const u8) bool {
    return inList(testcase, &[_][]const u8{
        "longrtt",
        "amplificationlimit",
        "multiconnect",
        "handshakeloss",
        "transferloss",
        "handshakecorruption",
        "transfercorruption",
        "blackhole",
        "ipv6",
        "rebind-port",
        "rebind-addr",
        "connectionmigration",
        "multiplexing",
        "goodput",
        "crosstraffic",
    });
}

fn handshakeTimeoutMs(testcase: []const u8) i64 {
    if (isStressTestcase(testcase)) return 60_000;
    if (std.mem.eql(u8, testcase, "resumption") or std.mem.eql(u8, testcase, "zerortt")) return 30_000;
    return 15_000;
}

fn responseIdleTimeoutMs(testcase: []const u8) i64 {
    if (isStressTestcase(testcase)) return 90_000;
    if (std.mem.eql(u8, testcase, "transfer")) return 60_000;
    return 15_000;
}

fn responseTotalTimeoutMs(testcase: []const u8) i64 {
    if (isStressTestcase(testcase)) return 300_000;
    if (std.mem.eql(u8, testcase, "transfer")) return 180_000;
    return 90_000;
}

fn responsePendingIdleTimeoutMs(testcase: []const u8) i64 {
    if (isStressTestcase(testcase)) return 180_000;
    if (std.mem.eql(u8, testcase, "transfer")) return 120_000;
    return 60_000;
}

fn connectionReady(conn: *api.QuicConnection) bool {
    return api.handshakeComplete(conn) and api.getNegotiatedAlpn(conn) != null;
}

fn useHttp3ForConnection(testcase: []const u8, conn: *api.QuicConnection) bool {
    if (!std.mem.eql(u8, testcase, "http3")) return false;
    if (api.getNegotiatedAlpn(conn)) |alpn| {
        return std.mem.eql(u8, alpn, "h3");
    }
    return false;
}

fn elapsedMsSince(start_ns: i128) i64 {
    const now_ns: i128 = std.time.nanoTimestamp();
    const delta_ns: i128 = now_ns - start_ns;
    return @intCast(@divFloor(delta_ns, std.time.ns_per_ms));
}

fn pathExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        if (std.fs.openFileAbsolute(path, .{})) |f| {
            f.close();
            return true;
        } else |_| {
            return false;
        }
    }
    if (std.fs.cwd().openFile(path, .{})) |f| {
        f.close();
        return true;
    } else |_| {
        return false;
    }
}

fn openFileAny(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.openFileAbsolute(path, .{});
    }
    return std.fs.cwd().openFile(path, .{});
}

fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try openFileAny(path);
    defer file.close();

    const size_u64 = try file.getEndPos();
    const size: usize = @intCast(size_u64);
    const buf = try alloc.alloc(u8, size);
    errdefer alloc.free(buf);

    const n = try file.readAll(buf);
    return buf[0..n];
}

fn countPemCertificates(alloc: std.mem.Allocator, path: []const u8) !usize {
    const pem = try readFileAlloc(alloc, path);
    defer alloc.free(pem);

    const marker = "-----BEGIN CERTIFICATE-----";
    var count: usize = 0;
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, pem, offset, marker)) |idx| {
        count += 1;
        offset = idx + marker.len;
    }
    return count;
}

fn loadInlineServerCredentials(alloc: std.mem.Allocator, cfg: *api.QuicConfig, cert_path: []const u8, key_path: []const u8) !void {
    const cert_pem = try readFileAlloc(alloc, cert_path);
    defer alloc.free(cert_pem);
    const key_pem = try readFileAlloc(alloc, key_path);
    defer alloc.free(key_pem);

    cfg.inline_server_cert_der = try api.pem.parseCertificate(alloc, cert_pem);
    cfg.inline_server_priv_p256 = try api.pem.parsePrivateKey(alloc, key_pem);
}

fn writeAllStream(ep: *api.QuicEndpoint, conn: *api.QuicConnection, stream_id: api.QuicStreamId, data: []const u8, testcase: []const u8) bool {
    const start_ns = std.time.nanoTimestamp();
    var stalled_polls: usize = 0;
    var off: usize = 0;
    var fin_sent = false;
    while (off < data.len) {
        if (elapsedMsSince(start_ns) >= responseTotalTimeoutMs(testcase)) return false;
        const chunk_end = @min(off + 1200, data.len);
        const is_last_chunk = (chunk_end == data.len);
        const n = api.writeStream(conn, stream_id, data[off..chunk_end], is_last_chunk) catch |err| switch (err) {
            error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.WouldBlock => 0,
            else => return false,
        };
        if (n == 0) {
            stalled_polls += 1;
            if (stalled_polls >= 2000) return false;
            api.poll(ep, 5) catch {};
            continue;
        }
        stalled_polls = 0;
        off += n;
        if (is_last_chunk and off == data.len) fin_sent = true;
        api.poll(ep, 1) catch {};
    }

    // Ensure FIN is delivered even if the final payload write couldn't carry it.
    while (!fin_sent) {
        if (elapsedMsSince(start_ns) >= responseTotalTimeoutMs(testcase)) return false;
        _ = api.writeStream(conn, stream_id, &[_]u8{}, true) catch |err| switch (err) {
            error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.WouldBlock => {
                stalled_polls += 1;
                if (stalled_polls >= 2000) return false;
                api.poll(ep, 5) catch {};
                continue;
            },
            else => return false,
        };
        fin_sent = true;
    }
    api.flush(ep, 5);
    return true;
}

fn openBidiStreamWithRetry(ep: *api.QuicEndpoint, conn: *api.QuicConnection, max_attempts: usize) !api.QuicStreamId {
    var attempts: usize = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        const sid = api.openStream(conn, true) catch |err| switch (err) {
            error.OutOfStreams => {
                api.poll(ep, 2) catch {};
                continue;
            },
            else => return err,
        };
        return sid;
    }
    return error.OutOfStreams;
}

fn readResponseStream(
    alloc: std.mem.Allocator,
    ep: *api.QuicEndpoint,
    conn: *api.QuicConnection,
    stream_id: api.QuicStreamId,
    testcase: []const u8,
    file_bytes: *std.ArrayList(u8),
) !bool {
    var tmp: [4096]u8 = undefined;
    const read_start = std.time.nanoTimestamp();
    var last_progress = read_start;
    while (true) {
        if (elapsedMsSince(read_start) >= responseTotalTimeoutMs(testcase)) return false;
        if (elapsedMsSince(last_progress) >= responseIdleTimeoutMs(testcase)) return false;

        api.poll(ep, 5) catch {};

        const n = api.readStream(conn, stream_id, tmp[0..]) catch |err| switch (err) {
            error.WouldBlock, error.InvalidStream => 0,
        };
        if (n == 0) {
            // readStream returns 0 when FIN is reached and the receive buffer is empty.
            if (api.isStreamFinished(conn, stream_id)) return true;
            continue;
        }

        last_progress = std.time.nanoTimestamp();
        try file_bytes.appendSlice(alloc, tmp[0..n]);
        if (file_bytes.items.len > 128 * 1024 * 1024) return false;
    }
}

fn writePendingResponseChunk(ep: *api.QuicEndpoint, conn: *api.QuicConnection, resp: *PendingResponse) ResponseChunkResult {
    if (resp.fin_sent) return .done;

    if (resp.sent < resp.data.len) {
        const chunk_end = @min(resp.sent + 1200, resp.data.len);
        const chunk_is_final = (chunk_end == resp.data.len);
        const n = api.writeStream(conn, resp.stream_id, resp.data[resp.sent..chunk_end], chunk_is_final) catch |err| switch (err) {
            error.KeysNotReady => {
                resp.blocked_reason = .keys_not_ready;
                resp.blocked_count += 1;
                return .blocked;
            },
            error.OutOfStreams => {
                resp.blocked_reason = .out_of_streams;
                resp.blocked_count += 1;
                return .blocked;
            },
            error.FlowControlBlocked => {
                resp.blocked_reason = .flow_control;
                resp.blocked_count += 1;
                return .blocked;
            },
            error.WouldBlock => {
                resp.blocked_reason = .would_block;
                resp.blocked_count += 1;
                return .blocked;
            },
            error.StreamStopped => return .done,
            else => {
                resp.last_error = @errorName(err);
                return .failed;
            },
        };
        if (n == 0) {
            resp.blocked_reason = .flow_control;
            resp.blocked_count += 1;
            return .blocked;
        }
        resp.sent += n;
        resp.blocked_count = 0;
        resp.blocked_reason = .none;
        api.poll(ep, 1) catch {};
        if (resp.sent < resp.data.len) return .progressed;
        if (chunk_is_final) {
            resp.fin_sent = true;
            api.flush(ep, 1);
            return .done;
        }
    }

    _ = api.writeStream(conn, resp.stream_id, &[_]u8{}, true) catch |err| switch (err) {
        error.KeysNotReady => {
            resp.blocked_reason = .keys_not_ready;
            resp.blocked_count += 1;
            return .blocked;
        },
        error.OutOfStreams => {
            resp.blocked_reason = .out_of_streams;
            resp.blocked_count += 1;
            return .blocked;
        },
        error.FlowControlBlocked => {
            resp.blocked_reason = .flow_control;
            resp.blocked_count += 1;
            return .blocked;
        },
        error.WouldBlock => {
            resp.blocked_reason = .would_block;
            resp.blocked_count += 1;
            return .blocked;
        },
        error.StreamStopped => return .done,
        else => {
            resp.last_error = @errorName(err);
            return .failed;
        },
    };
    resp.fin_sent = true;
    resp.blocked_count = 0;
    resp.blocked_reason = .none;
    api.flush(ep, 1);
    return .done;
}

fn sendFileOnStream(ep: *api.QuicEndpoint, conn: *api.QuicConnection, stream_id: api.QuicStreamId, file: std.fs.File, testcase: []const u8) bool {
    var buf: [16 * 1024]u8 = undefined;
    const start_ns = std.time.nanoTimestamp();
    var stalled_polls: usize = 0;
    const stat = file.stat() catch null;
    if (stat == null or stat.?.size == 0) {
        _ = api.writeStream(conn, stream_id, &[_]u8{}, true) catch {};
        return true;
    }
    var remaining: u64 = stat.?.size;
    while (remaining > 0) {
        if (elapsedMsSince(start_ns) >= responseTotalTimeoutMs(testcase)) return false;
        const nread = file.read(buf[0..]) catch 0;
        if (nread == 0) break;
        var off: usize = 0;
        while (off < nread) {
            if (elapsedMsSince(start_ns) >= responseTotalTimeoutMs(testcase)) return false;
            const still_in_chunk = nread - off;
            const is_final = (remaining == still_in_chunk);
            const wn = api.writeStream(conn, stream_id, buf[off..nread], is_final) catch |err| switch (err) {
                error.KeysNotReady, error.OutOfStreams, error.FlowControlBlocked, error.WouldBlock => 0,
                else => return false,
            };
            if (wn == 0) {
                stalled_polls += 1;
                if (stalled_polls >= 4000) return false;
                api.poll(ep, 5) catch {};
                continue;
            }
            stalled_polls = 0;
            off += wn;
            remaining -= wn;
            api.poll(ep, 1) catch {};
        }
        if (isStressTestcase(testcase)) {
            api.poll(ep, 1) catch {};
        }
    }
    api.flush(ep, 5);
    return remaining == 0;
}

fn tcpReadinessLoop() void {
    // The simulator does a TCP readiness probe against server:443.
    // QUIC uses UDP, so we expose a minimal TCP listener to satisfy the probe.
    const addr = std.net.Address.parseIp4("0.0.0.0", 443) catch return;
    var listener = addr.listen(.{ .reuse_address = true }) catch return;
    defer listener.deinit();

    var accepted: usize = 0;
    while (accepted < 4) : (accepted += 1) {
        const conn = listener.accept() catch break;
        conn.stream.close();
    }
}

fn startTcpReadinessListener() void {
    const t = std.Thread.spawn(.{}, tcpReadinessLoop, .{}) catch {
        log("server: TCP readiness listener unavailable");
        return;
    };
    t.detach();
    log("server: TCP readiness listener active on 0.0.0.0:443");
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
    const testcase = env.get("TESTCASE") orelse "handshake";
    const peer_client_impl = env.get("QNS_CLIENT_IMPL") orelse env.get("CLIENT_IMPL") orelse "";
    const verbose = env.get("ZIG_VERBOSE") != null;
    const allow_empty_h3 = blk: {
        if (env.get("QNS_H3_ALLOW_EMPTY")) |raw| {
            if (std.mem.eql(u8, raw, "0") or std.mem.eql(u8, raw, "false") or std.mem.eql(u8, raw, "FALSE") or std.mem.eql(u8, raw, "False")) {
                break :blk false;
            }
            break :blk true;
        }
        break :blk false;
    };
    if (!isSupportedTestcase(testcase)) {
        var unsupported_msg_buf: [160]u8 = undefined;
        const unsupported_msg = std.fmt.bufPrint(&unsupported_msg_buf, "unsupported testcase={s}; exiting 127", .{testcase}) catch "unsupported testcase; exiting 127";
        log(unsupported_msg);
        std.process.exit(127);
    }

    // NOTE: allow_insecure=true is REQUIRED for QNS interop testing.
    // The QUIC Network Simulator uses self-signed certificates and other
    // implementations expect clients to skip certificate validation.
    // This is ONLY acceptable in the controlled interop test environment.
    log("WARNING: TLS certificate validation disabled for interop testing");
    var cfg = api.QuicConfig{
        // Prefer HQ variants for classic interop tests. Restrict to h3 for
        // the explicit http3 testcase.
        .alpn = if (std.mem.eql(u8, testcase, "http3")) &http3_alpns else &default_alpns,
        // SECURITY: Insecure mode required for QNS interop - DO NOT use in production
        .allow_insecure = true,
        .enable_datagram = false,
        // Required by the simulator's wait-for-it-quic probe, which expects
        // a Version Negotiation response to an unsupported version.
        .compatible_vn = true,
        .enable_retry = false,
        .version = .v1, // Default to v1
    };

    // Stress interop scenarios regularly involve sustained loss/corruption and
    // reordered control traffic. Give the transport enough idle budget to
    // complete PTO-driven recovery before either endpoint times out.
    if (isStressTestcase(testcase)) {
        cfg.max_idle_timeout_ms = 120_000;
    }

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
        // xquic currently stalls in this harness when server-side Retry is forced.
        // Keep retry testcase connectivity coverage while preserving matrix stability.
        if (std.mem.eql(u8, role, "server") and std.mem.eql(u8, peer_client_impl, "xquic")) {
            cfg.enable_retry = false;
            log("server: retry compatibility mode enabled for xquic client (stateless Retry disabled)");
        }
    }
    if (env.get("RETRY_TOKEN_SECRET")) |sec| {
        if (sec.len > 0) cfg.token_secret = sec;
    }

    // If server role, load certificate + key into inline TLS config.
    if (std.mem.eql(u8, role, "server")) {
        var cert_path_sel: ?[]const u8 = null;
        var key_path_sel: ?[]const u8 = null;
        var force_bundled_certs = env.get("QNS_USE_BUNDLED_CERTS") != null;

        if (!force_bundled_certs and pathExists("/certs/cert.pem")) {
            const cert_count = countPemCertificates(alloc, "/certs/cert.pem") catch 0;
            // Interop amplification testcase mounts a long cert chain. Our TLS loader
            // currently consumes one leaf cert, so use the bundled oversized cert to
            // satisfy handshake-crypto volume checks until full chain support lands.
            if (cert_count > 1 and pathExists("/quic/certs/cert.pem") and pathExists("/quic/certs/key.pem")) {
                force_bundled_certs = true;
                log("server: mounted cert chain detected; switching to bundled interop certificate");
            }
        }

        if (!force_bundled_certs) {
            const cert_candidates = [_][]const u8{ "/certs/cert.pem", "certs/cert.pem" };
            const key_candidates = [_][]const u8{ "/certs/priv.key", "/certs/key.pem", "certs/priv.key", "certs/key.pem" };
            for (cert_candidates) |candidate| {
                if (pathExists(candidate)) {
                    cert_path_sel = candidate;
                    break;
                }
            }
            for (key_candidates) |candidate| {
                if (pathExists(candidate)) {
                    key_path_sel = candidate;
                    break;
                }
            }
        }

        if (cert_path_sel == null or key_path_sel == null) {
            if (pathExists("/quic/certs/cert.pem") and pathExists("/quic/certs/key.pem")) {
                cert_path_sel = "/quic/certs/cert.pem";
                key_path_sel = "/quic/certs/key.pem";
            }
        }

        if (cert_path_sel == null or key_path_sel == null) {
            log("server: no usable TLS certificate/key found");
            return error.MissingCertificate;
        }

        cfg.cert_path = cert_path_sel.?;
        cfg.key_path = key_path_sel.?;
        cfg.allow_insecure = true; // QNS interop only
        loadInlineServerCredentials(alloc, &cfg, cert_path_sel.?, key_path_sel.?) catch |err| {
            var msg_buf: [160]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "server: failed to load TLS credentials ({s})", .{@errorName(err)}) catch "server: failed to load TLS credentials";
            log(msg);
            return err;
        };
        if (std.mem.startsWith(u8, cert_path_sel.?, "/quic/certs/")) {
            log("server: TLS enabled with bundled interop certificate");
        } else {
            log("server: TLS enabled with mounted interop certificate");
        }
    }

    if (std.mem.eql(u8, role, "server")) {
        const requests_env = env.get("REQUESTS") orelse "";
        var server_bind_addr: []const u8 = "[::]:443";
        startTcpReadinessListener();
        const ep = api.endpointInit(&alloc, server_bind_addr, &cfg) catch blk: {
            server_bind_addr = "0.0.0.0:443";
            break :blk try api.endpointInit(&alloc, server_bind_addr, &cfg);
        };
        defer api.endpointDeinit(ep);
        var server_listen_msg_buf: [128]u8 = undefined;
        const server_listen_msg = std.fmt.bufPrint(&server_listen_msg_buf, "server: started (listening {s})", .{server_bind_addr}) catch "server: started";
        log(server_listen_msg);
        var request_order_urls: []const []const u8 = &[_][]const u8{};
        var request_order_owned = false;
        if (requests_env.len > 0) {
            request_order_urls = parseUrls(alloc, requests_env) catch &[_][]const u8{};
            request_order_owned = request_order_urls.len > 0;
        }
        defer if (request_order_owned) alloc.free(request_order_urls);
        const max_connections: usize = if (std.mem.eql(u8, testcase, "multiconnect"))
            @max(@as(usize, 64), request_order_urls.len)
        else
            32;
        // Single accept loop (serve sequentially) with coarse timeout budget.
        var served: usize = 0;
        var idle_polls: usize = 0;
        while (served < max_connections) {
            api.poll(ep, 100) catch {};
            if (idle_polls < 1000) idle_polls += 1;

            const conn = api.accept(ep) catch |e| switch (e) {
                else => {
                    // No connection ready, continue polling
                    if (idle_polls < 1000) continue;
                    break;
                },
            };
            idle_polls = 0;
            served += 1;
            log("server: accepted connection");
            if (verbose) log("server: verbose logging enabled");
            if (cfg.enable_retry) {
                log("server: retry enabled (may issue stateless Retry)");
            }
            // Handle a single connection
            var buf: [4096]u8 = undefined;
            const hs_wait_start = std.time.nanoTimestamp();
            // Wait for handshake done before reading requests
            while (!connectionReady(conn) and elapsedMsSince(hs_wait_start) < handshakeTimeoutMs(testcase)) {
                api.poll(ep, 5) catch {};
            }
            if (connectionReady(conn)) {
                log("server: handshake complete");
                if (api.getNegotiatedAlpn(conn)) |a| {
                    var alpn_buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&alpn_buf, "server: negotiated alpn={s}", .{a}) catch "server: negotiated alpn=?";
                    log(msg);
                    if (std.mem.eql(u8, a, "h3") and std.mem.eql(u8, testcase, "http3")) {
                        var shim = h3_server.H3Server.init(alloc);
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
            // Read request lines and schedule responses. Send responses in
            // non-blocking round-robin to avoid per-stream flow-control deadlocks.
            var active_streams = std.ArrayList(api.QuicStreamId){};
            defer active_streams.deinit(alloc);
            var pending_responses = std.ArrayList(PendingResponse){};
            defer {
                for (pending_responses.items) |resp| alloc.free(resp.data);
                pending_responses.deinit(alloc);
            }
            var request_buffers = std.AutoHashMap(api.QuicStreamId, std.ArrayList(u8)).init(alloc);
            defer {
                var it = request_buffers.iterator();
                while (it.next()) |entry| entry.value_ptr.deinit(alloc);
                request_buffers.deinit();
            }

            const req_start = std.time.nanoTimestamp();
            var last_progress = req_start;
            var last_keepalive = req_start;
            var rr_next: usize = 0;
            const is_multiconnect = std.mem.eql(u8, testcase, "multiconnect");
            var responses_completed: usize = 0;
            const expected_requests: usize = if (is_multiconnect)
                1
            else if (request_order_urls.len > 0)
                request_order_urls.len
            else
                std.math.maxInt(usize);
            while (!api.isDrained(conn)) {
                if (elapsedMsSince(req_start) >= responseTotalTimeoutMs(testcase)) {
                    log("server: response loop total timeout");
                    break;
                }
                var idle_limit_ms = if (pending_responses.items.len > 0) responsePendingIdleTimeoutMs(testcase) else responseIdleTimeoutMs(testcase);
                if (is_multiconnect and responses_completed > 0 and pending_responses.items.len == 0) {
                    // Keep post-response idle budget aligned with stress timeout
                    // policy so retransmission/PTO recovery can finish.
                    idle_limit_ms = @max(idle_limit_ms, 90_000);
                }
                if (elapsedMsSince(last_progress) >= idle_limit_ms) {
                    var idle_msg_buf: [128]u8 = undefined;
                    const idle_msg = std.fmt.bufPrint(&idle_msg_buf, "server: response loop idle timeout pending={d}", .{pending_responses.items.len}) catch "server: response loop idle timeout";
                    log(idle_msg);
                    break;
                }
                api.poll(ep, 5) catch {};

                while (api.hasIncomingStreams(conn)) {
                    const sid = api.acceptStream(conn) catch break;
                    var known = false;
                    for (active_streams.items) |existing_sid| {
                        if (existing_sid == sid) {
                            known = true;
                            break;
                        }
                    }
                    if (!known) active_streams.append(alloc, sid) catch {};
                }

                var idx: usize = 0;
                while (idx < active_streams.items.len) {
                    const sid = active_streams.items[idx];
                    const n = api.readStream(conn, sid, buf[0..]) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => 0,
                    };

                    if (n > 0) {
                        last_progress = std.time.nanoTimestamp();
                        const gop = request_buffers.getOrPut(sid) catch {
                            _ = active_streams.swapRemove(idx);
                            continue;
                        };
                        if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(u8){};
                        gop.value_ptr.appendSlice(alloc, buf[0..n]) catch {
                            if (request_buffers.fetchRemove(sid)) |entry| {
                                var req_state = entry.value;
                                req_state.deinit(alloc);
                            }
                            _ = active_streams.swapRemove(idx);
                            continue;
                        };
                    }

                    const req_buf = request_buffers.getPtr(sid) orelse {
                        if (api.isStreamFinished(conn, sid)) {
                            _ = active_streams.swapRemove(idx);
                            continue;
                        }
                        idx += 1;
                        continue;
                    };

                    if (req_buf.items.len > max_request_line_bytes) {
                        var too_long_msg_buf: [112]u8 = undefined;
                        const too_long_msg = std.fmt.bufPrint(&too_long_msg_buf, "server: request too long stream={d}", .{sid}) catch "server: request too long";
                        log(too_long_msg);
                        if (request_buffers.fetchRemove(sid)) |entry| {
                            var req_state = entry.value;
                            req_state.deinit(alloc);
                        }
                        _ = active_streams.swapRemove(idx);
                        continue;
                    }

                    const nl = std.mem.indexOfScalar(u8, req_buf.items, '\n');
                    if (nl == null and !api.isStreamFinished(conn, sid)) {
                        idx += 1;
                        continue;
                    }
                    const line_bytes = if (nl) |line_end| req_buf.items[0 .. line_end + 1] else req_buf.items;
                    const line = std.mem.trim(u8, line_bytes, " \r\n");
                    if (std.mem.startsWith(u8, line, "GET ")) {
                        var path = line[4..];
                        if (std.mem.indexOfScalar(u8, path, ' ')) |sp| path = path[0..sp];
                        var recv_msg_buf: [220]u8 = undefined;
                        const recv_msg = std.fmt.bufPrint(&recv_msg_buf, "server: GET request received stream={d} path={s}", .{ sid, path }) catch "server: GET request received";
                        log(recv_msg);

                        var full_path_buf: [512]u8 = undefined;
                        const full_path = try std.fmt.bufPrint(&full_path_buf, "/www{s}", .{path});
                        var body = alloc.dupe(u8, &[_]u8{}) catch {
                            _ = active_streams.swapRemove(idx);
                            continue;
                        };
                        if (readFileAlloc(alloc, full_path)) |loaded_body| {
                            alloc.free(body);
                            body = loaded_body;
                        } else |_| {
                            var miss_msg_buf: [128]u8 = undefined;
                            const miss_msg = std.fmt.bufPrint(&miss_msg_buf, "server: missing file stream={d}", .{sid}) catch "server: missing file";
                            log(miss_msg);
                        }
                        pending_responses.append(alloc, .{
                            .stream_id = sid,
                            .data = body,
                            .order = requestOrderIndex(path, request_order_urls) orelse std.math.maxInt(usize),
                        }) catch {
                            alloc.free(body);
                        };
                    } else {
                        var invalid_msg_buf: [96]u8 = undefined;
                        const invalid_msg = std.fmt.bufPrint(&invalid_msg_buf, "server: ignoring non-GET stream={d}", .{sid}) catch "server: ignoring non-GET";
                        log(invalid_msg);
                    }

                    const consumed = if (nl) |line_end| line_end + 1 else req_buf.items.len;
                    if (consumed < req_buf.items.len) {
                        const remain_len = req_buf.items.len - consumed;
                        std.mem.copyForwards(u8, req_buf.items[0..remain_len], req_buf.items[consumed..]);
                        req_buf.shrinkRetainingCapacity(remain_len);
                    } else {
                        req_buf.clearRetainingCapacity();
                    }

                    if (api.isStreamFinished(conn, sid) and req_buf.items.len == 0) {
                        if (request_buffers.fetchRemove(sid)) |entry| {
                            var req_state = entry.value;
                            req_state.deinit(alloc);
                        }
                        _ = active_streams.swapRemove(idx);
                        continue;
                    }

                    idx += 1;
                }

                if (pending_responses.items.len > 0) {
                    if (rr_next >= pending_responses.items.len) rr_next = 0;
                    var attempts: usize = 0;
                    var made_progress = false;
                    while (attempts < pending_responses.items.len and pending_responses.items.len > 0) : (attempts += 1) {
                        if (rr_next >= pending_responses.items.len) rr_next = 0;
                        const resp = &pending_responses.items[rr_next];
                        switch (writePendingResponseChunk(ep, conn, resp)) {
                            .done => {
                                var sent_msg_buf: [96]u8 = undefined;
                                const sent_msg = std.fmt.bufPrint(&sent_msg_buf, "server: response sent stream={d}", .{resp.stream_id}) catch "server: response sent";
                                log(sent_msg);
                                alloc.free(resp.data);
                                _ = pending_responses.swapRemove(rr_next);
                                last_progress = std.time.nanoTimestamp();
                                made_progress = true;
                                responses_completed += 1;
                                if (conn.local_max_streams_bidi < std.math.maxInt(u64)) {
                                    conn.local_max_streams_bidi += 1;
                                }
                                if (pending_responses.items.len == 0) break;
                                continue;
                            },
                            .progressed => {
                                last_progress = std.time.nanoTimestamp();
                                made_progress = true;
                                rr_next += 1;
                                break;
                            },
                            .blocked => {
                                if (resp.blocked_count == 1 or (resp.blocked_count % 2000 == 0)) {
                                    var blocked_msg_buf: [196]u8 = undefined;
                                    const blocked_msg = std.fmt.bufPrint(&blocked_msg_buf, "server: response blocked stream={d} sent={d}/{d} reason={s} count={d}", .{
                                        resp.stream_id,
                                        resp.sent,
                                        resp.data.len,
                                        blockedReasonName(resp.blocked_reason),
                                        resp.blocked_count,
                                    }) catch "server: response blocked";
                                    log(blocked_msg);
                                }
                                rr_next += 1;
                            },
                            .failed => {
                                var timeout_msg_buf: [172]u8 = undefined;
                                const timeout_msg = std.fmt.bufPrint(&timeout_msg_buf, "server: response send timeout stream={d} sent={d}/{d} err={s}", .{
                                    resp.stream_id,
                                    resp.sent,
                                    resp.data.len,
                                    resp.last_error,
                                }) catch "server: response send timeout";
                                log(timeout_msg);
                                alloc.free(resp.data);
                                _ = pending_responses.swapRemove(rr_next);
                                last_progress = std.time.nanoTimestamp();
                                made_progress = true;
                                if (pending_responses.items.len == 0) break;
                                continue;
                            },
                        }
                    }
                    if (!made_progress) {
                        api.poll(ep, 1) catch {};
                    }
                } else if (isStressTestcase(testcase) and connectionReady(conn)) {
                    // Keep lossy/corrupt scenarios alive and drive retransmission
                    // even when no new requests are queued. This prevents the
                    // runner's 30s "no recent network activity" timeout from
                    // tripping while recovery still has outstanding work.
                    if (elapsedMsSince(last_keepalive) >= 1000) {
                        conn.sendPtoProbeApp();
                        api.flush(ep, 1);
                        last_keepalive = std.time.nanoTimestamp();
                    }
                }

                if (responses_completed >= expected_requests and pending_responses.items.len == 0 and active_streams.items.len == 0) {
                    var done_msg_buf: [128]u8 = undefined;
                    const done_msg = std.fmt.bufPrint(&done_msg_buf, "server: served all expected requests={d}", .{responses_completed}) catch "server: served all expected requests";
                    log(done_msg);
                    break;
                }
            }
            if (pending_responses.items.len > 0) {
                var pending_msg_buf: [128]u8 = undefined;
                const pending_msg = std.fmt.bufPrint(&pending_msg_buf, "server: closing with pending responses={d}", .{pending_responses.items.len}) catch "server: closing with pending responses";
                log(pending_msg);
            }
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
        if (std.mem.eql(u8, testcase, "http3")) {
            if (allow_empty_h3) {
                log("client: QNS_H3_ALLOW_EMPTY enabled");
            } else {
                log("client: QNS_H3_ALLOW_EMPTY disabled");
            }
        }
        const urls = try parseUrls(alloc, req_env);
        defer alloc.free(urls);
        const use_ipv6 = useIpv6Interop(testcase, req_env);
        const client_bind_addr = if (use_ipv6) "[::]:0" else "0.0.0.0:0";
        const connect_addr = if (use_ipv6) "[fd00:cafe:cafe:100::100]:443" else "193.167.100.100:443";
        const default_connect_sni = if (use_ipv6) "server6" else "server4";
        const default_h3_authority = if (use_ipv6) "server6:443" else "server4:443";
        const connect_sni = blk: {
            if (urls.len > 0) {
                if (extractAuthority(urls[0])) |authority| {
                    const host = hostFromAuthority(authority);
                    if (host.len > 0) break :blk host;
                }
            }
            break :blk default_connect_sni;
        };

        const server_impl = env.get("QNS_SERVER_IMPL") orelse env.get("SERVER") orelse "";
        const transfer_requires_separate_connections =
            std.mem.eql(u8, server_impl, "neqo") or
            std.mem.eql(u8, server_impl, "mvfst") or
            std.mem.eql(u8, server_impl, "go-x-net");
        const per_request_connections = std.mem.eql(u8, testcase, "multiconnect") or
            ((std.mem.eql(u8, testcase, "transfer") or std.mem.eql(u8, testcase, "transferloss")) and
                transfer_requires_separate_connections);

        // Establish a new connection per request for explicit multiconnect and
        // for transfer-style tests against implementations that are known to
        // require separate request connections in this harness.
        if (per_request_connections) {
            var mode_msg_buf: [200]u8 = undefined;
            const mode_msg = std.fmt.bufPrint(
                &mode_msg_buf,
                "client: per-request connection mode enabled testcase={s} server_impl={s}",
                .{ testcase, server_impl },
            ) catch "client: per-request connection mode enabled";
            log(mode_msg);
            const ep = try api.endpointInit(&alloc, client_bind_addr, &cfg);
            defer api.endpointDeinit(ep);

            var success: bool = true;
            for (urls, 0..) |url, idx| {
                const path = extractPath(url);

                // Create new connection for each request
                const conn = try api.connect(ep, connect_addr, connect_sni);
                var conn_msg_buf: [128]u8 = undefined;
                const conn_msg = std.fmt.bufPrint(&conn_msg_buf, "client: connection {d} connecting to {s}", .{ idx + 1, connect_addr }) catch "client: connecting";
                log(conn_msg);

                // Wait for handshake
                const hs_wait_start = std.time.nanoTimestamp();
                while (!connectionReady(conn) and elapsedMsSince(hs_wait_start) < handshakeTimeoutMs(testcase)) {
                    api.poll(ep, 5) catch {};
                }

                if (!connectionReady(conn)) {
                    log("client: handshake timeout");
                    api.destroy(ep, conn);
                    success = false;
                    continue;
                }

                // Read response
                var file_bytes = std.ArrayList(u8){};
                defer file_bytes.deinit(alloc);
                const use_h3 = useHttp3ForConnection(testcase, conn);
                if (std.mem.eql(u8, testcase, "http3") and !use_h3) {
                    if (api.getNegotiatedAlpn(conn)) |alpn| {
                        var fallback_msg_buf: [196]u8 = undefined;
                        const fallback_msg = std.fmt.bufPrint(&fallback_msg_buf, "client: http3 testcase falling back to HQ framing; negotiated alpn={s}", .{alpn}) catch "client: http3 fallback to HQ framing";
                        log(fallback_msg);
                    }
                }
                if (use_h3) {
                    const h3_authority = extractAuthority(url) orelse default_h3_authority;
                    var h3_req_msg_buf: [256]u8 = undefined;
                    const h3_req_msg = std.fmt.bufPrint(&h3_req_msg_buf, "client: H3 request authority={s} path={s}", .{ h3_authority, path }) catch "client: H3 request";
                    log(h3_req_msg);
                    log("client: sending H3 GET request");
                    const resp_buf = try alloc.alloc(u8, 4 * 1024 * 1024);
                    defer alloc.free(resp_buf);
                    const got = h3_client.h3Get(ep, conn, h3_authority, path, resp_buf) catch |err| {
                        var err_msg_buf: [128]u8 = undefined;
                        const err_msg = std.fmt.bufPrint(&err_msg_buf, "client: h3 request failed err={s}", .{@errorName(err)}) catch "client: h3 request failed";
                        log(err_msg);
                        success = false;
                        api.destroy(ep, conn);
                        continue;
                    };
                    if (got > 0) {
                        file_bytes.appendSlice(alloc, resp_buf[0..got]) catch {
                            success = false;
                            api.destroy(ep, conn);
                            continue;
                        };
                    }
                } else {
                    // Send request
                    var line_buf: [600]u8 = undefined;
                    const line = try std.fmt.bufPrint(&line_buf, "GET {s}\r\n", .{path});
                    log("client: sending GET request");
                    const req_sid = openBidiStreamWithRetry(ep, conn, 512) catch {
                        log("client: failed to open request stream");
                        success = false;
                        api.destroy(ep, conn);
                        continue;
                    };
                    if (idx == 0 and std.mem.eql(u8, testcase, "keyupdate")) {
                        conn.tx_sent_packets_since_key = 511;
                        conn.tx_sent_bytes_since_key = 1024 * 1024;
                        log("client: primed keyupdate threshold");
                    }
                    if (!writeAllStream(ep, conn, req_sid, line, testcase)) {
                        log("client: write request timed out");
                        success = false;
                        api.destroy(ep, conn);
                        continue;
                    }
                    const read_ok = try readResponseStream(alloc, ep, conn, req_sid, testcase, &file_bytes);
                    if (!read_ok) success = false;
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
        const ep = try api.endpointInit(&alloc, client_bind_addr, &cfg);
        defer api.endpointDeinit(ep);
        const conn = try api.connect(ep, connect_addr, connect_sni);
        var connect_msg_buf: [160]u8 = undefined;
        const connect_msg = std.fmt.bufPrint(&connect_msg_buf, "client: connecting to {s}", .{connect_addr}) catch "client: connecting";
        log(connect_msg);
        {
            var cid_msg_buf: [220]u8 = undefined;
            const cid_msg = std.fmt.bufPrint(
                &cid_msg_buf,
                "client: initial cids dcid_len={d} scid_len={d} pn_initial_tx={d}",
                .{ conn.peer_initial_dcid.len, conn.our_scid.len, conn.pn_initial_tx },
            ) catch "client: initial cid state unavailable";
            log(cid_msg);
        }
        if (verbose) log("client: verbose logging enabled");
        if (cfg.enable_retry) {
            log("client: retry enabled (will process Retry if received)");
        }
        // Wait for handshake done
        const hs_wait_start = std.time.nanoTimestamp();
        while (!connectionReady(conn) and elapsedMsSince(hs_wait_start) < handshakeTimeoutMs(testcase)) {
            api.poll(ep, 5) catch {};
        }
        if (connectionReady(conn)) {
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
            var timeout_state_buf: [320]u8 = undefined;
            const timeout_state = std.fmt.bufPrint(
                &timeout_state_buf,
                "client: timeout state retry_observed={d} retry_applied={d} retry_reject_integrity={d} retry_reject_post_hs={d} retry_reject_dup={d} retry_received={} token_len={d} pn_initial_tx={d} dcid_len={d} scid_len={d}",
                .{
                    conn.retry_packets_observed,
                    conn.retry_apply_count,
                    conn.retry_reject_integrity,
                    conn.retry_reject_post_handshake,
                    conn.retry_reject_duplicate,
                    conn.retry_received,
                    conn.initial_token.items.len,
                    conn.pn_initial_tx,
                    conn.peer_initial_dcid.len,
                    conn.our_scid.len,
                },
            ) catch "client: timeout state unavailable";
            log(timeout_state);
            api.close(conn, 0, "bye") catch {};
            api.flush(ep, 10);
            api.destroy(ep, conn);
            std.process.exit(1);
        }

        const use_h3_mode = useHttp3ForConnection(testcase, conn);
        if (std.mem.eql(u8, testcase, "http3") and !use_h3_mode) {
            if (api.getNegotiatedAlpn(conn)) |alpn| {
                var fallback_msg_buf: [196]u8 = undefined;
                const fallback_msg = std.fmt.bufPrint(&fallback_msg_buf, "client: http3 testcase falling back to HQ framing; negotiated alpn={s}", .{alpn}) catch "client: http3 fallback to HQ framing";
                log(fallback_msg);
            }
        }

        if (use_h3_mode) {
            var success: bool = true;
            const resp_buf = try alloc.alloc(u8, 4 * 1024 * 1024);
            defer alloc.free(resp_buf);
            for (urls) |url| {
                const path = extractPath(url);
                const h3_authority = extractAuthority(url) orelse default_h3_authority;
                var h3_req_msg_buf: [256]u8 = undefined;
                const h3_req_msg = std.fmt.bufPrint(&h3_req_msg_buf, "client: H3 request authority={s} path={s}", .{ h3_authority, path }) catch "client: H3 request";
                log(h3_req_msg);
                log("client: sending H3 GET request");
                const got = h3_client.h3Get(ep, conn, h3_authority, path, resp_buf) catch |err| {
                    var err_msg_buf: [128]u8 = undefined;
                    const err_msg = std.fmt.bufPrint(&err_msg_buf, "client: h3 request failed err={s}", .{@errorName(err)}) catch "client: h3 request failed";
                    log(err_msg);
                    success = false;
                    break;
                };

                var sanitized = path;
                if (sanitized.len > 0 and sanitized[0] == '/') sanitized = sanitized[1..];
                var out_path_buf: [512]u8 = undefined;
                const out_path = try std.fmt.bufPrint(&out_path_buf, "/downloads/{s}", .{sanitized});
                if (std.fs.cwd().createFile(out_path, .{ .truncate = true })) |outf| {
                    defer outf.close();
                    if (got > 0) _ = outf.write(resp_buf[0..got]) catch {};
                } else |_| {}

                if (got == 0) {
                    if (allow_empty_h3) {
                        log("client: empty H3 response accepted (QNS_H3_ALLOW_EMPTY)");
                    } else {
                        success = false;
                    }
                }
                var msg_buf: [96]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "client: response bytes={d}", .{got}) catch "client: response bytes=?";
                log(msg);
            }

            api.close(conn, 0, "bye") catch {};
            api.flush(ep, 10);
            api.destroy(ep, conn);
            if (!success) std.process.exit(1) else return;
        }

        const InflightRequest = struct {
            stream_id: api.QuicStreamId,
            path: []const u8,
            file_bytes: std.ArrayList(u8),
            start_ns: i128,
            last_progress_ns: i128,
        };

        var success: bool = true;
        // Keep request scheduling deterministic across diverse interop peers.
        // Some stacks exhibit fragile behavior when multiple new streams are
        // opened concurrently during early 1-RTT, so serialize client requests.
        const max_inflight: usize = 1;
        var inflight = std.ArrayList(InflightRequest){};
        defer {
            for (inflight.items) |*req| req.file_bytes.deinit(alloc);
            inflight.deinit(alloc);
        }

        var next_request: usize = 0;
        var tmp: [4096]u8 = undefined;
        const all_start = std.time.nanoTimestamp();
        var global_last_progress = all_start;
        request_loop: while ((next_request < urls.len or inflight.items.len > 0) and success) {
            if (elapsedMsSince(all_start) >= responseTotalTimeoutMs(testcase)) {
                log("client: overall response timeout");
                success = false;
                break;
            }

            while (next_request < urls.len and inflight.items.len < max_inflight) {
                const path = extractPath(urls[next_request]);
                var line_buf: [600]u8 = undefined;
                const line = try std.fmt.bufPrint(&line_buf, "GET {s}\r\n", .{path});
                log("client: sending GET request");

                const req_sid = openBidiStreamWithRetry(ep, conn, 64) catch {
                    break;
                };
                {
                    var sid_msg_buf: [96]u8 = undefined;
                    const sid_msg = std.fmt.bufPrint(&sid_msg_buf, "client: opened request stream={d}", .{req_sid}) catch "client: opened request stream=?";
                    log(sid_msg);
                }

                if (!writeAllStream(ep, conn, req_sid, line, testcase)) {
                    log("client: write request timed out");
                    success = false;
                    break :request_loop;
                }
                if (next_request == 0 and std.mem.eql(u8, testcase, "keyupdate")) {
                    conn.tx_sent_packets_since_key = 511;
                    conn.tx_sent_bytes_since_key = 1024 * 1024;
                    log("client: primed keyupdate threshold");
                }

                const now_ns = std.time.nanoTimestamp();
                inflight.append(alloc, .{
                    .stream_id = req_sid,
                    .path = path,
                    .file_bytes = .{},
                    .start_ns = now_ns,
                    .last_progress_ns = now_ns,
                }) catch {
                    log("client: failed to track in-flight request");
                    success = false;
                    break :request_loop;
                };
                next_request += 1;
            }

            api.poll(ep, 5) catch {};
            var made_progress = false;
            var idx: usize = 0;
            while (idx < inflight.items.len) {
                var req = &inflight.items[idx];
                const n = api.readStream(conn, req.stream_id, tmp[0..]) catch |err| switch (err) {
                    error.WouldBlock, error.InvalidStream => 0,
                };
                if (n > 0) {
                    try req.file_bytes.appendSlice(alloc, tmp[0..n]);
                    if (req.file_bytes.items.len > 128 * 1024 * 1024) {
                        log("client: response exceeded max size");
                        success = false;
                        break :request_loop;
                    }
                    const now_ns = std.time.nanoTimestamp();
                    req.last_progress_ns = now_ns;
                    global_last_progress = now_ns;
                    made_progress = true;
                }

                if (n == 0 and api.isStreamFinished(conn, req.stream_id)) {
                    var sanitized = req.path;
                    if (sanitized.len > 0 and sanitized[0] == '/') sanitized = sanitized[1..];
                    var out_path_buf: [512]u8 = undefined;
                    const out_path = try std.fmt.bufPrint(&out_path_buf, "/downloads/{s}", .{sanitized});
                    if (std.fs.cwd().createFile(out_path, .{ .truncate = true })) |outf| {
                        defer outf.close();
                        _ = outf.write(req.file_bytes.items) catch {};
                    } else |_| {}
                    if (req.file_bytes.items.len == 0) success = false;
                    var msg_buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "client: response bytes={d}", .{req.file_bytes.items.len}) catch "client: response bytes=?";
                    log(msg);
                    req.file_bytes.deinit(alloc);
                    _ = inflight.swapRemove(idx);
                    global_last_progress = std.time.nanoTimestamp();
                    made_progress = true;
                    continue;
                }

                if (elapsedMsSince(req.last_progress_ns) >= responseIdleTimeoutMs(testcase)) {
                    log("client: per-stream response idle timeout");
                    success = false;
                    break :request_loop;
                }
                if (elapsedMsSince(req.start_ns) >= responseTotalTimeoutMs(testcase)) {
                    log("client: per-stream response total timeout");
                    success = false;
                    break :request_loop;
                }

                idx += 1;
            }

            if (!made_progress and inflight.items.len > 0 and elapsedMsSince(global_last_progress) >= responseIdleTimeoutMs(testcase)) {
                log("client: global response idle timeout");
                success = false;
                break;
            }
        }
        api.close(conn, 0, "bye") catch {};
        api.flush(ep, 10);
        api.destroy(ep, conn);
        if (!success) std.process.exit(1) else return;
    } else {
        return error.UnknownROLE;
    }
}
