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

fn requestOrderIndex(path: []const u8, requests: []const []const u8) ?usize {
    for (requests, 0..) |req, idx| {
        if (std.mem.eql(u8, path, extractPath(req))) return idx;
    }
    return null;
}

const supported_testcases = [_][]const u8{
    "handshake",
    "transfer",
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

fn parsePemCertificateChainConcat(alloc: std.mem.Allocator, cert_pem: []const u8) ![]u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    var out = std.ArrayList(u8){};
    errdefer out.deinit(alloc);

    var rest = cert_pem;
    var cert_count: usize = 0;
    while (std.mem.indexOf(u8, rest, begin_marker)) |begin_idx| {
        const from_begin = rest[begin_idx..];
        const end_rel = std.mem.indexOf(u8, from_begin, end_marker) orelse break;
        const block_end = end_rel + end_marker.len;
        const block = from_begin[0..block_end];

        const der = try api.pem.parseCertificate(alloc, block);
        defer alloc.free(der);
        try out.appendSlice(alloc, der);
        cert_count += 1;

        if (block_end >= from_begin.len) break;
        rest = from_begin[block_end..];
    }

    if (cert_count == 0) return error.NoCertificateFound;
    return try out.toOwnedSlice(alloc);
}

fn loadInlineServerCredentials(alloc: std.mem.Allocator, cfg: *api.QuicConfig, cert_path: []const u8, key_path: []const u8) !void {
    const cert_pem = try readFileAlloc(alloc, cert_path);
    defer alloc.free(cert_pem);
    const key_pem = try readFileAlloc(alloc, key_path);
    defer alloc.free(key_pem);

    // Parse all PEM certificate blocks and concatenate DER to preserve mounted
    // interop certificate-chain size in TLS Certificate CRYPTO payloads.
    cfg.inline_server_cert_der = try parsePemCertificateChainConcat(alloc, cert_pem);
    cfg.inline_server_priv_p256 = try api.pem.parsePrivateKey(alloc, key_pem);
}

fn writeAllStream(ep: *api.QuicEndpoint, conn: *api.QuicConnection, stream_id: api.QuicStreamId, data: []const u8, testcase: []const u8) bool {
    const start_ns = std.time.nanoTimestamp();
    var stalled_polls: usize = 0;
    var off: usize = 0;
    while (off < data.len) {
        if (elapsedMsSince(start_ns) >= responseTotalTimeoutMs(testcase)) return false;
        const chunk_end = @min(off + 1200, data.len);
        const n = api.writeStream(conn, stream_id, data[off..chunk_end], false) catch |err| switch (err) {
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
        api.poll(ep, 1) catch {};
    }
    // Send FIN explicitly as a zero-length STREAM frame after all payload bytes.
    // This avoids relying on short-write behavior to carry fin=true.
    _ = api.writeStream(conn, stream_id, &[_]u8{}, true) catch {};
    api.flush(ep, 5);
    return true;
}

fn writePendingResponseChunk(ep: *api.QuicEndpoint, conn: *api.QuicConnection, resp: *PendingResponse) ResponseChunkResult {
    if (resp.fin_sent) return .done;

    if (resp.sent < resp.data.len) {
        const chunk_end = @min(resp.sent + 1200, resp.data.len);
        const n = api.writeStream(conn, resp.stream_id, resp.data[resp.sent..chunk_end], false) catch |err| switch (err) {
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
    const verbose = env.get("ZIG_VERBOSE") != null;
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

    // If server role, load certificate + key into inline TLS config.
    if (std.mem.eql(u8, role, "server")) {
        var cert_path_sel: ?[]const u8 = null;
        var key_path_sel: ?[]const u8 = null;
        const force_bundled_certs = env.get("QNS_USE_BUNDLED_CERTS") != null;

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
        startTcpReadinessListener();
        const ep = try api.endpointInit(&alloc, "0.0.0.0:443", &cfg);
        defer api.endpointDeinit(ep);
        log("server: started (listening 0.0.0.0:443)");
        var request_order_urls: []const []const u8 = &[_][]const u8{};
        var request_order_owned = false;
        if (env.get("REQUESTS")) |request_env| {
            request_order_urls = parseUrls(alloc, request_env) catch &[_][]const u8{};
            request_order_owned = request_order_urls.len > 0;
        }
        defer if (request_order_owned) alloc.free(request_order_urls);
        // Single accept loop (serve sequentially) with coarse timeout budget.
        var served: usize = 0;
        var idle_polls: usize = 0;
        while (served < 32) {
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
            var rr_next: usize = 0;
            while (!api.isDrained(conn)) {
                if (elapsedMsSince(req_start) >= responseTotalTimeoutMs(testcase)) {
                    log("server: response loop total timeout");
                    break;
                }
                const idle_limit_ms = if (pending_responses.items.len > 0) responsePendingIdleTimeoutMs(testcase) else responseIdleTimeoutMs(testcase);
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

                    if (request_buffers.fetchRemove(sid)) |entry| {
                        var req_state = entry.value;
                        req_state.deinit(alloc);
                    }
                    _ = active_streams.swapRemove(idx);
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
        const urls = try parseUrls(alloc, req_env);
        defer alloc.free(urls);
        const connect_addr = if (std.mem.eql(u8, testcase, "ipv6")) "[fd00:cafe:cafe:100::100]:443" else "193.167.100.100:443";
        const connect_sni = if (std.mem.eql(u8, testcase, "ipv6")) "server6" else "server4";

        // For multiconnect test, establish a new connection for each request
        if (std.mem.eql(u8, testcase, "multiconnect")) {
            log("client: multiconnect mode - establishing separate connection per request");
            const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
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

                // Send request
                var line_buf: [600]u8 = undefined;
                const line = try std.fmt.bufPrint(&line_buf, "GET {s}\r\n", .{path});
                log("client: sending GET request");
                if (!writeAllStream(ep, conn, 0, line, testcase)) {
                    log("client: write request timed out");
                    success = false;
                    api.destroy(ep, conn);
                    continue;
                }

                // Read response
                var file_bytes = std.ArrayList(u8){};
                defer file_bytes.deinit(alloc);
                var tmp: [4096]u8 = undefined;
                const read_start = std.time.nanoTimestamp();
                var last_progress = read_start;
                while (true) {
                    if (elapsedMsSince(read_start) >= responseTotalTimeoutMs(testcase)) break;
                    if (elapsedMsSince(last_progress) >= responseIdleTimeoutMs(testcase)) break;
                    api.poll(ep, 5) catch {};
                    const n = api.readStream(conn, 0, tmp[0..]) catch 0;
                    if (n == 0) {
                        continue;
                    } else {
                        last_progress = std.time.nanoTimestamp();
                        try file_bytes.appendSlice(alloc, tmp[0..n]);
                        if (file_bytes.items.len > 128 * 1024 * 1024) break;
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
        const conn = try api.connect(ep, connect_addr, connect_sni);
        var connect_msg_buf: [160]u8 = undefined;
        const connect_msg = std.fmt.bufPrint(&connect_msg_buf, "client: connecting to {s}", .{connect_addr}) catch "client: connecting";
        log(connect_msg);
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
            api.close(conn, 0, "bye") catch {};
            api.flush(ep, 10);
            api.destroy(ep, conn);
            std.process.exit(1);
        }

        var success: bool = true;
        var request_i: usize = 0;
        while (request_i < urls.len) : (request_i += 1) {
            const path = extractPath(urls[request_i]);
            var line_buf: [600]u8 = undefined;
            const line = try std.fmt.bufPrint(&line_buf, "GET {s}\r\n", .{path});
            log("client: sending GET request");
            if (!writeAllStream(ep, conn, 0, line, testcase)) {
                log("client: write request timed out");
                success = false;
                break;
            }
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
            var tmp: [4096]u8 = undefined;
            const read_start = std.time.nanoTimestamp();
            var last_progress = read_start;
            while (true) {
                if (elapsedMsSince(read_start) >= responseTotalTimeoutMs(testcase)) break;
                if (elapsedMsSince(last_progress) >= responseIdleTimeoutMs(testcase)) break;
                api.poll(ep, 5) catch {};
                const n = api.readStream(conn, 0, tmp[0..]) catch 0;
                if (n == 0) {
                    continue;
                } else {
                    last_progress = std.time.nanoTimestamp();
                    try file_bytes.appendSlice(alloc, tmp[0..n]);
                    if (file_bytes.items.len > 128 * 1024 * 1024) break; // cap
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
