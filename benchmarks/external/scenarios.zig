// benchmarks/external/scenarios.zig
// SPDX-License-Identifier: Apache-2.0
//
// Cross-impl handshake benchmarks. Each scenario:
//   1. Checks toolchain availability (go / cargo / python3 + aioquic).
//      If missing, emits a placeholder RunOutput immediately (skip row).
//   2. Lazy-builds the test-client binary if needed (quic-go: `go build`,
//      quinn: `cargo build --release`, aioquic: no build).
//   3. Starts a Zig server endpoint on a fresh loopback port with the
//      cert/key pair from `tests/certs/` and ALPN "hq-interop" (what
//      all three clients speak).
//   4. Spawns the client subprocess `iterations` times, timing each
//      spawn-to-exit cycle via wall-clock.
//   5. Tears the server down and returns the collected latencies.
//
// Each client subprocess performs a full QUIC handshake + one HTTP/0.9
// request. Wall-clock latency therefore measures
// `handshake + 1 stream RT + process exit`. Subprocess startup overhead
// dominates (Go ~50ms, Rust ~30ms, Python ~200ms cold import) so these
// numbers are not directly comparable to our in-process `handshake_e2e`
// benches -- they track cross-impl compatibility latency, not raw
// handshake CPU cost.
//
// Port allocator: 20500+ (handshake_e2e uses 18900+, stream_throughput
// 19400+, flush_cadence 19800+, datagram_batch 20000+). The 500-port
// headroom above 20000 gives safe separation for the 7 runs of each
// scenario and cross-scenario overlap on `--suite=all`.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const api = @import("quic_api");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");
const harness = @import("harness.zig");
const h = @import("../integration/_helpers.zig");

// All three clients advertise "hq-interop" (standard QUIC interop ALPN).
const test_alpn = [_][]const u8{"hq-interop"};
const external_ca_path = "tests/certs/external/ca.pem";
const external_cert_path = "tests/certs/external/cert.pem";
const external_key_path = "tests/certs/external/key.pem";

// Dedicated port range to avoid collision with micro/integration benches.
var ext_next_port = std.atomic.Value(u16).init(20500);
fn allocatePort() u16 {
    return ext_next_port.fetchAdd(1, .seq_cst);
}

// -------------------- Server lifecycle --------------------

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
};

/// Minimal server poll thread. Accepts connections, drains any incoming
/// stream bytes, and echoes a short HTTP/0.9 response on the first stream
/// (enough to satisfy the external clients' read-to-end / FIN wait).
fn serverThread(ctx: ServerCtx) void {
    const ConnectionState = struct { conn: *api.Connection, responded: bool = false };
    var conns: std.ArrayList(ConnectionState) = .empty;
    defer conns.deinit(ctx.allocator);

    var scratch: [4096]u8 = undefined;
    const response = "HTTP/0.9 200 OK\r\nOK\n";

    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(1) catch {};

        while (api.tryAccept(ctx.ep)) |c| {
            conns.append(ctx.allocator, .{ .conn = c }) catch continue;
        }

        for (conns.items) |*state| {
            if (state.responded) continue;
            const conn = state.conn;
            while (api.hasIncomingStreams(conn)) {
                const sid = api.acceptStream(conn) catch break;
                // Drain the request bytes (client sends "GET /\r\n" + FIN).
                while (true) {
                    const n = api.readStream(conn, sid, &scratch) catch break;
                    if (n == 0) break;
                }
                // Write the tiny response and FIN. Ignore errors -- the
                // client will observe connection close as end-of-stream.
                _ = api.writeStream(conn, sid, response, true) catch {};
                state.responded = true;
                break;
            }
        }
    }

    // Final drain so FINs land.
    var drain_ticks: usize = 0;
    while (drain_ticks < 20) : (drain_ticks += 1) {
        _ = ctx.ep.pollWithStats(1) catch {};
    }
}

const ServerHandle = struct {
    ep: *endpoint_mod.Endpoint,
    done_flag: *std.atomic.Value(bool),
    thread: std.Thread,
    server_target: []const u8,
    allocator: std.mem.Allocator,
    certificate: []u8,
    private_key: []u8,

    fn stop(self: *ServerHandle) void {
        self.done_flag.store(true, .release);
        self.thread.join();
        self.ep.deinit();
        self.allocator.destroy(self.ep);
        self.allocator.destroy(self.done_flag);
        self.allocator.free(self.server_target);
        self.allocator.free(self.certificate);
        self.allocator.free(self.private_key);
    }
};

/// Start a server or invalidate the scenario. Startup failures are not skips.
fn startZigServer(allocator: std.mem.Allocator) !ServerHandle {
    // External clients verify a proper CA-signed server leaf. Keep these
    // credentials separate from the integration tier's existing fixtures.
    const io = h.benchIo();
    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, external_cert_path, allocator, .limited(64 * 1024));
    defer allocator.free(cert_pem);
    const cert = try api.pem.parseCertificate(allocator, cert_pem);
    errdefer allocator.free(cert);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, external_key_path, allocator, .limited(16 * 1024));
    defer allocator.free(key_pem);
    const private_key = try api.pem.parsePrivateKey(allocator, key_pem);
    errdefer allocator.free(private_key);
    const bind_addr = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{allocatePort()});
    defer allocator.free(bind_addr);
    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = cert,
        .inline_server_priv_p256 = private_key,
        .allow_insecure = true,
    };
    const ep_ptr = try allocator.create(endpoint_mod.Endpoint);
    errdefer allocator.destroy(ep_ptr);
    ep_ptr.* = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    errdefer ep_ptr.deinit();
    const done_ptr = try allocator.create(std.atomic.Value(bool));
    errdefer allocator.destroy(done_ptr);
    done_ptr.* = std.atomic.Value(bool).init(false);
    const server_target = try allocator.dupe(u8, bind_addr);
    errdefer allocator.free(server_target);
    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerCtx{
        .ep = ep_ptr,
        .done = done_ptr,
        .allocator = allocator,
    }});
    h.threadSleep(20 * std.time.ns_per_ms);
    return .{
        .ep = ep_ptr,
        .done_flag = done_ptr,
        .thread = thread,
        .server_target = server_target,
        .allocator = allocator,
        .certificate = cert,
        .private_key = private_key,
    };
}

// -------------------- quic-go --------------------

const QUIC_GO_SRC = "test-clients/quic-go-client";
const QUIC_GO_BIN = "test-clients/quic-go-client/quic-go-test-client";

fn ensureQuicGoBuilt(allocator: std.mem.Allocator) !void {
    if (harness.pathExists(QUIC_GO_BIN)) return;
    return harness.runBuild(
        allocator,
        &.{ "go", "build", "-o", "quic-go-test-client", "." },
        QUIC_GO_SRC,
        120,
    );
}

pub fn runQuicGoHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) return try harness.placeholderOutput(allocator, "quic-go");
    if (!try harness.checkToolchain(allocator, "go")) return try harness.placeholderOutput(allocator, "quic-go");
    try ensureQuicGoBuilt(allocator);

    var server = try startZigServer(allocator);
    defer server.stop();

    const addr_arg = try std.fmt.allocPrint(allocator, "--addr={s}", .{server.server_target});
    defer allocator.free(addr_arg);

    // `./` prefix so it's treated as an explicit relative path.
    const argv = [_][]const u8{ "./" ++ QUIC_GO_BIN, addr_arg, "--ca-file", external_ca_path };

    return try harness.runSubprocess(allocator, spec, .{
        .impl = "quic-go",
        .argv = &argv,
        .timeout_seconds = 10,
    });
}

// -------------------- quinn --------------------

const QUINN_SRC = "test-clients/quinn-client";
const QUINN_BIN = "test-clients/quinn-client/target/release/quinn-test-client";

fn ensureQuinnBuilt(allocator: std.mem.Allocator) !void {
    if (harness.pathExists(QUINN_BIN)) return;
    return harness.runBuild(
        allocator,
        &.{ "cargo", "build", "--release", "--bin", "quinn-test-client" },
        QUINN_SRC,
        240,
    );
}

pub fn runQuinnHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) return try harness.placeholderOutput(allocator, "quinn");
    if (!try harness.checkToolchain(allocator, "cargo")) return try harness.placeholderOutput(allocator, "quinn");
    try ensureQuinnBuilt(allocator);

    var server = try startZigServer(allocator);
    defer server.stop();

    const addr_arg = try std.fmt.allocPrint(allocator, "--addr={s}", .{server.server_target});
    defer allocator.free(addr_arg);

    const argv = [_][]const u8{
        "./" ++ QUINN_BIN,
        addr_arg,
        "--server-name",
        "localhost",
        "--ca-file",
        external_ca_path,
    };

    return try harness.runSubprocess(allocator, spec, .{
        .impl = "quinn",
        .argv = &argv,
        .timeout_seconds = 10,
    });
}

// -------------------- aioquic --------------------

const AIOQUIC_SCRIPT = "test-clients/aioquic-client/test_client.py";

pub fn runAioquicHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) return try harness.placeholderOutput(allocator, "aioquic");
    if (!try harness.checkToolchain(allocator, "python3")) return try harness.placeholderOutput(allocator, "aioquic");
    if (!try harness.checkPythonModule(allocator, "aioquic")) return try harness.placeholderOutput(allocator, "aioquic");
    if (!harness.pathExists(AIOQUIC_SCRIPT)) return error.MissingClient;

    var server = try startZigServer(allocator);
    defer server.stop();

    // aioquic client uses --host/--port rather than --addr.
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{parseTrailingPort(server.server_target)});
    defer allocator.free(port_str);

    const argv = [_][]const u8{
        "python3",
        AIOQUIC_SCRIPT,
        "--host",
        "127.0.0.1",
        "--port",
        port_str,
        "--ca-file",
        external_ca_path,
    };

    return try harness.runSubprocess(allocator, spec, .{
        .impl = "aioquic",
        .argv = &argv,
        .timeout_seconds = 15, // Python cold-start is slower than Go/Rust
    });
}

/// Extract the port from a "host:port" formatted string. On parse failure
/// returns 0 so the subprocess immediately fails.
fn parseTrailingPort(server_target: []const u8) u16 {
    const colon_idx = std.mem.lastIndexOfScalar(u8, server_target, ':') orelse return 0;
    const port_slice = server_target[colon_idx + 1 ..];
    return std.fmt.parseInt(u16, port_slice, 10) catch 0;
}

// -------------------- Scenario registrations --------------------

pub const scenarios_quic_go = [_]common.ScenarioSpec{
    .{ .name = "external/quic-go/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};
pub const scenarios_quinn = [_]common.ScenarioSpec{
    .{ .name = "external/quinn/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};
pub const scenarios_aioquic = [_]common.ScenarioSpec{
    .{ .name = "external/aioquic/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};

test "parseTrailingPort extracts numeric suffix" {
    try std.testing.expectEqual(@as(u16, 4433), parseTrailingPort("127.0.0.1:4433"));
    try std.testing.expectEqual(@as(u16, 20500), parseTrailingPort("127.0.0.1:20500"));
    try std.testing.expectEqual(@as(u16, 0), parseTrailingPort("no-colon"));
}
