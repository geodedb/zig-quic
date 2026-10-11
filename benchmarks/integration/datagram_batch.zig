// SPDX-License-Identifier: Apache-2.0
// RX dispatch under 100 idle connections and 1/16/64/32 active senders.
// Setup and teardown are outside the measurement window. A sample is valid
// only when every byte and FIN reaches the server and every sender receives
// the server's FIN acknowledgment. The latency sample is the mean wall time
// per datagram in one poll, not an individual packet's latency or lock time.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("bench_common");
const api = @import("quic_api");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");
const h = @import("_helpers.zig");
const accounting = @import("datagram_accounting.zig");

const alpn = [_][]const u8{"h3"};
const HANDSHAKE_TIMEOUT_NS = 3_000 * std.time.ns_per_ms;
const FLOOD_TIMEOUT_NS = 5_000 * std.time.ns_per_ms;
const CHUNK_BYTES = 1024;
const N_PRE = 100;
const TestFault = enum { none, missing_chunk, corrupt_payload };

const Signals = struct {
    stop: std.atomic.Value(bool) = .init(false),
    abort: std.atomic.Value(bool) = .init(false),
    start_ns: std.atomic.Value(u64) = .init(0),
};
const Client = struct {
    ep: *endpoint_mod.Endpoint,
    conn: *api.Connection,
};
const Flooder = struct {
    client: Client,
    chunks: u64,
    inter_chunk_ns: u64,
    signals: *Signals,
    failure: *?anyerror,
    fault: TestFault = .none,

    fn thread(self: Flooder) void {
        self.send() catch |err| {
            self.failure.* = err;
            self.signals.abort.store(true, .release);
        };
    }

    fn send(self: Flooder) !void {
        var start: u64 = 0;
        while (start == 0) {
            if (self.signals.abort.load(.acquire)) return error.Aborted;
            start = self.signals.start_ns.load(.acquire);
            if (start == 0) h.threadSleep(10_000);
        }
        const deadline = start + FLOOD_TIMEOUT_NS;
        const sid = try api.openStream(self.client.conn, true);
        var payload: [CHUNK_BYTES]u8 = undefined;
        for (&payload, 0..) |*b, i| b.* = @truncate(i);
        if (self.fault == .corrupt_payload) payload[0] ^= 1;
        const chunks = self.chunks - @intFromBool(self.fault == .missing_chunk);
        var chunk: u64 = 0;
        while (chunk < chunks) : (chunk += 1) {
            var offset: usize = 0;
            while (offset < payload.len) {
                try self.checkDeadline(deadline);
                const n = api.writeStream(self.client.conn, sid, payload[offset..], false) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                if (n > payload.len - offset) return error.InvalidWriteCount;
                offset += n;
                if (n == 0) _ = try self.client.ep.pollWithStats(1);
            }
            if (self.inter_chunk_ns != 0) h.threadSleep(self.inter_chunk_ns);
            // Retain the original workload's poll cadence. A poll per write
            // measures client timer scheduling rather than an RX flood.
            if ((chunk + 1) % 32 == 0) _ = try self.client.ep.pollWithStats(0);
        }
        // FIN is submitted separately so a short write cannot truncate a chunk.
        while (true) {
            try self.checkDeadline(deadline);
            _ = api.writeStream(self.client.conn, sid, &.{}, true) catch |err| switch (err) {
                error.WouldBlock => {
                    _ = try self.client.ep.pollWithStats(1);
                    continue;
                },
                else => return err,
            };
            break;
        }
        // The peer FIN is an application acknowledgment of complete receipt.
        // Keep the endpoint alive until all clients and the server have stopped.
        while (!api.isStreamFinished(self.client.conn, sid)) {
            try self.checkDeadline(deadline);
            _ = try self.client.ep.pollWithStats(1);
            var unexpected: [1]u8 = undefined;
            const n = api.readStream(self.client.conn, sid, &unexpected) catch |err| switch (err) {
                // The local stream's RX state is created by the first peer frame.
                error.WouldBlock, error.InvalidStream => 0,
            };
            if (n != 0) return error.UnexpectedResponsePayload;
        }
    }

    fn checkDeadline(self: Flooder, deadline: u64) !void {
        if (self.signals.abort.load(.acquire)) return error.Aborted;
        if (common.nowNs() >= deadline) return error.IncompleteTransfer;
    }
};

const Stream = struct {
    id: api.QuicStreamId,
    received: u64 = 0,
    acknowledged: bool = false,
};
const Accepted = struct {
    conn: *api.Connection,
    streams: std.ArrayList(Stream) = .empty,
};
const Server = struct {
    ep: *endpoint_mod.Endpoint,
    allocator: std.mem.Allocator,
    signals: *Signals,
    latencies: std.ArrayList(u64) = .empty,
    received: u64 = 0,
    finished_streams: u64 = 0,
    packets: u64 = 0,
    poll_wall_ns: u64 = 0,
    end_ns: u64 = 0,
    failure: ?anyerror = null,

    fn thread(self: *Server) void {
        defer self.end_ns = common.nowNs();
        self.serve() catch |err| {
            self.failure = err;
            self.signals.abort.store(true, .release);
        };
    }

    fn serve(self: *Server) !void {
        var conns: std.ArrayList(Accepted) = .empty;
        defer {
            for (conns.items) |*c| c.streams.deinit(self.allocator);
            conns.deinit(self.allocator);
        }
        var scratch: [64 * 1024]u8 = undefined;
        while (!self.signals.stop.load(.acquire) and !self.signals.abort.load(.acquire)) {
            const t0 = common.nowNs();
            const stats = try self.ep.pollWithStats(0);
            const dt = common.nowNs() - t0;
            const start = self.signals.start_ns.load(.acquire);
            // Only whole polls inside the shared window contribute. The end
            // timestamp is written by this thread after its final poll/pump.
            if (start != 0 and t0 >= start) {
                self.poll_wall_ns += dt;
                self.packets += stats.packets_processed;
                if (stats.packets_processed != 0)
                    try self.latencies.append(self.allocator, dt / stats.packets_processed);
            }
            while (api.tryAccept(self.ep)) |c| try conns.append(self.allocator, .{ .conn = c });
            for (conns.items) |*c| {
                while (api.hasIncomingStreams(c.conn)) {
                    const sid = try api.acceptStream(c.conn);
                    // acceptStream also notifies about new data on known streams.
                    // Preserve their receive offset and acknowledge each FIN once.
                    const known = for (c.streams.items) |stream| {
                        if (stream.id == sid) break true;
                    } else false;
                    if (!known) try c.streams.append(self.allocator, .{ .id = sid });
                }
                for (c.streams.items) |*stream| {
                    if (stream.acknowledged) continue;
                    while (true) {
                        const n = api.readStream(c.conn, stream.id, &scratch) catch |err| switch (err) {
                            error.WouldBlock => 0,
                            else => return err,
                        };
                        if (n == 0) break;
                        for (scratch[0..n], 0..) |b, i| {
                            if (b != @as(u8, @truncate(stream.received + i))) return error.CorruptPayload;
                        }
                        stream.received += n;
                        self.received += n;
                    }
                    if (api.isStreamFinished(c.conn, stream.id)) {
                        _ = api.writeStream(c.conn, stream.id, &.{}, true) catch |err| switch (err) {
                            error.WouldBlock => continue,
                            else => return err,
                        };
                        stream.acknowledged = true;
                        self.finished_streams += 1;
                    }
                }
            }
        }
    }
};

fn connectOne(allocator: std.mem.Allocator, target: []const u8, signals: *Signals) !Client {
    const ep = try allocator.create(endpoint_mod.Endpoint);
    errdefer allocator.destroy(ep);
    var config = cfg.QuicConfig{ .alpn = &alpn, .allow_insecure = true };
    ep.* = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    errdefer ep.deinit();
    const conn = try api.connect(ep, target, "localhost");
    const deadline = common.nowNs() + HANDSHAKE_TIMEOUT_NS;
    while (!api.isHandshakeConfirmed(conn)) {
        if (signals.abort.load(.acquire)) return error.Aborted;
        if (common.nowNs() >= deadline) return error.HandshakeTimeout;
        _ = try ep.pollWithStats(1);
    }
    return .{ .ep = ep, .conn = conn };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    return runImpl(allocator, spec, .none);
}

/// Negative real-UDP controls share the production completion path. This
/// entry point cannot be instantiated by a benchmark executable.
pub fn runFaultForTest(allocator: std.mem.Allocator, spec: common.ScenarioSpec, fault: TestFault) !common.RunOutput {
    if (!builtin.is_test) @compileError("fault injection is only available to tests");
    return runImpl(allocator, spec, fault);
}

fn runImpl(allocator: std.mem.Allocator, spec: common.ScenarioSpec, fault: TestFault) !common.RunOutput {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const n: usize = spec.connection_count;
    if (n == 0 or n > 64 or spec.iterations < n) return error.InvalidScenario;
    const expected_bytes = std.math.mul(u64, spec.iterations, CHUNK_BYTES) catch return error.InvalidScenario;
    // Credentials are cached for the process lifetime by _helpers.
    const creds = h.loadServerCreds(std.heap.page_allocator) orelse return error.MissingCredentials;
    var bind_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{h.allocatePort()});
    var server_cfg = cfg.QuicConfig{
        .alpn = &alpn,
        .inline_server_cert_der = creds.cert,
        .inline_server_priv_p256 = creds.key,
        .allow_insecure = true,
    };
    var ep = try endpoint_mod.Endpoint.init(allocator, target, &server_cfg);
    defer ep.deinit();
    var signals = Signals{};
    var clients: std.ArrayList(Client) = .empty;
    defer {
        for (clients.items) |client| {
            client.ep.deinit();
            allocator.destroy(client.ep);
        }
        clients.deinit(allocator);
    }
    var server = Server{ .ep = &ep, .allocator = allocator, .signals = &signals };
    defer server.latencies.deinit(allocator);
    const server_thread = try std.Thread.spawn(.{}, Server.thread, .{&server});
    var server_joined = false;
    defer if (!server_joined) {
        signals.stop.store(true, .release);
        server_thread.join();
    };
    try clients.ensureTotalCapacity(allocator, N_PRE + n);
    for (0..N_PRE + n) |_| clients.appendAssumeCapacity(try connectOne(allocator, target, &signals));

    const failures = try allocator.alloc(?anyerror, n);
    defer allocator.free(failures);
    @memset(failures, null);
    const threads = try allocator.alloc(std.Thread, n);
    defer allocator.free(threads);
    var spawned: usize = 0;
    var clients_joined = false;
    defer if (!clients_joined) {
        signals.abort.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    };
    for (clients.items[N_PRE..], 0..) |client, i| {
        threads[i] = try std.Thread.spawn(.{}, Flooder.thread, .{Flooder{
            .client = client,
            .chunks = spec.iterations / n + @intFromBool(i < spec.iterations % n),
            .inter_chunk_ns = if (n == 1) 50_000 else 0,
            .signals = &signals,
            .failure = &failures[i],
            .fault = if (i == 0) fault else .none,
        }});
        spawned += 1;
    }
    const start = common.nowNs();
    signals.start_ns.store(start, .release);
    for (threads) |thread| thread.join();
    clients_joined = true;
    signals.stop.store(true, .release);
    server_thread.join();
    server_joined = true;
    if (server.failure) |err| {
        if (fault == .none) std.debug.print("datagram {s}: server {s}, received={d}, finished={d}\n", .{ spec.variant, @errorName(err), server.received, server.finished_streams });
        return err;
    }
    for (failures, 0..) |failure, i| if (failure) |err| {
        if (fault == .none) std.debug.print("datagram {s}: client {d} {s}, received={d}, finished={d}\n", .{ spec.variant, i, @errorName(err), server.received, server.finished_streams });
        return err;
    };
    try accounting.validate(.{
        .expected_bytes = expected_bytes,
        .received_bytes = server.received,
        .expected_streams = n,
        .finished_streams = server.finished_streams,
        .start_ns = start,
        .end_ns = server.end_ns,
        .poll_ns = server.poll_wall_ns,
        .packets = server.packets,
        .samples = server.latencies.items.len,
    });
    return .{
        // Throughput is fully received 1-KiB chunks. Packets are counted
        // separately from poll statistics; a write is not a UDP datagram.
        .iterations = spec.iterations,
        .wall_time_ns = server.end_ns - start,
        .cpu_time_ns = 0, // CPU time is not measured by this wall-clock proxy.
        .latencies_ns = try allocator.dupe(u64, server.latencies.items),
        .bytes_transferred = server.received,
        .packets_transferred = server.packets,
        .mutex_hold_wall_ns = server.poll_wall_ns,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/datagram_batch", .variant = "batch_1", .iterations = 1024, .warmup_iterations = 0, .connection_count = 1 },
    .{ .name = "integration/datagram_batch", .variant = "batch_16", .iterations = 1024, .warmup_iterations = 0, .connection_count = 16 },
    .{ .name = "integration/datagram_batch", .variant = "batch_64", .iterations = 1024, .warmup_iterations = 0, .connection_count = 64 },
    .{ .name = "integration/datagram_batch", .variant = "concurrent_independent_progress", .iterations = 4096, .warmup_iterations = 0, .connection_count = 32 },
};
