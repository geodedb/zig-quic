// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Opt-in stress harness for the Endpoint.mu <-> poll-worker teardown deadlock
// (see tests/test_endpoint_teardown_deadlock_regression.zig for the
// deterministic reproducer). Run it with:
//
//   taskset -c 0 zig build test -Dtest-filter=teardown_churn_stress
//
// Shape mirrors geode's server: several threads poll ONE server endpoint
// configured with `defer_accept_until_stream`, an acceptor admits connections,
// and a reaper tears them down with `api.destroyBatch` while holding
// `pto_lifetime_mu` + `mu` (geode's QuicTransport.drainPendingDestroy) --
// while the clients are still streaming, so short-header packets for doomed
// connections keep landing in the poll workers. Clients connect, open a stream,
// write, close, and reconnect in a loop.
//
// Pass criteria: every reaper destroy returns within `destroy_stall_ms`, and
// after the churn a fresh client still completes a handshake (geode's symptom
// was that the engine stopped answering QUIC logins). A wedge fails the test on
// a deadline instead of hanging the suite.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const pem = api.pem;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

const server_poll_workers: usize = 4;
const client_threads: usize = 4;
const churn_duration_ms: i64 = 15_000;
const destroy_stall_ms: i64 = 5_000;
const final_handshake_timeout_ms: i64 = 5_000;

var next_port = std.atomic.Value(u16).init(19900);

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

const ServerCreds = struct {
    cert_der: []u8,
    priv_p256: []u8,
};

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const f = std.Io.Dir.cwd().openFile(io(), path, .{}) catch return null;
    defer f.close(io());
    const size = (f.stat(io()) catch return null).size;
    const buf = allocator.alloc(u8, size) catch return null;
    _ = f.readPositionalAll(io(), buf, 0) catch {
        allocator.free(buf);
        return null;
    };
    return buf;
}

fn loadServerCreds(allocator: std.mem.Allocator) ?ServerCreds {
    const cert_pem = readFileAlloc(allocator, "tests/certs/cert.pem") orelse return null;
    defer allocator.free(cert_pem);
    const key_pem = readFileAlloc(allocator, "tests/certs/key.pem") orelse return null;
    defer allocator.free(key_pem);
    const cert_der = pem.parseCertificate(allocator, cert_pem) catch return null;
    const priv = pem.parsePrivateKey(allocator, key_pem) catch {
        allocator.free(cert_der);
        return null;
    };
    return .{ .cert_der = cert_der, .priv_p256 = priv };
}

const Shared = struct {
    ep: *api.QuicEndpoint,
    target: []const u8,
    stop: std.atomic.Value(bool) = .init(false),
    // Accepted connections waiting for the reaper (geode's pending_destroy).
    pending_mu: std.Io.Mutex = .init,
    pending: std.ArrayList(*api.QuicConnection) = .empty,
    accepted: std.atomic.Value(u64) = .init(0),
    destroyed: std.atomic.Value(u64) = .init(0),
    client_handshakes: std.atomic.Value(u64) = .init(0),
    // Reaper heartbeat: start time of an in-progress destroyBatch, 0 if idle.
    destroy_started_ms: std.atomic.Value(i64) = .init(0),
    pollers_live: std.atomic.Value(u32) = .init(0),
};

fn pollWorker(s: *Shared) void {
    _ = s.pollers_live.fetchAdd(1, .acq_rel);
    defer _ = s.pollers_live.fetchSub(1, .acq_rel);
    while (!s.stop.load(.acquire)) {
        s.ep.poll(1) catch {};
    }
}

fn acceptor(s: *Shared) void {
    while (!s.stop.load(.acquire)) {
        const c = api.waitForAccepted(s.ep, 5) orelse continue;
        _ = s.accepted.fetchAdd(1, .acq_rel);
        s.pending_mu.lockUncancelable(io());
        s.pending.append(std.heap.page_allocator, c) catch {};
        s.pending_mu.unlock(io());
    }
}

fn reaper(s: *Shared) void {
    var batch: std.ArrayList(*api.QuicConnection) = .empty;
    defer batch.deinit(std.heap.page_allocator);
    while (!s.stop.load(.acquire)) {
        // Give clients time to put short-header packets in flight for the
        // connections we are about to destroy.
        std.Io.sleep(io(), std.Io.Duration.fromNanoseconds(2 * std.time.ns_per_ms), .awake) catch {};
        s.pending_mu.lockUncancelable(io());
        batch.clearRetainingCapacity();
        batch.appendSlice(std.heap.page_allocator, s.pending.items) catch {};
        s.pending.clearRetainingCapacity();
        s.pending_mu.unlock(io());
        if (batch.items.len == 0) continue;

        s.destroy_started_ms.store(nowMs(), .release);
        {
            s.ep.pto_lifetime_mu.lockUncancelable(io());
            defer s.ep.pto_lifetime_mu.unlock(io());
            s.ep.mu.lockUncancelable(io());
            defer s.ep.mu.unlock(io());
            api.destroyBatch(s.ep, batch.items);
        }
        s.destroy_started_ms.store(0, .release);
        _ = s.destroyed.fetchAdd(batch.items.len, .acq_rel);
    }
}

fn clientLoop(s: *Shared) void {
    var alloc = std.heap.page_allocator;
    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    const ep = api.endpointInit(&alloc, "127.0.0.1:0", &cli_cfg) catch return;
    defer api.endpointDeinit(ep);
    const payload = [_]u8{'x'} ** 512;
    while (!s.stop.load(.acquire)) {
        const conn = api.connect(ep, s.target, SERVER_SNI) catch continue;
        const t0 = nowMs();
        var confirmed = false;
        while (nowMs() - t0 < 2_000 and !s.stop.load(.acquire)) {
            ep.poll(1) catch {};
            if (api.isHandshakeConfirmed(conn)) {
                confirmed = true;
                break;
            }
        }
        if (confirmed) {
            _ = s.client_handshakes.fetchAdd(1, .acq_rel);
            if (api.openStream(conn, true)) |sid| {
                // Keep streaming so the server keeps receiving short-header
                // packets while the reaper destroys this connection.
                var i: usize = 0;
                while (i < 40 and !s.stop.load(.acquire)) : (i += 1) {
                    _ = api.writeStream(conn, sid, &payload, false) catch break;
                    ep.poll(0) catch {};
                }
            } else |_| {}
        }
        api.close(conn, 0, "churn") catch {};
        var d: usize = 0;
        while (d < 3) : (d += 1) ep.poll(1) catch {};
        api.destroy(ep, conn);
    }
}

fn finalHandshake(target: []const u8) bool {
    var alloc = std.heap.page_allocator;
    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    const ep = api.endpointInit(&alloc, "127.0.0.1:0", &cli_cfg) catch return false;
    defer api.endpointDeinit(ep);
    const conn = api.connect(ep, target, SERVER_SNI) catch return false;
    const t0 = nowMs();
    while (nowMs() - t0 < final_handshake_timeout_ms) {
        ep.poll(1) catch {};
        if (api.isHandshakeConfirmed(conn)) return true;
    }
    return false;
}

test "teardown_churn_stress: connect/stream/close/destroyBatch churn never wedges the server endpoint" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.heap.page_allocator;
    const creds = loadServerCreds(allocator) orelse return error.SkipZigTest;

    const port = next_port.fetchAdd(1, .seq_cst);
    var bind_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert_der,
        .inline_server_priv_p256 = creds.priv_p256,
        .allow_insecure = true,
        .defer_accept_until_stream = true,
    };
    var alloc_for_init = allocator;
    const ep = try api.endpointInit(&alloc_for_init, target, &server_cfg);

    var s = Shared{ .ep = ep, .target = target };
    var threads: [server_poll_workers + client_threads + 2]std.Thread = undefined;
    var n: usize = 0;
    for (0..server_poll_workers) |_| {
        threads[n] = try std.Thread.spawn(.{}, pollWorker, .{&s});
        n += 1;
    }
    threads[n] = try std.Thread.spawn(.{}, acceptor, .{&s});
    n += 1;
    threads[n] = try std.Thread.spawn(.{}, reaper, .{&s});
    n += 1;
    for (0..client_threads) |_| {
        threads[n] = try std.Thread.spawn(.{}, clientLoop, .{&s});
        n += 1;
    }

    const t0 = nowMs();
    var wedged = false;
    while (nowMs() - t0 < churn_duration_ms) {
        std.Io.sleep(io(), std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
        const started = s.destroy_started_ms.load(.acquire);
        if (started != 0 and nowMs() - started > destroy_stall_ms) {
            wedged = true;
            break;
        }
    }

    // Responsiveness probe while the churn threads are still running.
    const responsive = !wedged and finalHandshake(target);

    s.stop.store(true, .release);
    std.debug.print(
        "\n  teardown churn: accepted={d} destroyed={d} client_handshakes={d} wedged={} responsive={}\n",
        .{ s.accepted.load(.acquire), s.destroyed.load(.acquire), s.client_handshakes.load(.acquire), wedged, responsive },
    );
    if (wedged or !responsive) {
        // Stuck threads can never be joined; leak them and the endpoint.
        for (threads[0..n]) |t| t.detach();
        return error.EndpointTeardownWedged;
    }
    for (threads[0..n]) |t| t.join();
    // Drain the remaining pending connections the way geode does on shutdown.
    {
        ep.mu.lockUncancelable(io());
        defer ep.mu.unlock(io());
        api.destroyBatch(ep, s.pending.items);
    }
    s.pending.deinit(allocator);
    try testing.expect(s.destroyed.load(.acquire) > 0);
    api.endpointDeinit(ep);
}
