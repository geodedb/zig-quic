// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

const std = @import("std");
const testing = std.testing;
const transport = @import("transport");

var next_port = std.atomic.Value(u16).init(18000);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

/// Zig 0.16.0 compat: std.time.milliTimestamp() was removed.
fn milliTimestamp() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// Zig 0.16.0 compat: std.time.nanoTimestamp() was removed.
fn nanoTimestamp() i128 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + @as(i128, ts.nsec);
}

fn threadSleep(ns: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

fn waitForFlag(flag: *std.atomic.Value(bool), timeout_ms: u64) !void {
    const start = milliTimestamp();
    while (!flag.load(.acquire)) {
        if (milliTimestamp() - start > @as(i64, @intCast(timeout_ms))) {
            return error.Timeout;
        }
        threadSleep(1 * std.time.ns_per_ms);
    }
}

fn interruptNever() bool {
    return false;
}

fn interruptAlways() bool {
    return true;
}

fn requireOpenSsl(allocator: std.mem.Allocator) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const result = std.process.run(allocator, io, .{
        .argv = &[_][]const u8{ "openssl", "version" },
    }) catch {
        return error.SkipZigTest;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        return error.SkipZigTest;
    }
}

fn pathExists(path: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn runOpenSsl(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const result = std.process.run(allocator, io, .{
        .argv = argv,
    }) catch {
        return error.SkipZigTest;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        return error.TestCertsUnavailable;
    }
}

fn ensureTestCertFiles(allocator: std.mem.Allocator) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const cert_path = "tests/certs/cert.pem";
    const key_path = "tests/certs/key.pem";

    if (pathExists(cert_path) and pathExists(key_path)) return;

    std.Io.Dir.cwd().createDirPath(io, "tests/certs") catch {};

    try runOpenSsl(allocator, &[_][]const u8{
        "openssl",
        "ecparam",
        "-genkey",
        "-name",
        "prime256v1",
        "-out",
        key_path,
    });
    try runOpenSsl(allocator, &[_][]const u8{
        "openssl",
        "req",
        "-new",
        "-x509",
        "-key",
        key_path,
        "-out",
        cert_path,
        "-days",
        "365",
        "-subj",
        "/CN=localhost/O=Test/C=US",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    });
}

test "transport geode compat: invalid states and nonblocking contracts" {
    var client = transport.QuicClient.init(testing.allocator);
    defer client.deinit();

    try testing.expectError(transport.QuicError.InvalidState, client.waitForHandshake(1));
    try testing.expectError(transport.QuicError.InvalidState, client.openStream(true));
    try testing.expectError(transport.QuicError.InvalidState, client.getStream());
    try testing.expectError(transport.QuicError.CertificateError, client.connectEx("127.0.0.1", 65535, null, null, null));

    var qt = try transport.QuicTransport.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = allocatePort(),
        .cert_path = "tests/certs/cert.pem",
        .key_path = "tests/certs/key.pem",
    });
    defer qt.deinit();

    try testing.expect(qt.tryAccept() == null);
    try testing.expectError(transport.QuicError.InvalidState, qt.accept());
}

test "transport geode compat: PollSync waits for active readers" {
    var sync = transport.PollSync{};
    var io_entered = std.atomic.Value(bool).init(false);
    var io_left = std.atomic.Value(bool).init(false);

    const worker = try std.Thread.spawn(.{}, struct {
        fn run(s: *transport.PollSync, entered: *std.atomic.Value(bool), left: *std.atomic.Value(bool)) void {
            s.enterIo();
            entered.store(true, .release);
            threadSleep(30 * std.time.ns_per_ms);
            // Set flag BEFORE leaveIo so enterPoll's return guarantees visibility
            left.store(true, .release);
            s.leaveIo();
        }
    }.run, .{ &sync, &io_entered, &io_left });
    defer worker.join();

    try waitForFlag(&io_entered, 500);
    sync.enterPoll();
    sync.leavePoll();

    try testing.expect(io_left.load(.acquire));
}

test "transport geode compat: PollSync blocks new readers while polling" {
    var sync = transport.PollSync{};
    var io_entered = std.atomic.Value(bool).init(false);

    sync.enterPoll();

    const worker = try std.Thread.spawn(.{}, struct {
        fn run(s: *transport.PollSync, entered: *std.atomic.Value(bool)) void {
            s.enterIo();
            entered.store(true, .release);
            s.leaveIo();
        }
    }.run, .{ &sync, &io_entered });

    threadSleep(10 * std.time.ns_per_ms);
    try testing.expect(!io_entered.load(.acquire));

    sync.leavePoll();
    worker.join();
    try waitForFlag(&io_entered, 500);
}

test "transport geode compat: listen applies config and tryAccept is null when idle" {
    const allocator = std.heap.page_allocator;
    try ensureTestCertFiles(allocator);

    var qt = try transport.QuicTransport.init(allocator, .{
        .address = "localhost",
        .port = allocatePort(),
        .max_connections = 17,
        .cert_path = "tests/certs/cert.pem",
        .key_path = "tests/certs/key.pem",
        .allow_insecure = true,
    });
    defer qt.deinit();

    try qt.listen();
    try testing.expect(qt.endpoint != null);
    try testing.expect(qt.tryAccept() == null);
    try qt.poll(1);
}

test "transport geode compat: client-server migration path over localhost" {
    const allocator = std.heap.page_allocator;
    try ensureTestCertFiles(allocator);

    var qt = try transport.QuicTransport.init(allocator, .{
        .address = "localhost",
        .port = allocatePort(),
        .max_connections = 32,
        .cert_path = "tests/certs/cert.pem",
        .key_path = "tests/certs/key.pem",
        .allow_insecure = true,
    });
    defer qt.deinit();
    try qt.listen();
    try testing.expect(qt.tryAccept() == null);

    var client = transport.QuicClient.init(allocator);
    defer client.deinit();
    try client.connectInsecure("localhost", qt.config.port, true);
    try testing.expectEqualStrings("127.0.0.1", client.server_addr);
    try testing.expect(client.quic_config != null);
    try testing.expectEqual(@as(u64, 300000), client.quic_config.?.max_idle_timeout_ms);

    var server_conn: ?*transport.QuicConnection = null;
    const handshake_start = milliTimestamp();
    while (milliTimestamp() - handshake_start < 5000 and server_conn == null) {
        try qt.poll(1);
        try client.poll(1);
        server_conn = qt.tryAccept();
        threadSleep(500 * std.time.ns_per_us);
    }
    if (server_conn == null) return error.Timeout;
    const conn = server_conn.?;

    // Drive both endpoints concurrently until both client and server
    // handshakes are confirmed. `client.waitForHandshake` only polls the
    // client endpoint, which means the server never processes the final
    // ACK that transitions `conn.isHandshakeConfirmed()` to true. Poll
    // both sides in a shared loop instead.
    const hs_start = milliTimestamp();
    while (milliTimestamp() - hs_start < 5000) {
        try qt.poll(1);
        try client.poll(1);
        if (conn.isHandshakeConfirmed()) break;
        threadSleep(500 * std.time.ns_per_us);
    }
    try testing.expect(conn.isHandshakeConfirmed());
    try testing.expect(conn.getPeerCertificateDer() == null);

    var stream = try client.openStream(true);

    _ = try stream.write("ping\n");
    try stream.finish();

    var scratch: [16]u8 = undefined;
    try testing.expectError(error.WouldBlock, stream.read(&scratch));
    try client.poll(10);
    try qt.poll(10);

    const stream_wait_start = milliTimestamp();
    while (milliTimestamp() - stream_wait_start < 3000 and !conn.hasIncomingStreams()) {
        try qt.poll(1);
        try client.poll(1);
        threadSleep(500 * std.time.ns_per_us);
    }
    if (!conn.hasIncomingStreams()) return error.Timeout;

    const server_stream = try conn.acceptStream();
    const request = try server_stream.readLine(256);
    defer allocator.free(request);
    try testing.expectEqualStrings("ping\n", request);

    _ = try server_stream.write("pong\n");
    try server_stream.finish();
    conn.destroyStream(server_stream);
    try testing.expectEqual(@as(usize, 0), conn.streams.items.len);

    var response: ?[]u8 = null;
    const response_wait_start = milliTimestamp();
    while (milliTimestamp() - response_wait_start < 3000 and response == null) {
        response = stream.readLineWithInterrupt(256, &interruptNever) catch |err| {
            if (err == error.WouldBlock) {
                try client.poll(1);
                try qt.poll(1);
                threadSleep(500 * std.time.ns_per_us);
                continue;
            }
            return err;
        };
    }
    if (response == null) return error.Timeout;
    const response_line = response.?;
    defer allocator.free(response_line);
    try testing.expectEqualStrings("pong\n", response_line);
    try testing.expectError(error.Interrupted, stream.readLineWithInterrupt(16, &interruptAlways));

    stream.deinit();
    qt.destroyConnection(conn);
    try testing.expectEqual(@as(usize, 0), qt.connections.items.len);
    qt.drainPendingDestroy();
    try testing.expectEqual(@as(usize, 0), qt.pending_destroy.items.len);
}

test "transport geode compat: auto-generated cert is ECDSA P-256" {
    const allocator = std.heap.page_allocator;
    try requireOpenSsl(allocator);

    const io = std.Io.Threaded.global_single_threaded.io();
    const cert_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/quic-transport-cert-{d}.pem",
        .{@as(u64, @intCast(@as(i64, @truncate(nanoTimestamp()))))},
    );
    defer allocator.free(cert_path);

    const key_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/quic-transport-key-{d}.pem",
        .{@as(u64, @intCast(@as(i64, @truncate(nanoTimestamp()))))},
    );
    defer allocator.free(key_path);

    std.Io.Dir.cwd().deleteFile(io, cert_path) catch {};
    std.Io.Dir.cwd().deleteFile(io, key_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, cert_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, key_path) catch {};

    var qt = try transport.QuicTransport.init(allocator, .{
        .address = "127.0.0.1",
        .port = allocatePort(),
        .cert_path = cert_path,
        .key_path = key_path,
        .allow_insecure = true,
        .auto_generate_certs = true,
    });
    defer qt.deinit();

    try qt.listen();
    try std.Io.Dir.cwd().access(io, cert_path, .{});
    try std.Io.Dir.cwd().access(io, key_path, .{});

    const dump = std.process.run(allocator, io, .{
        .argv = &[_][]const u8{
            "openssl",
            "x509",
            "-in",
            cert_path,
            "-noout",
            "-text",
        },
    }) catch return error.SkipZigTest;
    defer allocator.free(dump.stdout);
    defer allocator.free(dump.stderr);

    if (dump.term != .exited or dump.term.exited != 0) {
        return error.CertificateDumpFailed;
    }

    try testing.expect(
        std.mem.containsAtLeast(u8, dump.stdout, 1, "id-ecPublicKey") or
            std.mem.containsAtLeast(u8, dump.stdout, 1, "prime256v1"),
    );
}

test "transport geode compat: tryAccept is non-blocking and does not call poll" {
    // Regression test for idle CPU issue: tryAccept() should be a lightweight
    // queue check, not a full poll cycle.  Previously tryAccept called ep.poll(10)
    // which burned ~40% CPU when called in a loop.
    const allocator = std.heap.page_allocator;
    try ensureTestCertFiles(allocator);

    var qt = try transport.QuicTransport.init(allocator, .{
        .address = "localhost",
        .port = allocatePort(),
        .cert_path = "tests/certs/cert.pem",
        .key_path = "tests/certs/key.pem",
        .allow_insecure = true,
    });
    defer qt.deinit();
    try qt.listen();

    // Call tryAccept 1000 times and measure wall-clock time.
    // With the old ep.poll(10) this would take 1000 * 10ms = 10+ seconds.
    // With the fix it should complete in <100ms (just queue checks).
    const start = milliTimestamp();
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        try testing.expect(qt.tryAccept() == null);
    }
    const elapsed = milliTimestamp() - start;

    // Must complete in under 500ms (generous margin; typically <10ms).
    try testing.expect(elapsed < 500);
}

test "transport geode compat: waitForAccepted returns null on timeout" {
    const allocator = std.heap.page_allocator;
    try ensureTestCertFiles(allocator);

    var qt = try transport.QuicTransport.init(allocator, .{
        .address = "localhost",
        .port = allocatePort(),
        .cert_path = "tests/certs/cert.pem",
        .key_path = "tests/certs/key.pem",
        .allow_insecure = true,
    });
    defer qt.deinit();
    try qt.listen();

    // waitForAccepted with short timeout should return null when idle.
    const start = milliTimestamp();
    const result = qt.waitForAccepted(50);
    const elapsed = milliTimestamp() - start;

    try testing.expect(result == null);
    // Should block for roughly the timeout period (plus/minus 30ms for scheduling).
    try testing.expect(elapsed >= 20);
    try testing.expect(elapsed < 200);
}
