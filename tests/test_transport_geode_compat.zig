// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

const std = @import("std");
const testing = std.testing;
const transport = @import("transport");

var next_port = std.atomic.Value(u16).init(18000);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

fn waitForFlag(flag: *std.atomic.Value(bool), timeout_ms: u64) !void {
    const start = std.time.milliTimestamp();
    while (!flag.load(.acquire)) {
        if (std.time.milliTimestamp() - start > @as(i64, @intCast(timeout_ms))) {
            return error.Timeout;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

fn interruptNever() bool {
    return false;
}

fn interruptAlways() bool {
    return true;
}

fn requireOpenSsl(allocator: std.mem.Allocator) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "openssl", "version" },
    }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        return error.SkipZigTest;
    }
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn runOpenSsl(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) {
        return error.TestCertsUnavailable;
    }
}

fn ensureTestCertFiles(allocator: std.mem.Allocator) !void {
    const cert_path = "tests/certs/cert.pem";
    const key_path = "tests/certs/key.pem";

    if (pathExists(cert_path) and pathExists(key_path)) return;

    std.fs.cwd().makePath("tests/certs") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

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
            std.Thread.sleep(30 * std.time.ns_per_ms);
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

    std.Thread.sleep(10 * std.time.ns_per_ms);
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
    const handshake_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - handshake_start < 5000 and server_conn == null) {
        try qt.poll(1);
        try client.poll(1);
        server_conn = qt.tryAccept();
        std.Thread.sleep(500 * std.time.ns_per_us);
    }
    if (server_conn == null) return error.Timeout;
    const conn = server_conn.?;

    try client.waitForHandshake(5);
    try testing.expect(conn.isHandshakeConfirmed());
    try testing.expect(conn.getPeerCertificateDer() == null);

    var stream = try client.openStream(true);

    _ = try stream.write("ping\n");
    try stream.finish();

    var scratch: [16]u8 = undefined;
    try testing.expectError(error.WouldBlock, stream.read(&scratch));
    try client.poll(10);
    try qt.poll(10);

    const stream_wait_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - stream_wait_start < 3000 and !conn.hasIncomingStreams()) {
        try qt.poll(1);
        try client.poll(1);
        std.Thread.sleep(500 * std.time.ns_per_us);
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
    const response_wait_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - response_wait_start < 3000 and response == null) {
        response = stream.readLineWithInterrupt(256, &interruptNever) catch |err| {
            if (err == error.WouldBlock) {
                try client.poll(1);
                try qt.poll(1);
                std.Thread.sleep(500 * std.time.ns_per_us);
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

    const cert_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/quic-transport-cert-{d}.pem",
        .{@as(u64, @intCast(std.time.nanoTimestamp()))},
    );
    defer allocator.free(cert_path);

    const key_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/quic-transport-key-{d}.pem",
        .{@as(u64, @intCast(std.time.nanoTimestamp()))},
    );
    defer allocator.free(key_path);

    std.fs.cwd().deleteFile(cert_path) catch {};
    std.fs.cwd().deleteFile(key_path) catch {};
    defer std.fs.cwd().deleteFile(cert_path) catch {};
    defer std.fs.cwd().deleteFile(key_path) catch {};

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
    try std.fs.cwd().access(cert_path, .{});
    try std.fs.cwd().access(key_path, .{});

    const dump = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "openssl",
            "x509",
            "-in",
            cert_path,
            "-noout",
            "-text",
        },
    });
    defer allocator.free(dump.stdout);
    defer allocator.free(dump.stderr);

    if (dump.term != .Exited or dump.term.Exited != 0) {
        return error.CertificateDumpFailed;
    }

    try testing.expect(
        std.mem.containsAtLeast(u8, dump.stdout, 1, "id-ecPublicKey") or
            std.mem.containsAtLeast(u8, dump.stdout, 1, "prime256v1"),
    );
}
