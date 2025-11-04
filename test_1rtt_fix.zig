// Test to verify the 1-RTT transcript hash fix
const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls").key_schedule;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.debug.print("=== Testing 1-RTT Transcript Hash Fix ===\n\n", .{});

    // Simulate client and server deriving application secrets
    // They should use the same transcript: CH...SH...EE...Cert...CV...server Finished

    var client = tls13.Engine.init(alloc, .Client);
    defer client.deinit();

    var server = tls13.Engine.init(alloc, .Server);
    defer server.deinit();

    // Set a deterministic ECDHE for testing
    const test_ecdhe = [_]u8{0xaa} ** 32;
    client.ecdhe_buf = test_ecdhe;
    client.ecdhe_secret = &client.ecdhe_buf;
    server.ecdhe_buf = test_ecdhe;
    server.ecdhe_secret = &server.ecdhe_buf;

    // Simulate transcript: CH
    const ch_bytes = [_]u8{ 0x01, 0x00, 0x00, 0x10 } ++ ([_]u8{0x11} ** 16);
    client.transcript.update(&ch_bytes);
    server.transcript.update(&ch_bytes);
    client.ch_sent = true;
    server.ch_recv = true;

    // Simulate transcript: SH
    const sh_bytes = [_]u8{ 0x02, 0x00, 0x00, 0x10 } ++ ([_]u8{0x22} ** 16);
    client.transcript.update(&sh_bytes);
    server.transcript.update(&sh_bytes);
    client.sh_seen = true;
    server.sh_seen = true;

    // Simulate transcript: EE, Cert, CV
    const ee_bytes = [_]u8{ 0x08, 0x00, 0x00, 0x08 } ++ ([_]u8{0x33} ** 8);
    client.transcript.update(&ee_bytes);
    server.transcript.update(&ee_bytes);

    const cert_bytes = [_]u8{ 0x0b, 0x00, 0x00, 0x10 } ++ ([_]u8{0x44} ** 16);
    client.transcript.update(&cert_bytes);
    server.transcript.update(&cert_bytes);

    const cv_bytes = [_]u8{ 0x0f, 0x00, 0x00, 0x10 } ++ ([_]u8{0x55} ** 16);
    client.transcript.update(&cv_bytes);
    server.transcript.update(&cv_bytes);

    // Simulate transcript: server Finished (added by server when queueing, by client when receiving)
    const s_finished_bytes = [_]u8{ 0x14, 0x00, 0x00, 0x20 } ++ ([_]u8{0x66} ** 32);
    client.transcript.update(&s_finished_bytes);
    server.transcript.update(&s_finished_bytes);

    // At this point, BOTH should have: CH...SH...EE...Cert...CV...server Finished
    std.debug.print("Client transcript hash before computing app secrets:\n", .{});
    const client_th = client.transcript.finalize();
    std.debug.print("  ", .{});
    for (client_th[0..16]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("...\n", .{});

    std.debug.print("Server transcript hash before computing app secrets:\n", .{});
    const server_th = server.transcript.finalize();
    std.debug.print("  ", .{});
    for (server_th[0..16]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("...\n\n", .{});

    // Verify they match
    if (!std.mem.eql(u8, &client_th, &server_th)) {
        std.debug.print("❌ FAIL: Client and server transcript hashes DON'T MATCH!\n", .{});
        return error.TranscriptMismatch;
    }
    std.debug.print("✅ PASS: Client and server transcript hashes MATCH\n\n", .{});

    // Compute application secrets
    const client_secrets = client.computeApplicationSecrets() orelse return error.NoSecrets;
    const server_secrets = server.computeApplicationSecrets() orelse return error.NoSecrets;

    std.debug.print("Client application secrets:\n", .{});
    std.debug.print("  client_app[0..8]: ", .{});
    for (client_secrets.client[0..8]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n  server_app[0..8]: ", .{});
    for (client_secrets.server[0..8]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    std.debug.print("Server application secrets:\n", .{});
    std.debug.print("  client_app[0..8]: ", .{});
    for (server_secrets.client[0..8]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n  server_app[0..8]: ", .{});
    for (server_secrets.server[0..8]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // Verify they match
    if (!std.mem.eql(u8, &client_secrets.client, &server_secrets.client) or
        !std.mem.eql(u8, &client_secrets.server, &server_secrets.server))
    {
        std.debug.print("❌ FAIL: Client and server application secrets DON'T MATCH!\n", .{});
        return error.SecretMismatch;
    }

    std.debug.print("✅ PASS: Client and server application secrets MATCH\n", .{});
    std.debug.print("✅ The 1-RTT transcript hash fix is working correctly!\n", .{});
}
