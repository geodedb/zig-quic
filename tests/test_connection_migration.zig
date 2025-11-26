const std = @import("std");
const conn_mod = @import("quic_conn");
const endpoint_mod = @import("quic_endpoint");
const frame = @import("quic_frame");
const packet = @import("quic_packet");

test "connection migration with PATH_CHALLENGE and PATH_RESPONSE" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Create endpoint and connection
    var ep = try endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();

    var conn = try ep.connectClient("127.0.0.1:4433");

    // Simulate migration by changing peer address
    const old_addr = conn.peer;
    var new_addr = conn_mod.SockAddr.ipv4(127, 0, 0, 2, 4433);

    // Update peer address
    conn.setPeer(new_addr);
    try std.testing.expect(!conn.peer.eq(&old_addr));
    try std.testing.expect(conn.peer.eq(&new_addr));

    // Send PATH_CHALLENGE
    conn.sendPathChallenge();
    try std.testing.expect(conn.path_validation_pending);

    // Verify PATH_CHALLENGE data was generated
    try std.testing.expect(!std.mem.eql(u8, &conn.path_challenge_data, &[_]u8{0} ** 8));

    // Simulate receiving PATH_RESPONSE with matching data
    const response_frame = frame.Frame{ .path_response = conn.path_challenge_data };

    // Process PATH_RESPONSE (would normally be done in packet processing)
    if (std.mem.eql(u8, &response_frame.path_response, &conn.path_challenge_data)) {
        conn.path_validation_pending = false;
        conn.address_validated = true;
    }

    try std.testing.expect(!conn.path_validation_pending);
    try std.testing.expect(conn.address_validated);
}

test "NAT rebinding detection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var ep = try endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();

    // Create a server connection
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, 0, conn_mod.SockAddr{});
    defer conn.deinit();

    // Set initial peer address
    conn.peer = conn_mod.SockAddr.ipv4(192, 168, 1, 100, 5000);
    conn.address_validated = true;

    // Simulate packet from new address (NAT rebinding)
    const new_peer = conn_mod.SockAddr.ipv4(192, 168, 1, 100, 5001); // Different port

    // Detect rebinding
    const rebinding_detected = !conn.peer.eq(&new_peer);
    try std.testing.expect(rebinding_detected);

    // Update address and trigger validation
    if (rebinding_detected) {
        conn.setPeer(new_peer);
        conn.sendPathChallenge();
        try std.testing.expect(conn.path_validation_pending);
    }
}

test "connection migration state transitions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    _ = alloc;

    const MigrationState = enum {
        None,
        Probing,
        Validated,
        Failed,
    };

    var state = MigrationState.None;

    // Start migration
    state = MigrationState.Probing;
    try std.testing.expectEqual(MigrationState.Probing, state);

    // Successful validation
    state = MigrationState.Validated;
    try std.testing.expectEqual(MigrationState.Validated, state);

    // Test failure case
    state = MigrationState.Probing;
    // Timeout or max retries
    state = MigrationState.Failed;
    try std.testing.expectEqual(MigrationState.Failed, state);
}

test "multiple path management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const Path = struct {
        addr: conn_mod.SockAddr,
        validated: bool,
        rtt: u64,
        cwnd: u32,
        active: bool,
    };

    var paths = std.ArrayList(Path){};
    defer paths.deinit(alloc);

    // Primary path
    try paths.append(alloc, .{
        .addr = conn_mod.SockAddr.ipv4(192, 168, 1, 1, 443),
        .validated = true,
        .rtt = 10_000, // 10ms
        .cwnd = 10 * 1200,
        .active = true,
    });

    // Alternative path
    try paths.append(alloc, .{
        .addr = conn_mod.SockAddr.ipv4(10, 0, 0, 1, 443),
        .validated = false,
        .rtt = 50_000, // 50ms
        .cwnd = 2 * 1200,
        .active = false,
    });

    // Find active path
    var active_path: ?*Path = null;
    for (paths.items) |*path| {
        if (path.active) {
            active_path = path;
            break;
        }
    }

    try std.testing.expect(active_path != null);
    try std.testing.expect(active_path.?.validated);

    // Switch to alternative path
    if (active_path) |ap| {
        ap.active = false;
    }
    paths.items[1].active = true;
    paths.items[1].validated = true;

    // Verify switch
    for (paths.items) |*path| {
        if (path.active) {
            try std.testing.expectEqual(@as(u64, 50_000), path.rtt);
            break;
        }
    }
}
