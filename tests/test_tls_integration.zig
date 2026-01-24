// Integration test: Alert handling and zero-RTT replay detection
// Demonstrates wiring of alert.zig and zero_rtt.zig into Context
const std = @import("std");
const tls13 = @import("quic_tls13");
const alert_mod = @import("alert");
const zero_rtt_mod = @import("zero_rtt");

test "alert mapping for handshake errors" {
    // Verify Context can translate errors to alerts
    const err = error.UnexpectedMessage;
    const alert_desc = alert_mod.fromHandshakeError(err);
    try std.testing.expectEqual(alert_mod.AlertDescription.unexpected_message, alert_desc);
    
    // Verify QUIC error code mapping
    const quic_err = alert_mod.toQuicCryptoError(alert_desc);
    try std.testing.expectEqual(@as(u64, 0x0100 + 10), quic_err);
}

test "zero-RTT replay detection in handshake flow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    // Create anti-replay window
    var replay_window = zero_rtt_mod.AntiReplayWindow.init(alloc);
    defer replay_window.deinit();
    
    // Simulate ClientHello random value
    const random1: [32]u8 = .{0xAA} ** 32;
    const random2: [32]u8 = .{0xBB} ** 32;
    
    // First ClientHello - should succeed
    try replay_window.add(random1);
    try std.testing.expect(replay_window.contains(random1));
    
    // Replay attempt - should fail
    try std.testing.expectError(error.ReplayDetected, replay_window.add(random1));
    
    // Different ClientHello - should succeed
    try replay_window.add(random2);
    try std.testing.expect(replay_window.contains(random2));
}

test "context error handling with alert translation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Server }, .{});
    defer ctx.deinit();
    
    // Simulate an error condition
    const test_err = error.AlpnNegotiationFailed;
    
    // Verify error maps to correct alert
    const alert_desc = alert_mod.fromHandshakeError(test_err);
    try std.testing.expectEqual(alert_mod.AlertDescription.no_application_protocol, alert_desc);
    
    // Verify alert encodes correctly
    const alert = alert_mod.Alert{
        .level = .fatal,
        .description = alert_desc,
    };
    const encoded = alert.encode();
    try std.testing.expectEqual(@as(u8, 2), encoded[0]); // fatal
    try std.testing.expectEqual(@as(u8, 120), encoded[1]); // no_application_protocol
}

test "complete TLS integration: Context with alert and replay protection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    // Initialize Context
    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Server }, .{});
    defer ctx.deinit();
    
    // Initialize replay window (would be stored in server state)
    var replay_window = zero_rtt_mod.AntiReplayWindow.init(alloc);
    defer replay_window.deinit();
    
    // Simulate error scenarios and verify alert handling
    const errors = [_]anyerror{
        error.UnexpectedMessage,
        error.MissingKeyShare,
        error.FinishedVerifyFailed,
        error.DowngradeAttempt,
    };
    
    for (errors) |err| {
        const alert_desc = alert_mod.fromHandshakeError(err);
        const quic_code = alert_mod.toQuicCryptoError(alert_desc);
        
        // Verify all errors map to valid QUIC crypto errors
        try std.testing.expect(quic_code >= 0x0100);
        try std.testing.expect(quic_code < 0x0200);
    }
    
    // Test zero-RTT limits
    const limits = zero_rtt_mod.ZeroRttLimits{};
    try std.testing.expectEqual(@as(u32, 16384), limits.max_early_data_size);
}
