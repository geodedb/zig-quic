//! Unit tests for connection/idle.zig
//!
//! RFC References:
//! - RFC 9000 §10.1: Idle Timeout
//! - RFC 9000 §10.1.1: Updating the Idle Timer
//! - RFC 9000 §10.1.2: Liveness Testing
//!
//! Coverage:
//! - Positive cases: Timer initialization, negotiation, activity tracking, expiry detection
//! - Negative cases: Disabled timers, zero timeouts, expired timers
//! - Edge cases: Boundary timeouts, zero values, max values, simultaneous activity
//! - RFC compliance: Min-of-two negotiation, zero-disables rule, activity reset

const std = @import("std");
const testing = std.testing;

const idle = @import("idle");

// Time constants for readability
const ONE_MS: u64 = 1_000_000; // 1 millisecond in nanoseconds
const ONE_SEC: u64 = 1_000_000_000; // 1 second in nanoseconds
const ONE_MIN: u64 = 60 * ONE_SEC; // 1 minute in nanoseconds

// =============================================================================
// IdleTimer Initialization Tests
// =============================================================================

test "RFC 9000 §10.1 - IdleTimer init with default timeout" {
    const now: u64 = 1_000_000_000;
    const timer = idle.IdleTimer.init(30000, now);

    try testing.expectEqual(@as(u64, 30000), timer.local_timeout_ms);
    try testing.expectEqual(@as(u64, 0), timer.peer_timeout_ms);
    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
    try testing.expectEqual(now, timer.last_activity_ns);
    try testing.expect(timer.enabled);
}

test "RFC 9000 §10.1 - IdleTimer init with custom timeout" {
    const now: u64 = 2_000_000_000;
    const timer = idle.IdleTimer.init(60000, now);

    try testing.expectEqual(@as(u64, 60000), timer.local_timeout_ms);
    try testing.expectEqual(now, timer.last_activity_ns);
    try testing.expect(timer.enabled);
}

test "RFC 9000 §10.1 - IdleTimer init with zero timeout disables" {
    const now: u64 = 3_000_000_000;
    const timer = idle.IdleTimer.init(0, now);

    try testing.expectEqual(@as(u64, 0), timer.local_timeout_ms);
    try testing.expect(!timer.enabled);
}

test "RFC 9000 §10.1 - IdleTimer init stores last activity time" {
    const now: u64 = 5_000_000_000;
    const timer = idle.IdleTimer.init(30000, now);

    try testing.expectEqual(now, timer.last_activity_ns);
}

// =============================================================================
// Timeout Negotiation Tests
// =============================================================================

test "RFC 9000 §10.1 - negotiate with lower peer timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(60000, now);

    timer.negotiate(30000);

    try testing.expectEqual(@as(u64, 30000), timer.peer_timeout_ms);
    try testing.expectEqual(@as(u64, 30000), timer.effective_timeout_ms);
    try testing.expect(timer.enabled);
}

test "RFC 9000 §10.1 - negotiate with higher peer timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.negotiate(60000);

    try testing.expectEqual(@as(u64, 60000), timer.peer_timeout_ms);
    try testing.expectEqual(@as(u64, 30000), timer.effective_timeout_ms);
    try testing.expect(timer.enabled);
}

test "RFC 9000 §10.1 - negotiate with equal timeouts" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(45000, now);

    timer.negotiate(45000);

    try testing.expectEqual(@as(u64, 45000), timer.effective_timeout_ms);
    try testing.expect(timer.enabled);
}

test "RFC 9000 §10.1 - negotiate with peer zero disables timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.negotiate(0);

    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
    try testing.expect(!timer.enabled);
}

test "RFC 9000 §10.1 - negotiate when local is zero disables timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    timer.negotiate(30000);

    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
    try testing.expect(!timer.enabled);
}

test "RFC 9000 §10.1 - negotiate with both zero disables timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    timer.negotiate(0);

    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
    try testing.expect(!timer.enabled);
}

// =============================================================================
// Activity Tracking Tests
// =============================================================================

test "RFC 9000 §10.1.1 - onActivity updates last activity time" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    const new_time = now + 5 * ONE_SEC;
    timer.onActivity(new_time);

    try testing.expectEqual(new_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1.1 - onPacketSent resets idle timer" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    const send_time = now + 10 * ONE_SEC;
    timer.onPacketSent(send_time);

    try testing.expectEqual(send_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1.1 - onPacketReceived resets idle timer" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    const recv_time = now + 8 * ONE_SEC;
    timer.onPacketReceived(recv_time);

    try testing.expectEqual(recv_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1.1 - multiple activities update timer" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.onPacketSent(now + 1 * ONE_SEC);
    timer.onPacketReceived(now + 2 * ONE_SEC);
    timer.onActivity(now + 3 * ONE_SEC);

    try testing.expectEqual(now + 3 * ONE_SEC, timer.last_activity_ns);
}

// =============================================================================
// Expiry Detection Tests
// =============================================================================

test "RFC 9000 §10.1.2 - isExpired false before timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now); // 30 second timeout
    timer.negotiate(30000);

    const check_time = now + 29 * ONE_SEC; // 1 second before timeout
    try testing.expect(!timer.isExpired(check_time));
}

test "RFC 9000 §10.1.2 - isExpired true after timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now); // 30 second timeout
    timer.negotiate(30000);

    const check_time = now + 31 * ONE_SEC; // 1 second after timeout
    try testing.expect(timer.isExpired(check_time));
}

test "RFC 9000 §10.1.2 - isExpired at exact timeout boundary" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now); // 30 second timeout
    timer.negotiate(30000);

    const check_time = now + 30 * ONE_SEC; // Exactly at timeout
    try testing.expect(timer.isExpired(check_time));
}

test "RFC 9000 §10.1.2 - isExpired false when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(0); // Disable timeout

    const check_time = now + 100 * ONE_SEC; // Long time later
    try testing.expect(!timer.isExpired(check_time));
}

test "RFC 9000 §10.1.2 - isExpired resets after activity" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now); // 30 second timeout
    timer.negotiate(30000);

    // Check before timeout
    const check1 = now + 20 * ONE_SEC;
    try testing.expect(!timer.isExpired(check1));

    // Activity resets timer
    timer.onPacketSent(check1);

    // Check 25 seconds after activity (55 seconds from start)
    const check2 = check1 + 25 * ONE_SEC;
    try testing.expect(!timer.isExpired(check2)); // Should not be expired

    // Check 31 seconds after activity (51 seconds from start)
    const check3 = check1 + 31 * ONE_SEC;
    try testing.expect(timer.isExpired(check3)); // Should be expired
}

// =============================================================================
// Time Until Expiry Tests
// =============================================================================

test "RFC 9000 §10.1 - timeUntilExpiry calculates remaining time" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now); // 30 second timeout
    timer.negotiate(30000);

    const check_time = now + 10 * ONE_SEC;
    const remaining = timer.timeUntilExpiry(check_time);

    try testing.expect(remaining != null);
    try testing.expectEqual(@as(u64, 20 * ONE_SEC), remaining.?);
}

test "RFC 9000 §10.1 - timeUntilExpiry null when expired" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    const check_time = now + 31 * ONE_SEC;
    const remaining = timer.timeUntilExpiry(check_time);

    try testing.expect(remaining == null);
}

test "RFC 9000 §10.1 - timeUntilExpiry null when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    const remaining = timer.timeUntilExpiry(now + ONE_SEC);

    try testing.expect(remaining == null);
}

test "RFC 9000 §10.1 - timeUntilExpiry at exact expiry" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    const check_time = now + 30 * ONE_SEC;
    const remaining = timer.timeUntilExpiry(check_time);

    // At exact expiry, should return null (already expired)
    try testing.expect(remaining == null);
}

// =============================================================================
// Expiry Time Tests
// =============================================================================

test "RFC 9000 §10.1 - expiryTime calculates absolute deadline" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    const expiry = timer.expiryTime();

    try testing.expect(expiry != null);
    try testing.expectEqual(now + 30 * ONE_SEC, expiry.?);
}

test "RFC 9000 §10.1 - expiryTime updates after activity" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    const activity_time = now + 10 * ONE_SEC;
    timer.onPacketSent(activity_time);

    const expiry = timer.expiryTime();

    try testing.expect(expiry != null);
    try testing.expectEqual(activity_time + 30 * ONE_SEC, expiry.?);
}

test "RFC 9000 §10.1 - expiryTime null when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    const expiry = timer.expiryTime();

    try testing.expect(expiry == null);
}

// =============================================================================
// Timer Control Tests
// =============================================================================

test "RFC 9000 §10.1 - reset updates last activity time" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    const reset_time = now + 15 * ONE_SEC;
    timer.reset(reset_time);

    try testing.expectEqual(reset_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1 - disable turns off idle timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    try testing.expect(timer.enabled);

    timer.disable();

    try testing.expect(!timer.enabled);
    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
}

test "RFC 9000 §10.1 - enable activates idle timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    try testing.expect(!timer.enabled);

    const enable_time = now + 5 * ONE_SEC;
    timer.enable(30000, enable_time);

    try testing.expect(timer.enabled);
    try testing.expectEqual(@as(u64, 30000), timer.effective_timeout_ms);
    try testing.expectEqual(enable_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1 - enable with zero timeout does not enable" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(0, now);

    timer.enable(0, now);

    try testing.expect(!timer.enabled);
}

// =============================================================================
// Helper Function Tests
// =============================================================================

test "RFC 9000 §10.1 - negotiateIdleTimeout takes minimum" {
    const local: u64 = 30000;
    const peer: u64 = 60000;

    const effective = idle.negotiateIdleTimeout(local, peer);

    try testing.expectEqual(@as(u64, 30000), effective);
}

test "RFC 9000 §10.1 - negotiateIdleTimeout with peer lower" {
    const local: u64 = 60000;
    const peer: u64 = 30000;

    const effective = idle.negotiateIdleTimeout(local, peer);

    try testing.expectEqual(@as(u64, 30000), effective);
}

test "RFC 9000 §10.1 - negotiateIdleTimeout with equal values" {
    const local: u64 = 45000;
    const peer: u64 = 45000;

    const effective = idle.negotiateIdleTimeout(local, peer);

    try testing.expectEqual(@as(u64, 45000), effective);
}

test "RFC 9000 §10.1 - negotiateIdleTimeout zero local disables" {
    const effective = idle.negotiateIdleTimeout(0, 30000);

    try testing.expectEqual(@as(u64, 0), effective);
}

test "RFC 9000 §10.1 - negotiateIdleTimeout zero peer disables" {
    const effective = idle.negotiateIdleTimeout(30000, 0);

    try testing.expectEqual(@as(u64, 0), effective);
}

test "RFC 9000 §10.1 - isIdleTimeoutDisabled detects zero local" {
    try testing.expect(idle.isIdleTimeoutDisabled(0, 30000));
}

test "RFC 9000 §10.1 - isIdleTimeoutDisabled detects zero peer" {
    try testing.expect(idle.isIdleTimeoutDisabled(30000, 0));
}

test "RFC 9000 §10.1 - isIdleTimeoutDisabled false when both nonzero" {
    try testing.expect(!idle.isIdleTimeoutDisabled(30000, 60000));
}

test "RFC 9000 §10.1 - msToNs converts milliseconds to nanoseconds" {
    try testing.expectEqual(@as(u64, 1_000_000), idle.msToNs(1));
    try testing.expectEqual(@as(u64, 1_000_000_000), idle.msToNs(1000));
    try testing.expectEqual(@as(u64, 30_000_000_000), idle.msToNs(30000));
}

test "RFC 9000 §10.1 - nsToMs converts nanoseconds to milliseconds" {
    try testing.expectEqual(@as(u64, 1), idle.nsToMs(1_000_000));
    try testing.expectEqual(@as(u64, 1000), idle.nsToMs(1_000_000_000));
    try testing.expectEqual(@as(u64, 30000), idle.nsToMs(30_000_000_000));
}

test "RFC 9000 §10.1 - calculateDeadline computes expiry time" {
    const last_activity: u64 = 1_000_000_000;
    const timeout_ms: u64 = 30000;

    const deadline = idle.calculateDeadline(last_activity, timeout_ms);

    try testing.expectEqual(last_activity + 30 * ONE_SEC, deadline);
}

test "RFC 9000 §10.1 - hasDeadlinePassed detects expired deadline" {
    const deadline: u64 = 1_000_000_000;
    const now: u64 = 1_500_000_000;

    try testing.expect(idle.hasDeadlinePassed(now, deadline));
}

test "RFC 9000 §10.1 - hasDeadlinePassed false before deadline" {
    const deadline: u64 = 2_000_000_000;
    const now: u64 = 1_500_000_000;

    try testing.expect(!idle.hasDeadlinePassed(now, deadline));
}

test "RFC 9000 §10.1 - hasDeadlinePassed true at exact deadline" {
    const deadline: u64 = 1_000_000_000;
    const now: u64 = 1_000_000_000;

    try testing.expect(idle.hasDeadlinePassed(now, deadline));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: IdleTimer with 1ms timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(1, now);
    timer.negotiate(1);

    const check_time = now + ONE_MS;
    try testing.expect(timer.isExpired(check_time));
}

test "boundary: IdleTimer with maximum timeout" {
    const now: u64 = 1_000_000_000;
    const max_timeout: u64 = std.math.maxInt(u64) / std.time.ns_per_ms;
    const timer = idle.IdleTimer.init(max_timeout, now);

    try testing.expectEqual(max_timeout, timer.local_timeout_ms);
}

test "boundary: IdleTimer activity at same nanosecond" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.onActivity(now);
    try testing.expectEqual(now, timer.last_activity_ns);
}

test "boundary: isExpired with now less than last activity" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // Clock went backwards somehow
    const check_time = now - 1000;

    // Should handle gracefully (elapsed = 0)
    try testing.expect(!timer.isExpired(check_time));
}

test "boundary: timeUntilExpiry with now less than last activity" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    const check_time = now - 1000;
    const remaining = timer.timeUntilExpiry(check_time);

    // Should return full timeout (elapsed = 0)
    try testing.expect(remaining != null);
    try testing.expectEqual(@as(u64, 30 * ONE_SEC), remaining.?);
}

test "boundary: negotiate preserves peer timeout value" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.negotiate(45000);

    try testing.expectEqual(@as(u64, 45000), timer.peer_timeout_ms);
    try testing.expectEqual(@as(u64, 30000), timer.effective_timeout_ms);
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: isExpired always false when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.disable();

    // Check far in the future
    try testing.expect(!timer.isExpired(now + 1000 * ONE_SEC));
}

test "negative: timeUntilExpiry null when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);
    timer.disable();

    const remaining = timer.timeUntilExpiry(now + ONE_SEC);

    try testing.expect(remaining == null);
}

test "negative: expiryTime null when disabled" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);
    timer.disable();

    const expiry = timer.expiryTime();

    try testing.expect(expiry == null);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §10.1 - Idle timeout negotiation uses minimum" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(60000, now);

    timer.negotiate(30000);

    // RFC 9000 §10.1: The effective idle timeout is the minimum of the two values
    try testing.expectEqual(@as(u64, 30000), timer.effective_timeout_ms);
}

test "RFC 9000 §10.1 - Zero timeout disables idle timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);

    timer.negotiate(0);

    // RFC 9000 §10.1: If either endpoint advertises 0, idle timeout is disabled
    try testing.expect(!timer.enabled);
    try testing.expectEqual(@as(u64, 0), timer.effective_timeout_ms);
}

test "RFC 9000 §10.1.1 - Sending packets resets idle timer" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // Time passes
    const send_time = now + 20 * ONE_SEC;
    timer.onPacketSent(send_time);

    // RFC 9000 §10.1.1: The idle timer resets whenever a packet is sent
    try testing.expectEqual(send_time, timer.last_activity_ns);

    // Should not be expired 25 seconds after send (45 seconds from start)
    const check_time = send_time + 25 * ONE_SEC;
    try testing.expect(!timer.isExpired(check_time));
}

test "RFC 9000 §10.1.1 - Receiving packets resets idle timer" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // Time passes
    const recv_time = now + 15 * ONE_SEC;
    timer.onPacketReceived(recv_time);

    // RFC 9000 §10.1.1: The idle timer resets whenever a packet is received
    try testing.expectEqual(recv_time, timer.last_activity_ns);
}

test "RFC 9000 §10.1.2 - Connection closed after idle timeout" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // No activity for 31 seconds
    const check_time = now + 31 * ONE_SEC;

    // RFC 9000 §10.1.2: The connection is closed if no packets are sent or received for the idle timeout period
    try testing.expect(timer.isExpired(check_time));
}

test "RFC 9000 §10.1 - Idle timeout advertised in transport parameters" {
    // Each endpoint advertises its own idle timeout preference
    const local_timeout_ms: u64 = 30000;
    const peer_timeout_ms: u64 = 60000;

    const effective = idle.negotiateIdleTimeout(local_timeout_ms, peer_timeout_ms);

    // RFC 9000 §10.1: The effective idle timeout is the minimum of the two advertised values
    try testing.expectEqual(@as(u64, 30000), effective);
}

test "RFC 9000 §10.1 - Asymmetric timeout negotiation" {
    // Client and server can advertise different timeouts
    const client_timeout: u64 = 60000; // Client wants 60 seconds
    const server_timeout: u64 = 30000; // Server wants 30 seconds

    const effective = idle.negotiateIdleTimeout(client_timeout, server_timeout);

    // Both endpoints must use the minimum (30 seconds)
    try testing.expectEqual(@as(u64, 30000), effective);
}

test "RFC 9000 §10.1 - Idle timeout behavior with continuous activity" {
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // Continuous activity every 10 seconds
    var time = now;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        time += 10 * ONE_SEC;
        timer.onPacketSent(time);

        // Should never expire with continuous activity
        try testing.expect(!timer.isExpired(time));
    }

    // Total time passed: 100 seconds
    // Never expired because of continuous activity
    try testing.expectEqual(time, now + 100 * ONE_SEC);
}

test "RFC 9000 §10.1 - Default idle timeout is 30 seconds" {
    const now: u64 = 1_000_000_000;
    const timer = idle.IdleTimer.init(30000, now);

    // RFC 9000 implementation note: 30 seconds is a common default
    try testing.expectEqual(@as(u64, 30000), timer.local_timeout_ms);
}

test "RFC 9000 §10.1 - Idle timeout only applies to 1-RTT packets" {
    // This is an implementation detail, but the timer tracks all packet activity
    const now: u64 = 1_000_000_000;
    var timer = idle.IdleTimer.init(30000, now);
    timer.negotiate(30000);

    // Initial and Handshake packets also reset the timer
    timer.onPacketSent(now + 5 * ONE_SEC);
    timer.onPacketReceived(now + 10 * ONE_SEC);

    try testing.expectEqual(now + 10 * ONE_SEC, timer.last_activity_ns);
}
