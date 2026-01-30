// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC idle timeout management.
//!
//! RFC 9000 §10.1: Idle Timeout

const std = @import("std");

/// Maximum tolerable backward clock skew before triggering timeout (5 seconds in ns).
/// CWE-191 mitigation: Prevents attackers from keeping connections alive via clock manipulation.
const MAX_CLOCK_SKEW_NS: u64 = 5 * std.time.ns_per_s;

/// Idle timeout timer state.
/// RFC 9000 §10.1: An endpoint closes the connection if it does not send or receive packets for the idle timeout period.
pub const IdleTimer = struct {
    /// Local idle timeout preference in milliseconds (from config).
    /// RFC 9000 §10.1: Each endpoint advertises its own idle timeout.
    local_timeout_ms: u64 = 30000, // 30 seconds default

    /// Peer's advertised idle timeout in milliseconds (from transport parameters).
    /// RFC 9000 §10.1: The effective idle timeout is the minimum of the two values.
    peer_timeout_ms: u64 = 0,

    /// Negotiated idle timeout in milliseconds (min of local and peer, or 0 if disabled).
    /// RFC 9000 §10.1: If either endpoint sets 0, idle timeout is disabled.
    effective_timeout_ms: u64 = 0,

    /// Last time a packet was sent or received (nanoseconds).
    /// RFC 9000 §10.1: The idle timer resets whenever a packet is sent or received.
    last_activity_ns: u64 = 0,

    /// Whether idle timeout is enabled.
    /// RFC 9000 §10.1: Disabled if either peer advertises 0.
    enabled: bool = false,

    /// Count of significant backward clock skew events detected.
    /// CWE-191 mitigation: Triggers timeout if clock manipulation detected.
    clock_skew_count: u8 = 0,

    /// Initialize idle timer with local timeout preference.
    /// RFC 9000 §10.1: Each endpoint advertises an idle_timeout in transport parameters.
    pub fn init(local_timeout_ms: u64, now_ns: u64) IdleTimer {
        return .{
            .local_timeout_ms = local_timeout_ms,
            .last_activity_ns = now_ns,
            .enabled = local_timeout_ms > 0,
        };
    }

    /// Negotiate idle timeout with peer's transport parameters.
    /// RFC 9000 §10.1: The idle timeout is the minimum of the two advertised values.
    /// RFC 9000 §10.1: If either endpoint sets 0, idle timeout is disabled.
    pub fn negotiate(self: *IdleTimer, peer_timeout_ms: u64) void {
        self.peer_timeout_ms = peer_timeout_ms;

        // RFC 9000 §10.1: Disabled if either endpoint advertises 0
        if (self.local_timeout_ms == 0 or peer_timeout_ms == 0) {
            self.effective_timeout_ms = 0;
            self.enabled = false;
            return;
        }

        // RFC 9000 §10.1: The effective idle timeout is the minimum of the two values
        self.effective_timeout_ms = @min(self.local_timeout_ms, peer_timeout_ms);
        self.enabled = true;
    }

    /// Update idle timer on packet activity (sent or received).
    /// RFC 9000 §10.1: The idle timer resets whenever a packet is sent or received.
    pub fn onActivity(self: *IdleTimer, now_ns: u64) void {
        self.last_activity_ns = now_ns;
        // Reset clock skew counter on legitimate activity
        self.clock_skew_count = 0;
    }

    /// Update on packet sent.
    /// RFC 9000 §10.1.1: Sending any packet resets the idle timer.
    pub fn onPacketSent(self: *IdleTimer, now_ns: u64) void {
        self.onActivity(now_ns);
    }

    /// Update on packet received.
    /// RFC 9000 §10.1.1: Receiving any packet resets the idle timer.
    pub fn onPacketReceived(self: *IdleTimer, now_ns: u64) void {
        self.onActivity(now_ns);
    }

    /// Check if idle timeout has expired.
    /// RFC 9000 §10.1.2: The connection is closed if no packets are sent or received for the idle timeout period.
    /// CWE-191 mitigation: Handles backward clock skew safely.
    pub fn isExpired(self: *IdleTimer, now_ns: u64) bool {
        if (!self.enabled) return false;
        if (self.effective_timeout_ms == 0) return false;

        const timeout_ns = self.effective_timeout_ms * std.time.ns_per_ms;

        // CWE-191 mitigation: Detect significant backward clock skew.
        // If clock went backward by more than MAX_CLOCK_SKEW_NS, count it as
        // potential clock manipulation and trigger timeout after 3 occurrences.
        if (now_ns < self.last_activity_ns) {
            const backward_skew = self.last_activity_ns - now_ns;
            if (backward_skew > MAX_CLOCK_SKEW_NS) {
                // Significant backward clock skew detected
                self.clock_skew_count +|= 1; // saturating add
                if (self.clock_skew_count >= 3) {
                    // Too many clock skew events - treat as timeout to prevent
                    // connections staying alive indefinitely via clock manipulation
                    return true;
                }
            }
            // For small backward skews, use 0 elapsed (clock jitter is normal)
            return false;
        }

        const elapsed_ns = now_ns - self.last_activity_ns;
        return elapsed_ns >= timeout_ns;
    }

    /// Get time until idle timeout expires (nanoseconds).
    /// Returns null if idle timeout is disabled or has already expired.
    /// CWE-191 mitigation: Handles backward clock skew safely.
    pub fn timeUntilExpiry(self: *const IdleTimer, now_ns: u64) ?u64 {
        if (!self.enabled) return null;
        if (self.effective_timeout_ms == 0) return null;

        const timeout_ns = self.effective_timeout_ms * std.time.ns_per_ms;

        // Handle backward clock skew: if clock went backward, return full timeout
        // to prevent busy-waiting (small skew is normal clock jitter)
        if (now_ns < self.last_activity_ns) {
            const backward_skew = self.last_activity_ns - now_ns;
            if (backward_skew > MAX_CLOCK_SKEW_NS) {
                // Significant backward skew - if too many, report expired
                if (self.clock_skew_count >= 3) return null;
            }
            // For small skews, return full timeout period
            return timeout_ns;
        }

        const elapsed_ns = now_ns - self.last_activity_ns;
        if (elapsed_ns >= timeout_ns) return null; // Already expired

        return timeout_ns - elapsed_ns;
    }

    /// Get absolute time when idle timeout will expire (nanoseconds).
    /// Returns null if idle timeout is disabled.
    pub fn expiryTime(self: *const IdleTimer) ?u64 {
        if (!self.enabled) return null;
        if (self.effective_timeout_ms == 0) return null;

        const timeout_ns = self.effective_timeout_ms * std.time.ns_per_ms;
        return self.last_activity_ns + timeout_ns;
    }

    /// Reset idle timer (useful after renegotiation or connection reset).
    pub fn reset(self: *IdleTimer, now_ns: u64) void {
        self.last_activity_ns = now_ns;
    }

    /// Disable idle timeout (e.g., during connection migration or testing).
    pub fn disable(self: *IdleTimer) void {
        self.enabled = false;
        self.effective_timeout_ms = 0;
    }

    /// Enable idle timeout with a new negotiated value.
    pub fn enable(self: *IdleTimer, timeout_ms: u64, now_ns: u64) void {
        if (timeout_ms > 0) {
            self.effective_timeout_ms = timeout_ms;
            self.enabled = true;
            self.last_activity_ns = now_ns;
        }
    }
};

/// Negotiate idle timeout between local and peer values.
/// RFC 9000 §10.1: The effective idle timeout is the minimum of the two advertised values.
/// RFC 9000 §10.1: If either endpoint advertises 0, idle timeout is disabled.
pub fn negotiateIdleTimeout(local_timeout_ms: u64, peer_timeout_ms: u64) u64 {
    // RFC 9000 §10.1: Disabled if either endpoint advertises 0
    if (local_timeout_ms == 0 or peer_timeout_ms == 0) {
        return 0;
    }

    // RFC 9000 §10.1: The effective idle timeout is the minimum of the two values
    return @min(local_timeout_ms, peer_timeout_ms);
}

/// Check if idle timeout should be disabled based on local and peer values.
/// RFC 9000 §10.1: Idle timeout is disabled if either endpoint advertises 0.
pub fn isIdleTimeoutDisabled(local_timeout_ms: u64, peer_timeout_ms: u64) bool {
    return local_timeout_ms == 0 or peer_timeout_ms == 0;
}

/// Convert milliseconds to nanoseconds for timeout calculations.
pub fn msToNs(ms: u64) u64 {
    return ms * std.time.ns_per_ms;
}

/// Convert nanoseconds to milliseconds for transport parameters.
pub fn nsToMs(ns: u64) u64 {
    return ns / std.time.ns_per_ms;
}

/// Calculate idle timeout deadline from last activity time.
/// RFC 9000 §10.1: The idle timeout period starts from the time of last packet activity.
pub fn calculateDeadline(last_activity_ns: u64, timeout_ms: u64) u64 {
    return last_activity_ns + msToNs(timeout_ms);
}

/// Check if current time has passed the idle timeout deadline.
pub fn hasDeadlinePassed(now_ns: u64, deadline_ns: u64) bool {
    return now_ns >= deadline_ns;
}
