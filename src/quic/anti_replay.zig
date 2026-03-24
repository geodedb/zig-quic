// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Server-side 0-RTT anti-replay cache per RFC 8446 S8 and RFC 9001 S9.2.
//!
//! This module provides a bounded, time-windowed cache that tracks Client Hello
//! hashes (or ticket nonces) to detect replayed 0-RTT data. Each entry records
//! the timestamp at which the ticket was first seen. Entries older than the
//! configured time window are evicted on every `checkAndRecord` call.
//!
//! The cache is designed to be shared across connections on a single server
//! endpoint. Thread safety is provided via an internal mutex so that concurrent
//! connections can safely call `checkAndRecord`.
const std = @import("std");

/// Anti-replay cache for 0-RTT data (RFC 8446 S8, RFC 9001 S9.2).
///
/// Maintains a bounded set of recently-seen ticket hashes with time-windowed
/// expiry. A ticket that appears more than once within the window is rejected
/// as a replay.
pub const AntiReplayCache = struct {
    /// Map from ticket hash to the nanosecond timestamp when first recorded.
    entries: std.AutoHashMapUnmanaged(u64, u64),
    /// Time window in nanoseconds; entries older than this are evicted.
    window_ns: u64,
    /// Maximum number of entries; when exceeded the oldest entries are evicted.
    max_entries: u32,
    /// Allocator used for the internal hash map.
    allocator: std.mem.Allocator,
    /// Mutex protecting the entries map for concurrent access.
    mu: std.Thread.Mutex,

    /// Initialize a new anti-replay cache.
    ///
    /// `max_entries` bounds heap usage. `window_ns` controls how long a ticket
    /// hash is remembered (RFC 8446 S8 recommends a small window, typically
    /// matching the ticket lifetime or a few seconds).
    pub fn init(allocator: std.mem.Allocator, max_entries: u32, window_ns: u64) AntiReplayCache {
        return .{
            .entries = .{},
            .window_ns = window_ns,
            .max_entries = max_entries,
            .allocator = allocator,
            .mu = .{},
        };
    }

    /// Release all memory held by the cache.
    pub fn deinit(self: *AntiReplayCache) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.entries.deinit(self.allocator);
    }

    /// Check whether `ticket_hash` has been seen within the current time window.
    ///
    /// Returns `true` if this is the **first** time the hash is observed (fresh
    /// -- 0-RTT should be accepted). Returns `false` if the hash was already
    /// recorded (replay -- 0-RTT must be rejected).
    ///
    /// Automatically evicts expired entries and enforces the capacity bound
    /// before recording.
    pub fn checkAndRecord(self: *AntiReplayCache, ticket_hash: u64, now_ns: u64) !bool {
        self.mu.lock();
        defer self.mu.unlock();

        // 1. Evict entries outside the time window.
        self.evictExpired(now_ns);

        // 2. Check for an existing (non-expired) entry.
        if (self.entries.get(ticket_hash)) |recorded_ns| {
            // Still within window -- this is a replay.
            if (now_ns -| recorded_ns <= self.window_ns) {
                return false;
            }
            // Entry exists but is conceptually expired (should have been
            // evicted above, but guard defensively). Overwrite below.
        }

        // 3. Enforce capacity bound: if full, evict the oldest entry.
        if (self.entries.count() >= self.max_entries) {
            self.evictOldest();
        }

        // 4. Record the new entry.
        try self.entries.put(self.allocator, ticket_hash, now_ns);
        return true;
    }

    /// Evict all entries whose timestamp is older than `now_ns - window_ns`.
    fn evictExpired(self: *AntiReplayCache, now_ns: u64) void {
        // Collect keys to remove (cannot mutate map during iteration).
        // Use a small stack buffer to avoid allocation in the common case.
        var to_remove: [128]u64 = undefined;
        var remove_count: usize = 0;

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now_ns -| entry.value_ptr.* > self.window_ns) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
                // If more than 128 expired entries exist we will catch them
                // on the next call. This keeps the stack budget bounded.
            }
        }

        for (to_remove[0..remove_count]) |key| {
            _ = self.entries.remove(key);
        }
    }

    /// Evict the single oldest entry (by timestamp). Called when the map is at
    /// capacity and a new entry must be inserted.
    fn evictOldest(self: *AntiReplayCache) void {
        var oldest_key: ?u64 = null;
        var oldest_ts: u64 = std.math.maxInt(u64);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < oldest_ts) {
                oldest_ts = entry.value_ptr.*;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            _ = self.entries.remove(key);
        }
    }

    /// Compute a 64-bit hash from an arbitrary byte slice (e.g., serialised
    /// Client Hello, session ticket, or transport parameters). Uses the Zig
    /// standard Wyhash which is fast and has good distribution for hash-map
    /// keys. This is NOT a cryptographic hash -- it only needs to be
    /// collision-resistant enough for the bounded cache.
    pub fn hashBytes(data: []const u8) u64 {
        return std.hash.Wyhash.hash(0, data);
    }

    /// Convenience: hash a fixed-size connection ID (Cid-style struct with
    /// `len` and `bytes` fields).
    pub fn hashCid(len: u8, bytes: *const [20]u8) u64 {
        return hashBytes(bytes[0..len]);
    }
};

// ============================================================================
// Inline tests
// ============================================================================

test "anti-replay: first check returns true (accepted)" {
    var cache = AntiReplayCache.init(std.testing.allocator, 100, 10_000_000_000);
    defer cache.deinit();

    const hash: u64 = 0xDEAD_BEEF_CAFE_1234;
    const now: u64 = 1_000_000_000; // 1 second in ns

    const result = try cache.checkAndRecord(hash, now);
    try std.testing.expect(result == true);
}

test "anti-replay: second check with same hash returns false (rejected)" {
    var cache = AntiReplayCache.init(std.testing.allocator, 100, 10_000_000_000);
    defer cache.deinit();

    const hash: u64 = 0xDEAD_BEEF_CAFE_1234;
    const now: u64 = 1_000_000_000;

    _ = try cache.checkAndRecord(hash, now);
    const result = try cache.checkAndRecord(hash, now + 1_000); // 1 microsecond later
    try std.testing.expect(result == false);
}

test "anti-replay: check after window expiry returns true (re-accepted)" {
    const window_ns: u64 = 5_000_000_000; // 5 seconds
    var cache = AntiReplayCache.init(std.testing.allocator, 100, window_ns);
    defer cache.deinit();

    const hash: u64 = 0xDEAD_BEEF_CAFE_1234;
    const t0: u64 = 1_000_000_000;

    _ = try cache.checkAndRecord(hash, t0);

    // Attempt within window -- should be rejected.
    const within = try cache.checkAndRecord(hash, t0 + 2_000_000_000);
    try std.testing.expect(within == false);

    // Attempt after window -- should be accepted (entry expired).
    const after = try cache.checkAndRecord(hash, t0 + window_ns + 1);
    try std.testing.expect(after == true);
}

test "anti-replay: capacity eviction when max_entries exceeded" {
    var cache = AntiReplayCache.init(std.testing.allocator, 3, 60_000_000_000);
    defer cache.deinit();

    // Fill to capacity: {1(100), 2(200), 3(300)}
    _ = try cache.checkAndRecord(1, 100);
    _ = try cache.checkAndRecord(2, 200);
    _ = try cache.checkAndRecord(3, 300);

    // All three should be present (replay detected).
    try std.testing.expect(try cache.checkAndRecord(1, 350) == false);
    try std.testing.expect(try cache.checkAndRecord(2, 350) == false);
    try std.testing.expect(try cache.checkAndRecord(3, 350) == false);

    // Insert a 4th entry -- oldest (hash=1, ts=100) should be evicted.
    // After: {2(200), 3(300), 4(400)}
    const fresh_4 = try cache.checkAndRecord(4, 400);
    try std.testing.expect(fresh_4 == true);

    // Hash 1 was evicted -- should be accepted as fresh.
    // Cache is full so oldest (hash=2, ts=200) is evicted first.
    // After: {3(300), 4(400), 1(450)}
    try std.testing.expect(try cache.checkAndRecord(1, 450) == true);

    // Hash 3 and 4 should still be in the cache (replay).
    try std.testing.expect(try cache.checkAndRecord(3, 450) == false);
    try std.testing.expect(try cache.checkAndRecord(4, 450) == false);

    // Hash 2 was evicted (oldest at the time hash 1 was re-inserted).
    try std.testing.expect(try cache.checkAndRecord(2, 460) == true);
}

test "anti-replay: hashBytes produces consistent output" {
    const data = "hello world";
    const h1 = AntiReplayCache.hashBytes(data);
    const h2 = AntiReplayCache.hashBytes(data);
    try std.testing.expect(h1 == h2);

    // Different input should (almost certainly) produce a different hash.
    const h3 = AntiReplayCache.hashBytes("goodbye world");
    try std.testing.expect(h1 != h3);
}

test "anti-replay: distinct hashes are independent" {
    var cache = AntiReplayCache.init(std.testing.allocator, 100, 10_000_000_000);
    defer cache.deinit();

    const now: u64 = 1_000_000_000;
    _ = try cache.checkAndRecord(0xAAAA, now);
    _ = try cache.checkAndRecord(0xBBBB, now);

    // Each hash is recorded independently.
    try std.testing.expect(try cache.checkAndRecord(0xAAAA, now + 1) == false);
    try std.testing.expect(try cache.checkAndRecord(0xBBBB, now + 1) == false);
    // A new hash is still accepted.
    try std.testing.expect(try cache.checkAndRecord(0xCCCC, now + 1) == true);
}
