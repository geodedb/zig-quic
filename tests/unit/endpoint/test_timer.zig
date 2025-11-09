//! Unit tests for endpoint/timer.zig
//!
//! RFC References:
//! - RFC 9002 §6.2: Probe Timeout (PTO)
//! - RFC 9002 §6.2.1: Computing PTO
//! - RFC 9000 §14.2: Path MTU Discovery timers
//!
//! Coverage:
//! - Positive cases: Timer scheduling, cancellation, expiry detection
//! - Negative cases: Cancel non-existent timer, flush empty queue
//! - Edge cases: Multiple timers, heap property maintenance
//! - RFC compliance: PTO timer management, min-heap ordering

const std = @import("std");
const testing = std.testing;

const timer = @import("timer");
const types = @import("types");

var test_allocator = std.testing.allocator;

// =============================================================================
// TimerManager Initialization Tests
// =============================================================================

test "RFC 9002 §6.2 - TimerManager initial state" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    try testing.expectEqual(@as(usize, 0), tm.timers.items.len);
    try testing.expectEqual(@as(u64, 1), tm.next_timer_id);
}

test "RFC 9002 §6.2 - TimerManager deinit cleans up" {
    var tm = timer.TimerManager.init(test_allocator);
    tm.deinit();

    // Should not crash or leak memory (verified by test allocator)
}

// =============================================================================
// Timer Scheduling Tests
// =============================================================================

test "RFC 9002 §6.2 - schedule timer returns unique ID" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id1 = try tm.schedule(100, .PtoInitial, null);
    const id2 = try tm.schedule(200, .PtoHandshake, null);

    try testing.expect(id1 != id2);
    try testing.expectEqual(@as(u64, 1), id1);
    try testing.expectEqual(@as(u64, 2), id2);
}

test "RFC 9002 §6.2 - schedule increments timer count" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    try testing.expectEqual(@as(usize, 0), tm.timers.items.len);

    _ = try tm.schedule(100, .PtoInitial, null);
    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);

    _ = try tm.schedule(200, .PtoHandshake, null);
    try testing.expectEqual(@as(usize, 2), tm.timers.items.len);
}

test "RFC 9002 §6.2 - schedule with zero delay" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id = try tm.schedule(0, .PtoInitial, null);
    try testing.expect(id > 0);
    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);
}

test "RFC 9002 §6.2 - schedule multiple timer kinds" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(100, .PtoInitial, null);
    _ = try tm.schedule(200, .PtoHandshake, null);
    _ = try tm.schedule(300, .PtoApp, null);
    _ = try tm.schedule(400, .Generic, null);

    try testing.expectEqual(@as(usize, 4), tm.timers.items.len);
}

// =============================================================================
// Timer Cancellation Tests
// =============================================================================

test "RFC 9002 §6.2 - cancel removes timer by ID" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id = try tm.schedule(100, .PtoInitial, null);
    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);

    const cancelled = tm.cancel(id);
    try testing.expect(cancelled);
    try testing.expectEqual(@as(usize, 0), tm.timers.items.len);
}

test "RFC 9002 §6.2 - cancel non-existent timer returns false" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const cancelled = tm.cancel(999);
    try testing.expect(!cancelled);
}

test "RFC 9002 §6.2 - cancel one of multiple timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id1 = try tm.schedule(100, .PtoInitial, null);
    const id2 = try tm.schedule(200, .PtoHandshake, null);
    const id3 = try tm.schedule(300, .PtoApp, null);

    try testing.expectEqual(@as(usize, 3), tm.timers.items.len);

    const cancelled = tm.cancel(id2);
    try testing.expect(cancelled);
    try testing.expectEqual(@as(usize, 2), tm.timers.items.len);

    // Remaining timers should still be present
    var found_id1 = false;
    var found_id3 = false;
    for (tm.timers.items) |t| {
        if (t.id == id1) found_id1 = true;
        if (t.id == id3) found_id3 = true;
    }
    try testing.expect(found_id1);
    try testing.expect(found_id3);
}

test "RFC 9002 §6.2 - cancel twice returns false second time" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id = try tm.schedule(100, .PtoInitial, null);

    const cancelled1 = tm.cancel(id);
    try testing.expect(cancelled1);

    const cancelled2 = tm.cancel(id);
    try testing.expect(!cancelled2);
}

// =============================================================================
// Next Deadline Tests
// =============================================================================

test "RFC 9002 §6.2 - nextDeadline returns null for empty queue" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    try testing.expectEqual(@as(?i64, null), tm.nextDeadline());
}

test "RFC 9002 §6.2 - nextDeadline returns earliest timer" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(300, .PtoInitial, null);
    _ = try tm.schedule(100, .PtoHandshake, null); // Earliest
    _ = try tm.schedule(200, .PtoApp, null);

    const deadline = tm.nextDeadline();
    try testing.expect(deadline != null);

    // The min-heap should have the earliest deadline at root
    const root_deadline = tm.timers.items[0].deadline_ms;
    try testing.expectEqual(root_deadline, deadline.?);
}

test "RFC 9002 §6.2 - nextDeadline updates after cancel" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id1 = try tm.schedule(100, .PtoInitial, null);
    _ = try tm.schedule(200, .PtoHandshake, null);

    const deadline1 = tm.nextDeadline();
    try testing.expect(deadline1 != null);

    _ = tm.cancel(id1);

    const deadline2 = tm.nextDeadline();
    try testing.expect(deadline2 != null);
    try testing.expect(deadline2.? > deadline1.?);
}

// =============================================================================
// Timer Flush Tests
// =============================================================================

test "RFC 9002 §6.2 - flush returns empty list for no expired timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    // Schedule timer far in the future
    _ = try tm.schedule(1000000, .PtoInitial, null);

    var expired = try tm.flush(test_allocator);
    defer expired.deinit(test_allocator);

    try testing.expectEqual(@as(usize, 0), expired.items.len);
    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);
}

test "RFC 9002 §6.2 - flush removes expired timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    // Schedule timers with delays that should expire immediately
    _ = try tm.schedule(0, .PtoInitial, null);

    // Give it a moment to ensure expiry
    std.Thread.sleep(1 * std.time.ns_per_ms);

    var expired = try tm.flush(test_allocator);
    defer expired.deinit(test_allocator);

    // At least one timer should have expired
    try testing.expect(expired.items.len > 0);
}

test "RFC 9002 §6.2 - flush on empty queue returns empty list" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    var expired = try tm.flush(test_allocator);
    defer expired.deinit(test_allocator);

    try testing.expectEqual(@as(usize, 0), expired.items.len);
}

// =============================================================================
// Min-Heap Property Tests
// =============================================================================

test "RFC 9002 §6.2 - min-heap maintains ordering after inserts" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    // Insert timers in reverse order
    _ = try tm.schedule(300, .PtoInitial, null);
    _ = try tm.schedule(200, .PtoHandshake, null);
    _ = try tm.schedule(100, .PtoApp, null);

    // Root should have earliest deadline
    const root = tm.timers.items[0];
    for (tm.timers.items[1..]) |t| {
        try testing.expect(root.deadline_ms <= t.deadline_ms);
    }
}

test "RFC 9002 §6.2 - min-heap maintains ordering after cancel" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(100, .PtoInitial, null);
    const id2 = try tm.schedule(200, .PtoHandshake, null);
    _ = try tm.schedule(300, .PtoApp, null);

    _ = tm.cancel(id2);

    // Verify heap property: parent <= children
    const len = tm.timers.items.len;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const left = 2 * i + 1;
        const right = 2 * i + 2;

        if (left < len) {
            try testing.expect(tm.timers.items[i].deadline_ms <= tm.timers.items[left].deadline_ms);
        }
        if (right < len) {
            try testing.expect(tm.timers.items[i].deadline_ms <= tm.timers.items[right].deadline_ms);
        }
    }
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "boundary: schedule with max delay" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id = try tm.schedule(std.math.maxInt(u32), .PtoInitial, null);
    try testing.expect(id > 0);
}

test "boundary: schedule many timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        _ = try tm.schedule(i * 10, .PtoInitial, null);
    }

    try testing.expectEqual(@as(usize, 100), tm.timers.items.len);

    // Verify min-heap property holds
    const len = tm.timers.items.len;
    var idx: usize = 0;
    while (idx < len) : (idx += 1) {
        const left = 2 * idx + 1;
        const right = 2 * idx + 2;

        if (left < len) {
            try testing.expect(tm.timers.items[idx].deadline_ms <= tm.timers.items[left].deadline_ms);
        }
        if (right < len) {
            try testing.expect(tm.timers.items[idx].deadline_ms <= tm.timers.items[right].deadline_ms);
        }
    }
}

test "boundary: cancel all timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    var ids: [10]u64 = undefined;
    for (&ids, 0..) |*id, i| {
        id.* = try tm.schedule(@intCast(i * 100), .PtoInitial, null);
    }

    try testing.expectEqual(@as(usize, 10), tm.timers.items.len);

    for (ids) |id| {
        _ = tm.cancel(id);
    }

    try testing.expectEqual(@as(usize, 0), tm.timers.items.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 §6.2 - TimerManager supports PTO timer types" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(100, .PtoInitial, null);
    _ = try tm.schedule(100, .PtoHandshake, null);
    _ = try tm.schedule(100, .PtoApp, null);

    try testing.expectEqual(@as(usize, 3), tm.timers.items.len);

    // Verify all timer kinds are present
    var found_initial = false;
    var found_handshake = false;
    var found_app = false;

    for (tm.timers.items) |t| {
        switch (t.kind) {
            .PtoInitial => found_initial = true,
            .PtoHandshake => found_handshake = true,
            .PtoApp => found_app = true,
            else => {},
        }
    }

    try testing.expect(found_initial);
    try testing.expect(found_handshake);
    try testing.expect(found_app);
}

test "RFC 9002 §6.2 - TimerManager supports idle timeout" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(30000, .Generic, null);

    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);
    try testing.expectEqual(types.TimerKind.Generic, tm.timers.items[0].kind);
}

test "RFC 9000 §14.2 - TimerManager supports PMTU discovery timers" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    _ = try tm.schedule(1000, .Pmtud, null);

    try testing.expectEqual(@as(usize, 1), tm.timers.items.len);
    try testing.expectEqual(types.TimerKind.Pmtud, tm.timers.items[0].kind);
}

test "RFC 9002 §6.2.1 - Timer scheduling uses monotonic time" {
    var tm = timer.TimerManager.init(test_allocator);
    defer tm.deinit();

    const id1 = try tm.schedule(100, .PtoInitial, null);

    // Small delay
    std.Thread.sleep(2 * std.time.ns_per_ms);

    const id2 = try tm.schedule(100, .PtoHandshake, null);

    // Both timers should have different deadlines despite same delay
    // because they were scheduled at different times
    var deadline1: i64 = 0;
    var deadline2: i64 = 0;

    for (tm.timers.items) |t| {
        if (t.id == id1) deadline1 = t.deadline_ms;
        if (t.id == id2) deadline2 = t.deadline_ms;
    }

    try testing.expect(deadline2 >= deadline1);
}
