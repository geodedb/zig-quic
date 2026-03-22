const std = @import("std");

pub const Timer = struct { id: u64, deadline_us: u64 };

pub const TimerHeap = struct {
    a: std.ArrayList(Timer),

    pub fn init(allocator: std.mem.Allocator) !TimerHeap {
        return .{ .a = try std.ArrayList(Timer).initCapacity(allocator, 0) };
    }
    pub fn deinit(self: *TimerHeap, allocator: std.mem.Allocator) void {
        self.a.deinit(allocator);
    }

    fn less(a: Timer, b: Timer) bool {
        return a.deadline_us < b.deadline_us;
    }

    pub fn push(self: *TimerHeap, allocator: std.mem.Allocator, t: Timer) !void {
        try self.a.append(allocator, t);
        var i = self.a.items.len - 1;
        // up-heap
        while (i > 0) : (i = (i - 1) / 2) {
            const p = (i - 1) / 2;
            if (!less(self.a.items[i], self.a.items[p])) break;
            std.mem.swap(Timer, &self.a.items[i], &self.a.items[p]);
        }
    }

    pub fn peek(self: *TimerHeap) ?Timer {
        return if (self.a.items.len == 0) null else self.a.items[0];
    }

    pub fn pop(self: *TimerHeap) ?Timer {
        if (self.a.items.len == 0) return null;
        const min = self.a.items[0];
        const last = self.a.items[self.a.items.len - 1];
        self.a.items[0] = last;
        _ = self.a.pop();
        // down-heap
        var i: usize = 0;
        while (true) {
            const l = 2 * i + 1;
            const r = 2 * i + 2;
            var m = i;
            if (l < self.a.items.len and less(self.a.items[l], self.a.items[m])) m = l;
            if (r < self.a.items.len and less(self.a.items[r], self.a.items[m])) m = r;
            if (m == i) break;
            std.mem.swap(Timer, &self.a.items[i], &self.a.items[m]);
            i = m;
        }
        return min;
    }
};

test "timer: order by deadline" {
    var th = try TimerHeap.init(std.testing.allocator);
    defer th.deinit(std.testing.allocator);
    try th.push(std.testing.allocator, .{ .id = 1, .deadline_us = 300 });
    try th.push(std.testing.allocator, .{ .id = 2, .deadline_us = 100 });
    try th.push(std.testing.allocator, .{ .id = 3, .deadline_us = 200 });
    try std.testing.expectEqual(@as(u64, 2), th.pop().?.id);
    try std.testing.expectEqual(@as(u64, 3), th.pop().?.id);
    try std.testing.expectEqual(@as(u64, 1), th.pop().?.id);
}

test "timer: edge — empty peek/pop" {
    var th = try TimerHeap.init(std.testing.allocator);
    defer th.deinit(std.testing.allocator);
    try std.testing.expect(th.peek() == null);
    try std.testing.expect(th.pop() == null);
}

test "timer: invalid — handles many inserts without overflow" {
    var th = try TimerHeap.init(std.testing.allocator);
    defer th.deinit(std.testing.allocator);
    var i: usize = 0;
    while (i < 1024) : (i += 1) try th.push(std.testing.allocator, .{ .id = i, .deadline_us = @as(u64, 1024 - i) });
    try std.testing.expect(th.pop() != null);
}
