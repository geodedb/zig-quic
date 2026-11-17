const std = @import("std");
const common = @import("bench_common");

test "summarizeLatencies: sorted percentiles" {
    var vals = [_]u64{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(usize, 10), s.count);
    try std.testing.expectEqual(@as(u64, 10), s.min_ns);
    try std.testing.expectEqual(@as(u64, 100), s.max_ns);
    try std.testing.expect(s.p50_ns >= 40 and s.p50_ns <= 60);
    try std.testing.expect(s.p95_ns >= 90);
    try std.testing.expect(s.p99_ns >= 90);
}

test "summarizeLatencies: empty slice" {
    var vals = [_]u64{};
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(u64, 0), s.min_ns);
    try std.testing.expectEqual(@as(u64, 0), s.p50_ns);
}

test "parseOutputArg: --output=PATH" {
    const args = [_][]const u8{ "prog", "--output=foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseOutputArg: --output PATH" {
    const args = [_][]const u8{ "prog", "--output", "foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseSuiteArg: --suite=NAME" {
    const args = [_][]const u8{ "prog", "--suite=micro" };
    try std.testing.expectEqualStrings("micro", common.parseSuiteArg(&args).?);
}

const AllocationScenario = struct {
    var calls: usize = 0;
    var fail_at: ?usize = null;

    fn run(allocator: std.mem.Allocator, _: common.ScenarioSpec) !common.RunOutput {
        calls += 1;
        if (fail_at == calls) return error.SampleFailed;
        const scratch = try allocator.alloc(u8, 1024 * 1024);
        defer allocator.free(scratch);
        @memset(scratch, 1);
        const latencies = try allocator.alloc(u64, 1);
        errdefer allocator.free(latencies);
        latencies[0] = 100;
        return .{
            .iterations = 1,
            .wall_time_ns = 1000,
            .cpu_time_ns = 1000,
            .latencies_ns = latencies,
            .external_impl = try allocator.dupe(u8, "allocation-test"),
        };
    }
};

test "runRepeated releases workload allocations and retains report metadata" {
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    AllocationScenario.calls = 0;
    AllocationScenario.fail_at = null;
    const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "allocation-test" }, AllocationScenario.run);
    try std.testing.expectEqual(@as(usize, 7), AllocationScenario.calls);
    try std.testing.expectEqualStrings("allocation-test", row.external_impl.?);
    try std.testing.expectEqual(@as(u64, 100), row.latency_p50_ns);
}

test "runRepeated frees earlier outputs when a later sample fails" {
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    AllocationScenario.calls = 0;
    AllocationScenario.fail_at = 2;
    try std.testing.expectError(error.SampleFailed, common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "allocation-test" }, AllocationScenario.run));
}

// SONNY-6668: a scenario on a platform it cannot measure on (the loopback
// QUIC scenarios are Linux-only) returns a not-measured row, which fails the
// perf gate, never placeholder numbers that pass it.
test "requireLinux: not measured on another OS, nothing on Linux" {
    const A = std.testing.allocator;
    inline for (.{ .macos, .windows, .freebsd }) |os| {
        const out = (try common.requireLinux(A, os)) orelse return error.TestExpectedNotMeasured;
        defer A.free(out.latencies_ns);
        try std.testing.expectEqualStrings("UnsupportedPlatform", out.not_measured.?);
        try std.testing.expectEqual(@as(u64, 0), out.iterations);
    }
    try std.testing.expect((try common.requireLinux(A, .linux)) == null);
}
