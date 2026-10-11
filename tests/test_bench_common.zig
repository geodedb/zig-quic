const std = @import("std");
const common = @import("bench_common");

fn prewarmBenchmarkEnv() !void {
    // Cached host metadata outlives each test's report arena.
    try common.prewarmEnvCache(std.heap.page_allocator, std.testing.io);
}

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
    try prewarmBenchmarkEnv();
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
    try prewarmBenchmarkEnv();
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    AllocationScenario.calls = 0;
    AllocationScenario.fail_at = 2;
    try std.testing.expectError(error.SampleFailed, common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "allocation-test" }, AllocationScenario.run));
}

const BatchLatencyScenario = struct {
    var calls: usize = 0;
    var operations: u32 = 1000;
    var mismatch: bool = false;

    fn run(allocator: std.mem.Allocator, _: common.ScenarioSpec) !common.RunOutput {
        calls += 1;
        return .{
            .iterations = 3000,
            .wall_time_ns = 9000,
            .cpu_time_ns = 9000,
            .latencies_ns = try allocator.dupe(u64, &.{3001}),
            .latency_sample_operations = if (mismatch and calls == 3) 256 else operations,
        };
    }
};

test "SONNY-4798 harness preserves raw batch percentiles through JSON" {
    try prewarmBenchmarkEnv();
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    BatchLatencyScenario.calls = 0;
    BatchLatencyScenario.operations = 1000;
    BatchLatencyScenario.mismatch = false;
    const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "batch-test" }, BatchLatencyScenario.run);
    try std.testing.expectEqual(@as(u64, 3), row.latency_p95_ns);
    try std.testing.expectEqual(@as(u32, 1000), row.latency_batch.?.operations);
    try std.testing.expectEqual(@as(u64, 3001), row.latency_batch.?.p95_ns);
    try std.testing.expectEqual(@as(u64, 9000), row.wall_time_ns);
    try std.testing.expectApproxEqAbs(@as(f64, 3000.0 / 9000.0 * 1e9), row.throughput_ops_per_sec, 0.001);
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, row, .{});
    defer std.testing.allocator.free(json);
    const decoded = try std.json.parseFromSlice(common.ResultRow, std.testing.allocator, json, .{});
    defer decoded.deinit();
    try std.testing.expectEqualDeep(row.latency_batch, decoded.value.latency_batch);
}

test "SONNY-4798 invalid batch sizes fail and release workload allocations" {
    try prewarmBenchmarkEnv();
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    BatchLatencyScenario.calls = 0;
    BatchLatencyScenario.operations = 0;
    BatchLatencyScenario.mismatch = false;
    try std.testing.expectError(error.InvalidLatencySampleOperations, common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "invalid-batch" }, BatchLatencyScenario.run));
    BatchLatencyScenario.calls = 0;
    BatchLatencyScenario.operations = 1000;
    BatchLatencyScenario.mismatch = true;
    try std.testing.expectError(error.InconsistentLatencySampleOperations, common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "mismatched-batch" }, BatchLatencyScenario.run));
}

test "SONNY-4798 unbatched runs retain existing latency units" {
    try prewarmBenchmarkEnv();
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    BatchLatencyScenario.calls = 0;
    BatchLatencyScenario.operations = 1;
    BatchLatencyScenario.mismatch = false;
    const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "unbatched-test" }, BatchLatencyScenario.run);
    try std.testing.expectEqual(@as(u64, 3001), row.latency_p95_ns);
    try std.testing.expectEqual(@as(?common.LatencyBatch, null), row.latency_batch);
}

const RetainedLatencyScenario = struct {
    var calls: usize = 0;
    var reverse_throughput: bool = false;
    var handshake_mode: enum { all, sparse, warmup_only, empty } = .all;

    fn run(allocator: std.mem.Allocator, _: common.ScenarioSpec) !common.RunOutput {
        const index = calls;
        calls += 1;
        const value: u64 = if (index == 0) 999_999 else @as(u64, @intCast(index)) * 10;
        const latencies = try allocator.dupe(u64, &.{ value, value + 1 });
        errdefer allocator.free(latencies);
        const include_handshake = index == 0 or handshake_mode == .all or
            (handshake_mode == .sparse and (index == 1 or index == 6));
        const handshake: ?[]u64 = if (include_handshake)
            try allocator.dupe(u64, &.{ value * 10, value * 10 + 1 })
        else if (handshake_mode == .empty)
            try allocator.alloc(u64, 0)
        else
            null;
        const time_factor: u64 = if (index == 0) 1000 else if (reverse_throughput) 7 - index else index;
        return .{
            .iterations = 100,
            .wall_time_ns = time_factor * 1000,
            .cpu_time_ns = time_factor * 1000,
            .latencies_ns = latencies,
            .handshake_latencies_ns = handshake,
            .alloc_count = @intCast(index),
        };
    }
};

test "SONNY-4784 latency percentiles include all retained runs regardless of throughput order" {
    try prewarmBenchmarkEnv();
    for ([_]bool{ false, true }) |reverse| {
        var report = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer report.deinit();
        RetainedLatencyScenario.calls = 0;
        RetainedLatencyScenario.reverse_throughput = reverse;
        RetainedLatencyScenario.handshake_mode = .all;
        const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "retained-latencies" }, RetainedLatencyScenario.run);
        try std.testing.expectEqual(@as(usize, 7), RetainedLatencyScenario.calls);
        // Six pairs 10/11 through 60/61; the warmup's 999999 must be absent.
        try std.testing.expectEqual(@as(u64, 31), row.latency_p50_ns);
        try std.testing.expectEqual(@as(u64, 60), row.latency_p95_ns);
        try std.testing.expectEqual(@as(u64, 60), row.latency_p99_ns);
        try std.testing.expectEqual(@as(?u64, 301), row.handshake_latency_p50_ns);
        try std.testing.expectEqual(@as(?u64, 600), row.handshake_latency_p99_ns);
        // Throughput and cost metadata still describe the representative run.
        try std.testing.expectEqual(@as(u64, 3000), row.wall_time_ns);
        try std.testing.expectEqual(@as(u64, if (reverse) 4 else 3), row.alloc_count);
    }
}

test "SONNY-4784 handshake samples outside the representative run are retained" {
    try prewarmBenchmarkEnv();
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    RetainedLatencyScenario.calls = 0;
    RetainedLatencyScenario.reverse_throughput = false;
    RetainedLatencyScenario.handshake_mode = .sparse;
    const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "sparse-handshakes" }, RetainedLatencyScenario.run);
    try std.testing.expectEqual(@as(?u64, 101), row.handshake_latency_p50_ns);
    try std.testing.expectEqual(@as(?u64, 600), row.handshake_latency_p99_ns);
}

test "SONNY-4784 absent or empty retained handshakes do not report warmup data" {
    try prewarmBenchmarkEnv();
    inline for (.{ .warmup_only, .empty }) |mode| {
        var report = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer report.deinit();
        RetainedLatencyScenario.calls = 0;
        RetainedLatencyScenario.reverse_throughput = false;
        RetainedLatencyScenario.handshake_mode = mode;
        const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "absent-handshakes" }, RetainedLatencyScenario.run);
        try std.testing.expectEqual(@as(?u64, null), row.handshake_latency_p50_ns);
        try std.testing.expectEqual(@as(?u64, null), row.handshake_latency_p99_ns);
    }
}

fn retainedLatencyAllocationCheck(allocator: std.mem.Allocator) !void {
    var report = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer report.deinit();
    RetainedLatencyScenario.calls = 0;
    RetainedLatencyScenario.reverse_throughput = false;
    RetainedLatencyScenario.handshake_mode = .all;
    _ = try common.runRepeated(report.allocator(), allocator, std.testing.io, .{ .name = "latency-allocation-failures" }, RetainedLatencyScenario.run);
}

test "SONNY-4784 every workload allocation failure releases retained samples" {
    try prewarmBenchmarkEnv();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, retainedLatencyAllocationCheck, .{});
}

const RetainedBatchScenario = struct {
    fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
        var output = try RetainedLatencyScenario.run(allocator, spec);
        for (output.latencies_ns) |*sample| sample.* = sample.* * 100 + 1;
        output.latency_sample_operations = 1000;
        return output;
    }
};

test "SONNY-4784 SONNY-4798 retained raw batch percentiles keep fractional precision" {
    try prewarmBenchmarkEnv();
    for ([_]bool{ false, true }) |reverse| {
        var report = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer report.deinit();
        RetainedLatencyScenario.calls = 0;
        RetainedLatencyScenario.reverse_throughput = reverse;
        RetainedLatencyScenario.handshake_mode = .all;
        const row = try common.runRepeated(report.allocator(), std.testing.allocator, std.testing.io, .{ .name = "retained-batches" }, RetainedBatchScenario.run);
        // Pool 1001/1101 through 6001/6101; exclude warmup. Preserve the
        // fractional ns/op data regardless of the representative run.
        try std.testing.expectEqual(@as(u32, 1000), row.latency_batch.?.operations);
        try std.testing.expectEqual(@as(u64, 3101), row.latency_batch.?.p50_ns);
        try std.testing.expectEqual(@as(u64, 6001), row.latency_batch.?.p95_ns);
        try std.testing.expectEqual(@as(u64, 6001), row.latency_batch.?.p99_ns);
        try std.testing.expectEqual(@as(u64, 3), row.latency_p50_ns);
        try std.testing.expectEqual(@as(u64, 6), row.latency_p95_ns);
        // Handshake observations are unbatched and keep their own units.
        try std.testing.expectEqual(@as(?u64, 301), row.handshake_latency_p50_ns);
        try std.testing.expectEqual(@as(?u64, 600), row.handshake_latency_p99_ns);
        try std.testing.expectEqual(@as(u64, 3000), row.wall_time_ns);
    }
}
