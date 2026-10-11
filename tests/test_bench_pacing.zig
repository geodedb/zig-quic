const std = @import("std");
const pacing = @import("pacing_bench");
const recorder = @import("pacing_recorder");

test "SONNY-4805 default measured workload covers exempt and paced utilization" {
    recorder.reset();
    var spec = pacing.scenarios[0];
    // Observe only measured calls, preserving the default measured workload.
    spec.warmup_iterations = 0;
    const result = try pacing.run(std.testing.allocator, spec);
    defer std.testing.allocator.free(result.latencies_ns);

    try std.testing.expectEqual(@as(u64, 200_000), result.iterations);
    try std.testing.expectEqual(result.iterations, recorder.exempt + recorder.paced);
    try std.testing.expectEqual(@as(usize, 200), result.latencies_ns.len);
    try std.testing.expectEqual(@as(u32, 1_000), result.latency_sample_operations);
    try std.testing.expect(recorder.exempt > 0);
    try std.testing.expect(recorder.paced > 0);
    try std.testing.expectEqual(@as(usize, 0), recorder.outside_sweep);
    // Includes both sides of cwnd/2, the cwnd boundary, and maximum input.
    for (recorder.seen) |observed| try std.testing.expect(observed);
}
