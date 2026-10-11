const std = @import("std");
const builtin = @import("builtin");
const datagram = @import("datagram");

test "SONNY-4792 every datagram variant completes exact payload and FIN within one window" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    for (datagram.scenarios) |spec| {
        const result = try datagram.run(std.heap.smp_allocator, spec);
        defer std.heap.smp_allocator.free(result.latencies_ns);
        try std.testing.expectEqual(spec.iterations * 1024, result.bytes_transferred);
        try std.testing.expectEqual(spec.iterations, result.iterations);
        try std.testing.expect(result.packets_transferred > 0);
        try std.testing.expect(result.latencies_ns.len > 0);
        try std.testing.expect(result.mutex_hold_wall_ns > 0);
        try std.testing.expect(result.mutex_hold_wall_ns <= result.wall_time_ns);
    }
}

test "SONNY-4792 uneven client budgets preserve the exact requested workload" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var spec = datagram.scenarios[1];
    spec.iterations = 19;
    const result = try datagram.run(std.heap.smp_allocator, spec);
    defer std.heap.smp_allocator.free(result.latencies_ns);
    try std.testing.expectEqual(@as(u64, 19 * 1024), result.bytes_transferred);
    try std.testing.expectEqual(@as(u64, 19), result.iterations);
}

test "SONNY-4792 a sender FIN with missing payload cannot produce a result" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var spec = datagram.scenarios[1];
    spec.iterations = 19;
    try std.testing.expectError(error.IncompleteTransfer, datagram.runFaultForTest(std.heap.smp_allocator, spec, .missing_chunk));
}

test "SONNY-4792 corrupt UDP-delivered payload cannot produce a result" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var spec = datagram.scenarios[1];
    spec.iterations = 19;
    try std.testing.expectError(error.CorruptPayload, datagram.runFaultForTest(std.heap.smp_allocator, spec, .corrupt_payload));
}
