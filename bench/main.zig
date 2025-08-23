const std = @import("std");
const varint = @import("quic_varint");
const rec = @import("quic_recovery");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    _ = alloc; // unused for now

    // Micro-bench 1: varint encode (existing)
    var timer = try std.time.Timer.start();
    var buf: [8]u8 = undefined;
    var total: usize = 0;
    const iters: usize = 100_000;
    for (0..iters) |_| {
        total += try varint.encode(16383, &buf);
    }
    const dt1 = timer.read();
    const per1 = @as(f64, @floatFromInt(dt1)) / @as(f64, @floatFromInt(iters));
    try std.io.getStdOut().writer().print("varint encode: {d} ns/op\n", .{per1});

    // Micro-bench 2: pacing delay computation with varying in-flight levels
    var nr = rec.NewReno{ .mds = 1200, .cwnd = 12000 };
    var sum_delay: u128 = 0;
    var delay_buf: u64 = 0;
    const iters2: usize = 1_000_000;
    timer.reset();
    for (0..iters2) |i| {
        // sweep bytes_in_flight between 0..1.5*cwnd in a stable pattern
        nr.bytes_in_flight = (@as(usize, (i % (nr.cwnd + nr.cwnd / 2))));
        delay_buf = rec.computePacingDelayNs(nr.cwnd, nr.bytes_in_flight);
        sum_delay += delay_buf;
    }
    const dt2 = timer.read();
    const per2 = @as(f64, @floatFromInt(dt2)) / @as(f64, @floatFromInt(iters2));
    // Avoid optimizing away
    std.mem.doNotOptimizeAway(sum_delay);
    try std.io.getStdOut().writer().print("pacing delay compute: {d} ns/op (avg_delay={d} ns)\n", .{ per2, @as(u64, @intCast(sum_delay / iters2)) });

    // Micro-bench 3: simulate send pacing on/off (busy-loop emulate sleep cost 0)
    const samples: usize = 200_000;
    // Off: just call compute and ignore
    timer.reset();
    var sink: u64 = 0;
    for (0..samples) |i| {
        const bif = @as(usize, i % (nr.cwnd + nr.cwnd / 2));
        sink ^= rec.computePacingDelayNs(nr.cwnd, bif);
    }
    const off_ns = timer.read();

    // On: same compute plus a dummy branch that would call sleep when non-zero
    timer.reset();
    var cnt_nonzero: usize = 0;
    for (0..samples) |i| {
        const bif = @as(usize, i % (nr.cwnd + nr.cwnd / 2));
        const d = rec.computePacingDelayNs(nr.cwnd, bif);
        if (d != 0) cnt_nonzero += 1;
        sink ^= d;
    }
    const on_ns = timer.read();
    std.mem.doNotOptimizeAway(sink);
    try std.io.getStdOut().writer().print(
        "pacing on/off emulate: off={d} ns total, on={d} ns total, nonzero={d}\n",
        .{ off_ns, on_ns, cnt_nonzero },
    );
}
