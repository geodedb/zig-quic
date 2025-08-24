const std = @import("std");
const varint = @import("quic_varint");
const rec = @import("quic_recovery");

fn parseU64Arg(args: []const [:0]u8, idx: usize, default: u64) u64 {
    if (idx >= args.len) return default;
    return std.fmt.parseInt(u64, args[idx], 10) catch default;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Optional args: [rtt_ns] [bdp_packets] [loss_every]
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    // program name is args[0]
    const rtt_ns_cfg: u64 = parseU64Arg(args, 1, 100_000); // 100us
    const bdp_pkts_cfg: u64 = parseU64Arg(args, 2, 100); // target BDP in packets
    const loss_every_cfg: u64 = parseU64Arg(args, 3, 0); // 0 = no loss

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

    // Bench 4: CUBIC vs NewReno cwnd growth under ACKs (parameterized)
    var R = rec.Recovery.init(alloc);
    defer R.deinit();
    const pkts: usize = 200_000;
    const mds: usize = 1200;
    const ack_bytes: usize = mds;

    // Simulated RTT and BDP
    const rtt_ns = rtt_ns_cfg;
    const target_bdp_pkts = bdp_pkts_cfg;
    // Back-to-back acks, each step spaced by rtt_ns/target_bdp_pkts to emulate cwnd worth in flight
    const dt_ack_ns: u64 = if (target_bdp_pkts > 0) rtt_ns / target_bdp_pkts else 0;

    // Helper: ACK a sent pn and update RTT with measured delay
    const ack_one = struct {
        fn f(r: *rec.Recovery, space: rec.PacketNumberSpace, pn: u64, now_ns: u64, apply_loss_every: u64) void {
            // Optionally simulate loss by not acking every Nth packet
            if (apply_loss_every != 0 and pn != 0 and (pn % apply_loss_every) == 0) {
                // No ACK for this pn
                return;
            }
            _ = r.onAckReceived(space, &[_]u64{pn}, 0, now_ns);
        }
    }.f;

    // NewReno growth
    R.setCcMode(false);
    R.cc = .{ .mds = mds, .cwnd = 10 * mds, .ssthresh = std.math.maxInt(usize) / 2, .bytes_in_flight = 0 };
    // Clear any previous sent state
    inline for (&R.spaces) |*s| s.sent.shrinkRetainingCapacity(0);
    timer.reset();
    var now_ns: u64 = 0;
    var pn: u64 = 0;
    while (pn < pkts) : (pn += 1) {
        now_ns +%= dt_ack_ns;
        _ = R.onPacketSent(.Application, pn, ack_bytes, true, now_ns) catch {};
        ack_one(&R, .Application, pn, now_ns + rtt_ns, loss_every_cfg);
    }
    const nr_total_ns = timer.read();
    const nr_cwnd = R.cc.cwnd;

    // CUBIC growth
    R.setCcMode(true);
    R.cc = .{ .mds = mds, .cwnd = 10 * mds, .ssthresh = std.math.maxInt(usize) / 2, .bytes_in_flight = 0 };
    inline for (&R.spaces) |*s| s.sent.shrinkRetainingCapacity(0);
    timer.reset();
    now_ns = 0;
    pn = 0;
    while (pn < pkts) : (pn += 1) {
        now_ns +%= dt_ack_ns;
        _ = R.onPacketSent(.Application, pn, ack_bytes, true, now_ns) catch {};
        ack_one(&R, .Application, pn, now_ns + rtt_ns, loss_every_cfg);
    }
    const cubic_total_ns = timer.read();
    const cubic_cwnd = R.cc.cwnd;

    try std.io.getStdOut().writer().print(
        "cc bench: rtt_ns={d} bdp_pkts={d} loss_every={d} | newreno cwnd={d}, time={d} ns; cubic cwnd={d}, time={d} ns\n",
        .{ rtt_ns, target_bdp_pkts, loss_every_cfg, nr_cwnd, nr_total_ns, cubic_cwnd, cubic_total_ns },
    );
}
