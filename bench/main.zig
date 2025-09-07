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

    // Optional args: [rtt_ns] [bdp_packets] [loss_every] or flags: --grid [--csv]
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var grid: bool = false;
    var csv: bool = false;
    // Detect flags
    for (args, 0..) |a, i| {
        if (i == 0) continue; // program name
        if (std.mem.eql(u8, a, "--grid")) grid = true;
        if (std.mem.eql(u8, a, "--csv")) csv = true;
    }

    // program name is args[0]; positional args retained for single scenario mode
    const rtt_ns_cfg: u64 = if (!grid) parseU64Arg(args, 1, 100_000) else 100_000; // 100us
    const bdp_pkts_cfg: u64 = if (!grid) parseU64Arg(args, 2, 100) else 100; // target BDP in packets
    const loss_every_cfg: u64 = if (!grid) parseU64Arg(args, 3, 0) else 0; // 0 = no loss

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
    std.debug.print("varint encode: {d} ns/op\n", .{per1});

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
    std.debug.print("pacing delay compute: {d} ns/op (avg_delay={d} ns)\n", .{ per2, @as(u64, @intCast(sum_delay / iters2)) });

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
    std.debug.print(
        "pacing on/off emulate: off={d} ns total, on={d} ns total, nonzero={d}\n",
        .{ off_ns, on_ns, cnt_nonzero },
    );

    // Bench 4: CUBIC vs NewReno cwnd growth under ACKs (single or grid)
    const writer = std.debug;

    const ScenarioResult = struct {
        nr_cwnd: usize,
        nr_time_ns: u64,
        cubic_cwnd: usize,
        cubic_time_ns: u64,
    };

    const cc_scenario = struct {
        fn run(alloc_: std.mem.Allocator, rtt_ns: u64, bdp_pkts: u64, loss_every: u64) !ScenarioResult {
            var R = rec.Recovery.init(alloc_);
            defer R.deinit();

            const pkts: usize = 200_000;
            const mds: usize = 1200;
            const ack_bytes: usize = mds;
            const dt_ack_ns: u64 = if (bdp_pkts > 0) rtt_ns / bdp_pkts else 0;

            const ack_one = struct {
                fn f(r: *rec.Recovery, space: rec.PacketNumberSpace, pn: u64, now_ns: u64, apply_loss_every: u64) void {
                    if (apply_loss_every != 0 and pn != 0 and (pn % apply_loss_every) == 0) {
                        return; // simulate loss by not acking this pn
                    }
                    _ = r.onAckReceived(space, &[_]u64{pn}, 0, now_ns);
                }
            }.f;

            var timer_local = try std.time.Timer.start();
            var now_ns: u64 = 0;
            var pn: u64 = 0;

            // NewReno
            R.setCcMode(false);
            R.cc = .{ .mds = mds, .cwnd = 10 * mds, .ssthresh = std.math.maxInt(usize) / 2, .bytes_in_flight = 0 };
            inline for (&R.spaces) |*s| s.sent.shrinkRetainingCapacity(0);
            timer_local.reset();
            now_ns = 0;
            pn = 0;
            while (pn < pkts) : (pn += 1) {
                now_ns +%= dt_ack_ns;
                _ = R.onPacketSent(.Application, pn, ack_bytes, true, now_ns) catch {};
                ack_one(&R, .Application, pn, now_ns + rtt_ns, loss_every);
            }
            const nr_total_ns = timer_local.read();
            const nr_cwnd_val = R.cc.cwnd;

            // CUBIC
            R.setCcMode(true);
            R.cc = .{ .mds = mds, .cwnd = 10 * mds, .ssthresh = std.math.maxInt(usize) / 2, .bytes_in_flight = 0 };
            inline for (&R.spaces) |*s| s.sent.shrinkRetainingCapacity(0);
            timer_local.reset();
            now_ns = 0;
            pn = 0;
            while (pn < pkts) : (pn += 1) {
                now_ns +%= dt_ack_ns;
                _ = R.onPacketSent(.Application, pn, ack_bytes, true, now_ns) catch {};
                ack_one(&R, .Application, pn, now_ns + rtt_ns, loss_every);
            }
            const cubic_total_ns = timer_local.read();
            const cubic_cwnd_val = R.cc.cwnd;

            return ScenarioResult{
                .nr_cwnd = nr_cwnd_val,
                .nr_time_ns = nr_total_ns,
                .cubic_cwnd = cubic_cwnd_val,
                .cubic_time_ns = cubic_total_ns,
            };
        }
    }.run;

    if (grid) {
        const rtts = [_]u64{ 100_000, 1_000_000 }; // 100us, 1ms
        const bdps = [_]u64{ 50, 200 };
        const losses = [_]u64{ 0, 50 }; // no loss, 1-in-50 loss
        if (csv) {
            writer.print("mode,rtt_ns,bdp_pkts,loss_every,cwnd,time_ns\n", .{});
        }
        for (rtts) |rtt_ns| {
            for (bdps) |bdp_pkts| {
                for (losses) |loss_every| {
                    const res = try cc_scenario(alloc, rtt_ns, bdp_pkts, loss_every);
                    if (csv) {
                        writer.print("newreno,{d},{d},{d},{d},{d}\n", .{ rtt_ns, bdp_pkts, loss_every, res.nr_cwnd, res.nr_time_ns });
                        writer.print("cubic,{d},{d},{d},{d},{d}\n", .{ rtt_ns, bdp_pkts, loss_every, res.cubic_cwnd, res.cubic_time_ns });
                    } else {
                        writer.print(
                            "cc bench: rtt_ns={d} bdp_pkts={d} loss_every={d} | newreno cwnd={d}, time={d} ns; cubic cwnd={d}, time={d} ns\n",
                            .{ rtt_ns, bdp_pkts, loss_every, res.nr_cwnd, res.nr_time_ns, res.cubic_cwnd, res.cubic_time_ns },
                        );
                    }
                }
            }
        }
    } else {
        const res = try cc_scenario(alloc, rtt_ns_cfg, bdp_pkts_cfg, loss_every_cfg);
        if (csv) {
            writer.print("mode,rtt_ns,bdp_pkts,loss_every,cwnd,time_ns\n", .{});
            writer.print("newreno,{d},{d},{d},{d},{d}\n", .{ rtt_ns_cfg, bdp_pkts_cfg, loss_every_cfg, res.nr_cwnd, res.nr_time_ns });
            writer.print("cubic,{d},{d},{d},{d},{d}\n", .{ rtt_ns_cfg, bdp_pkts_cfg, loss_every_cfg, res.cubic_cwnd, res.cubic_time_ns });
        } else {
            writer.print(
                "cc bench: rtt_ns={d} bdp_pkts={d} loss_every={d} | newreno cwnd={d}, time={d} ns; cubic cwnd={d}, time={d} ns\n",
                .{ rtt_ns_cfg, bdp_pkts_cfg, loss_every_cfg, res.nr_cwnd, res.nr_time_ns, res.cubic_cwnd, res.cubic_time_ns },
            );
        }
    }

    // Micro-bench 5: header protection decode timing guardrail
    // Measure decodeShortProtected and decodeInitialProtected over random inputs and two key phases.
    const pkt = @import("quic_packet");
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const rng = prng.random();
    const dcid = "HPBM";
    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    std.debug.print("hp bench: generating...\n", .{});
    frames.clearRetainingCapacity();
    _ = (pkt.ShortHeader{ .dcid = dcid, .packet_number = 1, .payload = &[_]u8{0x01} }).encode(frames.writer(alloc)) catch {};
    const payload = frames.items[frames.items.len - 1 ..];
    // Build two short protected packets for phase 0/1
    const sp0 = try pkt.encodeShortProtected(alloc, dcid, 1, 2, payload, keys, false);
    defer alloc.free(sp0);
    const sp1 = try pkt.encodeShortProtected(alloc, dcid, 2, 2, payload, keys, true);
    defer alloc.free(sp1);
    // Build an Initial packet too
    const ik = pkt.derive_initial_keys(false, dcid);
    var fbi = std.ArrayList(u8){};
    defer fbi.deinit(alloc);
    _ = fbi.writer(alloc).writeByte(0x01) catch {};
    const ip = try pkt.encodeInitialProtected(alloc, pkt.QUIC_V1, dcid, "S", &[_]u8{}, 1, 2, fbi.items, .{ .key = ik.client.key, .iv = ik.client.iv, .hp = ik.client.hp });
    defer alloc.free(ip);
    // Time decode loops
    timer.reset();
    var total_ns: u64 = 0;
    const loops: usize = 10000;
    for (0..loops) |i| {
        const which = rng.int(u1);
        if (which == 0) {
            const phase = (i & 1) == 0;
            const pkt_bytes = if (phase) sp1 else sp0;
            const d = pkt.decodeShortProtected(alloc, pkt_bytes, dcid.len, keys) catch continue;
            alloc.free(d.payload);
        } else {
            const d2 = pkt.decodeInitialProtected(alloc, ip, .{ .key = ik.server.key, .iv = ik.server.iv, .hp = ik.server.hp }) catch continue;
            alloc.free(d2.payload);
        }
    }
    total_ns = timer.read();
    std.debug.print("hp decode timing: {d} ns total for {d} ops\n", .{ total_ns, loops });
}
