// Test-only call recorder. Always return the production pacing result.
const congestion = @import("real_congestion");

pub var seen: [18_000]bool = @splat(false);
pub var exempt: usize = 0;
pub var paced: usize = 0;
pub var outside_sweep: usize = 0;

pub fn reset() void {
    seen = @splat(false);
    exempt = 0;
    paced = 0;
    outside_sweep = 0;
}

pub fn computePacingDelayNs(cwnd: usize, bif: usize, rtt_ns: u64, packet_size: usize) u64 {
    const delay = congestion.computePacingDelayNs(cwnd, bif, rtt_ns, packet_size);
    if (bif < seen.len) seen[bif] = true else outside_sweep += 1;
    if (delay == 0) exempt += 1 else paced += 1;
    return delay;
}
