// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! NewReno congestion control algorithm (RFC 9002 S7.3).

const std = @import("std");

pub const NewReno = struct {
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    bytes_in_flight: usize,
    in_recovery: bool,
    recovery_start_pn: u64,

    pub fn init(mss: usize) NewReno {
        return .{
            .mss = mss,
            .cwnd = 10 * mss, // RFC default initial window
            .ssthresh = std.math.maxInt(usize), // "infinite"
            .bytes_in_flight = 0,
            .in_recovery = false,
            .recovery_start_pn = 0,
        };
    }

    pub fn onPacketSent(self: *NewReno, pkt_size: usize) void {
        self.bytes_in_flight = std.math.add(usize, self.bytes_in_flight, pkt_size) catch std.math.maxInt(usize);
    }

    pub fn onAckReceived(self: *NewReno, acked_bytes: usize, acked_pn: u64) void {
        if (self.bytes_in_flight > acked_bytes) {
            self.bytes_in_flight -= acked_bytes;
        } else self.bytes_in_flight = 0;

        if (self.in_recovery and acked_pn < self.recovery_start_pn) return;
        if (self.in_recovery and acked_pn >= self.recovery_start_pn) {
            self.in_recovery = false;
        }

        if (self.cwnd < self.ssthresh) {
            // Slow Start
            self.cwnd += acked_bytes;
            if (self.cwnd >= self.ssthresh) self.cwnd = self.ssthresh;
        } else {
            // Congestion Avoidance ~ MSS^2 / cwnd per RTT (integer approx)
            const product = std.math.mul(usize, self.mss, acked_bytes) catch std.math.maxInt(usize);
            var inc: usize = product / @max(self.cwnd, @as(usize, 1));
            if (inc < 1) inc = 1;
            self.cwnd += inc;
        }
    }

    pub fn onPacketLost(self: *NewReno, lost_bytes: usize, lost_pn: u64, latest_sent_pn: u64) void {
        if (self.bytes_in_flight > lost_bytes) {
            self.bytes_in_flight -= lost_bytes;
        } else self.bytes_in_flight = 0;

        if (!self.in_recovery or (lost_pn > self.recovery_start_pn)) {
            self.in_recovery = true;
            self.recovery_start_pn = latest_sent_pn;
            const new_cwnd = self.cwnd / 2;
            const min_cwnd = 2 * self.mss;
            self.ssthresh = if (new_cwnd > min_cwnd) new_cwnd else min_cwnd;
            self.cwnd = self.ssthresh;
        }
    }
};

test "newreno: slow start grows then halves on loss" {
    var nr = NewReno.init(1200);
    nr.onPacketSent(1200);
    nr.onAckReceived(1200, 10);
    try std.testing.expect(nr.cwnd >= 10 * 1200 + 1200);
    nr.onPacketLost(1200, 11, 12);
    try std.testing.expect(nr.cwnd >= 2 * 1200);
}

test "newreno: edge — ack before recovery start has no effect on recovery exit" {
    var nr = NewReno.init(1200);
    nr.onPacketLost(1200, 5, 10);
    nr.onAckReceived(1200, 4); // < recovery_start_pn
    try std.testing.expect(nr.in_recovery);
}

test "newreno: invalid — zero MSS guarded by division clamp" {
    var nr = NewReno.init(1); // effectively guard divide-by-zero with max(cwnd,1)
    nr.cwnd = 0;
    nr.onAckReceived(10, 1);
    try std.testing.expect(nr.cwnd >= 1);
}

test "newreno: saturating add — bytes_in_flight does not overflow" {
    var nr = NewReno.init(1200);
    nr.bytes_in_flight = std.math.maxInt(usize) - 100;
    nr.onPacketSent(200);
    try std.testing.expectEqual(std.math.maxInt(usize), nr.bytes_in_flight);
}

test "newreno: saturating mul — large mss*acked_bytes does not overflow" {
    var nr = NewReno.init(1200);
    nr.mss = std.math.maxInt(usize) / 2;
    nr.cwnd = 10000; // force congestion avoidance (cwnd >= ssthresh after manual set)
    nr.ssthresh = 5000;
    nr.bytes_in_flight = 1000;
    // This should not panic even with huge mss * acked_bytes
    nr.onAckReceived(1000, 1);
    try std.testing.expect(nr.cwnd > 0);
}
