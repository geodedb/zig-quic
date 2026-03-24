//! Unit tests for recovery/recovery.zig (coordinator module)
//!
//! RFC References:
//! - RFC 9002: QUIC Loss Detection and Congestion Control
//! - RFC 9002 §2: Design of the QUIC Transmission Machinery
//! - RFC 9002 §5: Estimating the Round-Trip Time
//! - RFC 9002 §6: Loss Detection
//! - RFC 9002 §7: Congestion Control
//! - RFC 3168: ECN
//!
//! Coverage:
//! - Positive cases: Module re-exports, Recovery initialization, packet tracking, ACK processing
//! - Negative cases: Invalid operations, empty state
//! - Boundary cases: Multiple spaces, ECN handling
//! - RFC compliance: Coordinator provides unified API

const std = @import("std");
const testing = std.testing;

const recovery = @import("recovery");
const frame = @import("frame");

// =============================================================================
// Module Re-export Tests
// =============================================================================

test "coordinator re-exports CcState from types module" {
    const cc: recovery.CcState = .{};
    try testing.expectEqual(@as(usize, 1200), cc.mds);
}

test "coordinator re-exports CUBIC constants from types module" {
    try testing.expectEqual(@as(f64, 0.4), recovery.CUBIC_C_DEFAULT);
    try testing.expectEqual(@as(f64, 0.7), recovery.CUBIC_BETA_DEFAULT);
}

test "coordinator re-exports PacketNumberSpace from types module" {
    const space: recovery.PacketNumberSpace = .Initial;
    try testing.expectEqual(recovery.PacketNumberSpace.Initial, space);
}

test "coordinator re-exports SentPacket from types module" {
    const sp: recovery.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expectEqual(@as(u64, 1), sp.pn);
}

test "coordinator re-exports RttState from rtt module" {
    const rtt: recovery.RttState = .{};
    try testing.expect(!rtt.have_sample);
}

test "coordinator re-exports LossDetector from loss_detection module" {
    const ld: recovery.LossDetector = .{};
    try testing.expectEqual(@as(u32, 3), ld.packet_threshold);
}

test "coordinator re-exports isAckElicitingFrame function" {
    const is_ack_eliciting_fn = recovery.isAckElicitingFrame;
    _ = is_ack_eliciting_fn;
}

test "coordinator re-exports NewReno from congestion module" {
    const nr: recovery.NewReno = .{};
    try testing.expectEqual(@as(usize, 12000), nr.cwnd);
}

test "coordinator re-exports Cubic from congestion module" {
    const cubic: recovery.Cubic = .{};
    try testing.expectEqual(@as(usize, 12000), cubic.cwnd);
}

test "coordinator re-exports computePacingDelayNs function" {
    // bytes_in_flight (5000) <= cwnd/2 (5000), so delay is 0
    const delay = recovery.computePacingDelayNs(10000, 5000, 100_000, 1200);
    try testing.expectEqual(@as(u64, 0), delay);
}

// =============================================================================
// Recovery Initialization Tests
// =============================================================================

test "Recovery initializes with default RTT state" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try testing.expect(!rec.rtt.have_sample);
}

test "Recovery initializes with default congestion control state" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try testing.expectEqual(@as(usize, 1200), rec.cc.mds);
    try testing.expectEqual(@as(usize, 12000), rec.cc.cwnd);
}

test "Recovery initializes with NewReno by default" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try testing.expect(!rec.use_cubic);
}

test "Recovery initializes with default loss detector" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try testing.expectEqual(@as(u32, 3), rec.loss.packet_threshold);
}

test "Recovery initializes pto_count to zero" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try testing.expectEqual(@as(u32, 0), rec.pto_count);
}

test "Recovery initializes three packet number spaces" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Verify all three spaces are initialized
    try testing.expectEqual(@as(usize, 3), rec.spaces.len);
}

test "Recovery can switch to CUBIC mode" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.setCcMode(true);
    try testing.expect(rec.use_cubic);
}

// =============================================================================
// Packet Sent Tests
// =============================================================================

test "RFC 9002 §2 - onPacketSent tracks packet in correct space" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const space = recovery.PacketNumberSpace.Handshake;
    try rec.onPacketSent(space, 1, 1200, true, 1000);

    const idx = @intFromEnum(space);
    try testing.expectEqual(@as(usize, 1), rec.spaces[idx].sent.items.len);
}

test "onPacketSent records packet metadata" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 42, 1200, true, 5000);

    const sp = rec.spaces[0].sent.items[0];
    try testing.expectEqual(@as(u64, 42), sp.pn);
    try testing.expectEqual(@as(u64, 5000), sp.time_ns);
    try testing.expectEqual(@as(usize, 1200), sp.size);
    try testing.expect(sp.ack_eliciting);
}

test "onPacketSent increases bytes_in_flight for ACK-eliciting packets" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    try testing.expectEqual(@as(usize, 1200), rec.cc.bytes_in_flight);
}

test "onPacketSent does not increase bytes_in_flight for non-ACK-eliciting" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, false, 1000);

    try testing.expectEqual(@as(usize, 0), rec.cc.bytes_in_flight);
}

test "onPacketSent tracks multiple packets across spaces" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Handshake, 1, 1200, true, 2000);
    try rec.onPacketSent(.Application, 1, 1200, true, 3000);

    try testing.expectEqual(@as(usize, 1), rec.spaces[0].sent.items.len);
    try testing.expectEqual(@as(usize, 1), rec.spaces[1].sent.items.len);
    try testing.expectEqual(@as(usize, 1), rec.spaces[2].sent.items.len);
}

// =============================================================================
// ACK Processing Tests
// =============================================================================

test "RFC 9002 §5 - onAckReceived updates RTT on first ACK" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const acked = [_]u64{1};
    _ = rec.onAckReceived(.Initial, &acked, 0, 51_000_000); // 50ms later

    try testing.expect(rec.rtt.have_sample);
    try testing.expect(rec.rtt.smoothed_rtt_ns > 0);
}

test "onAckReceived marks packets as acked" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 2, 1200, true, 2000);

    const acked = [_]u64{1};
    const result = rec.onAckReceived(.Initial, &acked, 0, 3000);

    // After ACK processing, compact() removes acked entries from the sent list.
    // Packet 1 was acked and compacted out; only packet 2 remains.
    try testing.expectEqual(@as(usize, 1200), result.bytes_acked);
    try testing.expectEqual(@as(usize, 1), rec.spaces[0].sent.items.len);

    const sp2 = rec.spaces[0].sent.items[0];
    try testing.expectEqual(@as(u64, 2), sp2.pn);
    try testing.expect(!sp2.acked);
}

test "onAckReceived returns bytes_acked count" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 2, 800, true, 2000);

    const acked = [_]u64{ 1, 2 };
    const result = rec.onAckReceived(.Initial, &acked, 0, 3000);

    try testing.expectEqual(@as(usize, 2000), result.bytes_acked);
}

test "RFC 9002 §7 - onAckReceived increases cwnd in slow start" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const initial_cwnd = rec.cc.cwnd;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const acked = [_]u64{1};
    _ = rec.onAckReceived(.Initial, &acked, 0, 2000);

    try testing.expect(rec.cc.cwnd > initial_cwnd);
}

test "onAckReceived resets pto_count on ACK-eliciting ACK" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.pto_count = 5;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const acked = [_]u64{1};
    _ = rec.onAckReceived(.Initial, &acked, 0, 2000);

    try testing.expectEqual(@as(u32, 0), rec.pto_count);
}

test "onAckReceived does not reset pto_count for non-ACK-eliciting" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.pto_count = 5;

    try rec.onPacketSent(.Initial, 1, 1200, false, 1000);

    const acked = [_]u64{1};
    _ = rec.onAckReceived(.Initial, &acked, 0, 2000);

    try testing.expectEqual(@as(u32, 5), rec.pto_count);
}

// =============================================================================
// Packet Threshold Loss Detection Tests (RFC 9002 §6.1.1)
// =============================================================================

test "RFC 9002 §6.1.1 - onAckReceived detects packet threshold loss" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Send 5 packets
    var i: u64 = 1;
    while (i <= 5) : (i += 1) {
        try rec.onPacketSent(.Initial, i, 1200, true, @intCast(i * 1000));
    }

    // ACK packet 5 (creates gap of 4 for packet 1)
    const acked = [_]u64{5};
    const result = rec.onAckReceived(.Initial, &acked, 0, 10000);

    // Packets 1 and 2 should be declared lost (gap >= 3)
    try testing.expect(result.bytes_lost > 0);
}

test "onAckReceived marks lost packets as declared_lost" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 5, 1200, true, 2000);

    const acked = [_]u64{5};
    _ = rec.onAckReceived(.Initial, &acked, 0, 3000);

    const sp1 = rec.spaces[0].sent.items[0];
    try testing.expect(sp1.declared_lost);
}

test "RFC 9002 §7 - onAckReceived reduces cwnd on loss" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Build up cwnd first
    rec.cc.cwnd = 50000;
    rec.cc.ssthresh = 25000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 10, 1200, true, 2000);

    const acked = [_]u64{10};
    _ = rec.onAckReceived(.Initial, &acked, 0, 3000);

    // cwnd should be reduced due to loss
    try testing.expect(rec.cc.cwnd < 50000);
}

// =============================================================================
// ECN Processing Tests (RFC 3168)
// =============================================================================

test "RFC 3168 - onAckReceivedWithEcn tracks ECN counters" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const acked = [_]u64{1};
    const ecn = frame.EcnCounts{
        .ect0 = 1,
        .ect1 = 0,
        .ce = 0,
    };
    _ = rec.onAckReceivedWithEcn(.Initial, &acked, 0, 2000, ecn);

    try testing.expect(rec.spaces[0].ecn_seen_any);
}

test "RFC 3168 - onAckReceivedWithEcn reduces cwnd on CE increase" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.cc.cwnd = 50000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 2, 1200, true, 2000);

    // First ACK with no CE
    const acked1 = [_]u64{1};
    const ecn1 = frame.EcnCounts{ .ect0 = 1, .ect1 = 0, .ce = 0 };
    _ = rec.onAckReceivedWithEcn(.Initial, &acked1, 0, 3000, ecn1);

    const cwnd_before = rec.cc.cwnd;

    // Second ACK with CE increased
    const acked2 = [_]u64{2};
    const ecn2 = frame.EcnCounts{ .ect0 = 2, .ect1 = 0, .ce = 1 };
    _ = rec.onAckReceivedWithEcn(.Initial, &acked2, 0, 4000, ecn2);

    // cwnd should be reduced
    try testing.expect(rec.cc.cwnd < cwnd_before);
}

test "onAckReceivedWithEcn ignores decreasing ECN counters" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    // Set initial ECN state
    const acked1 = [_]u64{1};
    const ecn1 = frame.EcnCounts{ .ect0 = 5, .ect1 = 0, .ce = 0 };
    _ = rec.onAckReceivedWithEcn(.Initial, &acked1, 0, 2000, ecn1);

    const cwnd_before = rec.cc.cwnd;

    try rec.onPacketSent(.Initial, 2, 1200, true, 3000);

    // Receive ECN with decreased counters (ignore this)
    const acked2 = [_]u64{2};
    const ecn2 = frame.EcnCounts{ .ect0 = 3, .ect1 = 0, .ce = 0 };
    _ = rec.onAckReceivedWithEcn(.Initial, &acked2, 0, 4000, ecn2);

    // cwnd should not be affected
    try testing.expect(rec.cc.cwnd >= cwnd_before);
}

// =============================================================================
// PTO Computation Tests (RFC 9002 §6.2)
// =============================================================================

test "RFC 9002 §6.2 - computeNextPtoTimeNs returns time when packets in flight" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 100_000_000;
    rec.rtt.rttvar_ns = 25_000_000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const pto_time = rec.computeNextPtoTimeNs(1000);
    try testing.expect(pto_time != null);
    try testing.expect(pto_time.? > 1000);
}

test "computeNextPtoTimeNs returns null when no packets in flight" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 100_000_000;

    const pto_time = rec.computeNextPtoTimeNs(1000);
    try testing.expect(pto_time == null);
}

test "computeSpacePtoTimeNs computes PTO for specific space" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 100_000_000;
    rec.rtt.rttvar_ns = 25_000_000;

    const pto_time = rec.computeSpacePtoTimeNs(.Handshake, 1000);
    try testing.expect(pto_time != null);
}

// =============================================================================
// Loss Time Expiry Tests
// =============================================================================

test "onLossTimeExpired detects time threshold losses" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Set up RTT
    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 50_000_000; // 50ms
    rec.rtt.latest_rtt_ns = 50_000_000;

    // Send packet at time 1000
    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    // Time threshold is 1.125 * 50ms = 56.25ms
    // Expire after threshold
    const bytes_lost = rec.onLossTimeExpired(60_000_000); // 60ms later

    try testing.expect(bytes_lost > 0);
}

test "onLossTimeExpired marks packets as declared_lost" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 50_000_000;
    rec.rtt.latest_rtt_ns = 50_000_000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    _ = rec.onLossTimeExpired(60_000_000);

    const sp = rec.spaces[0].sent.items[0];
    try testing.expect(sp.declared_lost);
}

test "onLossTimeExpired reduces cwnd on loss" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 50_000_000;
    rec.rtt.latest_rtt_ns = 50_000_000;
    rec.cc.cwnd = 50000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    _ = rec.onLossTimeExpired(60_000_000);

    try testing.expect(rec.cc.cwnd < 50000);
}

// =============================================================================
// Boundary Cases
// =============================================================================

test "boundary: Recovery with no packets sent" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const pto_time = rec.computeNextPtoTimeNs(1000);
    try testing.expect(pto_time == null);
}

test "boundary: onAckReceived with empty acked list" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);

    const acked: []const u64 = &[_]u64{};
    const result = rec.onAckReceived(.Initial, acked, 0, 2000);

    try testing.expectEqual(@as(usize, 0), result.bytes_acked);
}

test "boundary: onLossTimeExpired with no packets" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const bytes_lost = rec.onLossTimeExpired(1000);
    try testing.expectEqual(@as(usize, 0), bytes_lost);
}

test "boundary: multiple packets in all three spaces" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    var pn: u64 = 1;
    const spaces = [_]recovery.PacketNumberSpace{ .Initial, .Handshake, .Application };
    for (spaces) |space| {
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            try rec.onPacketSent(space, pn, 1200, true, pn * 1000);
            pn += 1;
        }
    }

    // Each space should have 5 packets
    for (rec.spaces) |space| {
        try testing.expectEqual(@as(usize, 5), space.sent.items.len);
    }
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 - Recovery provides unified loss detection and CC" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Verify integration of all components
    _ = rec.rtt; // RTT estimation
    _ = rec.cc; // Congestion control
    _ = rec.loss; // Loss detection
    _ = rec.spaces; // Per-space tracking
}

test "RFC 9002 §6 - Recovery tracks per-space loss state" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Verify each space has independent state
    for (rec.spaces) |space| {
        try testing.expect(space.largest_acked == null);
        try testing.expect(space.loss_time_ns == null);
    }
}

test "RFC 9002 §7 - Recovery enforces minimum cwnd after loss" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.cc.cwnd = 3000;

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Initial, 10, 1200, true, 2000);

    const acked = [_]u64{10};
    _ = rec.onAckReceived(.Initial, &acked, 0, 3000);

    // Should enforce minimum of 2 * mds = 2400
    try testing.expect(rec.cc.cwnd >= 2 * rec.cc.mds);
}

test "RFC 9002 - Recovery deinit cleans up resources" {
    var rec = recovery.Recovery.init(testing.allocator);

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Handshake, 1, 1200, true, 2000);
    try rec.onPacketSent(.Application, 1, 1200, true, 3000);

    rec.deinit(); // Should not leak
}

// =============================================================================
// Integration Tests
// =============================================================================

test "Recovery complete flow: send, ACK, loss detection, congestion control" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    // Send packets
    var pn: u64 = 1;
    while (pn <= 10) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 1200, true, pn * 1000);
    }

    // ACK some packets
    const acked = [_]u64{ 5, 6, 7, 10 };
    const result = rec.onAckReceived(.Application, &acked, 0, 20000);

    // Should have acked bytes
    try testing.expect(result.bytes_acked > 0);

    // Should have detected losses (packets 1-4 due to gap to 10)
    try testing.expect(result.bytes_lost > 0);

    // RTT should be updated
    try testing.expect(rec.rtt.have_sample);

    // cwnd should have changed
    try testing.expect(rec.cc.cwnd != 12000);
}

test "Recovery handles mixed ACK-eliciting and non-ACK-eliciting packets" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Initial, 1, 1200, true, 1000); // ACK-eliciting
    try rec.onPacketSent(.Initial, 2, 100, false, 2000); // Not ACK-eliciting
    try rec.onPacketSent(.Initial, 3, 1200, true, 3000); // ACK-eliciting

    // bytes_in_flight should only count ACK-eliciting
    try testing.expectEqual(@as(usize, 2400), rec.cc.bytes_in_flight);

    const acked = [_]u64{ 1, 2, 3 };
    const result = rec.onAckReceived(.Initial, &acked, 0, 4000);

    // All 3 packets ACKed (2500 bytes total)
    try testing.expectEqual(@as(usize, 2500), result.bytes_acked);

    // pto_count should reset (ACK-eliciting packets were ACKed)
    try testing.expectEqual(@as(u32, 0), rec.pto_count);
}

test "Recovery persistent congestion detection" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 50_000_000; // 50ms
    rec.rtt.latest_rtt_ns = 50_000_000;
    rec.rtt.rttvar_ns = 25_000_000; // 25ms (explicitly set for test clarity)
    rec.cc.cwnd = 100000;
    rec.k_pc_threshold = 3;

    // PTO calculation: smoothed_rtt + 4*rttvar + granularity
    // PTO = 50ms + 4*25ms + 1ms = 151ms
    // PC period = PTO * k_pc_threshold = 151ms * 3 = 453ms
    // Need gap > 453ms to trigger persistent congestion

    // Send 3 packets over a long period spanning > PC period (453ms)
    try rec.onPacketSent(.Application, 1, 1200, true, 1_000_000); // 1ms
    try rec.onPacketSent(.Application, 2, 1200, true, 600_000_000); // 600ms later
    try rec.onPacketSent(.Application, 100, 1200, true, 800_000_000); // 800ms from start

    // ACK only the last packet (first two are lost over long period)
    // This triggers packet-threshold loss for packets 1 and 2
    const acked = [_]u64{100};
    _ = rec.onAckReceived(.Application, &acked, 0, 850_000_000);

    // Persistent congestion should drive cwnd to minimum
    // Span between lost packets: 600_000_000 - 1_000_000 = 599ms > PC period (453ms)
    try testing.expect(rec.cc.cwnd == 2 * rec.cc.mds);
}

test "Recovery CUBIC mode operates independently per space" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    rec.setCcMode(true);

    // Send and ACK in different spaces
    try rec.onPacketSent(.Initial, 1, 1200, true, 1000);
    try rec.onPacketSent(.Handshake, 1, 1200, true, 2000);

    const acked_initial = [_]u64{1};
    _ = rec.onAckReceived(.Initial, &acked_initial, 0, 3000);

    const acked_handshake = [_]u64{1};
    _ = rec.onAckReceived(.Handshake, &acked_handshake, 0, 4000);

    // Both spaces should have updated their state
    try testing.expect(rec.spaces[0].largest_acked != null);
    try testing.expect(rec.spaces[1].largest_acked != null);
}

// =============================================================================
// Perf Gap #90: sent_packets bounded at 4096
// =============================================================================

test "sent_packets bounded at max_sent_packets (4096) after overflow" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const max_cap: usize = 4096;
    const total_packets: u64 = max_cap + 512; // Send 4608 packets total
    const space_idx = @intFromEnum(recovery.PacketNumberSpace.Application);

    // Send more than max_sent_packets into the Application space.
    var pn: u64 = 1;
    while (pn <= total_packets) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 100, true, pn * 1000);
    }

    // After all sends, the space must be bounded at max_sent_packets.
    const sent_len = rec.spaces[space_idx].sent.items.len;
    try testing.expect(sent_len <= max_cap);

    // The most recent packets should be retained (newest, not oldest).
    // The oldest retained packet number should be > 1 (oldest were dropped).
    const oldest_retained = rec.spaces[space_idx].sent.items[0].pn;
    try testing.expect(oldest_retained > 1);

    // The newest retained packet should be the last one we sent.
    const newest_retained = rec.spaces[space_idx].sent.items[sent_len - 1].pn;
    try testing.expectEqual(total_packets, newest_retained);

    // Verify sent_index is consistent with sent list:
    // Every entry in sent list that is not acked/lost must have a matching sent_index entry.
    for (rec.spaces[space_idx].sent.items, 0..) |sp, i| {
        if (!sp.acked and !sp.declared_lost) {
            const idx_val = rec.spaces[space_idx].sent_index.get(sp.pn);
            try testing.expect(idx_val != null);
            try testing.expectEqual(i, idx_val.?);
        }
    }

    // The sent_index must not contain entries for dropped (oldest) packets.
    // Packet 1 was dropped, so it must not be in the index.
    try testing.expect(rec.spaces[space_idx].sent_index.get(1) == null);
}

test "sent_packets cap retains newest packets across multiple overflow batches" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const max_cap: usize = 4096;
    const space_idx = @intFromEnum(recovery.PacketNumberSpace.Application);

    // First batch: fill to exactly max_cap
    var pn: u64 = 1;
    while (pn <= max_cap) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 100, true, pn * 1000);
    }
    try testing.expectEqual(max_cap, rec.spaces[space_idx].sent.items.len);

    // Second batch: push 1024 more, triggering overflow + compaction twice
    const second_batch_end = max_cap + 1024;
    while (pn <= second_batch_end) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 100, true, pn * 1000);
    }
    try testing.expect(rec.spaces[space_idx].sent.items.len <= max_cap);

    // Third batch: push another 1024 more
    const third_batch_end = second_batch_end + 1024;
    while (pn <= third_batch_end) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 100, true, pn * 1000);
    }
    try testing.expect(rec.spaces[space_idx].sent.items.len <= max_cap);

    // The newest packet should always be the last one sent.
    const sent_items = rec.spaces[space_idx].sent.items;
    try testing.expectEqual(third_batch_end, sent_items[sent_items.len - 1].pn);

    // Verify index consistency after multiple overflow cycles.
    for (sent_items, 0..) |sp, i| {
        if (!sp.acked and !sp.declared_lost) {
            const idx_val = rec.spaces[space_idx].sent_index.get(sp.pn);
            try testing.expect(idx_val != null);
            try testing.expectEqual(i, idx_val.?);
        }
    }
}

test "sent_packets cap is independent per space" {
    var rec = recovery.Recovery.init(testing.allocator);
    defer rec.deinit();

    const max_cap: usize = 4096;
    const total_packets: u64 = max_cap + 256;

    // Overflow only the Application space.
    var pn: u64 = 1;
    while (pn <= total_packets) : (pn += 1) {
        try rec.onPacketSent(.Application, pn, 100, true, pn * 1000);
    }

    // Send a few into Initial space (should not be affected).
    var ipn: u64 = 1;
    while (ipn <= 10) : (ipn += 1) {
        try rec.onPacketSent(.Initial, ipn, 100, true, ipn * 1000);
    }

    const app_idx = @intFromEnum(recovery.PacketNumberSpace.Application);
    const init_idx = @intFromEnum(recovery.PacketNumberSpace.Initial);

    // Application space is bounded.
    try testing.expect(rec.spaces[app_idx].sent.items.len <= max_cap);

    // Initial space is unaffected (only 10 packets).
    try testing.expectEqual(@as(usize, 10), rec.spaces[init_idx].sent.items.len);
}
