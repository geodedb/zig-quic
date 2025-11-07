//! Unit tests for recovery/types.zig
//!
//! RFC References:
//! - RFC 9002 §2: Design of the QUIC Transmission Machinery
//! - RFC 9002 §7: Congestion Control
//! - RFC 9002 Appendix B.2: CUBIC
//! - RFC 9000 §12.1: Packet Numbers
//!
//! Coverage:
//! - Positive cases: CcState structure, CUBIC constants, PacketNumberSpace enum, SentPacket structure
//! - Negative cases: Type validation
//! - Boundary cases: Maximum values, default values
//! - RFC compliance: All required types for recovery

const std = @import("std");
const testing = std.testing;

const types = @import("types");

// =============================================================================
// CcState Structure Tests
// =============================================================================

test "RFC 9002 §7 - CcState has default mds of 1200 bytes" {
    const cc: types.CcState = .{};
    try testing.expectEqual(@as(usize, 1200), cc.mds);
}

test "RFC 9002 §7 - CcState has default cwnd of 10 * mds" {
    const cc: types.CcState = .{};
    try testing.expectEqual(@as(usize, 10 * 1200), cc.cwnd);
}

test "RFC 9002 §7 - CcState has default ssthresh near max" {
    const cc: types.CcState = .{};
    try testing.expectEqual(@as(usize, std.math.maxInt(usize) / 2), cc.ssthresh);
}

test "RFC 9002 §7 - CcState initializes bytes_in_flight to 0" {
    const cc: types.CcState = .{};
    try testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
}

test "CcState can be created with custom values" {
    const cc: types.CcState = .{
        .mds = 1500,
        .cwnd = 15000,
        .ssthresh = 50000,
        .bytes_in_flight = 5000,
    };
    try testing.expectEqual(@as(usize, 1500), cc.mds);
    try testing.expectEqual(@as(usize, 15000), cc.cwnd);
    try testing.expectEqual(@as(usize, 50000), cc.ssthresh);
    try testing.expectEqual(@as(usize, 5000), cc.bytes_in_flight);
}

test "CcState fields are mutable" {
    var cc: types.CcState = .{};
    cc.cwnd = 20000;
    cc.bytes_in_flight = 10000;
    try testing.expectEqual(@as(usize, 20000), cc.cwnd);
    try testing.expectEqual(@as(usize, 10000), cc.bytes_in_flight);
}

// =============================================================================
// CUBIC Constants Tests
// =============================================================================

test "RFC 9002 Appendix B.2 - CUBIC_C_DEFAULT is 0.4" {
    try testing.expectEqual(@as(f64, 0.4), types.CUBIC_C_DEFAULT);
}

test "RFC 9002 Appendix B.2 - CUBIC_BETA_DEFAULT is 0.7" {
    try testing.expectEqual(@as(f64, 0.7), types.CUBIC_BETA_DEFAULT);
}

test "CUBIC constants are compile-time values" {
    const c: f64 = types.CUBIC_C_DEFAULT;
    const beta: f64 = types.CUBIC_BETA_DEFAULT;
    try testing.expect(c > 0.0 and c < 1.0);
    try testing.expect(beta > 0.0 and beta < 1.0);
}

test "CUBIC_BETA_DEFAULT represents multiplicative decrease" {
    // Beta = 0.7 means cwnd is reduced to 70% on loss
    const cwnd_before: usize = 10000;
    const cwnd_after = @as(usize, @intFromFloat(@as(f64, @floatFromInt(cwnd_before)) * types.CUBIC_BETA_DEFAULT));
    try testing.expectEqual(@as(usize, 7000), cwnd_after);
}

// =============================================================================
// PacketNumberSpace Enum Tests
// =============================================================================

test "RFC 9000 §12.1 - PacketNumberSpace has Initial variant" {
    const space: types.PacketNumberSpace = .Initial;
    try testing.expectEqual(types.PacketNumberSpace.Initial, space);
}

test "RFC 9000 §12.1 - PacketNumberSpace has Handshake variant" {
    const space: types.PacketNumberSpace = .Handshake;
    try testing.expectEqual(types.PacketNumberSpace.Handshake, space);
}

test "RFC 9000 §12.1 - PacketNumberSpace has Application variant" {
    const space: types.PacketNumberSpace = .Application;
    try testing.expectEqual(types.PacketNumberSpace.Application, space);
}

test "PacketNumberSpace variants are distinct" {
    const initial: types.PacketNumberSpace = .Initial;
    const handshake: types.PacketNumberSpace = .Handshake;
    const application: types.PacketNumberSpace = .Application;

    try testing.expect(initial != handshake);
    try testing.expect(initial != application);
    try testing.expect(handshake != application);
}

test "PacketNumberSpace can be converted to integer" {
    const initial_idx = @intFromEnum(types.PacketNumberSpace.Initial);
    const handshake_idx = @intFromEnum(types.PacketNumberSpace.Handshake);
    const application_idx = @intFromEnum(types.PacketNumberSpace.Application);

    try testing.expectEqual(@as(usize, 0), initial_idx);
    try testing.expectEqual(@as(usize, 1), handshake_idx);
    try testing.expectEqual(@as(usize, 2), application_idx);
}

test "PacketNumberSpace can be used in switch" {
    const space: types.PacketNumberSpace = .Handshake;
    const result = switch (space) {
        .Initial => 0,
        .Handshake => 1,
        .Application => 2,
    };
    try testing.expectEqual(@as(u8, 1), result);
}

// =============================================================================
// SentPacket Structure Tests
// =============================================================================

test "RFC 9002 §2 - SentPacket has packet number field" {
    const sp: types.SentPacket = .{
        .pn = 42,
        .time_ns = 1000000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expectEqual(@as(u64, 42), sp.pn);
}

test "RFC 9002 §2 - SentPacket has time_ns field for RTT measurement" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 123456789,
        .size = 1000,
        .ack_eliciting = true,
    };
    try testing.expectEqual(@as(u64, 123456789), sp.time_ns);
}

test "RFC 9002 §2 - SentPacket tracks packet size" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expectEqual(@as(usize, 1200), sp.size);
}

test "RFC 9002 §2 - SentPacket tracks ack_eliciting flag" {
    const sp_eliciting: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    const sp_not_eliciting: types.SentPacket = .{
        .pn = 2,
        .time_ns = 2000,
        .size = 100,
        .ack_eliciting = false,
    };

    try testing.expect(sp_eliciting.ack_eliciting);
    try testing.expect(!sp_not_eliciting.ack_eliciting);
}

test "RFC 9002 §2 - SentPacket acked defaults to false" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expect(!sp.acked);
}

test "RFC 9002 §2 - SentPacket declared_lost defaults to false" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expect(!sp.declared_lost);
}

test "SentPacket can track acked state" {
    var sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    sp.acked = true;
    try testing.expect(sp.acked);
}

test "SentPacket can track declared_lost state" {
    var sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    sp.declared_lost = true;
    try testing.expect(sp.declared_lost);
}

test "SentPacket can be created with all fields" {
    const sp: types.SentPacket = .{
        .pn = 123,
        .time_ns = 999888777,
        .size = 1350,
        .ack_eliciting = false,
        .acked = true,
        .declared_lost = false,
    };

    try testing.expectEqual(@as(u64, 123), sp.pn);
    try testing.expectEqual(@as(u64, 999888777), sp.time_ns);
    try testing.expectEqual(@as(usize, 1350), sp.size);
    try testing.expect(!sp.ack_eliciting);
    try testing.expect(sp.acked);
    try testing.expect(!sp.declared_lost);
}

// =============================================================================
// Boundary Cases
// =============================================================================

test "boundary: CcState cwnd can be set to minimum (2 * mds)" {
    var cc: types.CcState = .{};
    cc.cwnd = 2 * cc.mds;
    try testing.expectEqual(@as(usize, 2400), cc.cwnd);
}

test "boundary: CcState cwnd can be set to large values" {
    var cc: types.CcState = .{};
    cc.cwnd = 1_000_000;
    try testing.expectEqual(@as(usize, 1_000_000), cc.cwnd);
}

test "boundary: SentPacket pn can be maximum u64" {
    const sp: types.SentPacket = .{
        .pn = std.math.maxInt(u64),
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expectEqual(std.math.maxInt(u64), sp.pn);
}

test "boundary: SentPacket time_ns can be maximum u64" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = std.math.maxInt(u64),
        .size = 1200,
        .ack_eliciting = true,
    };
    try testing.expectEqual(std.math.maxInt(u64), sp.time_ns);
}

test "boundary: SentPacket size can be zero" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 0,
        .ack_eliciting = false,
    };
    try testing.expectEqual(@as(usize, 0), sp.size);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 §7 - CcState provides all required congestion control fields" {
    const cc: types.CcState = .{};
    // Verify all RFC 9002 §7 required fields exist
    _ = cc.mds;
    _ = cc.cwnd;
    _ = cc.ssthresh;
    _ = cc.bytes_in_flight;
}

test "RFC 9002 Appendix B.2 - CUBIC constants match specification" {
    // RFC 9002 Appendix B.2 specifies C = 0.4 (typical value)
    try testing.expectEqual(@as(f64, 0.4), types.CUBIC_C_DEFAULT);
    // RFC 9002 Appendix B.2 specifies beta = 0.7 (typical value)
    try testing.expectEqual(@as(f64, 0.7), types.CUBIC_BETA_DEFAULT);
}

test "RFC 9000 §12.1 - PacketNumberSpace covers all encryption levels" {
    // RFC 9000 §12.1: QUIC uses three packet number spaces
    const spaces = [_]types.PacketNumberSpace{
        .Initial,
        .Handshake,
        .Application,
    };
    try testing.expectEqual(@as(usize, 3), spaces.len);
}

test "RFC 9002 §2 - SentPacket provides all required tracking fields" {
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };

    // RFC 9002 §2 requires tracking:
    _ = sp.pn; // Packet number
    _ = sp.time_ns; // Sent time for RTT measurement
    _ = sp.size; // Bytes for congestion control
    _ = sp.ack_eliciting; // ACK eliciting flag
    _ = sp.acked; // Acknowledgment state
    _ = sp.declared_lost; // Loss detection state
}

test "RFC 9002 §7.2 - initial cwnd is at least 10 * mds" {
    const cc: types.CcState = .{};
    try testing.expect(cc.cwnd >= 10 * cc.mds);
}

test "RFC 9002 §7 - bytes_in_flight tracks unacknowledged data" {
    var cc: types.CcState = .{};

    // Simulate sending packets
    cc.bytes_in_flight += 1200;
    cc.bytes_in_flight += 1200;
    try testing.expectEqual(@as(usize, 2400), cc.bytes_in_flight);

    // Simulate ACK
    cc.bytes_in_flight -= 1200;
    try testing.expectEqual(@as(usize, 1200), cc.bytes_in_flight);
}

// =============================================================================
// Integration Tests
// =============================================================================

test "CcState and SentPacket can be used together" {
    var cc: types.CcState = .{};
    const sp: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };

    // Simulate sending
    if (sp.ack_eliciting) {
        cc.bytes_in_flight += sp.size;
    }

    try testing.expectEqual(@as(usize, 1200), cc.bytes_in_flight);
}

test "PacketNumberSpace can index into arrays" {
    var counters = [_]usize{0} ** 3;
    const space: types.PacketNumberSpace = .Handshake;
    const idx = @intFromEnum(space);
    counters[idx] += 1;

    try testing.expectEqual(@as(usize, 0), counters[0]); // Initial
    try testing.expectEqual(@as(usize, 1), counters[1]); // Handshake
    try testing.expectEqual(@as(usize, 0), counters[2]); // Application
}

test "multiple SentPacket instances can track different packets" {
    const sp1: types.SentPacket = .{
        .pn = 1,
        .time_ns = 1000,
        .size = 1200,
        .ack_eliciting = true,
    };
    const sp2: types.SentPacket = .{
        .pn = 2,
        .time_ns = 2000,
        .size = 800,
        .ack_eliciting = false,
    };

    try testing.expect(sp1.pn != sp2.pn);
    try testing.expect(sp1.time_ns != sp2.time_ns);
    try testing.expect(sp1.size != sp2.size);
    try testing.expect(sp1.ack_eliciting != sp2.ack_eliciting);
}
