// SPDX-License-Identifier: Apache-2.0
const std = @import("std");

pub const Observation = struct {
    expected_bytes: u64,
    received_bytes: u64,
    expected_streams: u64,
    finished_streams: u64,
    start_ns: u64,
    end_ns: u64,
    poll_ns: u64,
    packets: u64,
    samples: usize,
};

pub fn validate(o: Observation) !void {
    if (o.expected_bytes == 0 or o.received_bytes != o.expected_bytes or
        o.expected_streams == 0 or o.finished_streams != o.expected_streams)
        return error.IncompleteTransfer;
    if (o.end_ns <= o.start_ns or o.poll_ns == 0 or o.poll_ns > o.end_ns - o.start_ns)
        return error.InvalidMeasurementWindow;
    if (o.packets == 0 or o.samples == 0 or o.samples > o.packets)
        return error.InvalidPacketSamples;
}

const complete = Observation{ .expected_bytes = 1024, .received_bytes = 1024, .expected_streams = 1, .finished_streams = 1, .start_ns = 100, .end_ns = 200, .poll_ns = 80, .packets = 2, .samples = 1 };

test "datagram accounting rejects incomplete, excessive and FIN-less delivery" {
    try validate(complete);
    for ([_]u64{ 0, 700, 1025 }) |n| {
        var o = complete;
        o.received_bytes = n;
        try std.testing.expectError(error.IncompleteTransfer, validate(o));
    }
    var o = complete;
    o.finished_streams = 0;
    try std.testing.expectError(error.IncompleteTransfer, validate(o));
}

test "datagram accounting rejects polling outside its elapsed window" {
    var o = complete;
    o.poll_ns = 101;
    try std.testing.expectError(error.InvalidMeasurementWindow, validate(o));
    o = complete;
    o.end_ns = o.start_ns;
    try std.testing.expectError(error.InvalidMeasurementWindow, validate(o));
    o.end_ns = o.start_ns - 1;
    try std.testing.expectError(error.InvalidMeasurementWindow, validate(o));
}

test "datagram accounting cannot turn no packets or no samples into a measurement" {
    var o = complete;
    o.packets = 0;
    try std.testing.expectError(error.InvalidPacketSamples, validate(o));
    o = complete;
    o.samples = 0;
    try std.testing.expectError(error.InvalidPacketSamples, validate(o));
    o.samples = 3;
    try std.testing.expectError(error.InvalidPacketSamples, validate(o));
}
