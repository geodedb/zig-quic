const std = @import("std");
const common = @import("bench_common");

test "summarizeLatencies: sorted percentiles" {
    var vals = [_]u64{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(usize, 10), s.count);
    try std.testing.expectEqual(@as(u64, 10), s.min_ns);
    try std.testing.expectEqual(@as(u64, 100), s.max_ns);
    try std.testing.expect(s.p50_ns >= 40 and s.p50_ns <= 60);
    try std.testing.expect(s.p95_ns >= 90);
    try std.testing.expect(s.p99_ns >= 90);
}

test "summarizeLatencies: empty slice" {
    var vals = [_]u64{};
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(u64, 0), s.min_ns);
    try std.testing.expectEqual(@as(u64, 0), s.p50_ns);
}

test "parseOutputArg: --output=PATH" {
    const args = [_][]const u8{ "prog", "--output=foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseOutputArg: --output PATH" {
    const args = [_][]const u8{ "prog", "--output", "foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseSuiteArg: --suite=NAME" {
    const args = [_][]const u8{ "prog", "--suite=micro" };
    try std.testing.expectEqualStrings("micro", common.parseSuiteArg(&args).?);
}
