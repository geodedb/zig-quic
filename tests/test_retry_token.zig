const std = @import("std");
const token = @import("quic_token");

fn monotonicNowMs() u64 {
    const ns: i128 = std.time.nanoTimestamp();
    if (ns <= 0) return 0;
    return @intCast(@as(u128, @intCast(ns)) / std.time.ns_per_ms);
}

// RFC 9000 §8.1.4: Retry tokens must bind to client address and expire.
test "retry token verification" {
    const secret = "retry-secret";
    const client_ip = "203.0.113.10";
    const odcid = "client-odcid";

    const buf = try token.encode(std.testing.allocator, client_ip, odcid, secret, 1_000);
    defer std.testing.allocator.free(buf);

    const now_ms = monotonicNowMs();
    try std.testing.expect(token.verify(buf, client_ip, secret, now_ms));
    try std.testing.expect(!token.verify(buf, "198.51.100.77", secret, now_ms));
    try std.testing.expect(!token.verify(buf, client_ip, secret, now_ms + 60_000));
}
