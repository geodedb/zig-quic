// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (v0.1.51 follow-up, found by geode-client-zig on v0.1.50):
// a failed `api.connect` freed the connection but left it registered with
// the endpoint, so endpoint deinit freed it a second time. Any failed dial
// triggered it, e.g. an IPv6 address from an IPv4-bound endpoint.
//
// Real endpoints under std.testing.allocator: every failed dial must leave
// nothing behind (no use after free, no double free, no leak).

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");

const test_alpn = [_][]const u8{"h3"};

fn clientCfg() cfg.QuicConfig {
    return .{ .alpn = &test_alpn, .allow_insecure = true };
}

test "a dial to an IPv6 address from an IPv4 endpoint fails cleanly" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var c = clientCfg();
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &c);
    defer ep.deinit();
    if (api.connect(&ep, "[::1]:4433", "localhost")) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
    // The endpoint must still be usable and own nothing of the failed dial.
    _ = ep.pollWithStats(0) catch {};
}

test "dials to unusable addresses fail cleanly and the endpoint survives" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var c = clientCfg();
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &c);
    defer ep.deinit();
    const bad = [_][]const u8{
        "not-an-address",
        "127.0.0.1", // no port
        "127.0.0.1:99999", // port out of range
        "[::1]:443", // family mismatch
        "no-such-host.invalid:4433", // not in /etc/hosts
        "[fe80::1%eth0]:4433", // zone id
    };
    for (bad) |addr| {
        if (api.connect(&ep, addr, "localhost")) |conn| {
            // Some may be accepted at dial time; they must then be
            // destroyable without leaking.
            api.destroy(&ep, conn);
        } else |_| {}
    }
    // A good dial still works after the failures.
    const conn = try api.connect(&ep, "127.0.0.1:9", "localhost");
    api.destroy(&ep, conn);
}

test "a host name that is not in /etc/hosts, or a zone id, is a clear error" {
    // The resolver reads only /etc/hosts (no DNS) and cannot resolve IPv6
    // zone ids; both used to fail as the generic error.InvalidAddress, the
    // same error as a malformed address.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var c = clientCfg();
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &c);
    defer ep.deinit();
    try testing.expectError(error.HostNotFound, api.connect(&ep, "no-such-host.invalid:4433", "localhost"));
    try testing.expectError(error.UnsupportedZoneId, api.connect(&ep, "[fe80::1%eth0]:4433", "localhost"));
    // Malformed input keeps its own error.
    try testing.expectError(error.InvalidAddress, api.connect(&ep, "127.0.0.1", "localhost"));
    try testing.expectError(error.InvalidAddress, api.connect(&ep, "bad host!:4433", "localhost"));
}

test "allocation failure at every point of endpoint setup and dial leaves nothing behind" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var c = clientCfg();
    var fail_index: usize = 0;
    while (fail_index < 10_000) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const alloc = failing.allocator();
        var ep = endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &c) catch continue;
        if (api.connect(&ep, "127.0.0.1:9", "localhost")) |conn| {
            api.destroy(&ep, conn);
        } else |_| {}
        ep.deinit();
        if (!failing.has_induced_failure) break;
    }
    // Reached an index past every allocation (a full successful run).
    try testing.expect(fail_index < 10_000);
}
