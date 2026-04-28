//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! quic publishes its public surface as the "quic" module rooted at
//! lib.zig. The seam is exposed as `quic.observability` so this test
//! can drive the disabled-mode invariants through the public root.

const std = @import("std");
const quic = @import("quic");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, quic.observability.enabled);
}

test "client/server seams are no-ops when otel disabled" {
    if (quic.observability.enabled) return error.SkipZigTest;
    var span = quic.observability.startClientSpan(.{
        .method = "GET",
        .url = "https://example.test/",
    });
    quic.observability.endClientSpan(span, 200);
    // Belt-and-suspenders: the seam's `endClientSpan` already covers
    // the lifecycle; this line just verifies the no-op fallback's
    // signature matches the real API's `Span.end(?u64) void`.
    span.end(null);

    var sspan = quic.observability.startServerSpan(.{
        .method = "GET",
        .route = "/",
        .url = "/",
    });
    quic.observability.endServerSpan(sspan, 200);
    sspan.end(null);
}

test "QUIC connection span helper is a no-op when otel disabled" {
    if (quic.observability.enabled) return error.SkipZigTest;
    var span = quic.observability.startConnectionSpan(.client, "127.0.0.1:443");
    quic.observability.endConnectionSpan(span, true, "ok");
    span.end(null);

    var sspan = quic.observability.startConnectionSpan(.server, "127.0.0.1:443");
    quic.observability.endConnectionSpan(sspan, false, "peer_reset");
    sspan.end(null);
}

test "QUIC stream span helper is a no-op when otel disabled" {
    if (quic.observability.enabled) return error.SkipZigTest;
    const parent = quic.observability.startConnectionSpan(.client, "127.0.0.1:443");
    var sspan = quic.observability.startStreamSpan(parent, 4, .bidi);
    sspan.end(null);
    quic.observability.endConnectionSpan(parent, true, "ok");
}
