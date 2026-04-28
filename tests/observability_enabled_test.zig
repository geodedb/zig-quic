//! Verifies one QUIC connection span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than driving a real QUIC handshake.
//! End-to-end QUIC requires UDP sockets and a TLS handshake; the seam's
//! contract is identical: `startConnectionSpan` -> `endConnectionSpan`
//! enters and leaves one tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const quic = @import("quic");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one QUIC connection span recorded when otel enabled" {
    if (!quic.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "quic-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "quic-test" });
    quic.observability.global.tracer = &tracer;
    defer quic.observability.global.tracer = null;

    const span = quic.observability.startConnectionSpan(.client, "127.0.0.1:443");
    quic.observability.endConnectionSpan(span, true, "ok");

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "QUIC connection client".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("QUIC connection client", recorded.name);

    // Verify the network.peer.address attribute landed on the span.
    var found_attr: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "network.peer.address")) {
            found_attr = kv.value;
            break;
        }
    }
    const attr_value = found_attr orelse return error.MissingPeerAddressAttribute;
    try std.testing.expectEqualStrings("127.0.0.1:443", attr_value);
}
