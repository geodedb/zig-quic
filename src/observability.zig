//! observability.zig — single-file otel seam for quic.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break QUIC transport.
//!
//! NOTE: deviation from template — QUIC connections don't fit the HTTP
//! `instrumentation.http.startClientSpan` shape (HTTP method/url is
//! lossy for a UDP-multiplexed transport). We expose the generic
//! `startClientSpan` / `startServerSpan` helpers for symmetry with
//! grpc-zig (and to keep the seam template-compatible), AND a
//! QUIC-specific `startConnectionSpan(role, peer_addr)` helper that
//! constructs a span via `otel.api.trace.Tracer.startSpan` directly with
//! a QUIC-shaped span name (`"QUIC connection {role}"`) and the
//! `network.protocol.name` / `network.transport` / `network.peer.address`
//! semantic conventions.

const std = @import("std");
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import + the conditional otel import. The previous pattern surfaced
// a Zig 0.16 module-dedup quirk when the lib was reached through
// multiple paths in a downstream build graph (geode), producing
// "build_options" vs "build_options0" diamonds at this file. The
// seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is
// resolved.
pub const enabled: bool = false;

const otel = struct {};

/// Connection role used when starting a QUIC connection span. Mirrors
/// `quic.Role` (Client / Server) but kept local so the seam stays
/// import-clean for the disabled build (no transitive pull on
/// `quic_api`).
pub const Role = enum { client, server };

/// Stream direction for `startStreamSpan`. Currently unused — stream
/// spans are deferred to v1; the type is included so the helper
/// signature is stable for future wiring.
pub const StreamDir = enum { uni, bidi };

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; quic hot paths use `startConnectionSpan` instead.
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

/// Start a span for a QUIC connection lifetime.
///
/// Span shape:
///   - name: `"QUIC connection client"` or `"QUIC connection server"`
///   - kind: `.client` for outbound (client role), `.server` for inbound
///   - attributes:
///       * `network.protocol.name = "quic"`
///       * `network.transport = "udp"`
///       * `network.peer.address = peer_addr`
pub fn startConnectionSpan(role: Role, peer_addr: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span_name = switch (role) {
        .client => "QUIC connection client",
        .server => "QUIC connection server",
    };
    const kind: otel.api.trace.SpanKind = switch (role) {
        .client => .client,
        .server => .server,
    };
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = kind }) catch return Span{};
    // Best-effort attribute attachment. Failures (OOM in attribute set)
    // cannot block the transport — telemetry is non-fatal.
    span.setStringAttribute("network.protocol.name", "quic") catch {};
    span.setStringAttribute("network.transport", "udp") catch {};
    span.setStringAttribute("network.peer.address", peer_addr) catch {};
    return span;
}

/// Close a connection span, recording success/failure plus the close
/// reason as an attribute.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` with `close_reason` as the description. Either path also
/// records `quic.close_reason = close_reason` so successful graceful
/// closes still carry the reason text.
pub fn endConnectionSpan(span: Span, ok: bool, close_reason: []const u8) void {
    if (!enabled) return;
    span.setStringAttribute("quic.close_reason", close_reason) catch {};
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", close_reason);
    }
    span.end(null);
}

/// Start a span for a QUIC stream as a child of the connection span.
/// Stream spans are valuable but high-volume; this helper is exposed
/// for future v1 wiring. parent is the connection span; when disabled
/// the parent argument is unused.
pub fn startStreamSpan(parent: Span, stream_id: u64, dir: StreamDir) Span {
    _ = parent;
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    var name_buf: [64]u8 = undefined;
    const dir_str = switch (dir) {
        .uni => "uni",
        .bidi => "bidi",
    };
    const span_name = std.fmt.bufPrint(name_buf[0..], "QUIC stream {s} {d}", .{ dir_str, stream_id }) catch "QUIC stream";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .internal }) catch return Span{};
    span.setStringAttribute("network.protocol.name", "quic") catch {};
    span.setIntAttribute("quic.stream.id", @intCast(stream_id)) catch {};
    span.setStringAttribute("quic.stream.direction", dir_str) catch {};
    return span;
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
