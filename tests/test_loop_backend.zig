const std = @import("std");
const loop_backend = @import("quic_loop_backend");

// RFC 9000 §6 emphasises timely processing of network IO and timers. Confirm we
// pick the appropriate readiness backend for each supported platform so PTO
// machinery stays responsive.
test "default loop backend matches platform expectations" {
    const expected = switch (std.builtin.os.tag) {
        .linux => loop_backend.LoopBackend.epoll,
        .macos, .ios, .tvos, .watchos, .freebsd, .openbsd, .netbsd, .dragonfly => loop_backend.LoopBackend.kqueue,
        .windows => loop_backend.LoopBackend.iocp,
        else => loop_backend.LoopBackend.epoll,
    };
    try std.testing.expectEqual(expected, loop_backend.defaultLoopBackend());
}
