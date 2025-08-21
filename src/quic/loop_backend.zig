// MIT License
// loop_backend.zig — platform loop selection utilities shared by api and endpoint
const std = @import("std");
const builtin = @import("builtin");

/// Supported event loop backends per platform.
pub const LoopBackend = enum { epoll, kqueue, iocp };

/// Choose a reasonable default loop backend based on OS.
pub fn defaultLoopBackend() LoopBackend {
    return switch (builtin.target.os.tag) {
        .linux => .epoll,
        .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd, .dragonfly => .kqueue,
        .windows => .iocp,
        else => .epoll,
    };
}
