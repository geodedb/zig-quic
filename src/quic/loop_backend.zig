// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Platform event loop selection used by the QUIC endpoint.
//!
//! RFC 9000 §6 requires endpoints to service timers promptly; this helper picks
//! an appropriate OS backend so the transport can honour PTO/idle timeouts.
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
