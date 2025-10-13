const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const builtin = @import("builtin");

pub fn main() !void {
    std.debug.print("Testing WITHOUT IP_RECVERR/IPV6_RECVERR...\n", .{});

    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(fd);
    std.debug.print("Socket fd={}\n", .{fd});

    // Allow fast rebinding in tests
    var one: i32 = 1;
    _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

    // Linux: enable reception of TOS/TCLASS via ancillary data to read ECN bits per datagram
    if (builtin.target.os.tag == .linux) {
        var enable: i32 = 1;
        // Zig std may not expose IP.RECVTOS; use the Linux value (IP_RECVTOS = 13)
        const IP_RECVTOS: i32 = 13;
        _ = posix.setsockopt(fd, posix.IPPROTO.IP, IP_RECVTOS, std.mem.asBytes(&enable)) catch {};
        std.debug.print("Set IP_RECVTOS\n", .{});

        // Also request IPv6 traffic class delivery (IPV6_RECVTCLASS = 66)
        const IPV6_RECVTCLASS: i32 = 66;
        _ = posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_RECVTCLASS, std.mem.asBytes(&enable)) catch {};
        std.debug.print("Set IPV6_RECVTCLASS\n", .{});

        // SKIP IP_RECVERR and IPV6_RECVERR
        std.debug.print("SKIPPING IP_RECVERR and IPV6_RECVERR\n", .{});
    }

    // Bind to 127.0.0.1:4433
    var addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeTo(u16, 4433, .big),
        .addr = std.mem.nativeTo(u32, 0x7f000001, .big), // 127.0.0.1
        .zero = [_]u8{0} ** 8,
    };

    std.debug.print("Binding to 127.0.0.1:4433...\n", .{});
    try posix.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    std.debug.print("Bound successfully\n", .{});

    // Set non-blocking
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    const O_NONBLOCK: i32 = 0x800;
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | O_NONBLOCK);
    std.debug.print("Set non-blocking\n", .{});

    // Create epoll
    const epfd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
    defer posix.close(epfd);
    std.debug.print("Created epoll fd={}\n", .{epfd});

    // Add socket to epoll
    var ev = std.mem.zeroes(linux.epoll_event);
    ev.events = linux.EPOLL.IN;
    ev.data.fd = @as(i32, @intCast(fd));
    try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev);
    std.debug.print("Added socket to epoll\n", .{});

    std.debug.print("\nWaiting for packets (send with: echo TEST | nc -u 127.0.0.1 4433)...\n", .{});

    var count: usize = 0;
    while (count < 20) : (count += 1) {
        var events: [1]linux.epoll_event = undefined;
        const n = posix.epoll_wait(epfd, &events, 1000);

        if (n > 0) {
            std.debug.print("epoll triggered! Events: {}\n", .{n});

            var buf: [2048]u8 = undefined;
            var peer: posix.sockaddr.storage = undefined;
            var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));

            const nbytes = posix.recvfrom(fd, &buf, 0, @ptrCast(&peer), &peer_len) catch |err| {
                std.debug.print("recvfrom error: {}\n", .{err});
                continue;
            };

            std.debug.print("Received {} bytes: {s}\n", .{nbytes, buf[0..nbytes]});
        } else {
            std.debug.print("epoll timeout (iteration {})\n", .{count});
        }
    }
}
