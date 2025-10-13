const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub fn main() !void {
    // Create UDP socket
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(fd);

    std.debug.print("Created socket fd={}\n", .{fd});

    // Set socket to non-blocking mode
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    std.debug.print("Current socket flags: 0x{x}\n", .{flags});
    const O_NONBLOCK: i32 = 0x800;
    const new_flags = flags | O_NONBLOCK;
    _ = try posix.fcntl(fd, posix.F.SETFL, new_flags);
    const verify_flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    std.debug.print("Socket flags after setting: 0x{x} (has O_NONBLOCK: {})\n", .{verify_flags, (verify_flags & O_NONBLOCK) != 0});

    // Bind to port 5555
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 5555),
        .addr = 0, // 0.0.0.0
        .zero = [_]u8{0} ** 8,
    };

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    std.debug.print("Bound to port 5555\n", .{});

    // Create epoll
    const epfd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
    defer posix.close(epfd);

    // Add socket to epoll
    var ev = std.mem.zeroes(linux.epoll_event);
    ev.events = linux.EPOLL.IN;
    ev.data.fd = @as(i32, @intCast(fd));
    try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev);

    std.debug.print("Created epoll fd={} and added socket\n", .{epfd});

    // Start a thread that sends data to ourselves
    const thread = try std.Thread.spawn(.{}, sendThread, .{});

    // Wait for data with epoll
    var events: [16]linux.epoll_event = undefined;
    var total_received: usize = 0;

    while (total_received < 5) {
        std.debug.print("Calling epoll_wait...\n", .{});
        const n = posix.epoll_wait(epfd, &events, 1000);

        if (n > 0) {
            std.debug.print("epoll_wait returned {} events\n", .{n});

            for (0..n) |i| {
                const event = events[i];
                std.debug.print("Event {}: fd={}, events=0x{x}\n", .{i, event.data.fd, event.events});

                if (event.data.fd == fd) {
                    // Try to receive data
                    var buf: [1024]u8 = undefined;
                    var peer_addr: posix.sockaddr.storage = undefined;
                    var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer_addr));

                    while (true) {
                        const result = posix.recvfrom(fd, &buf, 0, @ptrCast(&peer_addr), &peer_len);

                        if (result) |nbytes| {
                            std.debug.print("Received {} bytes: {s}\n", .{nbytes, buf[0..nbytes]});
                            total_received += 1;
                        } else |err| {
                            if (err == error.WouldBlock) {
                                std.debug.print("recvfrom returned WouldBlock\n", .{});
                                break;
                            }
                            std.debug.print("recvfrom error: {}\n", .{err});
                            break;
                        }
                    }
                }
            }
        } else if (n == 0) {
            std.debug.print("epoll_wait timed out\n", .{});
        } else {
            std.debug.print("epoll_wait error\n", .{});
            break;
        }
    }

    thread.join();
    std.debug.print("Test completed, received {} messages\n", .{total_received});
}

fn sendThread() void {
    std.Thread.sleep(500 * std.time.ns_per_ms); // Wait 500ms before sending

    // Create UDP socket for sending
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return;
    defer posix.close(fd);

    var dest_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 5555),
        .addr = std.mem.nativeToBig(u32, 0x7f000001), // 127.0.0.1
        .zero = [_]u8{0} ** 8,
    };

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const msg = std.fmt.allocPrint(std.heap.page_allocator, "Message {}", .{i}) catch return;
        defer std.heap.page_allocator.free(msg);

        _ = posix.sendto(fd, msg, 0, @ptrCast(&dest_addr), @sizeOf(@TypeOf(dest_addr))) catch {
            std.debug.print("sendto failed\n", .{});
            return;
        };

        std.debug.print("Sent message {}\n", .{i});
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }
}