// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const Mode = enum { single, batch, both };

const Config = struct {
    iters: usize = 20_000,
    batch: usize = 16,
    payload: usize = 1200,
    mode: Mode = .both,
};

const Result = struct {
    mode: Mode,
    total_packets: usize,
    elapsed_ns: u64,
    send_syscalls: usize,
    recv_syscalls: usize,

    fn pps(self: Result) f64 {
        return @as(f64, @floatFromInt(self.total_packets)) / (@as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    }

    fn syscallsPerPacket(self: Result) f64 {
        return @as(f64, @floatFromInt(self.send_syscalls + self.recv_syscalls)) / @as(f64, @floatFromInt(self.total_packets));
    }
};

const SocketPair = struct {
    send_fd: i32,
    recv_fd: i32,

    fn deinit(self: SocketPair) void {
        _ = linux.close(self.send_fd);
        _ = linux.close(self.recv_fd);
    }
};

fn parseMode(name: []const u8) !Mode {
    if (std.mem.eql(u8, name, "single")) return .single;
    if (std.mem.eql(u8, name, "batch")) return .batch;
    if (std.mem.eql(u8, name, "both")) return .both;
    return error.InvalidMode;
}

fn parseArgs(init_arg: std.process.Init, allocator: std.mem.Allocator) !Config {
    var cfg = Config{};
    var args = try std.process.Args.Iterator.initAllocator(init_arg.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--iters")) {
            cfg.iters = try std.fmt.parseInt(usize, args.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--batch")) {
            cfg.batch = try std.fmt.parseInt(usize, args.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--payload")) {
            cfg.payload = try std.fmt.parseInt(usize, args.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--mode")) {
            cfg.mode = try parseMode(args.next() orelse return error.MissingValue);
        } else {
            return error.UnknownArgument;
        }
    }
    return cfg;
}

fn expectOk(rc: usize, comptime op: []const u8) !usize {
    // Linux raw syscalls return -errno as a small negative (i.e. huge usize).
    // If rc is within the errno range, convert and bail out.
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        const errno: u32 = @intCast(-signed);
        const e: posix.E = @enumFromInt(errno);
        switch (e) {
            .SUCCESS => return rc,
            .AGAIN => return error.WouldBlock,
            else => {
                std.debug.print("syscall {s} failed: errno={s}\n", .{ op, @tagName(e) });
                return error.SyscallFailed;
            },
        }
    }
    return rc;
}

fn setupSockets() !SocketPair {
    const sock_recv_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    _ = try expectOk(sock_recv_rc, "socket(recv)");
    const recv_fd: i32 = @intCast(sock_recv_rc);
    errdefer _ = linux.close(recv_fd);

    // 127.0.0.1:0 — kernel picks an ephemeral port.
    const bind_addr = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1 in network byte order
    };
    const bind_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const bind_rc = linux.bind(recv_fd, @ptrCast(&bind_addr), bind_len);
    _ = try expectOk(bind_rc, "bind");

    var recv_addr_storage: linux.sockaddr.storage = undefined;
    var recv_len: linux.socklen_t = @sizeOf(linux.sockaddr.storage);
    const getname_rc = linux.getsockname(recv_fd, @ptrCast(&recv_addr_storage), &recv_len);
    _ = try expectOk(getname_rc, "getsockname");

    const sock_send_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    _ = try expectOk(sock_send_rc, "socket(send)");
    const send_fd: i32 = @intCast(sock_send_rc);
    errdefer _ = linux.close(send_fd);

    const connect_rc = linux.connect(send_fd, @ptrCast(&recv_addr_storage), recv_len);
    _ = try expectOk(connect_rc, "connect");

    return .{ .send_fd = send_fd, .recv_fd = recv_fd };
}

fn nanoTimestamp() i128 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
}

const Timer = struct {
    start_ns: i128,
    fn start() !Timer {
        return .{ .start_ns = nanoTimestamp() };
    }
    fn read(self: *Timer) u64 {
        const diff = nanoTimestamp() - self.start_ns;
        return if (diff > 0) @intCast(diff) else 0;
    }
};

fn runSingle(cfg: Config, payload: []const u8, recv_buf: []u8) !Result {
    const sockets = try setupSockets();
    defer sockets.deinit();

    var timer = try Timer.start();
    var send_syscalls: usize = 0;
    var recv_syscalls: usize = 0;

    var iter: usize = 0;
    while (iter < cfg.iters) : (iter += 1) {
        var i: usize = 0;
        while (i < cfg.batch) : (i += 1) {
            const rc = linux.sendto(sockets.send_fd, payload.ptr, payload.len, 0, null, 0);
            const sent = try expectOk(rc, "sendto");
            if (sent != payload.len) return error.ShortWrite;
            send_syscalls += 1;
        }
        i = 0;
        while (i < cfg.batch) : (i += 1) {
            const rc = linux.recvfrom(sockets.recv_fd, recv_buf.ptr, recv_buf.len, 0, null, null);
            _ = try expectOk(rc, "recvfrom");
            recv_syscalls += 1;
        }
    }

    const elapsed_ns = timer.read();
    return .{
        .mode = .single,
        .total_packets = cfg.iters * cfg.batch,
        .elapsed_ns = elapsed_ns,
        .send_syscalls = send_syscalls,
        .recv_syscalls = recv_syscalls,
    };
}

fn runBatch(cfg: Config, payload: []const u8, recv_packet_bufs: [][2048]u8) !Result {
    const sockets = try setupSockets();
    defer sockets.deinit();

    var send_iov: [64]posix.iovec = undefined;
    var send_msgs: [64]linux.mmsghdr = undefined;
    var recv_iov: [64]posix.iovec = undefined;
    var recv_msgs: [64]linux.mmsghdr = undefined;

    var i: usize = 0;
    while (i < cfg.batch) : (i += 1) {
        // send_iov holds the const payload; kernel reads, never writes.
        send_iov[i] = .{
            .base = @constCast(payload.ptr),
            .len = payload.len,
        };
        send_msgs[i] = .{
            .hdr = .{
                .name = null,
                .namelen = 0,
                .iov = @ptrCast(&send_iov[i]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };

        recv_iov[i] = .{
            .base = recv_packet_bufs[i][0..].ptr,
            .len = recv_packet_bufs[i].len,
        };
        recv_msgs[i] = .{
            .hdr = .{
                .name = null,
                .namelen = 0,
                .iov = @ptrCast(&recv_iov[i]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };
    }

    var timer = try Timer.start();
    var send_syscalls: usize = 0;
    var recv_syscalls: usize = 0;

    var iter: usize = 0;
    while (iter < cfg.iters) : (iter += 1) {
        var send_idx: usize = 0;
        while (send_idx < cfg.batch) {
            const rc = linux.sendmmsg(
                sockets.send_fd,
                send_msgs[send_idx..].ptr,
                @intCast(cfg.batch - send_idx),
                0,
            );
            const sent = try expectOk(rc, "sendmmsg");
            if (sent == 0) return error.SendMmsgReturnedZero;
            send_idx += sent;
            send_syscalls += 1;
        }

        var recv_idx: usize = 0;
        while (recv_idx < cfg.batch) {
            const rc = linux.recvmmsg(
                sockets.recv_fd,
                recv_msgs[recv_idx..].ptr,
                @intCast(cfg.batch - recv_idx),
                0,
                null,
            );
            const got = try expectOk(rc, "recvmmsg");
            if (got == 0) return error.RecvMmsgReturnedZero;
            recv_idx += got;
            recv_syscalls += 1;
        }
    }

    const elapsed_ns = timer.read();
    return .{
        .mode = .batch,
        .total_packets = cfg.iters * cfg.batch,
        .elapsed_ns = elapsed_ns,
        .send_syscalls = send_syscalls,
        .recv_syscalls = recv_syscalls,
    };
}

fn printResult(r: Result) void {
    std.debug.print(
        "mode={s} packets={d} elapsed_ns={d} pps={d:.2} send_syscalls={d} recv_syscalls={d} syscalls_per_packet={d:.4}\n",
        .{
            @tagName(r.mode),
            r.total_packets,
            r.elapsed_ns,
            r.pps(),
            r.send_syscalls,
            r.recv_syscalls,
            r.syscallsPerPacket(),
        },
    );
}

pub fn main(init_arg: std.process.Init) !void {
    if (builtin.target.os.tag != .linux) {
        std.debug.print("udp_batch_bench requires linux target\n", .{});
        return;
    }

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const cfg = try parseArgs(init_arg, alloc);
    if (cfg.batch == 0 or cfg.batch > 64) return error.InvalidBatchSize;
    if (cfg.payload == 0 or cfg.payload > 2048) return error.InvalidPayloadSize;

    const payload = try alloc.alloc(u8, cfg.payload);
    defer alloc.free(payload);
    @memset(payload, 0xAB);

    var recv_buf: [2048]u8 = undefined;
    var recv_packet_bufs: [64][2048]u8 = undefined;

    var single_result: ?Result = null;
    var batch_result: ?Result = null;

    switch (cfg.mode) {
        .single => {
            single_result = try runSingle(cfg, payload, recv_buf[0..]);
            printResult(single_result.?);
        },
        .batch => {
            batch_result = try runBatch(cfg, payload, recv_packet_bufs[0..]);
            printResult(batch_result.?);
        },
        .both => {
            single_result = try runSingle(cfg, payload, recv_buf[0..]);
            batch_result = try runBatch(cfg, payload, recv_packet_bufs[0..]);
            printResult(single_result.?);
            printResult(batch_result.?);

            const speedup = batch_result.?.pps() / single_result.?.pps();
            const syscall_reduction = single_result.?.syscallsPerPacket() / batch_result.?.syscallsPerPacket();
            std.debug.print(
                "comparison speedup={d:.2} syscall_reduction={d:.2}\n",
                .{ speedup, syscall_reduction },
            );
        },
    }
}
