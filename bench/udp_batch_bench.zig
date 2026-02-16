// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const linux = std.os.linux;

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
    send_fd: posix.socket_t,
    recv_fd: posix.socket_t,

    fn deinit(self: SocketPair) void {
        posix.close(self.send_fd);
        posix.close(self.recv_fd);
    }
};

fn parseMode(name: []const u8) !Mode {
    if (std.mem.eql(u8, name, "single")) return .single;
    if (std.mem.eql(u8, name, "batch")) return .batch;
    if (std.mem.eql(u8, name, "both")) return .both;
    return error.InvalidMode;
}

fn parseArgs() !Config {
    var cfg = Config{};
    var args = std.process.args();
    _ = args.skip();
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

fn setupSockets() !SocketPair {
    const recv_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(recv_fd);

    const bind_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    try posix.bind(recv_fd, &bind_addr.any, bind_addr.getOsSockLen());

    var recv_addr: posix.sockaddr.storage = undefined;
    var recv_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try posix.getsockname(recv_fd, @ptrCast(&recv_addr), &recv_len);

    const send_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(send_fd);
    try posix.connect(send_fd, @ptrCast(&recv_addr), recv_len);

    return .{ .send_fd = send_fd, .recv_fd = recv_fd };
}

fn linuxResultToCount(rc: usize) !usize {
    return switch (linux.E.init(rc)) {
        .SUCCESS => rc,
        .AGAIN => error.WouldBlock,
        else => |err| posix.unexpectedErrno(err),
    };
}

fn runSingle(cfg: Config, payload: []const u8, recv_buf: []u8) !Result {
    const sockets = try setupSockets();
    defer sockets.deinit();

    var timer = try std.time.Timer.start();
    var send_syscalls: usize = 0;
    var recv_syscalls: usize = 0;

    var iter: usize = 0;
    while (iter < cfg.iters) : (iter += 1) {
        var i: usize = 0;
        while (i < cfg.batch) : (i += 1) {
            const sent = try posix.send(sockets.send_fd, payload, 0);
            if (sent != payload.len) return error.ShortWrite;
            send_syscalls += 1;
        }
        i = 0;
        while (i < cfg.batch) : (i += 1) {
            _ = try posix.recv(sockets.recv_fd, recv_buf, 0);
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

    var send_iov: [64]posix.iovec_const = undefined;
    var send_msgs: [64]linux.mmsghdr_const = undefined;
    var recv_iov: [64]posix.iovec = undefined;
    var recv_msgs: [64]linux.mmsghdr = undefined;

    var i: usize = 0;
    while (i < cfg.batch) : (i += 1) {
        send_iov[i] = .{
            .base = payload.ptr,
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

    var timer = try std.time.Timer.start();
    var send_syscalls: usize = 0;
    var recv_syscalls: usize = 0;

    var iter: usize = 0;
    while (iter < cfg.iters) : (iter += 1) {
        var send_idx: usize = 0;
        while (send_idx < cfg.batch) {
            const rc = linux.sendmmsg(
                @intCast(sockets.send_fd),
                send_msgs[send_idx..].ptr,
                @intCast(cfg.batch - send_idx),
                0,
            );
            const sent = try linuxResultToCount(rc);
            if (sent == 0) return error.SendMmsgReturnedZero;
            send_idx += sent;
            send_syscalls += 1;
        }

        var recv_idx: usize = 0;
        while (recv_idx < cfg.batch) {
            const rc = linux.recvmmsg(
                @intCast(sockets.recv_fd),
                recv_msgs[recv_idx..].ptr,
                @intCast(cfg.batch - recv_idx),
                0,
                null,
            );
            const got = try linuxResultToCount(rc);
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

pub fn main() !void {
    if (builtin.target.os.tag != .linux) {
        std.debug.print("udp_batch_bench requires linux target\n", .{});
        return;
    }

    const cfg = try parseArgs();
    if (cfg.batch == 0 or cfg.batch > 64) return error.InvalidBatchSize;
    if (cfg.payload == 0 or cfg.payload > 2048) return error.InvalidPayloadSize;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

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
