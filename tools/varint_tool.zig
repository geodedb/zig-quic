// quic-varint: encode/decode QUIC varints from CLI
// Usage:
//   quic-varint encode <u64>
//   quic-varint decode <hex-bytes...>
const std = @import("std");

const QuicError = error{ VARINT_UNDERFLOW, VARINT_OVERFLOW, INVALID_ARG };

fn toU8(v: u64) u8 {
    return @as(u8, @intCast(v));
}

fn varintEncode(value: u64, out: []u8) !usize {
    if (value > ((1 << 62) - 1)) return QuicError.VARINT_OVERFLOW;
    const len: usize = if (value < (1 << 6)) 1 else if (value < (1 << 14)) 2 else if (value < (1 << 30)) 4 else 8;
    if (out.len < len) return error.OutOfMemory; // shouldn't happen for fixed buffers
    switch (len) {
        1 => out[0] = toU8(value) | @as(u8, 0b00 << 6),
        2 => {
            out[0] = toU8((value >> 8) & 0x3f) | @as(u8, 0b01 << 6);
            out[1] = toU8(value & 0xff);
        },
        4 => {
            out[0] = toU8((value >> 24) & 0x3f) | @as(u8, 0b10 << 6);
            out[1] = toU8((value >> 16) & 0xff);
            out[2] = toU8((value >> 8) & 0xff);
            out[3] = toU8(value & 0xff);
        },
        8 => {
            out[0] = toU8((value >> 56) & 0x3f) | @as(u8, 0b11 << 6);
            out[1] = toU8((value >> 48) & 0xff);
            out[2] = toU8((value >> 40) & 0xff);
            out[3] = toU8((value >> 32) & 0xff);
            out[4] = toU8((value >> 24) & 0xff);
            out[5] = toU8((value >> 16) & 0xff);
            out[6] = toU8((value >> 8) & 0xff);
            out[7] = toU8(value & 0xff);
        },
        else => unreachable,
    }
    return len;
}

fn varintDecode(data: []const u8) !struct { n: usize, value: u64 } {
    if (data.len == 0) return QuicError.VARINT_UNDERFLOW;
    const first = data[0];
    const prefix = first >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (data.len < len) return QuicError.VARINT_UNDERFLOW;
    var v: u64 = 0;
    switch (len) {
        1 => v = (first & 0x3f),
        2 => v = (@as(u64, first & 0x3f) << 8) | @as(u64, data[1]),
        4 => v = (@as(u64, first & 0x3f) << 24) | (@as(u64, data[1]) << 16) | (@as(u64, data[2]) << 8) | @as(u64, data[3]),
        8 => v = (@as(u64, first & 0x3f) << 56) | (@as(u64, data[1]) << 48) | (@as(u64, data[2]) << 40) | (@as(u64, data[3]) << 32) |
            (@as(u64, data[4]) << 24) | (@as(u64, data[5]) << 16) | (@as(u64, data[6]) << 8) | @as(u64, data[7]),
        else => unreachable,
    }
    return .{ .n = len, .value = v };
}

fn parseHexByte(s: []const u8) !u8 {
    if (s.len != 2) return error.Invalid;
    const hi = std.fmt.charToDigit(s[0], 16) catch return error.Invalid;
    const lo = std.fmt.charToDigit(s[1], 16) catch return error.Invalid;
    return toU8(hi * 16 + lo);
}

fn writeStderr(bytes: []const u8) void {
    if (@import("builtin").target.os.tag == .windows) {
        const w = std.os.windows;
        const h = w.GetStdHandle(w.STD_ERROR_HANDLE) catch return;
        _ = std.posix.write(h, bytes) catch {};
    } else {
        _ = std.posix.write(std.posix.STDERR_FILENO, bytes) catch {};
    }
}

fn writeStdout(bytes: []const u8) void {
    if (@import("builtin").target.os.tag == .windows) {
        const w = std.os.windows;
        const h = w.GetStdHandle(w.STD_OUTPUT_HANDLE) catch return;
        _ = std.posix.write(h, bytes) catch {};
    } else {
        _ = std.posix.write(std.posix.STDOUT_FILENO, bytes) catch {};
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    if (args.len < 3) {
        writeStderr("usage: quic-varint encode <u64> | decode <hex-bytes...>\n");
        std.process.exit(2);
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "encode")) {
        const val = std.fmt.parseInt(u64, args[2], 10) catch {
            writeStderr("INVALID_ARG\n");
            std.process.exit(2);
        };
        var buf: [8]u8 = undefined;
        const n = varintEncode(val, &buf) catch |e| {
            if (e == QuicError.VARINT_OVERFLOW) {
                writeStderr("VARINT_OVERFLOW\n");
                std.process.exit(2);
            }
            return e;
        };
        // print as hex bytes, space separated
        var out_buf: [32]u8 = undefined;
        var k: usize = 0;
        var first = true;
        for (buf[0..n]) |b| {
            if (!first) {
                out_buf[k] = ' ';
                k += 1;
            }
            first = false;
            const s = std.fmt.bufPrint(out_buf[k..], "{X:0>2}", .{b}) catch out_buf[k..k];
            k += s.len;
        }
        out_buf[k] = '\n';
        k += 1;
        writeStdout(out_buf[0..k]);
    } else if (std.mem.eql(u8, cmd, "decode")) {
        if (args.len < 3) {
            writeStderr("VARINT_UNDERFLOW\n");
            std.process.exit(2);
        }
        const count = args.len - 2;
        const buf = try alloc.alloc(u8, count);
        defer alloc.free(buf);
        for (buf, 0..) |*b, i| {
            const s = args[2 + i];
            b.* = parseHexByte(std.mem.trim(u8, s, " ")) catch {
                writeStderr("INVALID_ARG\n");
                std.process.exit(2);
                unreachable;
            };
        }
        const res = varintDecode(buf) catch |e| {
            if (e == QuicError.VARINT_UNDERFLOW) {
                writeStderr("VARINT_UNDERFLOW\n");
                std.process.exit(2);
            }
            return e;
        };
        var numbuf: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&numbuf, "{d}\n", .{res.value}) catch return;
        writeStdout(s);
    } else {
        writeStderr("INVALID_ARG\n");
        std.process.exit(2);
    }
}
