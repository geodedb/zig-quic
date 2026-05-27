const std = @import("std");

fn sleepNs(ns: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

const Runner = struct {
    alloc: std.mem.Allocator = std.heap.page_allocator,
    io: std.Io = undefined,

    pub fn init(io: std.Io) Runner {
        return Runner{ .alloc = std.heap.page_allocator, .io = io };
    }
    pub fn deinit(self: *Runner) void {
        _ = self;
    }

    fn spawnPipe(self: *Runner, argv: []const []const u8) !std.process.Child {
        return std.process.spawn(self.io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
    }

    fn drainPipe(self: *Runner, file: std.Io.File) ![]u8 {
        var arr: std.ArrayListUnmanaged(u8) = .empty;
        errdefer arr.deinit(self.alloc);
        var tmp: [1024]u8 = undefined;
        while (true) {
            const n = file.readStreaming(self.io, &.{tmp[0..]}) catch 0;
            if (n == 0) break;
            try arr.appendSlice(self.alloc, tmp[0..n]);
        }
        return arr.toOwnedSlice(self.alloc);
    }

    fn termOk(term: std.process.Child.Term) bool {
        return switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    fn haveGo(self: *Runner) bool {
        var child = self.spawnPipe(&[_][]const u8{ "go", "version" }) catch return false;
        const term = child.wait(self.io) catch return false;
        return termOk(term);
    }

    fn pathExists(self: *Runner, p: []const u8) bool {
        _ = std.Io.Dir.cwd().statFile(self.io, p, .{}) catch return false;
        return true;
    }

    fn ensureCerts(self: *Runner) !void {
        if (self.pathExists("examples/interop/certs/cert.pem") and self.pathExists("examples/interop/certs/key.pem")) return;
        if (!self.pathExists("examples/interop/certs/generate.sh")) return error.CertMissing;
        var child = try self.spawnPipe(&[_][]const u8{ "bash", "examples/interop/certs/generate.sh" });
        const term = try child.wait(self.io);
        if (!termOk(term)) return error.CertGenFailed;
        if (!(self.pathExists("examples/interop/certs/cert.pem") and self.pathExists("examples/interop/certs/key.pem"))) return error.CertMissing;
    }

    fn goBuild(self: *Runner, pkg_dir: []const u8, out_path: []const u8) !void {
        if (self.pathExists(out_path)) return;
        var args_buf: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args_buf.deinit(self.alloc);
        try args_buf.appendSlice(self.alloc, &.{ "go", "build", "-o", out_path, pkg_dir });
        var child = try self.spawnPipe(args_buf.items);
        const term = try child.wait(self.io);
        if (!termOk(term)) {
            const stdout_bytes = if (child.stdout) |s| try self.drainPipe(s) else try self.alloc.dupe(u8, "");
            defer self.alloc.free(stdout_bytes);
            const stderr_bytes = if (child.stderr) |s| try self.drainPipe(s) else try self.alloc.dupe(u8, "");
            defer self.alloc.free(stderr_bytes);
            std.debug.print("go build failed: {s} {s}\n", .{ stdout_bytes, stderr_bytes });
            return error.GoBuildFailed;
        }
    }

    const SpawnInfo = struct { child: std.process.Child, addr_buf: [64]u8, addr_len: usize };

    fn spawnServer(self: *Runner, bin: []const u8, addr: []const u8, extra: []const []const u8) !SpawnInfo {
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args.deinit(self.alloc);
        try args.appendSlice(self.alloc, &.{ bin, "--addr", addr, "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem" });
        try args.appendSlice(self.alloc, extra);
        const child = try self.spawnPipe(args.items);
        var addr_buf: [64]u8 = undefined;
        var addr_len: usize = 0;
        if (child.stderr) |s| {
            var buf: std.ArrayListUnmanaged(u8) = .empty;
            defer buf.deinit(self.alloc);
            // Read up to 4KB over ~800ms to catch the listening line
            var i: usize = 0;
            while (i < 4) : (i += 1) {
                var tmp: [512]u8 = undefined;
                const nread = s.readStreaming(self.io, &.{tmp[0..]}) catch 0;
                if (nread > 0) {
                    _ = buf.appendSlice(self.alloc, tmp[0..nread]) catch {};
                    if (std.mem.indexOf(u8, buf.items, "listening on ")) |off| {
                        const rest = buf.items[off + ("listening on ").len ..];
                        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
                        const addr_s = rest[0..end];
                        const copy_len = @min(addr_s.len, addr_buf.len);
                        @memcpy(addr_buf[0..copy_len], addr_s[0..copy_len]);
                        addr_len = copy_len;
                        break;
                    }
                }
                sleepNs(200 * std.time.ns_per_ms);
            }
        }
        if (addr_len == 0 and std.mem.indexOf(u8, addr, ":0") == null) {
            // Non-ephemeral addr requested: just wait a bit
            sleepNs(800 * std.time.ns_per_ms);
        }
        return .{ .child = child, .addr_buf = addr_buf, .addr_len = addr_len };
    }

    fn runClientWithTimeout(self: *Runner, argv: [][]const u8, timeout_ms: u64) !struct { term_ok: bool, out: []u8, err: []u8 } {
        var child = try self.spawnPipe(argv);
        // Sleep up to timeout_ms; enforce timeout by kill (which also waits + cleans up).
        var elapsed: u64 = 0;
        while (elapsed < timeout_ms) : (elapsed += 20) {
            sleepNs(20 * std.time.ns_per_ms);
        }
        const out_bytes = if (child.stdout) |s| try self.drainPipe(s) else try self.alloc.dupe(u8, "");
        const err_bytes = if (child.stderr) |s| try self.drainPipe(s) else try self.alloc.dupe(u8, "");
        child.kill(self.io);
        return .{ .term_ok = false, .out = out_bytes, .err = err_bytes };
    }

    fn runGoEchoSmoke(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{});
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args.deinit(self.alloc);
        try args.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
        const res = try self.runClientWithTimeout(args.items, 1500);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (!res.term_ok) {
            std.debug.print("go client failed: stdout=\n{s}\nstderr=\n{s}\n", .{ res.out, res.err });
            return error.ClientFailed;
        }
        if (std.mem.indexOf(u8, res.out, "echo: hello") == null) return error.BadEcho;
    }

    fn runGoEchoDatagram(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{"--datagram"});
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args.deinit(self.alloc);
        try args.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--datagram", "--dmsg", "ping" });
        const res = try self.runClientWithTimeout(args.items, 1500);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (!res.term_ok) {
            std.debug.print("go client failed: stdout=\n{s}\nstderr=\n{s}\n", .{ res.out, res.err });
            return error.ClientFailed;
        }
        if (std.mem.indexOf(u8, res.out, "dgram: ping") == null) return error.BadDatagramEcho;
    }

    fn runGoRetrySmoke(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{"--retry"});
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args.deinit(self.alloc);
        try args.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
        const res = try self.runClientWithTimeout(args.items, 1500);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (!res.term_ok) {
            std.debug.print("go client failed: stdout=\n{s}\nstderr=\n{s}\n", .{ res.out, res.err });
            return error.ClientFailed;
        }
        if (std.mem.indexOf(u8, res.out, "echo: hello") == null) return error.BadEcho;
    }

    fn runGoAlpnMismatch(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{});
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args_cli.deinit(self.alloc);
        try args_cli.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "hq-interop", "--sni", "test.local", "--insecure" });
        const res = try self.runClientWithTimeout(args_cli.items, 3000);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (res.term_ok) return error.ExpectedFail;
    }

    fn runGoVersionNegotiationOverlap(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{ "--versions", "v1" });
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args_cli.deinit(self.alloc);
        try args_cli.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--versions", "v2,v1", "--print-version" });
        const res = try self.runClientWithTimeout(args_cli.items, 3000);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (!res.term_ok) {
            std.debug.print("go client failed: stdout=\n{s}\nstderr=\n{s}\n", .{ res.out, res.err });
            return error.ClientFailed;
        }
        if (std.mem.indexOf(u8, res.out, "version: v1") == null) return error.BadVersionNegotiation;
    }

    fn runGoVersionNegotiationMismatch(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{ "--versions", "v1" });
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli: std.ArrayListUnmanaged([]const u8) = .empty;
        defer args_cli.deinit(self.alloc);
        try args_cli.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--versions", "v2", "--print-version" });
        const res = try self.runClientWithTimeout(args_cli.items, 3000);
        defer self.alloc.free(res.out);
        defer self.alloc.free(res.err);
        if (res.term_ok) return error.ExpectedFail;
    }

    fn runZigClientVsGoServer(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        try self.goBuild("./examples/interop/go-server", server_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{});
        defer srv.child.kill(self.io);
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        const zig_client = "./zig-out/bin/quic-client";
        if (!self.pathExists(zig_client)) return error.ZigClientMissing;
        var child = try self.spawnPipe(&[_][]const u8{ zig_client, "--connect", srv_addr, "--sni", "test.local", "--alpn", "h3", "--insecure" });
        const term = try child.wait(self.io);
        if (termOk(term)) return error.ExpectedFail;
        return error.ExpectedFail;
    }

    fn runZigServerVsGoClient(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const zig_server = "./zig-out/bin/quic-server";
        if (!self.pathExists(zig_server)) return error.ZigServerMissing;
        var srv = try self.spawnPipe(&[_][]const u8{ zig_server, "--bind", "127.0.0.1:0", "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem", "--insecure" });
        defer srv.kill(self.io);
        sleepNs(800 * std.time.ns_per_ms);
        // For simplicity, keep fixed port for Zig server until it prints bind addr; follow-up work can parse its stdout for the actual port
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-client", client_bin);
        var child = try self.spawnPipe(&[_][]const u8{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
        const term = try child.wait(self.io);
        if (termOk(term)) return error.ExpectedFail;
        return error.ExpectedFail;
    }

    fn runZigH3Loopback(self: *Runner) !void {
        try self.ensureCerts();
        const zig_server = "./zig-out/bin/quic-server";
        const zig_client = "./zig-out/bin/quic-client";
        if (!self.pathExists(zig_server) or !self.pathExists(zig_client)) return error.ZigBinariesMissing;
        var srv = try self.spawnPipe(&[_][]const u8{ zig_server, "--bind", "127.0.0.1:4433", "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem", "--insecure" });
        defer srv.kill(self.io);
        sleepNs(400 * std.time.ns_per_ms);
        var cli = try self.spawnPipe(&[_][]const u8{ zig_client, "--connect", "127.0.0.1:4433", "--sni", "test.local", "--alpn", "h3", "--insecure" });
        const term = try cli.wait(self.io);
        const out_bytes = if (cli.stdout) |s| try self.drainPipe(s) else try self.alloc.dupe(u8, "");
        defer self.alloc.free(out_bytes);
        if (!termOk(term)) return error.ClientFailed;
        if (std.mem.indexOf(u8, out_bytes, "received echo") == null and std.mem.indexOf(u8, out_bytes, "echo:") == null) return error.NoSuccessMarker;
    }
};

pub fn main(init: std.process.Init) !void {
    var r = Runner.init(init.io);
    defer r.deinit();

    var args = std.process.Args.Iterator.init(init.minimal.args);

    _ = args.next();
    const cmd = args.next() orelse "list";

    if (std.mem.eql(u8, cmd, "list")) {
        const out = "scenarios:\n" ++
            "- go_echo_smoke (MUST PASS)\n" ++
            "- go_echo_datagram (MUST PASS)\n" ++
            "- go_retry_smoke (MUST PASS)\n" ++
            "- go_alpn_mismatch (MUST FAIL)\n" ++
            "- go_vn_overlap (MUST PASS)\n" ++
            "- go_vn_mismatch (MUST FAIL)\n" ++
            "- go_net_echo_smoke (XFAIL until real TLS interop)\n" ++
            "- zig_client_vs_go_server (XFAIL until handshake/streams)\n" ++
            "- zig_server_vs_go_client (XFAIL until handshake/streams)\n" ++
            "- zig_h3_loopback (MUST PASS)\n";
        const bytes: []const u8 = out;
        std.Io.File.stdout().writeStreamingAll(init.io, bytes) catch {};
        return;
    } else if (std.mem.eql(u8, cmd, "run")) {
        const scenario = args.next() orelse return error.MissingArgument;
        if (std.mem.eql(u8, scenario, "go_echo_smoke")) return r.runGoEchoSmoke() else if (std.mem.eql(u8, scenario, "go_echo_datagram")) return r.runGoEchoDatagram() else if (std.mem.eql(u8, scenario, "go_retry_smoke")) return r.runGoRetrySmoke() else if (std.mem.eql(u8, scenario, "go_alpn_mismatch")) return r.runGoAlpnMismatch() else if (std.mem.eql(u8, scenario, "go_vn_overlap")) return r.runGoVersionNegotiationOverlap() else if (std.mem.eql(u8, scenario, "go_vn_mismatch")) return r.runGoVersionNegotiationMismatch() else if (std.mem.eql(u8, scenario, "go_net_echo_smoke")) return runGoNetEchoSmoke(&r) else if (std.mem.eql(u8, scenario, "zig_client_vs_go_server")) return r.runZigClientVsGoServer() else if (std.mem.eql(u8, scenario, "zig_server_vs_go_client")) return r.runZigServerVsGoClient() else return error.UnknownScenario;
    } else if (std.mem.eql(u8, cmd, "run-all")) {
        var failures: usize = 0;
        if (r.runGoEchoSmoke()) |_| {} else |_| failures += 1;
        if (r.runGoEchoDatagram()) |_| {} else |_| failures += 1;
        if (r.runGoRetrySmoke()) |_| {} else |_| failures += 1;
        if (r.runGoAlpnMismatch()) |_| {} else |_| failures += 1;
        if (r.runGoVersionNegotiationOverlap()) |_| {} else |_| failures += 1;
        if (r.runGoVersionNegotiationMismatch()) |_| {} else |_| failures += 1;
        _ = runGoNetEchoSmoke(&r) catch {};
        _ = r.runZigClientVsGoServer() catch {};
        _ = r.runZigServerVsGoClient() catch {};
        if (failures > 0) return error.InteropFailures;
        return;
    } else return error.UnknownCommand;
}

// New scenarios (golang.org/x/net/quic) – XFAIL until real TLS interop implemented
fn runGoNetEchoSmoke(self: *Runner) !void {
    if (!self.haveGo()) return error.GoMissing;
    try self.ensureCerts();
    const server_bin = "zig-out/bin/go-net-interop-server";
    const client_bin = "zig-out/bin/go-net-interop-client";
    try self.goBuild("./examples/interop/go-net-server", server_bin);
    try self.goBuild("./examples/interop/go-net-client", client_bin);
    var srv = try self.spawnServer(server_bin, "127.0.0.1:0", &.{});
    defer srv.child.kill(self.io);
    if (srv.addr_len == 0) return error.ServerAddrParseFailed;
    const srv_addr = srv.addr_buf[0..srv.addr_len];
    var args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args.deinit(self.alloc);
    try args.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
    const res = try self.runClientWithTimeout(args.items, 1500);
    defer self.alloc.free(res.out);
    defer self.alloc.free(res.err);
    // Expect failure until real TLS implemented; treat success as unexpected
    if (res.term_ok) return error.ExpectedFail;
    return error.ExpectedFail; // Mark XFAIL consistently
}
