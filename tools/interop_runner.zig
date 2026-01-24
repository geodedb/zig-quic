const std = @import("std");

const Runner = struct {
    alloc: std.mem.Allocator = std.heap.page_allocator,

    pub fn init() Runner {
        return Runner{ .alloc = std.heap.page_allocator };
    }
    pub fn deinit(self: *Runner) void {
        _ = self;
    }

    fn haveGo(self: *Runner) bool {
        var child = std.process.Child.init(&[_][]const u8{ "go", "version" }, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = child.spawnAndWait() catch return false;
        return switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
    }

    fn pathExists(_: *Runner, p: []const u8) bool {
        const st = std.fs.cwd().statFile(p) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => return false,
        };
        _ = st;
        return true;
    }

    fn ensureCerts(self: *Runner) !void {
        if (self.pathExists("examples/interop/certs/cert.pem") and self.pathExists("examples/interop/certs/key.pem")) return;
        if (!self.pathExists("examples/interop/certs/generate.sh")) return error.CertMissing;
        var child = std.process.Child.init(&[_][]const u8{ "bash", "examples/interop/certs/generate.sh" }, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.CertGenFailed;
        if (!(self.pathExists("examples/interop/certs/cert.pem") and self.pathExists("examples/interop/certs/key.pem"))) return error.CertMissing;
    }

    fn goBuild(self: *Runner, pkg_dir: []const u8, out_path: []const u8) !void {
        if (self.pathExists(out_path)) return;
        var args_buf = std.ArrayListUnmanaged([]const u8){};
        defer args_buf.deinit(self.alloc);
        try args_buf.appendSlice(self.alloc, &.{ "go", "build", "-o", out_path, pkg_dir });
        var child = std.process.Child.init(args_buf.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();
        const term = try child.wait();
        if (!(term == .Exited and term.Exited == 0)) {
            var stdout_buf: [1024]u8 = undefined;
            const stdout_bytes = if (child.stdout) |s| blk: {
                var a = std.ArrayListUnmanaged(u8){};
                defer a.deinit(self.alloc);
                while (true) {
                    const n = s.read(stdout_buf[0..]) catch 0;
                    if (n == 0) break;
                    _ = a.appendSlice(self.alloc, stdout_buf[0..n]) catch {};
                }
                break :blk a.toOwnedSlice(self.alloc) catch try self.alloc.dupe(u8, "");
            } else (try self.alloc.dupe(u8, ""));
            defer self.alloc.free(stdout_bytes);
            var stderr_buf: [1024]u8 = undefined;
            const stderr_bytes = if (child.stderr) |s| blk: {
                var a2 = std.ArrayListUnmanaged(u8){};
                defer a2.deinit(self.alloc);
                while (true) {
                    const n2 = s.read(stderr_buf[0..]) catch 0;
                    if (n2 == 0) break;
                    _ = a2.appendSlice(self.alloc, stderr_buf[0..n2]) catch {};
                }
                break :blk a2.toOwnedSlice(self.alloc) catch try self.alloc.dupe(u8, "");
            } else (try self.alloc.dupe(u8, ""));
            defer self.alloc.free(stderr_bytes);
            std.debug.print("go build failed: {s} {s}\n", .{ stdout_bytes, stderr_bytes });
            return error.GoBuildFailed;
        }
    }

    const SpawnInfo = struct { child: std.process.Child, addr_buf: [64]u8, addr_len: usize };

    fn spawnServer(self: *Runner, bin: []const u8, addr: []const u8, extra: []const []const u8) !SpawnInfo {
        var args = std.ArrayListUnmanaged([]const u8){};
        defer args.deinit(self.alloc);
        try args.appendSlice(self.alloc, &.{ bin, "--addr", addr, "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem" });
        try args.appendSlice(self.alloc, extra);
        var child = std.process.Child.init(args.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();
        var addr_buf: [64]u8 = undefined;
        var addr_len: usize = 0;
        if (child.stderr) |s| {
            var buf = std.ArrayListUnmanaged(u8){};
            defer buf.deinit(self.alloc);
            // Read up to 4KB over ~800ms to catch the listening line
            var i: usize = 0;
            while (i < 4) : (i += 1) {
                var tmp: [512]u8 = undefined;
                const nread = s.read(tmp[0..]) catch 0;
                const chunk = if (nread == 0) null else (try self.alloc.dupe(u8, tmp[0..nread]));
                if (chunk) |bytes| {
                    defer self.alloc.free(bytes);
                    _ = buf.appendSlice(self.alloc, bytes) catch {};
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
                std.Thread.sleep(200 * std.time.ns_per_ms);
            }
        }
        if (addr_len == 0 and std.mem.indexOf(u8, addr, ":0") == null) {
            // Non-ephemeral addr requested: just wait a bit
            std.Thread.sleep(800 * std.time.ns_per_ms);
        }
        return .{ .child = child, .addr_buf = addr_buf, .addr_len = addr_len };
    }

    fn runClientWithTimeout(self: *Runner, argv: [][]const u8, timeout_ms: u64) !struct { term_ok: bool, out: []u8, err: []u8 } {
        var child = std.process.Child.init(argv, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();
        // Sleep up to timeout_ms; without tryWait in Zig 0.14, enforce timeout by kill+wait
        var elapsed: u64 = 0;
        while (elapsed < timeout_ms) : (elapsed += 20) {
            std.Thread.sleep(20 * std.time.ns_per_ms);
            // We cannot non-blockingly detect termination here on 0.14; rely on timeout or short sleeps
        }
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        var outb: [1024]u8 = undefined;
        const out_bytes = if (child.stdout) |s| blk: {
            var arr = std.ArrayListUnmanaged(u8){};
            defer arr.deinit(self.alloc);
            while (true) {
                const n = s.read(outb[0..]) catch 0;
                if (n == 0) break;
                _ = arr.appendSlice(self.alloc, outb[0..n]) catch {};
            }
            break :blk arr.toOwnedSlice(self.alloc) catch try self.alloc.dupe(u8, "");
        } else (try self.alloc.dupe(u8, ""));
        var errb: [1024]u8 = undefined;
        const err_bytes = if (child.stderr) |s| blk2: {
            var arr2 = std.ArrayListUnmanaged(u8){};
            defer arr2.deinit(self.alloc);
            while (true) {
                const n2 = s.read(errb[0..]) catch 0;
                if (n2 == 0) break;
                _ = arr2.appendSlice(self.alloc, errb[0..n2]) catch {};
            }
            break :blk2 arr2.toOwnedSlice(self.alloc) catch try self.alloc.dupe(u8, "");
        } else (try self.alloc.dupe(u8, ""));
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        std.debug.print("server_addr={s}\n", .{srv_addr});
        var args = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        var args_cli = std.ArrayListUnmanaged([]const u8){};
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
        defer {
            _ = srv.child.kill() catch {};
            _ = srv.child.wait() catch {};
        }
        if (srv.addr_len == 0) return error.ServerAddrParseFailed;
        const srv_addr = srv.addr_buf[0..srv.addr_len];
        const zig_client = "./zig-out/bin/quic-client";
        if (!self.pathExists(zig_client)) return error.ZigClientMissing;
        var child = std.process.Child.init(&[_][]const u8{ zig_client, "--connect", srv_addr, "--sni", "test.local", "--alpn", "h3", "--insecure" }, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (term == .Exited and term.Exited == 0) return error.ExpectedFail;
        return error.ExpectedFail;
    }

    fn runZigServerVsGoClient(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const zig_server = "./zig-out/bin/quic-server";
        if (!self.pathExists(zig_server)) return error.ZigServerMissing;
        var srv = std.process.Child.init(&[_][]const u8{ zig_server, "--bind", "127.0.0.1:0", "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem", "--insecure" }, self.alloc);
        srv.stdin_behavior = .Ignore;
        srv.stdout_behavior = .Pipe;
        srv.stderr_behavior = .Pipe;
        try srv.spawn();
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.Thread.sleep(800 * std.time.ns_per_ms);
        // For simplicity, keep fixed port for Zig server until it prints bind addr; follow-up work can parse its stdout for the actual port
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-client", client_bin);
        var child = std.process.Child.init(&[_][]const u8{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" }, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (term == .Exited and term.Exited == 0) return error.ExpectedFail;
        return error.ExpectedFail;
    }

    fn runZigH3Loopback(self: *Runner) !void {
        try self.ensureCerts();
        const zig_server = "./zig-out/bin/quic-server";
        const zig_client = "./zig-out/bin/quic-client";
        if (!self.pathExists(zig_server) or !self.pathExists(zig_client)) return error.ZigBinariesMissing;
        var srv = std.process.Child.init(&[_][]const u8{ zig_server, "--bind", "127.0.0.1:4433", "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem", "--insecure" }, self.alloc);
        srv.stdin_behavior = .Ignore;
        srv.stdout_behavior = .Pipe;
        srv.stderr_behavior = .Pipe;
        try srv.spawn();
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.Thread.sleep(400 * std.time.ns_per_ms);
        var cli = std.process.Child.init(&[_][]const u8{ zig_client, "--connect", "127.0.0.1:4433", "--sni", "test.local", "--alpn", "h3", "--insecure" }, self.alloc);
        cli.stdin_behavior = .Ignore;
        cli.stdout_behavior = .Pipe;
        cli.stderr_behavior = .Pipe;
        const term = try cli.spawnAndWait();
        var outb: [2048]u8 = undefined;
        const out_bytes = if (cli.stdout) |s| blk: {
            var arr = std.ArrayListUnmanaged(u8){};
            defer arr.deinit(self.alloc);
            while (true) {
                const n = s.read(outb[0..]) catch 0;
                if (n == 0) break;
                _ = arr.appendSlice(self.alloc, outb[0..n]) catch {};
            }
            break :blk arr.toOwnedSlice(self.alloc) catch try self.alloc.dupe(u8, "");
        } else (try self.alloc.dupe(u8, ""));
        defer self.alloc.free(out_bytes);
        const ok = (term == .Exited and term.Exited == 0);
        if (!ok) return error.ClientFailed;
        if (std.mem.indexOf(u8, out_bytes, "received echo") == null and std.mem.indexOf(u8, out_bytes, "echo:") == null) return error.NoSuccessMarker;
    }
};

pub fn main() !void {
    var r = Runner.init();
    defer r.deinit();

    var args = try std.process.argsWithAllocator(r.alloc);
    defer args.deinit();

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
        if (@import("builtin").target.os.tag == .windows) {
            const w = std.os.windows;
            const h = w.GetStdHandle(w.STD_OUTPUT_HANDLE) catch return;
            _ = std.posix.write(h, bytes) catch {};
        } else {
            _ = std.posix.write(std.posix.STDOUT_FILENO, bytes) catch {};
        }
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
    defer {
        _ = srv.child.kill() catch {};
        _ = srv.child.wait() catch {};
    }
    if (srv.addr_len == 0) return error.ServerAddrParseFailed;
    const srv_addr = srv.addr_buf[0..srv.addr_len];
    var args = std.ArrayListUnmanaged([]const u8){};
    defer args.deinit(self.alloc);
    try args.appendSlice(self.alloc, &.{ client_bin, "--addr", srv_addr, "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
    const res = try self.runClientWithTimeout(args.items, 1500);
    defer self.alloc.free(res.out);
    defer self.alloc.free(res.err);
    // Expect failure until real TLS implemented; treat success as unexpected
    if (res.term_ok) return error.ExpectedFail;
    return error.ExpectedFail; // Mark XFAIL consistently
}
