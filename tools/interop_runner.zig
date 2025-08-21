const std = @import("std");

const Runner = struct {
    // Use a stable global allocator to avoid GPA lifetime issues in child spawning paths
    alloc: std.mem.Allocator = std.heap.page_allocator,

    pub fn init() Runner {
        return Runner{ .alloc = std.heap.page_allocator };
    }
    pub fn deinit(self: *Runner) void {
        _ = self; // no-op
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
        var args_buf = std.ArrayList([]const u8).init(self.alloc);
        defer args_buf.deinit();
        try args_buf.appendSlice(&.{ "go", "build", "-o", out_path, pkg_dir });
        var child = std.process.Child.init(args_buf.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.GoBuildFailed;
    }

    fn spawnServer(self: *Runner, bin: []const u8, addr: []const u8, extra: []const []const u8) !std.process.Child {
        var args = std.ArrayList([]const u8).init(self.alloc);
        defer args.deinit();
        try args.appendSlice(&.{ bin, "--addr", addr, "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem" });
        try args.appendSlice(extra);
        var child = std.process.Child.init(args.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();
        std.time.sleep(200 * std.time.ns_per_ms);
        return child;
    }

    fn runGoEchoSmoke(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{});
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        var args = std.ArrayList([]const u8).init(self.alloc);
        defer args.deinit();
        try args.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
        var child = std.process.Child.init(args.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.ClientFailed;
        const out_bytes = try child.stdout.?.reader().readAllAlloc(self.alloc, 64 * 1024);
        defer self.alloc.free(out_bytes);
        if (std.mem.indexOf(u8, out_bytes, "echo: hello") == null) return error.BadEcho;
    }

    fn runGoEchoDatagram(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{"--datagram"});
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(200 * std.time.ns_per_ms);
        var args_cli = std.ArrayList([]const u8).init(self.alloc);
        defer args_cli.deinit();
        try args_cli.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--datagram", "--dmsg", "ping" });
        var child = std.process.Child.init(args_cli.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.ClientFailed;
        const out_bytes = try child.stdout.?.reader().readAllAlloc(self.alloc, 64 * 1024);
        defer self.alloc.free(out_bytes);
        if (std.mem.indexOf(u8, out_bytes, "dgram: ping") == null) return error.BadDatagramEcho;
    }

    fn runGoRetrySmoke(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{"--retry"});
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(200 * std.time.ns_per_ms);
        var args_cli = std.ArrayList([]const u8).init(self.alloc);
        defer args_cli.deinit();
        try args_cli.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--msg", "hello" });
        var child = std.process.Child.init(args_cli.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.ClientFailed;
        const out_bytes = try child.stdout.?.reader().readAllAlloc(self.alloc, 64 * 1024);
        defer self.alloc.free(out_bytes);
        if (std.mem.indexOf(u8, out_bytes, "echo: hello") == null) return error.BadEcho;
    }

    fn runGoAlpnMismatch(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{});
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(150 * std.time.ns_per_ms);
        var args_cli = std.ArrayList([]const u8).init(self.alloc);
        defer args_cli.deinit();
        try args_cli.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "hq-interop", "--sni", "test.local", "--insecure" });
        var child = std.process.Child.init(args_cli.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        // Expect failure
        if (term == .Exited and term.Exited == 0) return error.ExpectedFail;
    }

    fn runGoVersionNegotiationOverlap(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{ "--versions", "v1" });
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(150 * std.time.ns_per_ms);
        var args_cli = std.ArrayList([]const u8).init(self.alloc);
        defer args_cli.deinit();
        try args_cli.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--versions", "v2,v1", "--print-version" });
        var child = std.process.Child.init(args_cli.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (!(term == .Exited and term.Exited == 0)) return error.ClientFailed;
        const out_bytes = try child.stdout.?.reader().readAllAlloc(self.alloc, 64 * 1024);
        defer self.alloc.free(out_bytes);
        if (std.mem.indexOf(u8, out_bytes, "version: v1") == null) return error.BadVersionNegotiation;
    }

    fn runGoVersionNegotiationMismatch(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        const client_bin = "zig-out/bin/go-interop-client";
        try self.goBuild("./examples/interop/go-server", server_bin);
        try self.goBuild("./examples/interop/go-client", client_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{ "--versions", "v1" });
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(150 * std.time.ns_per_ms);
        var args_cli = std.ArrayList([]const u8).init(self.alloc);
        defer args_cli.deinit();
        try args_cli.appendSlice(&.{ client_bin, "--addr", "127.0.0.1:4433", "--alpn", "h3", "--sni", "test.local", "--insecure", "--versions", "v2", "--print-version" });
        var child = std.process.Child.init(args_cli.items, self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        const term = try child.spawnAndWait();
        if (term == .Exited and term.Exited == 0) return error.ExpectedFail;
    }

    fn runZigClientVsGoServer(self: *Runner) !void {
        if (!self.haveGo()) return error.GoMissing;
        try self.ensureCerts();
        const server_bin = "zig-out/bin/go-interop-server";
        try self.goBuild("./examples/interop/go-server", server_bin);
        var srv = try self.spawnServer(server_bin, "127.0.0.1:4433", &.{});
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        const zig_client = "./zig-out/bin/quic-client";
        if (!self.pathExists(zig_client)) return error.ZigClientMissing;
        var child = std.process.Child.init(&[_][]const u8{ zig_client, "--connect", "127.0.0.1:4433", "--sni", "test.local", "--alpn", "h3", "--insecure" }, self.alloc);
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
        var srv = std.process.Child.init(&[_][]const u8{ zig_server, "--bind", "127.0.0.1:4433", "--alpn", "h3", "--cert", "examples/interop/certs/cert.pem", "--key", "examples/interop/certs/key.pem", "--insecure" }, self.alloc);
        srv.stdin_behavior = .Ignore;
        srv.stdout_behavior = .Pipe;
        srv.stderr_behavior = .Pipe;
        try srv.spawn();
        defer {
            _ = srv.kill() catch {};
            _ = srv.wait() catch {};
        }
        std.time.sleep(200 * std.time.ns_per_ms);
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
};

pub fn main() !void {
    var r = Runner.init();
    defer r.deinit();

    var args = try std.process.argsWithAllocator(r.alloc);
    defer args.deinit();

    _ = args.next(); // program name
    const cmd = args.next() orelse "list";

    if (std.mem.eql(u8, cmd, "list")) {
        const out = "scenarios:\n" ++
            "- go_echo_smoke (MUST PASS)\n" ++
            "- go_echo_datagram (MUST PASS)\n" ++
            "- go_retry_smoke (MUST PASS)\n" ++
            "- go_alpn_mismatch (MUST FAIL)\n" ++
            "- go_vn_overlap (MUST PASS)\n" ++
            "- go_vn_mismatch (MUST FAIL)\n" ++
            "- zig_client_vs_go_server (XFAIL until handshake/streams)\n" ++
            "- zig_server_vs_go_client (XFAIL until handshake/streams)\n";
        try std.io.getStdOut().writer().print("{s}", .{out});
        return;
    } else if (std.mem.eql(u8, cmd, "run")) {
        const scenario = args.next() orelse return error.MissingArgument;
        if (std.mem.eql(u8, scenario, "go_echo_smoke")) {
            try r.runGoEchoSmoke();
            return;
        } else if (std.mem.eql(u8, scenario, "go_echo_datagram")) {
            try r.runGoEchoDatagram();
            return;
        } else if (std.mem.eql(u8, scenario, "go_retry_smoke")) {
            try r.runGoRetrySmoke();
            return;
        } else if (std.mem.eql(u8, scenario, "go_alpn_mismatch")) {
            try r.runGoAlpnMismatch();
            return;
        } else if (std.mem.eql(u8, scenario, "go_vn_overlap")) {
            try r.runGoVersionNegotiationOverlap();
            return;
        } else if (std.mem.eql(u8, scenario, "go_vn_mismatch")) {
            try r.runGoVersionNegotiationMismatch();
            return;
        } else if (std.mem.eql(u8, scenario, "zig_client_vs_go_server")) {
            return r.runZigClientVsGoServer();
        } else if (std.mem.eql(u8, scenario, "zig_server_vs_go_client")) {
            return r.runZigServerVsGoClient();
        } else {
            return error.UnknownScenario;
        }
    } else if (std.mem.eql(u8, cmd, "run-all")) {
        var failures: usize = 0;
        if (r.runGoEchoSmoke()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        if (r.runGoEchoDatagram()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        if (r.runGoRetrySmoke()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        if (r.runGoAlpnMismatch()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        if (r.runGoVersionNegotiationOverlap()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        if (r.runGoVersionNegotiationMismatch()) |_| {} else |err| if (err != error.GoMissing) failures += 1;
        _ = r.runZigClientVsGoServer() catch {};
        _ = r.runZigServerVsGoClient() catch {};
        if (failures > 0) return error.InteropFailures;
        return;
    } else {
        return error.UnknownCommand;
    }
}
