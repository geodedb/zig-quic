const std = @import("std");

fn rp(s: []const u8) std.Build.LazyPath {
    if (@hasField(std.Build.LazyPath, "path")) {
        return .{ .path = s };
    } else {
        return .{ .cwd_relative = s };
    }
}

fn mkModule(b: *std.Build, path: []const u8) *std.Build.Module {
    if (@hasDecl(std.Build, "createModule")) {
        return b.createModule(.{ .root_source_file = rp(path) });
    } else {
        return b.createModule(.{ .root_source_file = rp(path) });
    }
}

fn addExe(b: *std.Build, name: []const u8, path: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    var exe = b.addExecutable(.{ .name = name, .root_module = b.createModule(.{ .root_source_file = rp(path), .target = target, .optimize = optimize }) });

    // Link OpenSSL for crypto operations (required for QUIC AEAD compatibility)
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");
    exe.linkLibC();

    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("ws2_32");
    }
    return exe;
}

fn addTst(b: *std.Build, path: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    var tst = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = rp(path), .target = target, .optimize = optimize }) });

    // Link OpenSSL for crypto operations (required for QUIC AEAD compatibility)
    tst.linkSystemLibrary("ssl");
    tst.linkSystemLibrary("crypto");
    tst.linkLibC();

    if (target.result.os.tag == .windows) {
        tst.linkSystemLibrary("ws2_32");
    }
    return tst;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize_base = b.standardOptimizeOption(.{});
    const release_safe = b.option(bool, "release-safe", "Build with ReleaseSafe optimization (convenience flag)") orelse false;
    const optimize: std.builtin.OptimizeMode = if (release_safe) .ReleaseSafe else optimize_base;
    _ = b.option(bool, "xdp", "Enable XDP path (no-op placeholder)") orelse false;

    // Parse optional user args to support `zig build test --test-filter <substr>`.
    const raw_args = b.args orelse &[_][]const u8{};
    var user_filter: ?[]const u8 = null;
    var i: usize = 0;
    while (i < raw_args.len) : (i += 1) {
        if (std.mem.eql(u8, raw_args[i], "--test-filter")) {
            if (i + 1 < raw_args.len) user_filter = raw_args[i + 1];
            break;
        }
    }

    // CLI tool: quic-varint
    // TODO: Update to new build API when migrating past current Zig version; for now use root_source_file field.
    const varint_exe = addExe(b, "quic-varint", "tools/varint_tool.zig", target, optimize);
    const install_varint = b.addInstallArtifact(varint_exe, .{});

    // tools: update-gap, doccheck
    const update_gap = addExe(b, "update-gap", "tools/update_gap.zig", target, optimize);
    const install_update_gap = b.addInstallArtifact(update_gap, .{});

    const doccheck = addExe(b, "doccheck", "tools/doccheck.zig", target, optimize);
    const install_doccheck = b.addInstallArtifact(doccheck, .{});

    const tools_step = b.step("tools", "Build CLI tools");
    tools_step.dependOn(&install_varint.step);
    tools_step.dependOn(&install_update_gap.step);
    tools_step.dependOn(&install_doccheck.step);

    // Add interop runner tool
    const interop_runner = addExe(b, "interop-runner", "tools/interop_runner.zig", target, optimize);
    const install_interop = b.addInstallArtifact(interop_runner, .{});
    tools_step.dependOn(&install_interop.step);

    const interop_list = b.step("interop-list", "List interop scenarios");
    interop_list.dependOn(&install_interop.step);
    const interop_run = b.step("interop-run", "Run interop scenario via -Dscenario=...");
    interop_run.dependOn(&install_interop.step);
    const scenario = b.option([]const u8, "scenario", "Interop scenario to run");
    if (scenario) |sc| {
        const run = b.addRunArtifact(interop_runner);
        run.addArg("run");
        run.addArg(sc);
        interop_run.dependOn(&run.step);
    } else {
        const run = b.addRunArtifact(interop_runner);
        run.addArg("list");
        interop_list.dependOn(&run.step);
    }

    const step_doccheck = b.step("doccheck", "Run documentation checker");
    step_doccheck.dependOn(&install_doccheck.step);

    const step_update_gap = b.step("update-gap", "Install update-gap tool");
    step_update_gap.dependOn(&install_update_gap.step);
    const gap_summary = b.option([]const u8, "gap-summary", "Summary string to append to GAP.md");
    if (gap_summary) |summary| {
        const run_update = b.addRunArtifact(update_gap);
        run_update.addArg("--summary");
        run_update.addArg(summary);
        step_update_gap.dependOn(&run_update.step);
    }

    // Tests
    const test_step = b.step("test", "Run unit tests");
    const filter_opt = b.option([]const u8, "test-filter", "Filter tests by substring");
    const filter = user_filter orelse (filter_opt orelse null);
    const legacy_tests = b.option(bool, "legacy-tests", "Run legacy tests in quic.zig") orelse false;
    const cc_opt = b.option([]const u8, "cc", "Congestion control: newreno (default) or cubic");

    // Expose TLS/crypto/packet modules
    const byteorder_mod = mkModule(b, "src/byteorder/byteorder.zig");

    // ========================================================================
    // Vendored TLS Library (vendor/ztls)
    // ========================================================================
    // Import TLS modules from the vendored ztls library instead of local implementation
    const ztls_byteorder_mod = mkModule(b, "vendor/ztls/src/byteorder.zig");
    const ztls_varint_mod = mkModule(b, "vendor/ztls/src/varint.zig");
    ztls_varint_mod.addImport("byteorder", ztls_byteorder_mod);

    const ztls_transport_params_mod = mkModule(b, "vendor/ztls/src/quic_transport_params.zig");
    ztls_transport_params_mod.addImport("varint", ztls_varint_mod);

    const quic_tls_mod = mkModule(b, "vendor/ztls/src/key_schedule.zig");
    const tls_record_mod = mkModule(b, "vendor/ztls/src/record.zig");
    tls_record_mod.addImport("quic_tls", quic_tls_mod);

    const alert_mod = mkModule(b, "vendor/ztls/src/alert.zig");
    const asn1_mod = mkModule(b, "vendor/ztls/src/asn1.zig");
    const sig_mod = mkModule(b, "vendor/ztls/src/sig.zig");
    sig_mod.addImport("asn1", asn1_mod);

    const x509_mod = mkModule(b, "vendor/ztls/src/x509.zig");
    x509_mod.addImport("asn1", asn1_mod);
    x509_mod.addImport("sig", sig_mod);

    const zero_rtt_mod = mkModule(b, "vendor/ztls/src/zero_rtt.zig");
    zero_rtt_mod.addImport("quic_tls", quic_tls_mod);

    const ztls_logger_mod = mkModule(b, "vendor/ztls/src/quic_logger.zig");
    const tls13_full_mod = mkModule(b, "vendor/ztls/src/tls13_full.zig");
    const ocsp_mod = mkModule(b, "vendor/ztls/src/ocsp.zig");
    ocsp_mod.addImport("asn1", asn1_mod);
    ocsp_mod.addImport("x509", x509_mod);
    const sct_mod = mkModule(b, "vendor/ztls/src/sct.zig");

    const tls13_mod = mkModule(b, "vendor/ztls/src/tls13.zig");
    tls13_mod.addImport("quic_tls", quic_tls_mod);
    tls13_mod.addImport("x509", x509_mod);
    tls13_mod.addImport("sig", sig_mod);
    tls13_mod.addImport("alert", alert_mod);
    tls13_mod.addImport("zero_rtt", zero_rtt_mod);
    tls13_mod.addImport("tls13_full", tls13_full_mod);
    tls13_mod.addImport("quic_logger", ztls_logger_mod);
    tls13_mod.addImport("quic_transport_params", ztls_transport_params_mod);
    tls13_mod.addImport("ocsp", ocsp_mod);
    tls13_mod.addImport("sct", sct_mod);

    // QUIC crypto and packet modules
    const quic_crypto_mod = mkModule(b, "src/quic/crypto_quic.zig");
    const quic_packet_mod = mkModule(b, "src/quic/packet.zig");
    quic_packet_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_mod.addImport("quic_crypto", quic_crypto_mod);
    // Ensure crypto module can import the key schedule
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // Varint/frame
    const quic_varint_mod = mkModule(b, "src/quic/varint.zig");
    quic_varint_mod.addImport("byteorder", byteorder_mod);
    const quic_frame_mod = mkModule(b, "src/quic/frame.zig");
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_mod.addImport("quic_varint", quic_varint_mod);

    // Local QUIC transport params (separate from vendored TLS transport params)
    const quic_transport_params_mod = mkModule(b, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);

    // Note: tls13_mod uses ztls_transport_params_mod from vendor/ztls (defined above)

    // Recovery
    const quic_recovery_mod = mkModule(b, "src/quic/recovery.zig");
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);
    if (cc_opt) |_| {
        // Placeholder: runtime selection occurs via config; both controllers are in same module
    }

    // Logger module for QUIC library (local QUIC logger, not vendored TLS logger)
    const quic_logger_mod = mkModule(b, "src/quic/logger.zig");

    // Add logger to modules that need it
    quic_crypto_mod.addImport("quic_logger", quic_logger_mod);
    quic_packet_mod.addImport("quic_logger", quic_logger_mod);

    // Note: alert_mod, zero_rtt_mod, and tls logger are now imported from vendor/ztls above

    // Connection/TP
    const quic_conn_mod = mkModule(b, "src/quic/conn.zig");
    quic_conn_mod.addImport("quic_packet", quic_packet_mod);
    quic_conn_mod.addImport("quic_frame", quic_frame_mod);
    quic_conn_mod.addImport("quic_tls13", tls13_mod);
    quic_conn_mod.addImport("quic_varint", quic_varint_mod);
    quic_conn_mod.addImport("quic_tls", quic_tls_mod);
    quic_conn_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_conn_mod.addImport("quic_logger", quic_logger_mod);
    quic_conn_mod.addImport("byteorder", byteorder_mod);
    // Make transport params available to connection and endpoint modules
    quic_conn_mod.addImport("quic_transport_params", quic_transport_params_mod);

    // Endpoint module for socket/event-loop tests
    const loop_backend_mod = mkModule(b, "src/quic/loop_backend.zig");
    const quic_config_mod = mkModule(b, "src/quic/config.zig");
    const quic_endpoint_mod = mkModule(b, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("quic_conn", quic_conn_mod);
    quic_endpoint_mod.addImport("quic_packet", quic_packet_mod);
    quic_endpoint_mod.addImport("quic_frame", quic_frame_mod);
    quic_endpoint_mod.addImport("quic_tls13", tls13_mod);
    quic_endpoint_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_endpoint_mod.addImport("quic_varint", quic_varint_mod);
    quic_endpoint_mod.addImport("quic_tls", quic_tls_mod);
    quic_endpoint_mod.addImport("sig", sig_mod);
    quic_endpoint_mod.addImport("x509", x509_mod);
    quic_endpoint_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_endpoint_mod.addImport("config.zig", quic_config_mod);
    quic_endpoint_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_endpoint_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_endpoint_mod.addImport("quic_logger", quic_logger_mod);
    quic_endpoint_mod.addImport("byteorder", byteorder_mod);

    // Public API module (reuse everywhere)
    const quic_api_mod = mkModule(b, "src/quic/api.zig");
    quic_api_mod.addImport("config.zig", quic_config_mod);
    quic_api_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_api_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_api_mod.addImport("quic_frame", quic_frame_mod);
    quic_api_mod.addImport("quic_varint", quic_varint_mod);
    quic_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
    quic_api_mod.addImport("quic_tls", quic_tls_mod);
    quic_api_mod.addImport("quic_tls13", tls13_mod);
    quic_api_mod.addImport("quic_conn", quic_conn_mod);
    quic_api_mod.addImport("quic_packet", quic_packet_mod);
    // Ensure submodule endpoint.zig (imported relatively by api.zig) can import recovery
    quic_api_mod.addImport("quic_recovery", quic_recovery_mod);
    // Add byteorder for endpoint.zig
    quic_api_mod.addImport("byteorder", byteorder_mod);
    // Add transport params for endpoint.zig
    quic_api_mod.addImport("quic_transport_params", quic_transport_params_mod);
    // Add logger for endpoint.zig
    quic_api_mod.addImport("quic_logger", quic_logger_mod);

    // Export named module for dependents: @import("quic")
    const quic_mod = b.addModule("quic", .{ .root_source_file = rp("src/quic/api.zig") }); // module API still supports root_source_file
    quic_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_mod.addImport("quic_frame", quic_frame_mod);
    quic_mod.addImport("quic_varint", quic_varint_mod);
    quic_mod.addImport("quic_tls", quic_tls_mod);
    quic_mod.addImport("quic_tls13", tls13_mod);
    quic_mod.addImport("quic_conn", quic_conn_mod);
    quic_mod.addImport("quic_packet", quic_packet_mod);

    // CLI binaries (scaffold): quic-client, quic-server + debug clients
    const quic_client = addExe(b, "quic-client", "cmd/quic-client.zig", target, optimize);
    quic_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client = b.addInstallArtifact(quic_client, .{});

    const quic_client_comprehensive = addExe(b, "quic-client-comprehensive", "cmd/quic-client-comprehensive.zig", target, optimize);
    quic_client_comprehensive.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client_comprehensive = b.addInstallArtifact(quic_client_comprehensive, .{});

    const quic_server = addExe(b, "quic-server", "cmd/quic-server.zig", target, optimize);
    quic_server.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_server = b.addInstallArtifact(quic_server, .{});
    b.getInstallStep().dependOn(&install_quic_server.step); // Add to default install

    const quic_debug_client = addExe(b, "quic-debug-client", "cmd/quic-debug-client.zig", target, optimize);
    quic_debug_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_debug_client = b.addInstallArtifact(quic_debug_client, .{});

    const quic_debug_dgram_client = addExe(b, "quic-debug-dgram-client", "cmd/quic-debug-dgram-client.zig", target, optimize);
    quic_debug_dgram_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_debug_dgram_client = b.addInstallArtifact(quic_debug_dgram_client, .{});

    // QNS endpoint binary for interop docker image
    // Minimal HTTP/3 shim module (kept separate from QUIC core)
    const h3_server_mod = mkModule(b, "src/h3/server.zig");
    h3_server_mod.addImport("quic_api", quic_api_mod);
    h3_server_mod.addImport("quic_conn", quic_conn_mod);
    // Export for dependents as named imports
    const h3_mod = b.addModule("h3_server", .{ .root_source_file = rp("src/h3/server.zig") });
    h3_mod.addImport("quic_api", quic_api_mod);
    h3_mod.addImport("quic_conn", quic_conn_mod);
    const h3_client_mod = b.addModule("h3_client", .{ .root_source_file = rp("src/h3/client.zig") });
    h3_client_mod.addImport("quic_api", quic_api_mod);
    h3_client_mod.addImport("quic_api", quic_api_mod);

    // High-level transport API module
    const transport_mod = mkModule(b, "src/quic/transport.zig");
    transport_mod.addImport("api", quic_api_mod);
    transport_mod.addImport("quic_endpoint", quic_endpoint_mod);
    transport_mod.addImport("quic_conn", quic_conn_mod);
    transport_mod.addImport("quic_crypto", quic_crypto_mod);
    transport_mod.addImport("quic_frame", quic_frame_mod);
    transport_mod.addImport("quic_varint", quic_varint_mod);
    transport_mod.addImport("quic_tls", quic_tls_mod);
    transport_mod.addImport("quic_packet", quic_packet_mod);
    transport_mod.addImport("config.zig", quic_config_mod);
    transport_mod.addImport("loop_backend.zig", loop_backend_mod);
    const transport_public = b.addModule("transport", .{ .root_source_file = rp("src/quic/transport.zig") });
    transport_public.addImport("api", quic_api_mod);
    transport_public.addImport("quic_endpoint", quic_endpoint_mod);
    transport_public.addImport("quic_conn", quic_conn_mod);
    transport_public.addImport("quic_crypto", quic_crypto_mod);
    transport_public.addImport("quic_frame", quic_frame_mod);
    transport_public.addImport("quic_varint", quic_varint_mod);
    transport_public.addImport("quic_tls", quic_tls_mod);
    transport_public.addImport("quic_packet", quic_packet_mod);
    transport_public.addImport("config.zig", quic_config_mod);
    transport_public.addImport("loop_backend.zig", loop_backend_mod);

    const qns_endpoint = addExe(b, "qns-endpoint", "cmd/qns-endpoint.zig", target, optimize);
    qns_endpoint.root_module.addImport("quic_api", quic_api_mod);
    qns_endpoint.root_module.addImport("h3_server", h3_server_mod);
    const install_qns_endpoint = b.addInstallArtifact(qns_endpoint, .{});

    const cli_step = b.step("cli", "Build QUIC CLI client/server");
    cli_step.dependOn(&install_quic_client.step);
    cli_step.dependOn(&install_quic_client_comprehensive.step);
    cli_step.dependOn(&install_quic_server.step);
    cli_step.dependOn(&install_quic_debug_client.step);
    cli_step.dependOn(&install_quic_debug_dgram_client.step);
    cli_step.dependOn(&install_qns_endpoint.step);

    // Explicit debug clients build step
    const debug_clients = b.step("debug-clients", "Build debug stream/datagram clients");
    debug_clients.dependOn(&install_quic_debug_client.step);
    debug_clients.dependOn(&install_quic_debug_dgram_client.step);

    // Transport layer examples
    const client_transport = addExe(b, "client-transport", "examples/client_transport.zig", target, optimize);
    client_transport.root_module.addImport("quic", transport_public);
    const install_client_transport = b.addInstallArtifact(client_transport, .{});

    const server_transport = addExe(b, "server-transport", "examples/server_transport.zig", target, optimize);
    server_transport.root_module.addImport("quic", transport_public);
    const install_server_transport = b.addInstallArtifact(server_transport, .{});

    const examples_step = b.step("examples", "Build transport layer examples");
    examples_step.dependOn(&install_client_transport.step);
    examples_step.dependOn(&install_server_transport.step);

    // Filtering
    if (filter) |f| {
        if (std.mem.containsAtLeast(u8, f, 1, "tls_key_schedule_kat")) {
            const test_tls_only = addTst(b, "tests/test_tls_key_schedule.zig", target, optimize);
            test_tls_only.root_module.addImport("quic_tls", quic_tls_mod);
            const run_test_tls_only = b.addRunArtifact(test_tls_only);
            test_step.dependOn(&run_test_tls_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "timers")) {
            const test_timers_only = addTst(b, "tests/test_timers.zig", target, optimize);
            test_timers_only.root_module.addImport("quic_api", quic_api_mod);
            test_timers_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_timers_only.root_module.addImport("quic_tls13", tls13_mod);
            const run_test_timers_only = b.addRunArtifact(test_timers_only);
            test_step.dependOn(&run_test_timers_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "stream_fc") or std.mem.containsAtLeast(u8, f, 1, "streams")) {
            const test_stream_fc = addTst(b, "tests/test_stream_flow_control.zig", target, optimize);
            test_stream_fc.root_module.addImport("quic_api", quic_api_mod);
            test_stream_fc.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_fc = b.addRunArtifact(test_stream_fc);
            test_step.dependOn(&run_test_stream_fc.step);
            const test_stream_edges = addTst(b, "tests/test_stream_edge_cases.zig", target, optimize);
            test_stream_edges.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_edges = b.addRunArtifact(test_stream_edges);
            test_step.dependOn(&run_test_stream_edges.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "migration_path") or std.mem.containsAtLeast(u8, f, 1, "path_reset")) {
            const test_migration = addTst(b, "tests/test_migration_scenarios.zig", target, optimize);
            test_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_migration.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_migration = b.addRunArtifact(test_migration);
            test_step.dependOn(&run_test_migration.step);
            const test_nat_amp = addTst(b, "tests/test_nat_rebinding_amplification.zig", target, optimize);
            test_nat_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_nat_amp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_nat_amp = b.addRunArtifact(test_nat_amp);
            test_step.dependOn(&run_test_nat_amp.step);
            const test_sr = addTst(b, "tests/test_stateless_reset.zig", target, optimize);
            test_sr.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_sr = b.addRunArtifact(test_sr);
            test_step.dependOn(&run_test_sr.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "bench_hp")) {
            // No separate test file; run a small subset to validate HP paths quickly
            const test_hp = addTst(b, "tests/test_hp_sample_offsets.zig", target, optimize);
            test_hp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_hp = b.addRunArtifact(test_hp);
            test_step.dependOn(&run_test_hp.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "h3_loopback")) {
            const test_h3_loop = addTst(b, "tests/test_h3_loopback.zig", target, optimize);
            test_h3_loop.root_module.addImport("quic_api", quic_api_mod);
            test_h3_loop.root_module.addImport("h3_server", h3_server_mod);
            test_h3_loop.root_module.addImport("h3_client", h3_client_mod);
            const run_test_h3_loop = b.addRunArtifact(test_h3_loop);
            test_step.dependOn(&run_test_h3_loop.step);
            return;
        }
    }

    if (!legacy_tests) {
        const test_byteorder = addTst(b, "tests/test_byteorder.zig", target, optimize);
        test_byteorder.root_module.addImport("byteorder", byteorder_mod);
        const run_test_byteorder = b.addRunArtifact(test_byteorder);
        test_step.dependOn(&run_test_byteorder.step);

        const test_tls_record = addTst(b, "tests/test_tls_record_layer.zig", target, optimize);
        test_tls_record.root_module.addImport("tls_record", tls_record_mod);
        const run_test_tls_record = b.addRunArtifact(test_tls_record);
        test_step.dependOn(&run_test_tls_record.step);

        const test_tls_context = addTst(b, "tests/test_tls_handshake_context.zig", target, optimize);
        test_tls_context.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_context.root_module.addImport("quic_tls", quic_tls_mod);
        test_tls_context.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_tls_context = b.addRunArtifact(test_tls_context);
        test_step.dependOn(&run_test_tls_context.step);

        const test_tls_server_flight = addTst(b, "tests/test_tls_server_handshake_flight.zig", target, optimize);
        test_tls_server_flight.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_tls_server_flight = b.addRunArtifact(test_tls_server_flight);
        test_step.dependOn(&run_test_tls_server_flight.step);

        const test_tls = addTst(b, "tests/test_tls_key_schedule.zig", target, optimize);
        test_tls.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls = b.addRunArtifact(test_tls);
        test_step.dependOn(&run_test_tls.step);

        const test_tls_hs = addTst(b, "tests/test_tls_handshake_secrets.zig", target, optimize);
        const test_tls_keyupdate = addTst(b, "tests/test_tls_key_update_exporter.zig", target, optimize);
        test_tls_keyupdate.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_keyupdate.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_keyupdate = b.addRunArtifact(test_tls_keyupdate);
        test_step.dependOn(&run_test_tls_keyupdate.step);
        test_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_hs = b.addRunArtifact(test_tls_hs);
        test_step.dependOn(&run_test_tls_hs.step);

        const test_tls_integration = addTst(b, "tests/test_tls_integration.zig", target, optimize);
        test_tls_integration.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_integration.root_module.addImport("alert", alert_mod);
        test_tls_integration.root_module.addImport("zero_rtt", zero_rtt_mod);
        const run_test_tls_integration = b.addRunArtifact(test_tls_integration);
        test_step.dependOn(&run_test_tls_integration.step);

        const test_initial = addTst(b, "tests/test_initial_protect.zig", target, optimize);
        test_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_initial.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_initial = b.addRunArtifact(test_initial);
        test_step.dependOn(&run_test_initial.step);

        const test_rfc_a1 = addTst(b, "tests/test_rfc9001_a1_initial.zig", target, optimize);
        test_rfc_a1.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a1.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a1.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a1 = b.addRunArtifact(test_rfc_a1);
        test_step.dependOn(&run_test_rfc_a1.step);

        const test_rfc_a3 = addTst(b, "tests/test_rfc9001_a3_server_initial.zig", target, optimize);
        test_rfc_a3.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a3.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a3.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a3 = b.addRunArtifact(test_rfc_a3);
        test_step.dependOn(&run_test_rfc_a3.step);

        const test_crypto_extract = addTst(b, "tests/test_crypto_extract.zig", target, optimize);
        test_crypto_extract.root_module.addImport("quic_tls", quic_tls_mod);
        test_crypto_extract.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_crypto_extract.root_module.addImport("quic_packet", quic_packet_mod);
        test_crypto_extract.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_crypto_extract = b.addRunArtifact(test_crypto_extract);
        test_step.dependOn(&run_test_crypto_extract.step);

        const test_recovery = addTst(b, "tests/test_recovery.zig", target, optimize);
        test_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
        test_recovery.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery = b.addRunArtifact(test_recovery);
        test_step.dependOn(&run_test_recovery.step);

        const test_loop = addTst(b, "tests/test_initial_handshake_loop.zig", target, optimize);
        test_loop.root_module.addImport("quic_tls", quic_tls_mod);
        test_loop.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_loop.root_module.addImport("quic_packet", quic_packet_mod);
        test_loop.root_module.addImport("quic_frame", quic_frame_mod);
        test_loop.root_module.addImport("quic_tls13", tls13_mod);
        test_loop.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_loop = b.addRunArtifact(test_loop);
        test_step.dependOn(&run_test_loop.step);

        const test_server_initial = addTst(b, "tests/test_server_initial_response.zig", target, optimize);
        test_server_initial.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_initial.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_initial.root_module.addImport("quic_api", quic_api_mod);
        test_server_initial.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_initial.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_initial.root_module.addImport("quic_varint", quic_varint_mod);
        test_server_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_initial.root_module.addImport("config.zig", quic_config_mod);
        const run_test_server_initial = b.addRunArtifact(test_server_initial);
        test_step.dependOn(&run_test_server_initial.step);

        const test_server_processing = addTst(b, "tests/test_server_initial_processing.zig", target, optimize);
        test_server_processing.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_processing.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_processing.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_processing.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_processing.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_processing.root_module.addImport("config.zig", quic_config_mod);
        const run_test_server_processing = b.addRunArtifact(test_server_processing);
        test_step.dependOn(&run_test_server_processing.step);

        const test_sh = addTst(b, "tests/test_shortrtt_roundtrip.zig", target, optimize);
        test_sh.root_module.addImport("quic_tls13", tls13_mod);
        test_sh.root_module.addImport("quic_packet", quic_packet_mod);
        test_sh.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_sh = b.addRunArtifact(test_sh);
        test_step.dependOn(&run_test_sh.step);

        // Regression test for RFC 8446 transcript hash handling in 1-RTT key derivation
        const test_transcript = addTst(b, "tests/test_transcript_hash.zig", target, optimize);
        test_transcript.root_module.addImport("quic_tls13", tls13_mod);
        test_transcript.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_transcript = b.addRunArtifact(test_transcript);
        test_step.dependOn(&run_test_transcript.step);

        const test_pn = addTst(b, "tests/test_pn_expansion.zig", target, optimize);
        test_pn.root_module.addImport("quic_tls13", tls13_mod);
        test_pn.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_pn = b.addRunArtifact(test_pn);
        test_step.dependOn(&run_test_pn.step);

        const test_tp = addTst(b, "tests/test_transport_params.zig", target, optimize);
        test_tp.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_tp = b.addRunArtifact(test_tp);
        test_step.dependOn(&run_test_tp.step);

        const test_timers = addTst(b, "tests/test_timers.zig", target, optimize);
        test_timers.root_module.addImport("quic_api", quic_api_mod);
        test_timers.root_module.addImport("quic_conn", quic_conn_mod);
        test_timers.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_timers = b.addRunArtifact(test_timers);
        test_step.dependOn(&run_test_timers.step);

        const test_vn = addTst(b, "tests/test_version_negotiation.zig", target, optimize);
        test_vn.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_vn = b.addRunArtifact(test_vn);
        test_step.dependOn(&run_test_vn.step);

        // Zero-length connection ID tests (RFC 9000 §12.2 / TLS Error 266 regression)
        const test_zero_scid = addTst(b, "tests/test_zero_length_scid_coalescing.zig", target, optimize);
        test_zero_scid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid.root_module.addImport("quic_frame", quic_frame_mod);
        test_zero_scid.root_module.addImport("quic_varint", quic_varint_mod);
        test_zero_scid.root_module.addImport("quic_tls", quic_tls_mod);
        test_zero_scid.root_module.addImport("config.zig", quic_config_mod);
        const run_test_zero_scid = b.addRunArtifact(test_zero_scid);
        test_step.dependOn(&run_test_zero_scid.step);

        const test_pto_zero_dcid = addTst(b, "tests/test_pto_probe_zero_length_dcid.zig", target, optimize);
        test_pto_zero_dcid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_pto_zero_dcid.root_module.addImport("quic_conn", quic_conn_mod);
        test_pto_zero_dcid.root_module.addImport("quic_packet", quic_packet_mod);
        test_pto_zero_dcid.root_module.addImport("quic_frame", quic_frame_mod);
        test_pto_zero_dcid.root_module.addImport("quic_tls", quic_tls_mod);
        test_pto_zero_dcid.root_module.addImport("config.zig", quic_config_mod);
        const run_test_pto_zero_dcid = b.addRunArtifact(test_pto_zero_dcid);
        test_step.dependOn(&run_test_pto_zero_dcid.step);

        // New: Retry issuance and amplification gating tests
        const test_retry = addTst(b, "tests/test_retry.zig", target, optimize);
        test_retry.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry = b.addRunArtifact(test_retry);
        test_step.dependOn(&run_test_retry.step);

        const test_retry_tamper = addTst(b, "tests/test_retry_tamper.zig", target, optimize);
        test_retry_tamper.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry_tamper.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry_tamper.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry_tamper.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry_tamper.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry_tamper = b.addRunArtifact(test_retry_tamper);
        test_step.dependOn(&run_test_retry_tamper.step);

        const test_amp = addTst(b, "tests/test_amplification.zig", target, optimize);
        test_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_amp.root_module.addImport("quic_packet", quic_packet_mod);
        test_amp.root_module.addImport("quic_varint", quic_varint_mod);
        test_amp.root_module.addImport("quic_tls", quic_tls_mod);
        test_amp.root_module.addImport("quic_frame", quic_frame_mod);
        test_amp.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_amp = b.addRunArtifact(test_amp);
        test_step.dependOn(&run_test_amp.step);

        // ALPN enforcement and getter tests
        const test_alpn = addTst(b, "tests/test_alpn.zig", target, optimize);
        test_alpn.root_module.addImport("quic_api", quic_api_mod);
        test_alpn.root_module.addImport("quic_conn", quic_conn_mod);
        test_alpn.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_alpn = b.addRunArtifact(test_alpn);
        test_step.dependOn(&run_test_alpn.step);

        const test_conn_metadata = addTst(b, "tests/test_conn_metadata.zig", target, optimize);
        test_conn_metadata.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_metadata.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_conn_metadata = b.addRunArtifact(test_conn_metadata);
        test_step.dependOn(&run_test_conn_metadata.step);

        // Regression test for TLS Error 266 (zero-length SCID in 1-RTT packets)
        const test_zero_scid_1rtt = addTst(b, "tests/test_zero_length_scid_1rtt.zig", target, optimize);
        test_zero_scid_1rtt.root_module.addImport("quic_api", quic_api_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_zero_scid_1rtt = b.addRunArtifact(test_zero_scid_1rtt);
        test_step.dependOn(&run_test_zero_scid_1rtt.step);

        // TLS SNI negative/allow_insecure tests
        const test_tls_sni = addTst(b, "tests/test_tls_sni.zig", target, optimize);
        test_tls_sni.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_sni = b.addRunArtifact(test_tls_sni);
        test_step.dependOn(&run_test_tls_sni.step);

        // TLS validity window KATs
        const test_tls_validity = addTst(b, "tests/test_tls_validity.zig", target, optimize);
        test_tls_validity.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_validity = b.addRunArtifact(test_tls_validity);
        test_step.dependOn(&run_test_tls_validity.step);

        // 0-RTT tests
        const test_0rtt = addTst(b, "tests/test_0rtt.zig", target, optimize);
        test_0rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_0rtt.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_0rtt.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_0rtt = b.addRunArtifact(test_0rtt);
        test_step.dependOn(&run_test_0rtt.step);

        // Session resumption tests
        const test_resumption = addTst(b, "tests/test_resumption.zig", target, optimize);
        test_resumption.root_module.addImport("quic_tls13", tls13_mod);
        test_resumption.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_resumption = b.addRunArtifact(test_resumption);
        test_step.dependOn(&run_test_resumption.step);

        // Connection migration tests
        const test_conn_migration = addTst(b, "tests/test_connection_migration.zig", target, optimize);
        test_conn_migration.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_conn_migration.root_module.addImport("quic_frame", quic_frame_mod);
        test_conn_migration.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_conn_migration = b.addRunArtifact(test_conn_migration);
        test_step.dependOn(&run_test_conn_migration.step);

        // Preferred address tests
        const test_pref_addr = addTst(b, "tests/test_preferred_address.zig", target, optimize);
        test_pref_addr.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_pref_addr = b.addRunArtifact(test_pref_addr);
        test_step.dependOn(&run_test_pref_addr.step);

        // TLS KU/EKU and malformed DER tests
        const test_kus_ekus = addTst(b, "tests/test_tls_kus_ekus.zig", target, optimize);
        test_kus_ekus.root_module.addImport("quic_x509", x509_mod);
        const run_test_kus_ekus = b.addRunArtifact(test_kus_ekus);
        test_step.dependOn(&run_test_kus_ekus.step);

        // AEAD/HP KATs
        const test_hp_aead = addTst(b, "tests/test_hp_aead_kats.zig", target, optimize);
        test_hp_aead.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_hp_aead.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_hp_aead = b.addRunArtifact(test_hp_aead);
        test_step.dependOn(&run_test_hp_aead.step);

        // ECN longitudinal multi-ACK across spaces
        const test_ecn_long = addTst(b, "tests/test_ecn_longitudinal.zig", target, optimize);
        test_ecn_long.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_ecn_long.root_module.addImport("quic_packet", quic_packet_mod);
        test_ecn_long.root_module.addImport("quic_frame", quic_frame_mod);
        test_ecn_long.root_module.addImport("quic_tls", quic_tls_mod);
        test_ecn_long.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_ecn_long.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_ecn_long = b.addRunArtifact(test_ecn_long);
        test_step.dependOn(&run_test_ecn_long.step);

        // RX Key Update acceptance tests
        const test_rx_ku = addTst(b, "tests/test_rx_key_update_accept.zig", target, optimize);
        test_rx_ku.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_rx_ku.root_module.addImport("quic_packet", quic_packet_mod);
        test_rx_ku.root_module.addImport("quic_tls13", tls13_mod);
        test_rx_ku.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_rx_ku = b.addRunArtifact(test_rx_ku);
        test_step.dependOn(&run_test_rx_ku.step);

        // PMTUD/DPLPMTUD probe sizing + ICMP clamp tests
        const test_pmtud = addTst(b, "tests/test_pmtud.zig", target, optimize);
        test_pmtud.root_module.addImport("quic_api", quic_api_mod);
        test_pmtud.root_module.addImport("quic_conn", quic_conn_mod);
        test_pmtud.root_module.addImport("quic_packet", quic_packet_mod);
        test_pmtud.root_module.addImport("quic_frame", quic_frame_mod);
        test_pmtud.root_module.addImport("quic_tls13", tls13_mod);
        test_pmtud.root_module.addImport("quic_tls", quic_tls_mod);
        test_pmtud.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_pmtud = b.addRunArtifact(test_pmtud);
        test_step.dependOn(&run_test_pmtud.step);
    } else {
        const test_quic = addTst(b, "quic.zig", target, optimize);
        const run_test_quic = b.addRunArtifact(test_quic);
        test_step.dependOn(&run_test_quic.step);
    }

    // Fuzzers
    const fuzz_varint = addExe(b, "fuzz_varint", "fuzz/fuzz_varint.zig", target, optimize);
    const fuzz_frame = addExe(b, "fuzz_frame_parse", "fuzz/fuzz_frame_parse.zig", target, optimize);
    const fuzz_vn = addExe(b, "fuzz_vn_parse", "fuzz/fuzz_vn_parse.zig", target, optimize);
    const fuzz_short = addExe(b, "fuzz_short_decode", "fuzz/fuzz_short_decode.zig", target, optimize);
    const fuzz_tls_hello = addExe(b, "fuzz_tls_hello", "fuzz/fuzz_tls_hello.zig", target, optimize);
    const fuzz_tls_cert = addExe(b, "fuzz_tls_cert", "fuzz/fuzz_tls_cert.zig", target, optimize);
    fuzz_varint.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_frame.root_module.addImport("quic_frame", quic_frame_mod);
    fuzz_frame.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_vn.root_module.addImport("quic_packet", quic_packet_mod);
    fuzz_short.root_module.addImport("quic_packet", quic_packet_mod);
    const install_fuzz_varint = b.addInstallArtifact(fuzz_varint, .{});
    const install_fuzz_frame = b.addInstallArtifact(fuzz_frame, .{});
    const install_fuzz_vn = b.addInstallArtifact(fuzz_vn, .{});
    const install_fuzz_short = b.addInstallArtifact(fuzz_short, .{});
    const install_fuzz_tls_hello = b.addInstallArtifact(fuzz_tls_hello, .{});
    const install_fuzz_tls_cert = b.addInstallArtifact(fuzz_tls_cert, .{});
    const fuzz_step = b.step("fuzz", "Build fuzzers");
    fuzz_step.dependOn(&install_fuzz_varint.step);
    fuzz_step.dependOn(&install_fuzz_frame.step);
    fuzz_step.dependOn(&install_fuzz_vn.step);
    fuzz_step.dependOn(&install_fuzz_short.step);
    fuzz_step.dependOn(&install_fuzz_tls_hello.step);
    fuzz_step.dependOn(&install_fuzz_tls_cert.step);

    // Benchmarks
    const bench = addExe(b, "quic-bench", "bench/main.zig", target, optimize);
    bench.root_module.addImport("quic_varint", quic_varint_mod);
    bench.root_module.addImport("quic_recovery", quic_recovery_mod);
    bench.root_module.addImport("quic_packet", quic_packet_mod);
    bench.root_module.addImport("quic_crypto", quic_crypto_mod);
    bench.root_module.addImport("quic_tls", quic_tls_mod);
    const install_bench = b.addInstallArtifact(bench, .{});
    const bench_step = b.step("bench", "Build benchmarks");
    bench_step.dependOn(&install_bench.step);

    // TLS benchmarks
    const bench_tls_hs = addExe(b, "bench_tls_handshake", "bench/bench_tls_handshake.zig", target, .ReleaseFast);
    bench_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
    bench_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
    const install_bench_tls_hs = b.addInstallArtifact(bench_tls_hs, .{});
    bench_step.dependOn(&install_bench_tls_hs.step);

    const bench_tls_aead = addExe(b, "bench_tls_aead", "bench/bench_tls_aead.zig", target, .ReleaseFast);
    const install_bench_tls_aead = b.addInstallArtifact(bench_tls_aead, .{});
    bench_step.dependOn(&install_bench_tls_aead.step);
}
