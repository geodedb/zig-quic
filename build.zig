// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const link = @import("src/link.zig");

fn mkModule(b: *std.Build, path: []const u8) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path(path) });
}

fn addExe(b: *std.Build, name: []const u8, path: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    var exe = b.addExecutable(.{ .name = name, .root_module = b.createModule(.{ .root_source_file = b.path(path), .target = target, .optimize = optimize }) });

    // NOTE: ssl/crypto were previously linked here for "QUIC AEAD compatibility"
    // but the codebase has no @cImport/@extern referencing OpenSSL — the
    // openssl CLI is only invoked at runtime via std.process.run for cert
    // generation. `ldd` on the produced binary confirms libssl/libcrypto are
    // not in the final ELF. Keeping the link broke cross-compile to any
    // non-host target ("unable to find dynamic system library 'ssl'" /
    // 'crypto' with `paths_first` strategy).
    exe.root_module.link_libc = true;

    if (target.result.os.tag == .windows) {
        exe.root_module.linkSystemLibrary("ws2_32", .{});
    }
    return exe;
}

fn addTst(
    b: *std.Build,
    testlog_mod: *std.Build.Module,
    compat_mod: *std.Build.Module,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const root_mod = b.createModule(.{ .root_source_file = b.path(path), .target = target, .optimize = optimize });
    root_mod.addImport("testlog", testlog_mod);
    root_mod.addImport("compat", compat_mod);
    var tst = b.addTest(.{ .root_module = root_mod });

    // See addExe(): ssl/crypto were unreferenced symbols and broke cross-compile.
    tst.root_module.link_libc = true;

    if (target.result.os.tag == .windows) {
        tst.root_module.linkSystemLibrary("ws2_32", .{});
    }
    return tst;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize_base = b.standardOptimizeOption(.{});
    const release_safe = b.option(bool, "release-safe", "Build with ReleaseSafe optimization (convenience flag)") orelse false;
    const optimize: std.builtin.OptimizeMode = if (release_safe) .ReleaseSafe else optimize_base;
    _ = b.option(bool, "xdp", "Enable XDP path (no-op placeholder)") orelse false;

    // Thread pool parallelism option
    const enable_tp = b.option(bool, "thread_pool", "Enable thread-pool-based parallelism") orelse true;

    // Get thread_pool dependency if enabled
    const tp_mod: ?*std.Build.Module = if (enable_tp) blk: {
        const tp_dep = b.dependency("thread_pool", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk tp_dep.module("thread_pool");
    } else null;

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = b.option(
        bool,
        "with_otel",
        "Compile in otel instrumentation (off by default; zero overhead when off)",
    ) orelse false;

    // -Dfips: route security crypto through the linked FIPS-140-3 provider.
    // OFF by default with zero overhead; the `fips` dependency is resolved
    // only when true (mirrors the otel seam). HKDF + all PQC reach quic
    // transitively via `quic_tls`; this flag governs AEAD/HMAC/CSPRNG that
    // quic calls directly. Forces AES-GCM (ChaCha20-Poly1305 becomes
    // error.Unsupported in the AEAD seam).
    const fips = b.option(bool, "fips", "Route security crypto through the linked FIPS-140-3 provider (off by default; zero overhead when off)") orelse false;
    const openssl_path = b.option([]const u8, "openssl_path", "OpenSSL install prefix for non-standard installs (e.g. /usr/local/ssl)");

    // Build options module. Kept because endpoint.zig still imports
    // "quic_build_options"; now also carries `with_otel` for the
    // observability seam and `fips` for the FIPS-140-3 crypto seam.
    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    build_options.addOption(bool, "fips", fips);
    build_options.addOption([]const u8, "package_name", "quic");
    const build_options_mod = build_options.createModule();

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (lib.zig, conn/api/endpoint, plus the seam tests)
    // resolves to the same source file via `@import("observability")`.
    // The seam's `enabled` flag tracks `build_options.with_otel`; when
    // off, every helper compiles to a comptime-known no-op and the otel
    // dependency is never resolved. The optional `otel` import is wired
    // at the bottom of build() inside the `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

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
    const full_test_graph = b.option(bool, "full-test-graph", "Run full per-file test graph (slower, maximum coverage)") orelse false;
    const cc_opt = b.option([]const u8, "cc", "Congestion control: newreno (default) or cubic");

    // Expose TLS/crypto/packet modules
    const byteorder_mod = mkModule(b, "src/byteorder/byteorder.zig");

    // ========================================================================
    // External TLS Library (from build.zig.zon dependency)
    // ========================================================================
    // Import TLS modules from the external tls library instead of vendored implementation.
    //
    // SEC-077 (tls v0.1.2): `x509.InsecureValidation.testing_only_i_know_what_i_am_doing`
    // runtime-panics unless the tls dep is built with `-Dtls-insecure-testing=true`.
    // QUIC tests, benchmarks, and interop all exercise self-signed / peer-untrusted
    // paths via `QuicConfig.allow_insecure = true`; forward the build flag so those
    // targets compile & run. Production callers that set `allow_insecure = false`
    // are unaffected (they flow to the `.secure` variant, which never panics).
    //
    // FIPS review (CRITICAL): propagate -Dfips and -Dopenssl_path DOWN to the
    // tls dependency so its crypto_backend seam activates transitively. Without
    // this, the TLS-layer crypto (handshake, key-schedule HKDF, PQC) that quic
    // consumes via quic_tls/tls13/sig/x509 would run on tls's std_shim backend
    // even under -Dfips=true, bypassing the FIPS provider. The local
    // seam-enabled tls (build.zig.zon .tls = .{ .path = "../tls" }) accepts
    // both options; passing them here flips its `if (fips)` lazyDependency wire
    // so the SAME local fips package (single instance — GAP-0020) backs both
    // quic's and tls's seam, and OpenSSL links onto the tls-derived modules.
    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
        .@"tls-insecure-testing" = true,
        .fips = fips,
        .openssl_path = openssl_path orelse "/usr/local/ssl",
    });

    // Get TLS modules from the external dependency (only the ones actually used)
    const quic_tls_mod = tls_dep.module("quic_tls");
    const tls13_mod = tls_dep.module("tls13");
    const alert_mod = tls_dep.module("alert");
    const sig_mod = tls_dep.module("sig");
    const x509_mod = tls_dep.module("x509");
    const zero_rtt_mod = tls_dep.module("zero_rtt");
    const tls_record_mod = tls_dep.module("record");
    // TLS package's quic_logger (separate from our local src/quic/logger.zig).
    // Used by cmd/qns-endpoint.zig to register a sink that forwards
    // [TLS-HRR] diagnostics into our stderr logger for interop debugging.
    const tls_quic_logger_mod = tls_dep.module("quic_logger");

    // QUIC crypto and packet modules
    const quic_crypto_mod = mkModule(b, "src/quic/crypto_quic.zig");
    // Ensure crypto module can import the key schedule
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // ====================================================================
    // FIPS seam (crypto_backend) — shared named module wiring
    // ====================================================================
    // The non-fips backend is the LOCAL vendored std_shim (src/fips_backend/
    // std_shim.zig), which imports its sibling policy.zig (src/fips_backend/
    // policy.zig) via @import("policy.zig"). Because the canonical std_shim +
    // policy are copied INTO this repo (Task 0), the -Dfips=false path needs
    // NO fips dependency at all (no fetch, no OpenSSL). The crypto_backend
    // seam imports the SINGLE build_options_mod plus std_shim (always) and the
    // fips backend (only under -Dfips=true). All are SHARED NAMED MODULES so
    // every consumer reaches one source identity (avoids GAP-0020 "file exists
    // in modules X and Y").
    const std_shim_mod = b.addModule("std_shim", .{
        .root_source_file = b.path("src/fips_backend/std_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    const crypto_backend_mod = b.addModule("crypto_backend", .{
        .root_source_file = b.path("src/crypto_backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
            // std_shim is always reachable; the seam only selects it when
            // -Dfips=false (the fips branch is comptime-dead in that build).
            .{ .name = "std_shim", .module = std_shim_mod },
        },
    });
    if (fips) {
        // Resolved ONLY when -Dfips=true; the disabled build never reaches
        // the fips dependency (which links OpenSSL). The fips package is a
        // LOCAL PATH dependency (see build.zig.zon); the eventual published
        // form is a git+https lazy dep documented there.
        // fips is `.lazy = true` in build.zig.zon, so it MUST be accessed via
        // lazyDependency (b.dependency panics on a lazy dep). We are inside
        // `if (fips)`, so the dependency is requested + resolved here.
        if (b.lazyDependency("fips", .{
            .target = target,
            .optimize = optimize,
            .openssl_path = openssl_path orelse "/usr/local/ssl",
        })) |fips_dep| {
            const fips_mod = fips_dep.module("fips");
            crypto_backend_mod.addImport("fips", fips_mod);
            // Link OpenSSL onto the fips backend module so it propagates to every
            // consuming artifact. The fips package's own build.zig also links it,
            // but linking here keeps the consumer artifact self-sufficient.
            link.linkOpenssl(b, fips_mod, openssl_path orelse "/usr/local/ssl");
        }
    }
    quic_crypto_mod.addImport("crypto_backend", crypto_backend_mod);

    // Varint module (needed by packet and frame modules)
    const quic_varint_mod = mkModule(b, "src/quic/varint.zig");
    quic_varint_mod.addImport("byteorder", byteorder_mod);

    // Zig 0.16 compatibility helpers (ArrayList writer adapter, etc.)
    const compat_mod = mkModule(b, "src/quic/compat.zig");

    // Version negotiation module (needed by packet and connection modules)
    const quic_version_mod = mkModule(b, "src/quic/version.zig");
    quic_version_mod.addImport("compat", compat_mod);

    // Token module (Retry token encode/verify)
    const quic_token_mod = mkModule(b, "src/quic/token.zig");
    quic_token_mod.addImport("byteorder", byteorder_mod);
    quic_token_mod.addImport("compat", compat_mod);
    quic_token_mod.addImport("crypto_backend", crypto_backend_mod);

    // Logger module for QUIC library (local QUIC logger, not vendored TLS logger)
    const quic_logger_mod = mkModule(b, "src/quic/logger.zig");

    // ========================================================================
    // Packet Sub-Modules (Phase 7 Refactoring)
    // ========================================================================
    const packet_types_mod = mkModule(b, "src/quic/packet/types.zig");

    const packet_header_mod = mkModule(b, "src/quic/packet/header.zig");
    packet_header_mod.addImport("types", packet_types_mod);
    packet_header_mod.addImport("quic_varint", quic_varint_mod);

    // Packet coordinator module (imports legacy packet.zig and new submodules)
    const quic_packet_mod = mkModule(b, "src/quic/packet/packet.zig");
    quic_packet_mod.addImport("types", packet_types_mod);
    quic_packet_mod.addImport("header", packet_header_mod);
    // Import legacy packet.zig for current implementations
    const quic_packet_legacy_mod = mkModule(b, "src/quic/packet.zig");
    quic_packet_legacy_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_legacy_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_packet_legacy_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_legacy_mod.addImport("quic_version", quic_version_mod);
    quic_packet_legacy_mod.addImport("quic_logger", quic_logger_mod);
    quic_packet_legacy_mod.addImport("compat", compat_mod);
    // NOTE: parallel import wired after parallel_mod definition (see ~line 580)
    quic_packet_mod.addImport("../packet.zig", quic_packet_legacy_mod);

    // ========================================================================
    // Frame Sub-Modules (Phase 6 Refactoring)
    // ========================================================================
    const frame_types_mod = mkModule(b, "src/quic/frame/types.zig");

    const frame_misc_mod = mkModule(b, "src/quic/frame/misc.zig");
    frame_misc_mod.addImport("types", frame_types_mod);
    frame_misc_mod.addImport("quic_varint", quic_varint_mod);

    const frame_crypto_mod = mkModule(b, "src/quic/frame/crypto.zig");
    frame_crypto_mod.addImport("types", frame_types_mod);
    frame_crypto_mod.addImport("quic_varint", quic_varint_mod);

    const frame_stream_mod = mkModule(b, "src/quic/frame/stream.zig");
    frame_stream_mod.addImport("types", frame_types_mod);
    frame_stream_mod.addImport("quic_varint", quic_varint_mod);

    const frame_ack_mod = mkModule(b, "src/quic/frame/ack.zig");
    frame_ack_mod.addImport("types", frame_types_mod);
    frame_ack_mod.addImport("quic_varint", quic_varint_mod);

    const frame_path_mod = mkModule(b, "src/quic/frame/path.zig");
    frame_path_mod.addImport("types", frame_types_mod);

    const frame_connection_mgmt_mod = mkModule(b, "src/quic/frame/connection_mgmt.zig");
    frame_connection_mgmt_mod.addImport("types", frame_types_mod);
    frame_connection_mgmt_mod.addImport("quic_varint", quic_varint_mod);

    const frame_flow_control_mod = mkModule(b, "src/quic/frame/flow_control.zig");
    frame_flow_control_mod.addImport("types", frame_types_mod);
    frame_flow_control_mod.addImport("quic_varint", quic_varint_mod);

    const frame_datagram_mod = mkModule(b, "src/quic/frame/datagram.zig");
    frame_datagram_mod.addImport("types", frame_types_mod);
    frame_datagram_mod.addImport("quic_varint", quic_varint_mod);

    // Frame coordinator module
    const quic_frame_mod = mkModule(b, "src/quic/frame/frame.zig");
    quic_frame_mod.addImport("types", frame_types_mod);
    quic_frame_mod.addImport("misc", frame_misc_mod);
    quic_frame_mod.addImport("crypto", frame_crypto_mod);
    quic_frame_mod.addImport("stream", frame_stream_mod);
    quic_frame_mod.addImport("ack", frame_ack_mod);
    quic_frame_mod.addImport("path", frame_path_mod);
    quic_frame_mod.addImport("connection_mgmt", frame_connection_mgmt_mod);
    quic_frame_mod.addImport("flow_control", frame_flow_control_mod);
    quic_frame_mod.addImport("datagram", frame_datagram_mod);
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);

    quic_packet_mod.addImport("quic_varint", quic_varint_mod);

    // Local QUIC transport params (separate from vendored TLS transport params)
    const quic_transport_params_mod = mkModule(b, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);
    quic_transport_params_mod.addImport("compat", compat_mod);

    // QUIC configuration module
    const quic_config_mod = mkModule(b, "src/quic/config.zig");

    // Note: tls13_mod uses ztls_transport_params_mod from vendor/ztls (defined above)

    // ========================================================================
    // Recovery Sub-Modules (Phase 8 Refactoring)
    // ========================================================================
    const recovery_types_mod = mkModule(b, "src/quic/recovery/types.zig");

    const recovery_rtt_mod = mkModule(b, "src/quic/recovery/rtt.zig");

    const recovery_loss_detection_mod = mkModule(b, "src/quic/recovery/loss_detection.zig");
    recovery_loss_detection_mod.addImport("quic_frame", quic_frame_mod);

    const recovery_congestion_mod = mkModule(b, "src/quic/recovery/congestion.zig");

    // Recovery coordinator module
    const quic_recovery_mod = mkModule(b, "src/quic/recovery/recovery.zig");
    quic_recovery_mod.addImport("types", recovery_types_mod);
    quic_recovery_mod.addImport("rtt.zig", recovery_rtt_mod);
    quic_recovery_mod.addImport("loss_detection.zig", recovery_loss_detection_mod);
    quic_recovery_mod.addImport("congestion.zig", recovery_congestion_mod);
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);
    if (cc_opt) |_| {
        // Placeholder: runtime selection occurs via config; both controllers are in same module
    }

    // Add logger to modules that need it
    quic_crypto_mod.addImport("quic_logger", quic_logger_mod);
    quic_crypto_mod.addImport("compat", compat_mod);
    quic_packet_mod.addImport("quic_logger", quic_logger_mod);
    quic_packet_mod.addImport("compat", compat_mod);
    quic_recovery_mod.addImport("quic_logger", quic_logger_mod);

    // NOTE: parallel_mod wiring deferred to after its definition (see below ~line 576)

    // Note: alert_mod, zero_rtt_mod, and tls logger are now imported from vendor/ztls above

    // ========================================================================
    // Algorithm Sub-Modules (Geode Extraction)
    // ========================================================================
    // Pure algorithm modules — self-contained, only depend on std
    const algo_drr_mod = mkModule(b, "src/quic/algorithms/drr.zig");
    const algo_congestion_mod = mkModule(b, "src/quic/algorithms/congestion_newreno.zig");
    const algo_loss_recovery_mod = mkModule(b, "src/quic/algorithms/loss_recovery.zig");
    const algo_timer_heap_mod = mkModule(b, "src/quic/algorithms/timer_heap.zig");
    const algo_sharding_mod = mkModule(b, "src/quic/algorithms/sharding.zig");

    // Connection manager (orchestrates algorithms: DRR, CC, loss, timers, sharding)
    const connection_manager_mod = mkModule(b, "src/quic/connection_manager.zig");
    connection_manager_mod.addImport("drr", algo_drr_mod);
    connection_manager_mod.addImport("congestion", algo_congestion_mod);
    connection_manager_mod.addImport("loss_recovery", algo_loss_recovery_mod);
    connection_manager_mod.addImport("timer_heap", algo_timer_heap_mod);
    connection_manager_mod.addImport("sharding", algo_sharding_mod);

    // ========================================================================
    // Connection Sub-Modules (Phase 1 Refactoring)
    // ========================================================================
    const conn_types_mod = mkModule(b, "src/quic/connection/types.zig");
    conn_types_mod.addImport("byteorder", byteorder_mod);

    const conn_crypto_buffer_mod = mkModule(b, "src/quic/connection/crypto_buffer.zig");
    conn_crypto_buffer_mod.addImport("quic_logger", quic_logger_mod);

    const conn_key_update_mod = mkModule(b, "src/quic/connection/key_update.zig");
    conn_key_update_mod.addImport("quic_tls", quic_tls_mod);

    const conn_packet_number_mod = mkModule(b, "src/quic/connection/packet_number.zig");
    conn_packet_number_mod.addImport("quic_frame", quic_frame_mod);

    const conn_ack_mod = mkModule(b, "src/quic/connection/ack.zig");
    conn_ack_mod.addImport("quic_frame", quic_frame_mod);

    const conn_stream_mod = mkModule(b, "src/quic/connection/stream.zig");
    conn_stream_mod.addImport("quic_logger", quic_logger_mod);

    const conn_connection_id_mod = mkModule(b, "src/quic/connection/connection_id.zig");
    conn_connection_id_mod.addImport("types", conn_types_mod);
    conn_connection_id_mod.addImport("quic_tls", quic_tls_mod);

    const conn_handshake_mod = mkModule(b, "src/quic/connection/handshake.zig");

    const conn_path_mod = mkModule(b, "src/quic/connection/path.zig");

    const conn_amplification_mod = mkModule(b, "src/quic/connection/amplification.zig");

    const conn_pmtud_mod = mkModule(b, "src/quic/connection/pmtud.zig");

    const conn_limits_mod = mkModule(b, "src/quic/connection/limits.zig");

    const conn_flow_control_mod = mkModule(b, "src/quic/connection/flow_control.zig");

    const conn_error_mod = mkModule(b, "src/quic/connection/error.zig");

    const conn_idle_mod = mkModule(b, "src/quic/connection/idle.zig");

    const conn_connection_mod = mkModule(b, "src/quic/connection/connection.zig");
    // Connection coordinator imports all sub-modules
    conn_connection_mod.addImport("types", conn_types_mod);
    conn_connection_mod.addImport("crypto_buffer", conn_crypto_buffer_mod);
    conn_connection_mod.addImport("packet_number", conn_packet_number_mod);
    conn_connection_mod.addImport("ack", conn_ack_mod);
    conn_connection_mod.addImport("stream", conn_stream_mod);
    conn_connection_mod.addImport("connection_id", conn_connection_id_mod);
    conn_connection_mod.addImport("handshake", conn_handshake_mod);
    conn_connection_mod.addImport("path", conn_path_mod);
    conn_connection_mod.addImport("amplification", conn_amplification_mod);
    conn_connection_mod.addImport("pmtud", conn_pmtud_mod);
    conn_connection_mod.addImport("limits", conn_limits_mod);
    conn_connection_mod.addImport("flow_control", conn_flow_control_mod);
    conn_connection_mod.addImport("error", conn_error_mod);
    conn_connection_mod.addImport("idle", conn_idle_mod);

    // ========================================================================
    // Endpoint Sub-Modules (Phase 2 Refactoring)
    // ========================================================================
    // Note: endpoint modules defined after quic_conn_mod is created below

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
    quic_conn_mod.addImport("quic_version", quic_version_mod);
    quic_conn_mod.addImport("quic_key_update", conn_key_update_mod);
    // Make transport params available to connection and endpoint modules
    quic_conn_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_conn_mod.addImport("compat", compat_mod);
    // Phase 5: conn.zig now imports connection/* modules directly via file paths to avoid diamond dependencies

    // Now define endpoint modules (they need quic_conn_mod)
    const endpoint_types_mod = mkModule(b, "src/quic/endpoint/types.zig");
    endpoint_types_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_timer_mod = mkModule(b, "src/quic/endpoint/timer.zig");
    endpoint_timer_mod.addImport("types", endpoint_types_mod);
    endpoint_timer_mod.addImport("compat", compat_mod);

    const endpoint_lookup_mod = mkModule(b, "src/quic/endpoint/lookup.zig");
    endpoint_lookup_mod.addImport("types", endpoint_types_mod);
    endpoint_lookup_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_lookup_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_io_mod = mkModule(b, "src/quic/endpoint/io.zig");
    endpoint_io_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_io_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_client_mod = mkModule(b, "src/quic/endpoint/client.zig");
    endpoint_client_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_client_mod.addImport("quic_packet", quic_packet_mod);
    endpoint_client_mod.addImport("quic_frame", quic_frame_mod);
    endpoint_client_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_client_mod.addImport("types", endpoint_types_mod);
    endpoint_client_mod.addImport("quic_logger", quic_logger_mod);
    endpoint_client_mod.addImport("compat", compat_mod);
    // Note: handshake_integration import added later after endpoint_handshake_integration_mod is declared

    const endpoint_server_mod = mkModule(b, "src/quic/endpoint/server.zig");
    endpoint_server_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_server_mod.addImport("types", endpoint_types_mod);
    endpoint_server_mod.addImport("config", quic_config_mod);
    endpoint_server_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_server_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_server_mod.addImport("x509", x509_mod);
    endpoint_server_mod.addImport("sig", sig_mod);
    endpoint_server_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_utils_mod = mkModule(b, "src/quic/endpoint/utils.zig");
    endpoint_utils_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_transport_mod = mkModule(b, "src/quic/endpoint/transport.zig");
    endpoint_transport_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_udp_transport_mod = mkModule(b, "src/quic/endpoint/udp_transport.zig");
    endpoint_udp_transport_mod.addImport("transport.zig", endpoint_transport_mod);
    endpoint_udp_transport_mod.addImport("conn.zig", quic_conn_mod);
    endpoint_udp_transport_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_incoming_mod = mkModule(b, "src/quic/endpoint/incoming.zig");
    endpoint_incoming_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_incoming_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_incoming_mod.addImport("types", endpoint_types_mod);
    endpoint_incoming_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_incoming_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_incoming_mod.addImport("quic_key_update", conn_key_update_mod);
    endpoint_incoming_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_incoming_mod.addImport("frame", quic_frame_mod);
    endpoint_incoming_mod.addImport("varint", quic_varint_mod);
    endpoint_incoming_mod.addImport("token", quic_token_mod);
    endpoint_incoming_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_incoming_mod.addImport("x509", x509_mod);
    endpoint_incoming_mod.addImport("sig", sig_mod);
    endpoint_incoming_mod.addImport("lookup", endpoint_lookup_mod);
    endpoint_incoming_mod.addImport("quic_logger", quic_logger_mod);
    endpoint_incoming_mod.addImport("compat", compat_mod);

    const endpoint_handshake_integration_mod = mkModule(b, "src/quic/endpoint/handshake_integration.zig");
    endpoint_handshake_integration_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_handshake_integration_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_handshake_integration_mod.addImport("frame", quic_frame_mod);
    endpoint_handshake_integration_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_handshake_integration_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_tls13", tls13_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_handshake_integration_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_handshake_integration_mod.addImport("quic_key_update", conn_key_update_mod);
    endpoint_handshake_integration_mod.addImport("quic_logger", quic_logger_mod);
    endpoint_handshake_integration_mod.addImport("compat", compat_mod);

    // Add handshake_integration import to endpoint_client_mod (declared earlier at line ~388)
    endpoint_client_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);
    endpoint_client_mod.addImport("quic_tls13", tls13_mod);

    const endpoint_pto_mod = mkModule(b, "src/quic/endpoint/pto.zig");
    endpoint_pto_mod.addImport("types", endpoint_types_mod);
    endpoint_pto_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_pto_mod.addImport("quic_packet", quic_packet_mod);
    endpoint_pto_mod.addImport("quic_frame", quic_frame_mod);
    endpoint_pto_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_pto_mod.addImport("quic_logger", quic_logger_mod);
    endpoint_pto_mod.addImport("compat", compat_mod);

    const endpoint_lifecycle_mod = mkModule(b, "src/quic/endpoint/lifecycle.zig");
    endpoint_lifecycle_mod.addImport("types", endpoint_types_mod);
    endpoint_lifecycle_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_lifecycle_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_frame_handler_mod = mkModule(b, "src/quic/endpoint/frame_handler.zig");
    endpoint_frame_handler_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_frame_handler_mod.addImport("frame", quic_frame_mod);
    endpoint_frame_handler_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_frame_handler_mod.addImport("quic_logger", quic_logger_mod);
    endpoint_frame_handler_mod.addImport("compat", compat_mod);

    const endpoint_endpoint_mod = mkModule(b, "src/quic/endpoint/endpoint.zig");
    // Endpoint coordinator imports all sub-modules
    endpoint_endpoint_mod.addImport("types", endpoint_types_mod);
    endpoint_endpoint_mod.addImport("timer", endpoint_timer_mod);
    endpoint_endpoint_mod.addImport("lookup", endpoint_lookup_mod);
    endpoint_endpoint_mod.addImport("io", endpoint_io_mod);
    endpoint_endpoint_mod.addImport("client", endpoint_client_mod);
    endpoint_endpoint_mod.addImport("server", endpoint_server_mod);
    endpoint_endpoint_mod.addImport("incoming", endpoint_incoming_mod);
    endpoint_endpoint_mod.addImport("pto", endpoint_pto_mod);

    // Endpoint module for socket/event-loop tests
    const loop_backend_mod = mkModule(b, "src/quic/loop_backend.zig");

    // Add config import to handshake_integration_mod, frame_handler_mod, and incoming_mod now that quic_config_mod is defined
    endpoint_handshake_integration_mod.addImport("config", quic_config_mod);
    endpoint_frame_handler_mod.addImport("config", quic_config_mod);
    endpoint_incoming_mod.addImport("config", quic_config_mod);
    endpoint_incoming_mod.addImport("frame_handler", endpoint_frame_handler_mod);
    endpoint_incoming_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);
    // SONNY-6457: endpoint_server_mod is also a test root (test-server-client-ca).
    endpoint_server_mod.addImport("compat", compat_mod);
    endpoint_server_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);

    const quic_endpoint_mod = mkModule(b, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("types", endpoint_types_mod);
    quic_endpoint_mod.addImport("compat", compat_mod);
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
    quic_endpoint_mod.addImport("quic_version", quic_version_mod);
    quic_endpoint_mod.addImport("quic_token", quic_token_mod);
    quic_endpoint_mod.addImport("endpoint/utils.zig", endpoint_utils_mod);
    quic_endpoint_mod.addImport("endpoint/transport.zig", endpoint_transport_mod);
    quic_endpoint_mod.addImport("endpoint/udp_transport.zig", endpoint_udp_transport_mod);
    quic_endpoint_mod.addImport("endpoint/incoming.zig", endpoint_incoming_mod);
    quic_endpoint_mod.addImport("endpoint/frame_handler.zig", endpoint_frame_handler_mod);
    quic_endpoint_mod.addImport("endpoint/lookup.zig", endpoint_lookup_mod);
    quic_endpoint_mod.addImport("endpoint/pto.zig", endpoint_pto_mod);
    quic_endpoint_mod.addImport("endpoint/lifecycle.zig", endpoint_lifecycle_mod);
    quic_endpoint_mod.addImport("endpoint/handshake_integration.zig", endpoint_handshake_integration_mod);
    quic_endpoint_mod.addImport("endpoint/client.zig", endpoint_client_mod);
    quic_endpoint_mod.addImport("endpoint/server.zig", endpoint_server_mod);
    quic_endpoint_mod.addImport("quic_build_options", build_options_mod);
    quic_endpoint_mod.addImport("crypto_backend", crypto_backend_mod);

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
    // Add version negotiation for endpoint.zig
    quic_api_mod.addImport("quic_version", quic_version_mod);

    // Parallel module for thread-pool-based parallelism
    const parallel_mod: ?*std.Build.Module = if (enable_tp) blk: {
        break :blk b.addModule("parallel", .{
            .root_source_file = b.path("src/parallel.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_crypto", .module = quic_crypto_mod },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        });
    } else null;
    if (parallel_mod) |pm| {
        if (tp_mod) |tm| pm.addImport("thread_pool", tm);

        // Wire parallel module into internal modules that need batch crypto/loss detection (PAR-009)
        quic_packet_legacy_mod.addImport("parallel", pm);
        quic_packet_mod.addImport("parallel", pm);
        quic_recovery_mod.addImport("parallel", pm);
        quic_endpoint_mod.addImport("parallel", pm);
    }

    // Observability seam: api/conn import the shared `observability`
    // module by name. Using a named module (instead of a sibling-file
    // import) is required so Zig doesn't end up with `observability.zig`
    // living in two module trees ("file exists in modules X and Y" error).
    quic_api_mod.addImport("observability", observability_mod);
    quic_conn_mod.addImport("observability", observability_mod);

    // Export named module for dependents: @import("quic")
    const quic_mod = b.addModule("quic", .{ .root_source_file = b.path("lib.zig") }); // aggregate export surface
    quic_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_mod.addImport("quic_frame", quic_frame_mod);
    quic_mod.addImport("quic_varint", quic_varint_mod);
    quic_mod.addImport("quic_tls", quic_tls_mod);
    quic_mod.addImport("quic_tls13", tls13_mod);
    quic_mod.addImport("quic_conn", quic_conn_mod);
    quic_mod.addImport("quic_packet", quic_packet_mod);
    quic_mod.addImport("config.zig", quic_config_mod);
    quic_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_mod.addImport("quic_logger", quic_logger_mod);
    quic_mod.addImport("byteorder", byteorder_mod);
    quic_mod.addImport("quic_api", quic_api_mod);
    quic_mod.addImport("observability", observability_mod);
    quic_mod.addImport("build_options", build_options_mod);
    if (parallel_mod) |pm| quic_mod.addImport("parallel", pm);

    // ========================================================================
    // Observability seam (otel) — gated dependency wiring
    // ========================================================================
    //
    // The `lazy = true` entry in build.zig.zon means Zig only fetches
    // the package when this branch executes; with the flag off the
    // dependency is never resolved and the produced artifacts contain
    // zero otel symbols (verified by otel/scripts/verify-consumer-noop.sh).
    if (with_otel) {
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        const otel_module = otel_dep.module("otel");
        // The seam itself imports `otel` when enabled. Wire it onto the
        // shared observability module so every consumer sees the same
        // otel namespace.
        observability_mod.addImport("otel", otel_module);
        quic_mod.addImport("otel", otel_module);

        // Bootstrap helper. Only registered when `-Dwith_otel=true` so
        // the disabled build never compiles otel-touching code. Gated
        // from lib.zig via `if (observability.enabled) @import("observability_init")`.
        const observability_init_mod = b.addModule("observability_init", .{
            .root_source_file = b.path("src/observability_init.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "otel", .module = otel_module },
                .{ .name = "observability", .module = observability_mod },
            },
        });
        quic_mod.addImport("observability_init", observability_init_mod);
    }

    // CLI binaries (scaffold): quic-client, quic-server + debug clients
    const quic_client = addExe(b, "quic-client", "cmd/quic-client.zig", target, optimize);
    quic_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client = b.addInstallArtifact(quic_client, .{});
    b.getInstallStep().dependOn(&install_quic_client.step);

    const quic_client_comprehensive = addExe(b, "quic-client-comprehensive", "cmd/quic-client-comprehensive.zig", target, optimize);
    quic_client_comprehensive.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client_comprehensive = b.addInstallArtifact(quic_client_comprehensive, .{});

    const quic_server = addExe(b, "quic-server", "cmd/quic-server.zig", target, optimize);
    quic_server.root_module.addImport("quic_api", quic_api_mod);
    quic_server.root_module.addImport("tls_quic_logger", tls_quic_logger_mod);
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
    const h3_varint_mod = mkModule(b, "src/h3/varint.zig");
    // Export for dependents as named imports. Use a single module per source
    // root and reuse it for both the public module table and internal
    // wiring; creating parallel private `mkModule` copies of the same file
    // produces "file exists in modules 'X' and 'X0'" diamonds in Zig 0.16
    // once a downstream consumer's graph is instantiated.
    const h3_mod = b.addModule("h3_server", .{ .root_source_file = b.path("src/h3/server.zig") });
    h3_mod.addImport("quic_api", quic_api_mod);
    h3_mod.addImport("quic_conn", quic_conn_mod);
    h3_mod.addImport("h3_varint", h3_varint_mod);
    const h3_server_mod = h3_mod;
    const h3_client_mod = b.addModule("h3_client", .{ .root_source_file = b.path("src/h3/client.zig") });
    h3_client_mod.addImport("quic_api", quic_api_mod);
    h3_client_mod.addImport("h3_varint", h3_varint_mod);
    quic_mod.addImport("h3_server", h3_server_mod);
    quic_mod.addImport("h3_client", h3_client_mod);

    // High-level transport API module (single instance, public-facing)
    const transport_public = b.addModule("transport", .{ .root_source_file = b.path("src/quic/transport.zig") });
    transport_public.addImport("quic_api", quic_api_mod);
    transport_public.addImport("compat", compat_mod);
    transport_public.addImport("quic_endpoint", quic_endpoint_mod);
    transport_public.addImport("quic_conn", quic_conn_mod);
    transport_public.addImport("quic_crypto", quic_crypto_mod);
    transport_public.addImport("quic_frame", quic_frame_mod);
    transport_public.addImport("quic_varint", quic_varint_mod);
    transport_public.addImport("quic_tls", quic_tls_mod);
    transport_public.addImport("quic_packet", quic_packet_mod);
    transport_public.addImport("config.zig", quic_config_mod);
    transport_public.addImport("loop_backend.zig", loop_backend_mod);
    transport_public.addImport("quic_logger", quic_logger_mod);

    // ========================================================================
    // Phase 14: Integration Test Framework Modules
    // ========================================================================

    // Loopback transport for in-memory testing
    const loopback_mod = mkModule(b, "tests/integration/loopback.zig");
    loopback_mod.addImport("compat", compat_mod);
    const testlog_mod = mkModule(b, "tests/helpers/testlog.zig");

    // Loopback transport adapter (adapts loopback to Transport interface)
    const adapter_mod = mkModule(b, "tests/integration/loopback_transport_adapter.zig");
    adapter_mod.addImport("loopback", loopback_mod);
    adapter_mod.addImport("transport", endpoint_transport_mod);
    adapter_mod.addImport("testlog", testlog_mod);

    // Integration test harness (TestEndpoint wrapper with packet capture, time control)
    const integration_harness_mod = mkModule(b, "tests/integration/harness.zig");
    integration_harness_mod.addImport("quic_endpoint", quic_endpoint_mod);
    integration_harness_mod.addImport("quic_conn", quic_conn_mod);
    integration_harness_mod.addImport("quic_config", quic_config_mod);
    integration_harness_mod.addImport("compat", compat_mod);

    // TLS test helpers (shared by scenarios and connection_pair)
    const tls_helpers_mod = mkModule(b, "tests/integration/tls_helpers.zig");

    // Shared Ed25519 test cert/key constants for tests requiring server certificates
    const test_certs_mod = mkModule(b, "tests/helpers/test_ed25519_certs.zig");

    // Endpoint loopback helpers (EndpointWrapper with real Endpoint)
    const endpoint_loopback_helpers_mod = mkModule(b, "tests/integration/endpoint_loopback_helpers.zig");
    endpoint_loopback_helpers_mod.addImport("quic_endpoint", quic_endpoint_mod);
    endpoint_loopback_helpers_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_loopback_helpers_mod.addImport("quic_config", quic_config_mod);
    endpoint_loopback_helpers_mod.addImport("loopback", loopback_mod);
    endpoint_loopback_helpers_mod.addImport("loopback_transport_adapter", adapter_mod);
    endpoint_loopback_helpers_mod.addImport("transport", endpoint_transport_mod);
    endpoint_loopback_helpers_mod.addImport("test_certs", test_certs_mod);

    // ConnectionPair fixture (client-server connection for testing)
    const connection_pair_mod = mkModule(b, "tests/integration/connection_pair.zig");
    connection_pair_mod.addImport("harness", integration_harness_mod);
    connection_pair_mod.addImport("loopback", loopback_mod);
    connection_pair_mod.addImport("endpoint_loopback_helpers", endpoint_loopback_helpers_mod);
    connection_pair_mod.addImport("tls_helpers", tls_helpers_mod);
    connection_pair_mod.addImport("testlog", testlog_mod);
    connection_pair_mod.addImport("compat", compat_mod);

    // Packet inspector (Phase 21.3: packet header parsing and frame extraction for tests)
    const packet_inspector_mod = mkModule(b, "tests/integration/packet_inspector.zig");
    packet_inspector_mod.addImport("harness", integration_harness_mod);
    packet_inspector_mod.addImport("quic_frame", quic_frame_mod);
    packet_inspector_mod.addImport("quic_crypto_quic", quic_crypto_mod);
    packet_inspector_mod.addImport("quic_packet", quic_packet_mod);
    packet_inspector_mod.addImport("quic_tls", quic_tls_mod);
    packet_inspector_mod.addImport("quic_varint", quic_varint_mod);
    packet_inspector_mod.addImport("testlog", testlog_mod);

    // Loss recovery helpers (Phase 21.4: loss detection, RTT estimation, PTO validation for tests)
    const loss_recovery_helpers_mod = mkModule(b, "tests/integration/loss_recovery_helpers.zig");
    loss_recovery_helpers_mod.addImport("harness", integration_harness_mod);
    loss_recovery_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    loss_recovery_helpers_mod.addImport("testlog", testlog_mod);

    // Advanced features helpers (Phase 21.5: transport params, CID management, Retry, error handling for tests)
    const advanced_features_helpers_mod = mkModule(b, "tests/integration/advanced_features_helpers.zig");
    advanced_features_helpers_mod.addImport("harness", integration_harness_mod);
    advanced_features_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    advanced_features_helpers_mod.addImport("testlog", testlog_mod);

    // Medium priority helpers (Phase 22: address validation, connection migration, flow control for tests)
    const medium_priority_helpers_mod = mkModule(b, "tests/integration/medium_priority_helpers.zig");
    medium_priority_helpers_mod.addImport("harness", integration_harness_mod);
    medium_priority_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    medium_priority_helpers_mod.addImport("testlog", testlog_mod);

    // Low priority helpers (Phase 23: key updates, 0-RTT, stress, fault injection, interop for tests)
    const low_priority_helpers_mod = mkModule(b, "tests/integration/low_priority_helpers.zig");
    low_priority_helpers_mod.addImport("harness", integration_harness_mod);
    low_priority_helpers_mod.addImport("packet_inspector", packet_inspector_mod);

    // Scenario builder (fluent API for test setup)
    const scenarios_mod = mkModule(b, "tests/integration/scenarios.zig");
    scenarios_mod.addImport("harness", integration_harness_mod);
    scenarios_mod.addImport("endpoint_loopback_helpers", endpoint_loopback_helpers_mod);
    scenarios_mod.addImport("connection_pair", connection_pair_mod);
    scenarios_mod.addImport("loopback", loopback_mod);
    scenarios_mod.addImport("tls_helpers", tls_helpers_mod);

    const qns_endpoint = addExe(b, "qns-endpoint", "cmd/qns-endpoint.zig", target, optimize);
    qns_endpoint.root_module.addImport("quic_api", quic_api_mod);
    qns_endpoint.root_module.addImport("h3_server", h3_server_mod);
    qns_endpoint.root_module.addImport("h3_client", h3_client_mod);
    qns_endpoint.root_module.addImport("tls_quic_logger", tls_quic_logger_mod);
    const install_qns_endpoint = b.addInstallArtifact(qns_endpoint, .{});
    // Include qns-endpoint in default install so interop-test CI job gets the artifact.
    b.getInstallStep().dependOn(&install_qns_endpoint.step);

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

    // SONNY-4776: terminal stream operations share the writer's packet-number
    // critical section. Keep this regression in the default test graph.
    const test_stream_lifecycle = addTst(b, testlog_mod, compat_mod, "tests/test_stream_lifecycle_serialization.zig", target, optimize);
    test_stream_lifecycle.root_module.addImport("quic_conn", quic_conn_mod);
    test_stream_lifecycle.root_module.addImport("quic_packet", quic_packet_mod);
    const run_test_stream_lifecycle = b.addRunArtifact(test_stream_lifecycle);
    const stream_lifecycle_step = b.step("test-stream-lifecycle", "Test stream lifecycle serialization with active writers");
    stream_lifecycle_step.dependOn(&run_test_stream_lifecycle.step);
    if (filter == null or std.mem.eql(u8, filter.?, "stream_lifecycle")) {
        test_step.dependOn(&run_test_stream_lifecycle.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "stream_lifecycle")) return;

    // SONNY-6434: ACK processing must not scale with the packets sent
    // (bulk-transfer stall). Keep this regression in the default test graph.
    const test_ack_path_scaling = addTst(b, testlog_mod, compat_mod, "tests/test_ack_path_scaling.zig", target, optimize);
    test_ack_path_scaling.root_module.addImport("quic_conn", quic_conn_mod);
    test_ack_path_scaling.root_module.addImport("quic_packet", quic_packet_mod);
    test_ack_path_scaling.root_module.addImport("quic_frame", quic_frame_mod);
    test_ack_path_scaling.root_module.addImport("quic_recovery", quic_recovery_mod);
    const run_test_ack_path_scaling = b.addRunArtifact(test_ack_path_scaling);
    const ack_path_scaling_step = b.step("test-ack-path-scaling", "Test that ACK processing work is bounded independent of packets sent");
    ack_path_scaling_step.dependOn(&run_test_ack_path_scaling.step);
    if (filter == null or std.mem.eql(u8, filter.?, "ack_path_scaling")) {
        test_step.dependOn(&run_test_ack_path_scaling.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "ack_path_scaling")) return;

    // SONNY-6457: the server's client CA list reaches the TLS context of every
    // server connection. Keep this regression in the default test graph.
    const test_server_client_ca = addTst(b, testlog_mod, compat_mod, "tests/test_server_client_ca.zig", target, optimize);
    test_server_client_ca.root_module.addImport("server", endpoint_server_mod);
    test_server_client_ca.root_module.addImport("quic_conn", quic_conn_mod);
    test_server_client_ca.root_module.addImport("quic_packet", quic_packet_mod);
    test_server_client_ca.root_module.addImport("quic_config", quic_config_mod);
    const run_test_server_client_ca = b.addRunArtifact(test_server_client_ca);
    const server_client_ca_step = b.step("test-server-client-ca", "Test that a server's client CA list reaches its TLS contexts (mTLS)");
    server_client_ca_step.dependOn(&run_test_server_client_ca.step);
    if (filter == null or std.mem.eql(u8, filter.?, "server_client_ca")) {
        test_step.dependOn(&run_test_server_client_ca.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "server_client_ca")) return;

    // SONNY-6478: completed request/response streams on one long-lived
    // connection must be retired, must not be resent once acknowledged, and
    // must return stream-count credit. Keep this regression in the default
    // test graph.
    const test_stream_retirement = addTst(b, testlog_mod, compat_mod, "tests/test_stream_retirement.zig", target, optimize);
    test_stream_retirement.root_module.addImport("quic_api", quic_api_mod);
    test_stream_retirement.root_module.addImport("quic_config", quic_config_mod);
    test_stream_retirement.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_stream_retirement.root_module.addImport("test_certs", test_certs_mod);
    test_stream_retirement.root_module.addImport("quic_build_options", build_options_mod);
    test_stream_retirement.root_module.addImport("quic_conn", quic_conn_mod);
    const run_test_stream_retirement = b.addRunArtifact(test_stream_retirement);
    const stream_retirement_step = b.step("test-stream-retirement", "Test that completed streams are retired and never resent on a long-lived connection");
    stream_retirement_step.dependOn(&run_test_stream_retirement.step);
    if (filter == null or std.mem.eql(u8, filter.?, "stream_retirement")) {
        test_step.dependOn(&run_test_stream_retirement.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "stream_retirement")) return;

    // SONNY-6475: a single stream carrying more than the receive window must
    // keep flowing. Keep this regression in the default test graph.
    const test_large_stream_fc = addTst(b, testlog_mod, compat_mod, "tests/test_large_stream_flow_control.zig", target, optimize);
    test_large_stream_fc.root_module.addImport("quic_api", quic_api_mod);
    test_large_stream_fc.root_module.addImport("quic_config", quic_config_mod);
    test_large_stream_fc.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_large_stream_fc.root_module.addImport("test_certs", test_certs_mod);
    test_large_stream_fc.root_module.addImport("quic_build_options", build_options_mod);
    test_large_stream_fc.root_module.addImport("quic_conn", quic_conn_mod);
    const run_test_large_stream_fc = b.addRunArtifact(test_large_stream_fc);
    const large_stream_fc_step = b.step("test-large-stream-flow-control", "Test that one stream carries more than the receive window at full speed");
    large_stream_fc_step.dependOn(&run_test_large_stream_fc.step);
    if (filter == null or std.mem.eql(u8, filter.?, "large_stream_flow_control")) {
        test_step.dependOn(&run_test_large_stream_fc.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "large_stream_flow_control")) return;

    // SONNY-6522: long transfers must not stall for good under heavy loss
    // (key-update desync, the handshake RTT sample, a server port taken over
    // by a second socket). Real endpoints over a loopback UDP relay that
    // drops chosen datagrams.
    const test_long_transfer_liveness = addTst(b, testlog_mod, compat_mod, "tests/test_long_transfer_liveness.zig", target, optimize);
    test_long_transfer_liveness.root_module.addImport("quic_api", quic_api_mod);
    test_long_transfer_liveness.root_module.addImport("quic_config", quic_config_mod);
    test_long_transfer_liveness.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_long_transfer_liveness.root_module.addImport("test_certs", test_certs_mod);
    test_long_transfer_liveness.root_module.addImport("quic_build_options", build_options_mod);
    test_long_transfer_liveness.root_module.addImport("quic_conn", quic_conn_mod);
    const run_test_long_transfer_liveness = b.addRunArtifact(test_long_transfer_liveness);
    const long_transfer_liveness_step = b.step("test-long-transfer-liveness", "Test that long transfers survive loss across a key update, the handshake RTT sample, and exclusive server ports");
    long_transfer_liveness_step.dependOn(&run_test_long_transfer_liveness.step);
    if (filter == null or std.mem.eql(u8, filter.?, "long_transfer_liveness")) {
        test_step.dependOn(&run_test_long_transfer_liveness.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "long_transfer_liveness")) return;

    // SONNY-6649: 1-RTT packet protection on the receive path (one key set
    // per packet, chosen by the key phase), packet number lengths on the
    // send path (RFC 9000 §17.1) and key update rules (RFC 9001 §6). Real
    // endpoints over a loopback UDP relay.
    const test_rx_packet_protection = addTst(b, testlog_mod, compat_mod, "tests/test_rx_packet_protection.zig", target, optimize);
    test_rx_packet_protection.root_module.addImport("quic_api", quic_api_mod);
    test_rx_packet_protection.root_module.addImport("quic_config", quic_config_mod);
    test_rx_packet_protection.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_rx_packet_protection.root_module.addImport("test_certs", test_certs_mod);
    test_rx_packet_protection.root_module.addImport("quic_build_options", build_options_mod);
    test_rx_packet_protection.root_module.addImport("quic_packet", quic_packet_mod);
    test_rx_packet_protection.root_module.addImport("quic_frame", quic_frame_mod);
    const run_test_rx_packet_protection = b.addRunArtifact(test_rx_packet_protection);
    const rx_packet_protection_step = b.step("test-rx-packet-protection", "Test 1-RTT packet protection, packet number lengths and key update rules against real endpoints");
    rx_packet_protection_step.dependOn(&run_test_rx_packet_protection.step);
    if (filter == null or std.mem.eql(u8, filter.?, "rx_packet_protection")) {
        test_step.dependOn(&run_test_rx_packet_protection.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "rx_packet_protection")) return;

    // SONNY-6654: no packet number (and AEAD nonce) is used twice while the
    // handshake completes and the application writes. Real endpoints over a
    // loopback UDP relay that records the server's 1-RTT datagrams.
    const test_sonny6654 = addTst(b, testlog_mod, compat_mod, "tests/test_sonny6654_handshake_pn_serialization.zig", target, optimize);
    test_sonny6654.root_module.addImport("quic_api", quic_api_mod);
    test_sonny6654.root_module.addImport("quic_config", quic_config_mod);
    test_sonny6654.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_sonny6654.root_module.addImport("test_certs", test_certs_mod);
    test_sonny6654.root_module.addImport("quic_build_options", build_options_mod);
    const run_test_sonny6654 = b.addRunArtifact(test_sonny6654);
    const sonny6654_step = b.step("test-sonny6654-handshake-pn", "Test that no packet number is used twice while the handshake completes and the application writes");
    sonny6654_step.dependOn(&run_test_sonny6654.step);
    if (filter == null or std.mem.eql(u8, filter.?, "sonny6654_handshake_pn")) {
        test_step.dependOn(&run_test_sonny6654.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "sonny6654_handshake_pn")) return;

    // SONNY-6655: lost NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames are
    // sent again (RFC 9000 §13.3), and connection IDs the peer retires are
    // retired with RETIRE_CONNECTION_ID (§5.1.2). Real endpoints over a
    // loopback UDP relay that drops chosen server datagrams.
    const test_sonny6655 = addTst(b, testlog_mod, compat_mod, "tests/test_sonny6655_cid_frame_retransmission.zig", target, optimize);
    test_sonny6655.root_module.addImport("quic_api", quic_api_mod);
    test_sonny6655.root_module.addImport("quic_config", quic_config_mod);
    test_sonny6655.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_sonny6655.root_module.addImport("test_certs", test_certs_mod);
    test_sonny6655.root_module.addImport("quic_build_options", build_options_mod);
    test_sonny6655.root_module.addImport("quic_packet", quic_packet_mod);
    test_sonny6655.root_module.addImport("quic_frame", quic_frame_mod);
    const run_test_sonny6655 = b.addRunArtifact(test_sonny6655);
    const sonny6655_step = b.step("test-sonny6655-cid-retransmission", "Test that lost NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames are sent again, and retired connection IDs are retired");
    sonny6655_step.dependOn(&run_test_sonny6655.step);
    if (filter == null or std.mem.eql(u8, filter.?, "sonny6655_cid_retransmission")) {
        test_step.dependOn(&run_test_sonny6655.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "sonny6655_cid_retransmission")) return;

    // SONNY-6668: the client issues connection IDs (RFC 9000 §5.1.1) and
    // resends a lost NEW_CONNECTION_ID. Real endpoints over a loopback UDP
    // relay that drops the client's 1-RTT datagrams.
    const test_sonny6668 = addTst(b, testlog_mod, compat_mod, "tests/test_sonny6668_client_new_cid.zig", target, optimize);
    test_sonny6668.root_module.addImport("quic_api", quic_api_mod);
    test_sonny6668.root_module.addImport("quic_config", quic_config_mod);
    test_sonny6668.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_sonny6668.root_module.addImport("test_certs", test_certs_mod);
    test_sonny6668.root_module.addImport("quic_build_options", build_options_mod);
    const run_test_sonny6668 = b.addRunArtifact(test_sonny6668);
    const sonny6668_step = b.step("test-sonny6668-client-new-cid", "Test that the client issues connection IDs and resends a lost NEW_CONNECTION_ID");
    sonny6668_step.dependOn(&run_test_sonny6668.step);
    if (filter == null or std.mem.eql(u8, filter.?, "sonny6668_client_new_cid")) {
        test_step.dependOn(&run_test_sonny6668.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "sonny6668_client_new_cid")) return;

    // SONNY-6656: key update windows, packet by packet through a real
    // client endpoint's receive path: previous-phase packets across a packet
    // number gap are opened for three PTOs and discarded after (RFC 9001
    // §6.5); a burst of them behind the update; repeated send-side updates
    // each waiting for an acknowledgement of the new keys (§6.1).
    inline for (.{
        .{ "key_update_ooo_pn_gap", "tests/test_key_update_ooo_pn_gap.zig", "test-key-update-ooo-pn-gap", "Test that previous-phase packets across a packet number gap are opened for three PTOs after a key update, then discarded" },
        .{ "key_update_stress", "tests/test_key_update_stress.zig", "test-key-update-stress", "Test bursts of reordered packets across a key update and repeated send-side key updates" },
    }) |ku| {
        const t = addTst(b, testlog_mod, compat_mod, ku[1], target, optimize);
        t.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        t.root_module.addImport("quic_packet", quic_packet_mod);
        t.root_module.addImport("quic_frame", quic_frame_mod);
        t.root_module.addImport("quic_tls", quic_tls_mod);
        t.root_module.addImport("quic_key_update", conn_key_update_mod);
        const run_t = b.addRunArtifact(t);
        const step = b.step(ku[2], ku[3]);
        step.dependOn(&run_t.step);
        if (filter == null or std.mem.eql(u8, filter.?, ku[0])) {
            test_step.dependOn(&run_t.step);
        }
        if (filter != null and std.mem.eql(u8, filter.?, ku[0])) return;
    }

    // SONNY-6673: a saturating stream writer does not starve the receive
    // path's ACK processing on Connection.mu. Real endpoints over the relay.
    const test_writer_ack_starvation = addTst(b, testlog_mod, compat_mod, "tests/test_writer_ack_starvation.zig", target, optimize);
    test_writer_ack_starvation.root_module.addImport("quic_api", quic_api_mod);
    test_writer_ack_starvation.root_module.addImport("quic_config", quic_config_mod);
    test_writer_ack_starvation.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_writer_ack_starvation.root_module.addImport("test_certs", test_certs_mod);
    test_writer_ack_starvation.root_module.addImport("quic_build_options", build_options_mod);
    const run_test_writer_ack_starvation = b.addRunArtifact(test_writer_ack_starvation);
    const writer_ack_starvation_step = b.step("test-writer-ack-starvation", "Test that a saturating stream writer does not starve the connection's ACK processing");
    writer_ack_starvation_step.dependOn(&run_test_writer_ack_starvation.step);
    if (filter == null or std.mem.eql(u8, filter.?, "writer_ack_starvation")) {
        test_step.dependOn(&run_test_writer_ack_starvation.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "writer_ack_starvation")) return;

    // SONNY-6673: ACK ranges are read from the frame the receive path
    // decoded, not from frame.decodeOne's dead stack frame.
    const test_sonny6673_ack_ranges = addTst(b, testlog_mod, compat_mod, "tests/test_sonny6673_ack_ranges.zig", target, optimize);
    test_sonny6673_ack_ranges.root_module.addImport("incoming", endpoint_incoming_mod);
    test_sonny6673_ack_ranges.root_module.addImport("quic_conn", quic_conn_mod);
    test_sonny6673_ack_ranges.root_module.addImport("config", quic_config_mod);
    test_sonny6673_ack_ranges.root_module.addImport("endpoint/types", endpoint_types_mod);
    test_sonny6673_ack_ranges.root_module.addImport("quic_frame", quic_frame_mod);
    test_sonny6673_ack_ranges.root_module.addImport("quic_packet", quic_packet_mod);
    const run_test_sonny6673_ack_ranges = b.addRunArtifact(test_sonny6673_ack_ranges);
    const sonny6673_ack_ranges_step = b.step("test-sonny6673-ack-ranges", "Test that received ACK ranges are read from the decoded frame");
    sonny6673_ack_ranges_step.dependOn(&run_test_sonny6673_ack_ranges.step);
    if (filter == null or std.mem.eql(u8, filter.?, "sonny6673_ack_ranges")) {
        test_step.dependOn(&run_test_sonny6673_ack_ranges.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "sonny6673_ack_ranges")) return;

    // SONNY-6737: every paced datagram is sent exactly once when a batched
    // send is only partly accepted. Real endpoint paced-send path over test
    // transports and over real UDP sockets.
    const test_sonny6737 = addTst(b, testlog_mod, compat_mod, "tests/test_sonny6737_partial_sendbatch.zig", target, optimize);
    test_sonny6737.root_module.addImport("quic_config", quic_config_mod);
    test_sonny6737.root_module.addImport("quic_conn", quic_conn_mod);
    test_sonny6737.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_sonny6737.root_module.addImport("quic_endpoint_transport", endpoint_transport_mod);
    test_sonny6737.root_module.addImport("quic_udp_transport", endpoint_udp_transport_mod);
    const run_test_sonny6737 = b.addRunArtifact(test_sonny6737);
    const sonny6737_step = b.step("test-sonny6737-partial-sendbatch", "Test that paced datagrams are sent exactly once when a batched send is only partly accepted");
    sonny6737_step.dependOn(&run_test_sonny6737.step);
    if (filter == null or std.mem.eql(u8, filter.?, "sonny6737_partial_sendbatch")) {
        test_step.dependOn(&run_test_sonny6737.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "sonny6737_partial_sendbatch")) return;

    // SONNY-6454: loss detection and persistent congestion per RFC 9002.
    const test_recovery_conformance = addTst(b, testlog_mod, compat_mod, "tests/test_recovery_rfc9002_conformance.zig", target, optimize);
    test_recovery_conformance.root_module.addImport("quic_recovery", quic_recovery_mod);
    const run_test_recovery_conformance = b.addRunArtifact(test_recovery_conformance);
    const recovery_conformance_step = b.step("test-recovery-rfc9002-conformance", "Test loss detection and persistent congestion against RFC 9002");
    recovery_conformance_step.dependOn(&run_test_recovery_conformance.step);
    if (filter == null or std.mem.eql(u8, filter.?, "recovery_rfc9002_conformance")) {
        test_step.dependOn(&run_test_recovery_conformance.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "recovery_rfc9002_conformance")) return;

    // SONNY-6486: final-size violations from a hostile peer (RFC 9000 §4.5).
    const test_final_size = addTst(b, testlog_mod, compat_mod, "tests/test_final_size.zig", target, optimize);
    test_final_size.root_module.addImport("quic_conn", quic_conn_mod);
    test_final_size.root_module.addImport("quic_frame", quic_frame_mod);
    test_final_size.root_module.addImport("quic_packet", quic_packet_mod);
    test_final_size.root_module.addImport("frame_handler", endpoint_frame_handler_mod);
    test_final_size.root_module.addImport("quic_config", quic_config_mod);
    const run_test_final_size = b.addRunArtifact(test_final_size);
    const final_size_step = b.step("test-final-size", "Test RFC 9000 final-size violations from a hostile peer");
    final_size_step.dependOn(&run_test_final_size.step);
    if (filter == null or std.mem.eql(u8, filter.?, "final_size")) {
        test_step.dependOn(&run_test_final_size.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "final_size")) return;

    // SONNY-6486: lost flow-control and RESET_STREAM frames are sent again
    // (RFC 9000 §13.3).
    const test_ctrl_retx = addTst(b, testlog_mod, compat_mod, "tests/test_control_frame_retransmission.zig", target, optimize);
    test_ctrl_retx.root_module.addImport("quic_conn", quic_conn_mod);
    test_ctrl_retx.root_module.addImport("quic_frame", quic_frame_mod);
    test_ctrl_retx.root_module.addImport("quic_packet", quic_packet_mod);
    test_ctrl_retx.root_module.addImport("quic_api", quic_api_mod);
    test_ctrl_retx.root_module.addImport("quic_config", quic_config_mod);
    test_ctrl_retx.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_ctrl_retx.root_module.addImport("test_certs", test_certs_mod);
    test_ctrl_retx.root_module.addImport("quic_build_options", build_options_mod);
    const run_test_ctrl_retx = b.addRunArtifact(test_ctrl_retx);
    const ctrl_retx_step = b.step("test-control-frame-retransmission", "Test that lost MAX_* and RESET_STREAM frames are sent again");
    ctrl_retx_step.dependOn(&run_test_ctrl_retx.step);
    if (filter == null or std.mem.eql(u8, filter.?, "control_frame_retransmission")) {
        test_step.dependOn(&run_test_ctrl_retx.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "control_frame_retransmission")) return;

    const test_tail_loss = addTst(b, testlog_mod, compat_mod, "tests/test_tail_loss_pto.zig", target, optimize);
    test_tail_loss.root_module.addImport("quic_conn", quic_conn_mod);
    test_tail_loss.root_module.addImport("quic_frame", quic_frame_mod);
    test_tail_loss.root_module.addImport("quic_packet", quic_packet_mod);
    test_tail_loss.root_module.addImport("quic_api", quic_api_mod);
    test_tail_loss.root_module.addImport("quic_config", quic_config_mod);
    test_tail_loss.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_tail_loss.root_module.addImport("test_certs", test_certs_mod);
    test_tail_loss.root_module.addImport("quic_build_options", build_options_mod);
    const run_test_tail_loss = b.addRunArtifact(test_tail_loss);
    const tail_loss_step = b.step("test-tail-loss-pto", "Test that lost tail packets (no later ACK) are recovered by the PTO probe");
    tail_loss_step.dependOn(&run_test_tail_loss.step);
    if (filter == null or std.mem.eql(u8, filter.?, "tail_loss_pto")) {
        test_step.dependOn(&run_test_tail_loss.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "tail_loss_pto")) return;

    // SONNY-6486: STREAM_DATA_BLOCKED is ack-eliciting; ACK delay uses our
    // own exponent.
    const test_ack_frame_conf = addTst(b, testlog_mod, compat_mod, "tests/test_ack_frame_conformance.zig", target, optimize);
    test_ack_frame_conf.root_module.addImport("quic_conn", quic_conn_mod);
    test_ack_frame_conf.root_module.addImport("quic_frame", quic_frame_mod);
    test_ack_frame_conf.root_module.addImport("quic_packet", quic_packet_mod);
    test_ack_frame_conf.root_module.addImport("frame_handler", endpoint_frame_handler_mod);
    test_ack_frame_conf.root_module.addImport("quic_config", quic_config_mod);
    test_ack_frame_conf.root_module.addImport("handshake_integration", endpoint_handshake_integration_mod);
    test_ack_frame_conf.root_module.addImport("quic_transport_params", quic_transport_params_mod);
    const run_test_ack_frame_conf = b.addRunArtifact(test_ack_frame_conf);
    const ack_frame_conf_step = b.step("test-ack-frame-conformance", "Test STREAM_DATA_BLOCKED acknowledgement and ACK delay encoding");
    ack_frame_conf_step.dependOn(&run_test_ack_frame_conf.step);
    if (filter == null or std.mem.eql(u8, filter.?, "ack_frame_conformance")) {
        test_step.dependOn(&run_test_ack_frame_conf.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "ack_frame_conformance")) return;

    // A failed connect must leave no connection registered with the endpoint.
    const test_connect_failure = addTst(b, testlog_mod, compat_mod, "tests/test_connect_failure.zig", target, optimize);
    test_connect_failure.root_module.addImport("quic_api", quic_api_mod);
    test_connect_failure.root_module.addImport("quic_config", quic_config_mod);
    test_connect_failure.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    const run_test_connect_failure = b.addRunArtifact(test_connect_failure);
    const connect_failure_step = b.step("test-connect-failure", "Test that failed dials leave the endpoint consistent");
    connect_failure_step.dependOn(&run_test_connect_failure.step);
    if (filter == null or std.mem.eql(u8, filter.?, "connect_failure")) {
        test_step.dependOn(&run_test_connect_failure.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "connect_failure")) return;

    // PEM parsing: no leak on malformed base64, key scratch zeroed.
    const test_pem = addTst(b, testlog_mod, compat_mod, "tests/test_pem.zig", target, optimize);
    test_pem.root_module.addImport("quic_api", quic_api_mod);
    const run_test_pem = b.addRunArtifact(test_pem);
    const pem_step = b.step("test-pem", "Test PEM parsing failure paths and key zeroing");
    pem_step.dependOn(&run_test_pem.step);
    if (filter == null or std.mem.eql(u8, filter.?, "pem")) {
        test_step.dependOn(&run_test_pem.step);
    }
    if (filter != null and std.mem.eql(u8, filter.?, "pem")) return;

    // The native smoke lane exercises the same runtime helpers used by the
    // endpoint, recovery timers, Retry tokens, and non-FIPS crypto backend.
    const portable_runtime_test = addTst(b, testlog_mod, compat_mod, "tests/test_portable_runtime.zig", target, optimize);
    portable_runtime_test.root_module.addImport("std_shim", std_shim_mod);
    portable_runtime_test.root_module.addImport("sharding", algo_sharding_mod);
    const run_portable_runtime_test = b.addRunArtifact(portable_runtime_test);
    const portable_runtime_step = b.step("test-portable-runtime", "Test native clocks, sleep, and OS entropy");
    portable_runtime_step.dependOn(&run_portable_runtime_test.step);
    if (filter == null) test_step.dependOn(&run_portable_runtime_test.step);

    // Filtering
    if (filter) |f| {
        if (std.mem.startsWith(u8, f, "transport_geode_compat")) {
            const test_transport_geode_compat_only = addTst(b, testlog_mod, compat_mod, "tests/test_transport_geode_compat.zig", target, optimize);
            test_transport_geode_compat_only.root_module.addImport("transport", transport_public);
            const run_test_transport_geode_compat_only = b.addRunArtifact(test_transport_geode_compat_only);
            test_step.dependOn(&run_test_transport_geode_compat_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "tls_key_schedule_kat")) {
            const test_tls_only = addTst(b, testlog_mod, compat_mod, "tests/test_tls_key_schedule.zig", target, optimize);
            test_tls_only.root_module.addImport("quic_tls", quic_tls_mod);
            const run_test_tls_only = b.addRunArtifact(test_tls_only);
            test_step.dependOn(&run_test_tls_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "timers")) {
            const test_timers_only = addTst(b, testlog_mod, compat_mod, "tests/test_timers.zig", target, optimize);
            test_timers_only.root_module.addImport("quic_api", quic_api_mod);
            test_timers_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_timers_only.root_module.addImport("quic_tls13", tls13_mod);
            const run_test_timers_only = b.addRunArtifact(test_timers_only);
            test_step.dependOn(&run_test_timers_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "udp_transport")) {
            const udp_transport_test_mod = b.createModule(.{
                .root_source_file = b.path("src/quic/endpoint/udp_transport.zig"),
                .target = target,
                .optimize = optimize,
            });
            udp_transport_test_mod.addImport("transport.zig", endpoint_transport_mod);
            udp_transport_test_mod.addImport("conn.zig", quic_conn_mod);
            udp_transport_test_mod.addImport("quic_logger", quic_logger_mod);
            const test_udp_transport_only = b.addTest(.{ .root_module = udp_transport_test_mod });
            test_udp_transport_only.root_module.link_libc = true;
            const run_test_udp_transport_only = b.addRunArtifact(test_udp_transport_only);
            test_step.dependOn(&run_test_udp_transport_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "teardown_churn_stress")) {
            // Opt-in stress harness (not in the default graph): geode-shaped
            // multi-poller server with connect/stream/close/destroyBatch churn.
            // Intended for `taskset -c 0` single-CPU runs.
            const test_teardown_churn = addTst(b, testlog_mod, compat_mod, "tests/test_endpoint_teardown_churn_stress.zig", target, optimize);
            test_teardown_churn.root_module.addImport("quic_api", quic_api_mod);
            test_teardown_churn.root_module.addImport("quic_config", quic_config_mod);
            const run_test_teardown_churn = b.addRunArtifact(test_teardown_churn);
            run_test_teardown_churn.has_side_effects = true;
            test_step.dependOn(&run_test_teardown_churn.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "teardown_deadlock")) {
            // Regression: Endpoint.mu <-> poll-worker deadlock between
            // destroyConnections (waiting for RX refs under mu) and a pinned
            // poll worker that needs mu (maybeQueueDeferredAccepted).
            const test_teardown_deadlock = addTst(b, testlog_mod, compat_mod, "tests/test_endpoint_teardown_deadlock_regression.zig", target, optimize);
            test_teardown_deadlock.root_module.addImport("quic_api", quic_api_mod);
            test_teardown_deadlock.root_module.addImport("quic_conn", quic_conn_mod);
            test_teardown_deadlock.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            const run_test_teardown_deadlock = b.addRunArtifact(test_teardown_deadlock);
            test_step.dependOn(&run_test_teardown_deadlock.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "pending_hs_retry_destroy")) {
            // Regression: pending-handshake retry vs destroyBatch use-after-free.
            const test_pending_hs_retry_destroy = addTst(b, testlog_mod, compat_mod, "tests/test_pending_hs_retry_destroy_regression.zig", target, optimize);
            test_pending_hs_retry_destroy.root_module.addImport("quic_api", quic_api_mod);
            test_pending_hs_retry_destroy.root_module.addImport("quic_conn", quic_conn_mod);
            test_pending_hs_retry_destroy.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            const run_test_pending_hs_retry_destroy = b.addRunArtifact(test_pending_hs_retry_destroy);
            test_step.dependOn(&run_test_pending_hs_retry_destroy.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "pto_handshake_uaf")) {
            // Regression test for the UAF in processExpiredTimers when a
            // PtoHandshake / PtoInitial timer fires after its captured
            // *Connection has been freed. See
            // docs/audit/bugfix-quic-handshake-triage.md (secondary defect).
            const test_pto_uaf = addTst(b, testlog_mod, compat_mod, "tests/test_endpoint_pto_handshake_uaf_regression.zig", target, optimize);
            test_pto_uaf.root_module.addImport("quic_api", quic_api_mod);
            test_pto_uaf.root_module.addImport("quic_conn", quic_conn_mod);
            test_pto_uaf.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            const run_test_pto_uaf = b.addRunArtifact(test_pto_uaf);
            test_step.dependOn(&run_test_pto_uaf.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "conn_init_mutex")) {
            // Regression test for the uninitialized std.Io.Mutex on
            // Connection.mu — Connection.init at conn.zig:927 omits
            // `self.mu = std.Io.Mutex.init;`, so the struct-literal
            // default is bypassed by allocator.create() + per-field
            // init(). See
            // /home/benji/src/devnw/codepros/geode/geode/docs/audit/bugfix-quic-deadlock-triage.md
            const test_conn_init_mutex = addTst(b, testlog_mod, compat_mod, "tests/test_conn_init_mutex.zig", target, optimize);
            test_conn_init_mutex.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_conn_init_mutex = b.addRunArtifact(test_conn_init_mutex);
            test_step.dependOn(&run_test_conn_init_mutex.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "thread_safety")) {
            const test_thread_safety = addTst(b, testlog_mod, compat_mod, "tests/test_thread_safety.zig", target, optimize);
            test_thread_safety.root_module.addImport("quic", quic_api_mod);
            test_thread_safety.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_thread_safety.root_module.addImport("quic_conn", quic_conn_mod);
            test_thread_safety.root_module.addImport("quic_config", quic_config_mod);
            const run_test_thread_safety = b.addRunArtifact(test_thread_safety);
            test_step.dependOn(&run_test_thread_safety.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "concurrent_handshake_race")) {
            const test_concurrent_handshake_race = addTst(
                b,
                testlog_mod,
                compat_mod,
                "tests/test_concurrent_handshake_race.zig",
                target,
                optimize,
            );
            test_concurrent_handshake_race.root_module.addImport("quic_api", quic_api_mod);
            test_concurrent_handshake_race.root_module.addImport("quic_config", quic_config_mod);
            const run_test_concurrent_handshake_race = b.addRunArtifact(test_concurrent_handshake_race);
            test_step.dependOn(&run_test_concurrent_handshake_race.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "pending_hs_send")) {
            const test_pending_hs_send = addTst(
                b,
                testlog_mod,
                compat_mod,
                "tests/test_pending_hs_send_retry.zig",
                target,
                optimize,
            );
            test_pending_hs_send.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_pending_hs_send.root_module.addImport("quic_conn", quic_conn_mod);
            test_pending_hs_send.root_module.addImport("quic_packet", quic_packet_mod);
            test_pending_hs_send.root_module.addImport("quic_frame", quic_frame_mod);
            test_pending_hs_send.root_module.addImport("quic_tls", quic_tls_mod);
            test_pending_hs_send.root_module.addImport("config.zig", quic_config_mod);
            test_pending_hs_send.root_module.addImport("test_certs", test_certs_mod);
            // FIPS seam: the test's hardcoded x25519-only ClientHello is a
            // non-FIPS key-share; under -Dfips the server CORRECTLY rejects it
            // (UnsupportedKeyShareGroup — X25519 alone is not FIPS-approved,
            // only the X25519MLKEM768 hybrid is). The pending_hs_send retry
            // mechanics under test are crypto-agnostic and fully covered by
            // the -Dfips=false gate, so the test skips under -Dfips=true.
            test_pending_hs_send.root_module.addImport("quic_build_options", build_options_mod);
            const run_test_pending_hs_send = b.addRunArtifact(test_pending_hs_send);
            test_step.dependOn(&run_test_pending_hs_send.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "tx_credit_generation")) {
            const test_tx_credit_generation = addTst(b, testlog_mod, compat_mod, "tests/test_tx_credit_generation.zig", target, optimize);
            test_tx_credit_generation.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_tx_credit_generation = b.addRunArtifact(test_tx_credit_generation);
            test_step.dependOn(&run_test_tx_credit_generation.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "udp_batch_runtime_smoke")) {
            const test_udp_batch_runtime_smoke = addTst(b, testlog_mod, compat_mod, "src/quic/endpoint/test_udp_batch_runtime_smoke.zig", target, optimize);
            test_udp_batch_runtime_smoke.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_udp_batch_runtime_smoke = b.addRunArtifact(test_udp_batch_runtime_smoke);
            test_step.dependOn(&run_test_udp_batch_runtime_smoke.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "app_ack_policy")) {
            const test_app_ack_policy = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_incoming_session3.zig", target, optimize);
            test_app_ack_policy.root_module.addImport("incoming", endpoint_incoming_mod);
            test_app_ack_policy.root_module.addImport("endpoint/types", endpoint_types_mod);
            test_app_ack_policy.root_module.addImport("endpoint/lookup", endpoint_lookup_mod);
            test_app_ack_policy.root_module.addImport("quic_conn", quic_conn_mod);
            test_app_ack_policy.root_module.addImport("config", quic_config_mod);
            test_app_ack_policy.root_module.addImport("packet", quic_packet_legacy_mod);
            const run_test_app_ack_policy = b.addRunArtifact(test_app_ack_policy);
            test_step.dependOn(&run_test_app_ack_policy.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "packet_pool")) {
            const packet_pool_mod = b.createModule(.{ .root_source_file = b.path("src/quic/conn.zig"), .target = target, .optimize = optimize });
            packet_pool_mod.addImport("quic_packet", quic_packet_mod);
            packet_pool_mod.addImport("quic_frame", quic_frame_mod);
            packet_pool_mod.addImport("quic_tls13", tls13_mod);
            packet_pool_mod.addImport("quic_varint", quic_varint_mod);
            packet_pool_mod.addImport("quic_tls", quic_tls_mod);
            packet_pool_mod.addImport("quic_recovery", quic_recovery_mod);
            packet_pool_mod.addImport("quic_logger", quic_logger_mod);
            packet_pool_mod.addImport("byteorder", byteorder_mod);
            packet_pool_mod.addImport("quic_version", quic_version_mod);
            packet_pool_mod.addImport("quic_transport_params", quic_transport_params_mod);
            packet_pool_mod.addImport("compat", compat_mod);
            const test_packet_pool = b.addTest(.{ .root_module = packet_pool_mod });
            if (target.result.os.tag != .windows) {
                test_packet_pool.root_module.linkSystemLibrary("ssl", .{});
                test_packet_pool.root_module.linkSystemLibrary("crypto", .{});
            }
            test_packet_pool.root_module.link_libc = true;
            if (target.result.os.tag == .windows) {
                test_packet_pool.root_module.linkSystemLibrary("ws2_32", .{});
            }
            const run_test_packet_pool = b.addRunArtifact(test_packet_pool);
            test_step.dependOn(&run_test_packet_pool.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "api_colocated")) {
            const test_api_mod = b.createModule(.{ .root_source_file = b.path("src/quic/api.zig"), .target = target, .optimize = optimize });
            test_api_mod.addImport("config.zig", quic_config_mod);
            test_api_mod.addImport("loop_backend.zig", loop_backend_mod);
            test_api_mod.addImport("quic_endpoint", quic_endpoint_mod);
            test_api_mod.addImport("quic_crypto", quic_crypto_mod);
            test_api_mod.addImport("quic_frame", quic_frame_mod);
            test_api_mod.addImport("quic_varint", quic_varint_mod);
            test_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
            test_api_mod.addImport("quic_tls", quic_tls_mod);
            test_api_mod.addImport("quic_tls13", tls13_mod);
            test_api_mod.addImport("quic_conn", quic_conn_mod);
            test_api_mod.addImport("quic_packet", quic_packet_mod);
            test_api_mod.addImport("quic_recovery", quic_recovery_mod);
            test_api_mod.addImport("byteorder", byteorder_mod);
            test_api_mod.addImport("quic_transport_params", quic_transport_params_mod);
            test_api_mod.addImport("quic_logger", quic_logger_mod);
            test_api_mod.addImport("quic_version", quic_version_mod);
            const test_api = b.addTest(.{ .root_module = test_api_mod });
            if (target.result.os.tag != .windows) {
                test_api.root_module.linkSystemLibrary("ssl", .{});
                test_api.root_module.linkSystemLibrary("crypto", .{});
            }
            test_api.root_module.link_libc = true;
            if (target.result.os.tag == .windows) {
                test_api.root_module.linkSystemLibrary("ws2_32", .{});
            }
            const run_test_api = b.addRunArtifact(test_api);
            test_step.dependOn(&run_test_api.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "h3_error")) {
            const test_h3_error = addTst(b, testlog_mod, compat_mod, "tests/test_h3_error_propagation.zig", target, optimize);
            test_h3_error.root_module.addImport("h3_client", h3_client_mod);
            test_h3_error.root_module.addImport("h3_server", h3_server_mod);
            const run_test_h3_error = b.addRunArtifact(test_h3_error);
            test_step.dependOn(&run_test_h3_error.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "pmtud")) {
            const test_conn_pmtud = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_pmtud.zig", target, optimize);
            test_conn_pmtud.root_module.addImport("pmtud", conn_pmtud_mod);
            const run_test_conn_pmtud = b.addRunArtifact(test_conn_pmtud);
            test_step.dependOn(&run_test_conn_pmtud.step);

            const test_pmtud = addTst(b, testlog_mod, compat_mod, "tests/test_pmtud.zig", target, optimize);
            test_pmtud.root_module.addImport("quic_api", quic_api_mod);
            test_pmtud.root_module.addImport("quic_conn", quic_conn_mod);
            test_pmtud.root_module.addImport("quic_packet", quic_packet_mod);
            test_pmtud.root_module.addImport("quic_frame", quic_frame_mod);
            test_pmtud.root_module.addImport("quic_tls13", tls13_mod);
            test_pmtud.root_module.addImport("quic_tls", quic_tls_mod);
            test_pmtud.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            const run_test_pmtud = b.addRunArtifact(test_pmtud);
            test_step.dependOn(&run_test_pmtud.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "reset_stream") or std.mem.containsAtLeast(u8, f, 1, "h3_api")) {
            const test_reset_stream = addTst(b, testlog_mod, compat_mod, "tests/test_reset_stream_api.zig", target, optimize);
            test_reset_stream.root_module.addImport("quic_api", quic_api_mod);
            test_reset_stream.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_reset_stream = b.addRunArtifact(test_reset_stream);
            test_step.dependOn(&run_test_reset_stream.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "stream_edges")) {
            const test_stream_edges = addTst(b, testlog_mod, compat_mod, "tests/test_stream_edge_cases.zig", target, optimize);
            test_stream_edges.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_edges = b.addRunArtifact(test_stream_edges);
            test_step.dependOn(&run_test_stream_edges.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "stream_fc") or std.mem.containsAtLeast(u8, f, 1, "streams")) {
            const test_stream_fc = addTst(b, testlog_mod, compat_mod, "tests/test_stream_flow_control.zig", target, optimize);
            test_stream_fc.root_module.addImport("quic_api", quic_api_mod);
            test_stream_fc.root_module.addImport("quic_conn", quic_conn_mod);
            test_stream_fc.root_module.addImport("quic_packet", quic_packet_mod);
            test_stream_fc.root_module.addImport("quic_frame", quic_frame_mod);
            test_stream_fc.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_stream_fc.root_module.addImport("compat", compat_mod);
            const run_test_stream_fc = b.addRunArtifact(test_stream_fc);
            test_step.dependOn(&run_test_stream_fc.step);
            const test_stream_edges = addTst(b, testlog_mod, compat_mod, "tests/test_stream_edge_cases.zig", target, optimize);
            test_stream_edges.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_edges = b.addRunArtifact(test_stream_edges);
            test_step.dependOn(&run_test_stream_edges.step);
            const test_reset_api = addTst(b, testlog_mod, compat_mod, "tests/test_reset_stream_api.zig", target, optimize);
            test_reset_api.root_module.addImport("quic_api", quic_api_mod);
            test_reset_api.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_reset_api = b.addRunArtifact(test_reset_api);
            test_step.dependOn(&run_test_reset_api.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "disable_active_migration")) {
            const test_disable_active_migration = addTst(b, testlog_mod, compat_mod, "tests/test_disable_active_migration.zig", target, optimize);
            test_disable_active_migration.root_module.addImport("quic_api", quic_api_mod);
            test_disable_active_migration.root_module.addImport("quic_conn", quic_conn_mod);
            test_disable_active_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_disable_active_migration.root_module.addImport("handshake_integration", endpoint_handshake_integration_mod);
            test_disable_active_migration.root_module.addImport("transport_params", quic_transport_params_mod);
            const run_test_disable_active_migration = b.addRunArtifact(test_disable_active_migration);
            test_step.dependOn(&run_test_disable_active_migration.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "v2_packet_types")) {
            const test_v2_packet_types = addTst(b, testlog_mod, compat_mod, "tests/test_quic_v2_packet_types.zig", target, optimize);
            test_v2_packet_types.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_v2_packet_types = b.addRunArtifact(test_v2_packet_types);
            test_step.dependOn(&run_test_v2_packet_types.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "connection_id") or std.mem.containsAtLeast(u8, f, 1, "active_connection_id_limit") or std.mem.containsAtLeast(u8, f, 1, "cid_lifecycle")) {
            const test_active_cid = addTst(b, testlog_mod, compat_mod, "tests/test_active_connection_id_limit.zig", target, optimize);
            test_active_cid.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_active_cid = b.addRunArtifact(test_active_cid);
            test_step.dependOn(&run_test_active_cid.step);

            const test_issue_cid = addTst(b, testlog_mod, compat_mod, "tests/test_issue_new_connection_id.zig", target, optimize);
            test_issue_cid.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_issue_cid = b.addRunArtifact(test_issue_cid);
            test_step.dependOn(&run_test_issue_cid.step);

            const test_retire_cid = addTst(b, testlog_mod, compat_mod, "tests/test_connection_id_retire_and_reissue.zig", target, optimize);
            test_retire_cid.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_retire_cid = b.addRunArtifact(test_retire_cid);
            test_step.dependOn(&run_test_retire_cid.step);

            const test_rotate_cid = addTst(b, testlog_mod, compat_mod, "tests/test_connection_id_rotation_retire_prior_to.zig", target, optimize);
            test_rotate_cid.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_rotate_cid = b.addRunArtifact(test_rotate_cid);
            test_step.dependOn(&run_test_rotate_cid.step);

            const test_emit_cid = addTst(b, testlog_mod, compat_mod, "tests/test_new_connection_id_emit.zig", target, optimize);
            test_emit_cid.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_emit_cid = b.addRunArtifact(test_emit_cid);
            test_step.dependOn(&run_test_emit_cid.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "path_validation")) {
            const test_path_validation = addTst(b, testlog_mod, compat_mod, "tests/test_path_validation.zig", target, optimize);
            test_path_validation.root_module.addImport("quic_api", quic_api_mod);
            test_path_validation.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_path_validation.root_module.addImport("quic_conn", quic_conn_mod);
            test_path_validation.root_module.addImport("quic_packet", quic_packet_mod);
            test_path_validation.root_module.addImport("quic_frame", quic_frame_mod);
            test_path_validation.root_module.addImport("compat", compat_mod);
            const run_test_path_validation = b.addRunArtifact(test_path_validation);
            test_step.dependOn(&run_test_path_validation.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "loss_edge") or std.mem.containsAtLeast(u8, f, 1, "recovery_protocol")) {
            const test_recovery_protocol_gaps = addTst(b, testlog_mod, compat_mod, "tests/test_recovery_protocol_gaps.zig", target, optimize);
            test_recovery_protocol_gaps.root_module.addImport("quic_conn", quic_conn_mod);
            test_recovery_protocol_gaps.root_module.addImport("quic_recovery", quic_recovery_mod);
            const run_test_recovery_protocol_gaps = b.addRunArtifact(test_recovery_protocol_gaps);
            test_step.dependOn(&run_test_recovery_protocol_gaps.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "rfc9002_recovery")) {
            const test_rfc9002_recovery = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9002_recovery.zig", target, optimize);
            test_rfc9002_recovery.root_module.addImport("scenarios", scenarios_mod);
            test_rfc9002_recovery.root_module.addImport("connection_pair", connection_pair_mod);
            test_rfc9002_recovery.root_module.addImport("loss_recovery_helpers", loss_recovery_helpers_mod);
            test_rfc9002_recovery.root_module.addImport("packet_inspector", packet_inspector_mod);
            test_rfc9002_recovery.root_module.addImport("harness", integration_harness_mod);
            test_rfc9002_recovery.root_module.addImport("loopback", loopback_mod);
            test_rfc9002_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
            test_rfc9002_recovery.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_rfc9002_recovery = b.addRunArtifact(test_rfc9002_recovery);
            test_step.dependOn(&run_test_rfc9002_recovery.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "version_negotiation")) {
            const test_vn = addTst(b, testlog_mod, compat_mod, "tests/test_version_negotiation.zig", target, optimize);
            test_vn.root_module.addImport("quic_packet", quic_packet_mod);
            test_vn.root_module.addImport("quic_conn", quic_conn_mod);
            test_vn.root_module.addImport("incoming", endpoint_incoming_mod);
            test_vn.root_module.addImport("endpoint/types", endpoint_types_mod);
            test_vn.root_module.addImport("config", quic_config_mod);
            test_vn.root_module.addImport("quic_api", quic_api_mod);
            test_vn.root_module.addImport("test_certs", test_certs_mod);
            const run_test_vn = b.addRunArtifact(test_vn);
            test_step.dependOn(&run_test_vn.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "handshake_error")) {
            const test_handshake_error = addTst(b, testlog_mod, compat_mod, "tests/test_handshake_error_propagation.zig", target, optimize);
            test_handshake_error.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_handshake_error = b.addRunArtifact(test_handshake_error);
            test_step.dependOn(&run_test_handshake_error.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "migration_path") or std.mem.containsAtLeast(u8, f, 1, "path_reset")) {
            const test_migration = addTst(b, testlog_mod, compat_mod, "tests/test_migration_scenarios.zig", target, optimize);
            test_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_migration.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_migration = b.addRunArtifact(test_migration);
            test_step.dependOn(&run_test_migration.step);
            const test_nat_amp = addTst(b, testlog_mod, compat_mod, "tests/test_nat_rebinding_amplification.zig", target, optimize);
            test_nat_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_nat_amp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_nat_amp = b.addRunArtifact(test_nat_amp);
            test_step.dependOn(&run_test_nat_amp.step);
            const test_sr = addTst(b, testlog_mod, compat_mod, "tests/test_stateless_reset.zig", target, optimize);
            test_sr.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_sr = b.addRunArtifact(test_sr);
            test_step.dependOn(&run_test_sr.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "bench_hp")) {
            // No separate test file; run a small subset to validate HP paths quickly
            const test_hp = addTst(b, testlog_mod, compat_mod, "tests/test_hp_sample_offsets.zig", target, optimize);
            test_hp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_hp = b.addRunArtifact(test_hp);
            test_step.dependOn(&run_test_hp.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "h3_loopback")) {
            const test_h3_loop = addTst(b, testlog_mod, compat_mod, "tests/test_h3_loopback.zig", target, optimize);
            test_h3_loop.root_module.addImport("quic_api", quic_api_mod);
            test_h3_loop.root_module.addImport("h3_server", h3_server_mod);
            test_h3_loop.root_module.addImport("h3_client", h3_client_mod);
            test_h3_loop.root_module.addImport("test_certs", test_certs_mod);
            const run_test_h3_loop = b.addRunArtifact(test_h3_loop);
            test_step.dependOn(&run_test_h3_loop.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "client_finished_wouldblock")) {
            const test_client_finished_wouldblock_only = addTst(b, testlog_mod, compat_mod, "tests/test_client_finished_wouldblock.zig", target, optimize);
            test_client_finished_wouldblock_only.root_module.addImport("quic_api", quic_api_mod);
            test_client_finished_wouldblock_only.root_module.addImport("quic_config", quic_config_mod);
            test_client_finished_wouldblock_only.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_client_finished_wouldblock_only.root_module.addImport("test_certs", test_certs_mod);
            test_client_finished_wouldblock_only.root_module.addImport("quic_build_options", build_options_mod);
            const run_test_client_finished_wouldblock_only = b.addRunArtifact(test_client_finished_wouldblock_only);
            test_step.dependOn(&run_test_client_finished_wouldblock_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "small_rcvbuf")) {
            const test_small_rcvbuf_only = addTst(b, testlog_mod, compat_mod, "tests/test_small_rcvbuf_bulk_stream.zig", target, optimize);
            test_small_rcvbuf_only.root_module.addImport("quic_api", quic_api_mod);
            test_small_rcvbuf_only.root_module.addImport("quic_config", quic_config_mod);
            test_small_rcvbuf_only.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_small_rcvbuf_only.root_module.addImport("test_certs", test_certs_mod);
            test_small_rcvbuf_only.root_module.addImport("quic_build_options", build_options_mod);
            const run_test_small_rcvbuf_only = b.addRunArtifact(test_small_rcvbuf_only);
            test_step.dependOn(&run_test_small_rcvbuf_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "concurrent_load")) {
            const test_concurrent_load_only = addTst(b, testlog_mod, compat_mod, "tests/test_concurrent_load.zig", target, optimize);
            test_concurrent_load_only.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_concurrent_load_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_concurrent_load_only.root_module.addImport("quic_config", quic_config_mod);
            const run_test_concurrent_load_only = b.addRunArtifact(test_concurrent_load_only);
            test_step.dependOn(&run_test_concurrent_load_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "high_parallel")) {
            const test_high_parallel_stream = addTst(b, testlog_mod, compat_mod, "tests/test_high_parallel_stream_progress.zig", target, optimize);
            test_high_parallel_stream.root_module.addImport("quic_api", quic_api_mod);
            test_high_parallel_stream.root_module.addImport("quic_config", quic_config_mod);
            test_high_parallel_stream.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            const run_test_high_parallel_stream = b.addRunArtifact(test_high_parallel_stream);
            test_step.dependOn(&run_test_high_parallel_stream.step);
            if (std.mem.containsAtLeast(u8, f, 1, "scale")) {
                const test_high_parallel_scale = addTst(b, testlog_mod, compat_mod, "tests/test_high_parallel_scale_mutex.zig", target, optimize);
                test_high_parallel_scale.root_module.addImport("quic_endpoint", quic_endpoint_mod);
                test_high_parallel_scale.root_module.addImport("quic_conn", quic_conn_mod);
                test_high_parallel_scale.root_module.addImport("quic_config", quic_config_mod);
                const run_test_high_parallel_scale = b.addRunArtifact(test_high_parallel_scale);
                test_step.dependOn(&run_test_high_parallel_scale.step);
            }
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "poll_perf")) {
            const test_poll_perf_only = addTst(b, testlog_mod, compat_mod, "tests/test_poll_perf.zig", target, optimize);
            test_poll_perf_only.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_poll_perf_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_poll_perf_only.root_module.addImport("quic_config", quic_config_mod);
            const run_test_poll_perf_only = b.addRunArtifact(test_poll_perf_only);
            test_step.dependOn(&run_test_poll_perf_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "contention_load")) {
            const test_contention_load_only = addTst(b, testlog_mod, compat_mod, "tests/test_contention_load.zig", target, optimize);
            test_contention_load_only.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_contention_load_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_contention_load_only.root_module.addImport("quic_config", quic_config_mod);
            const run_test_contention_load_only = b.addRunArtifact(test_contention_load_only);
            test_step.dependOn(&run_test_contention_load_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "public_quic_exports")) {
            const test_public_exports = addTst(b, testlog_mod, compat_mod, "tests/test_public_quic_exports.zig", target, optimize);
            test_public_exports.root_module.addImport("quic", quic_mod);
            const run_test_public_exports = b.addRunArtifact(test_public_exports);
            test_step.dependOn(&run_test_public_exports.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "acceptor_drain_budget")) {
            const test_acceptor_drain = addTst(b, testlog_mod, compat_mod, "tests/test_acceptor_drain_budget.zig", target, optimize);
            test_acceptor_drain.root_module.addImport("quic", quic_mod);
            const run_test_acceptor_drain = b.addRunArtifact(test_acceptor_drain);
            test_step.dependOn(&run_test_acceptor_drain.step);
            return;
        }
    }

    if (!legacy_tests and (full_test_graph or filter != null)) {
        const test_byteorder = addTst(b, testlog_mod, compat_mod, "tests/test_byteorder.zig", target, optimize);
        test_byteorder.root_module.addImport("byteorder", byteorder_mod);
        const run_test_byteorder = b.addRunArtifact(test_byteorder);
        test_step.dependOn(&run_test_byteorder.step);

        const test_public_exports = addTst(b, testlog_mod, compat_mod, "tests/test_public_quic_exports.zig", target, optimize);
        test_public_exports.root_module.addImport("quic", quic_mod);
        const run_test_public_exports = b.addRunArtifact(test_public_exports);
        test_step.dependOn(&run_test_public_exports.step);

        // mTLS config field tests
        const test_mtls_config = addTst(b, testlog_mod, compat_mod, "tests/test_mtls_config.zig", target, optimize);
        test_mtls_config.root_module.addImport("config", quic_config_mod);
        const run_test_mtls_config = b.addRunArtifact(test_mtls_config);
        test_step.dependOn(&run_test_mtls_config.step);

        // mTLS export verification tests
        const test_mtls_exports = addTst(b, testlog_mod, compat_mod, "tests/test_mtls_exports.zig", target, optimize);
        test_mtls_exports.root_module.addImport("quic", quic_mod);
        const run_test_mtls_exports = b.addRunArtifact(test_mtls_exports);
        test_step.dependOn(&run_test_mtls_exports.step);

        // ========================================================================
        // Phase 1 Unit Tests: Foundation Modules (RFC-based)
        // ========================================================================
        const test_conn_types = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_types.zig", target, optimize);
        test_conn_types.root_module.addImport("quic_connection_types", conn_types_mod);
        const run_test_conn_types = b.addRunArtifact(test_conn_types);
        test_step.dependOn(&run_test_conn_types.step);

        const test_frame_streaming = addTst(b, testlog_mod, compat_mod, "tests/test_frame_streaming.zig", target, optimize);
        test_frame_streaming.root_module.addImport("quic_frame", quic_frame_mod);
        test_frame_streaming.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_frame_streaming = b.addRunArtifact(test_frame_streaming);
        test_step.dependOn(&run_test_frame_streaming.step);

        const test_frame_alloc_caps = addTst(b, testlog_mod, compat_mod, "tests/test_frame_alloc_caps.zig", target, optimize);
        test_frame_alloc_caps.root_module.addImport("quic_frame", quic_frame_mod);
        test_frame_alloc_caps.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_frame_alloc_caps = b.addRunArtifact(test_frame_alloc_caps);
        test_step.dependOn(&run_test_frame_alloc_caps.step);

        const test_path_validation = addTst(b, testlog_mod, compat_mod, "tests/test_path_validation.zig", target, optimize);
        test_path_validation.root_module.addImport("quic_api", quic_api_mod);
        test_path_validation.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_path_validation.root_module.addImport("quic_conn", quic_conn_mod);
        test_path_validation.root_module.addImport("quic_packet", quic_packet_mod);
        test_path_validation.root_module.addImport("quic_frame", quic_frame_mod);
        test_path_validation.root_module.addImport("compat", compat_mod);
        const run_test_path_validation = b.addRunArtifact(test_path_validation);
        const test_pv_step = b.step("test-path-validation", "Run path validation tests");
        test_pv_step.dependOn(&run_test_path_validation.step);

        const test_endpoint_types = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_types.zig", target, optimize);
        test_endpoint_types.root_module.addImport("quic_endpoint_types", endpoint_types_mod);
        test_endpoint_types.root_module.addImport("quic_connection_types", conn_types_mod);
        test_endpoint_types.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_types = b.addRunArtifact(test_endpoint_types);
        test_step.dependOn(&run_test_endpoint_types.step);

        const test_endpoint_timer = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_timer.zig", target, optimize);
        test_endpoint_timer.root_module.addImport("timer", endpoint_timer_mod);
        test_endpoint_timer.root_module.addImport("types", endpoint_types_mod);
        const run_test_endpoint_timer = b.addRunArtifact(test_endpoint_timer);
        test_step.dependOn(&run_test_endpoint_timer.step);

        const test_endpoint_lookup = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_lookup.zig", target, optimize);
        test_endpoint_lookup.root_module.addImport("lookup", endpoint_lookup_mod);
        test_endpoint_lookup.root_module.addImport("types", endpoint_types_mod);
        test_endpoint_lookup.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_lookup.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_endpoint_lookup.root_module.addImport("quic_packet", quic_packet_legacy_mod);
        const run_test_endpoint_lookup = b.addRunArtifact(test_endpoint_lookup);
        test_step.dependOn(&run_test_endpoint_lookup.step);

        const test_endpoint_lifecycle = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_lifecycle.zig", target, optimize);
        test_endpoint_lifecycle.root_module.addImport("lifecycle", endpoint_lifecycle_mod);
        test_endpoint_lifecycle.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_lifecycle.root_module.addImport("types", endpoint_types_mod);
        const run_test_endpoint_lifecycle = b.addRunArtifact(test_endpoint_lifecycle);
        test_step.dependOn(&run_test_endpoint_lifecycle.step);
        const test_dead_conn_reap_step = b.step("test-dead-conn-reap", "Run dead-connection reaper (lifecycle) tests");
        test_dead_conn_reap_step.dependOn(&run_test_endpoint_lifecycle.step);

        const test_endpoint_io = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_io.zig", target, optimize);
        test_endpoint_io.root_module.addImport("io", endpoint_io_mod);
        test_endpoint_io.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_io = b.addRunArtifact(test_endpoint_io);
        test_step.dependOn(&run_test_endpoint_io.step);

        const test_endpoint_client = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_client.zig", target, optimize);
        test_endpoint_client.root_module.addImport("client", endpoint_client_mod);
        const run_test_endpoint_client = b.addRunArtifact(test_endpoint_client);
        test_step.dependOn(&run_test_endpoint_client.step);

        const test_endpoint_server = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_server.zig", target, optimize);
        test_endpoint_server.root_module.addImport("server", endpoint_server_mod);
        test_endpoint_server.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_server.root_module.addImport("quic_packet", quic_packet_mod);
        test_endpoint_server.root_module.addImport("quic_token", quic_token_mod);
        test_endpoint_server.root_module.addImport("quic_config", quic_config_mod);
        test_endpoint_server.root_module.addImport("endpoint/types", endpoint_types_mod);
        const run_test_endpoint_server = b.addRunArtifact(test_endpoint_server);
        test_step.dependOn(&run_test_endpoint_server.step);

        const test_endpoint_utils = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_utils.zig", target, optimize);
        test_endpoint_utils.root_module.addImport("utils", endpoint_utils_mod);
        test_endpoint_utils.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_utils = b.addRunArtifact(test_endpoint_utils);
        test_step.dependOn(&run_test_endpoint_utils.step);

        const test_endpoint_incoming = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_incoming.zig", target, optimize);
        test_endpoint_incoming.root_module.addImport("incoming", endpoint_incoming_mod);
        test_endpoint_incoming.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_endpoint_incoming.root_module.addImport("endpoint/utils", endpoint_utils_mod);
        test_endpoint_incoming.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_incoming.root_module.addImport("config", quic_config_mod);
        test_endpoint_incoming.root_module.addImport("token", quic_token_mod);
        test_endpoint_incoming.root_module.addImport("packet", quic_packet_legacy_mod);
        test_endpoint_incoming.root_module.addImport("varint", quic_varint_mod);
        const run_test_endpoint_incoming = b.addRunArtifact(test_endpoint_incoming);
        test_step.dependOn(&run_test_endpoint_incoming.step);

        const test_incoming_session3 = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_incoming_session3.zig", target, optimize);
        test_incoming_session3.root_module.addImport("incoming", endpoint_incoming_mod);
        test_incoming_session3.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_incoming_session3.root_module.addImport("endpoint/lookup", endpoint_lookup_mod);
        test_incoming_session3.root_module.addImport("quic_conn", quic_conn_mod);
        test_incoming_session3.root_module.addImport("config", quic_config_mod);
        test_incoming_session3.root_module.addImport("packet", quic_packet_legacy_mod);
        const run_test_incoming_session3 = b.addRunArtifact(test_incoming_session3);
        test_step.dependOn(&run_test_incoming_session3.step);

        const test_endpoint_handshake_integration = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_handshake_integration.zig", target, optimize);
        test_endpoint_handshake_integration.root_module.addImport("quic_endpoint_handshake_integration", endpoint_handshake_integration_mod);
        test_endpoint_handshake_integration.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_handshake_integration.root_module.addImport("config", quic_config_mod);
        test_endpoint_handshake_integration.root_module.addImport("vendor_ztls_key_schedule", quic_tls_mod);
        test_endpoint_handshake_integration.root_module.addImport("transport_params", quic_transport_params_mod);
        const run_test_endpoint_handshake_integration = b.addRunArtifact(test_endpoint_handshake_integration);
        test_step.dependOn(&run_test_endpoint_handshake_integration.step);

        const test_endpoint_pto = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_pto.zig", target, optimize);
        test_endpoint_pto.root_module.addImport("pto", endpoint_pto_mod);
        test_endpoint_pto.root_module.addImport("types", endpoint_types_mod);
        const run_test_endpoint_pto = b.addRunArtifact(test_endpoint_pto);
        test_step.dependOn(&run_test_endpoint_pto.step);

        const test_endpoint_frame_handler = addTst(b, testlog_mod, compat_mod, "tests/unit/endpoint/test_frame_handler.zig", target, optimize);
        test_endpoint_frame_handler.root_module.addImport("frame_handler", endpoint_frame_handler_mod);
        test_endpoint_frame_handler.root_module.addImport("frame", quic_frame_mod);
        test_endpoint_frame_handler.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_frame_handler.root_module.addImport("config", quic_config_mod);
        test_endpoint_frame_handler.root_module.addImport("quic_recovery", quic_recovery_mod);
        const run_test_endpoint_frame_handler = b.addRunArtifact(test_endpoint_frame_handler);
        test_step.dependOn(&run_test_endpoint_frame_handler.step);

        const test_packet_number = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_packet_number.zig", target, optimize);
        test_packet_number.root_module.addImport("quic_connection_packet_number", conn_packet_number_mod);
        test_packet_number.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_packet_number = b.addRunArtifact(test_packet_number);
        test_step.dependOn(&run_test_packet_number.step);

        // ========================================================================
        // New RFC Compliance Unit Tests
        // ========================================================================

        // Connection module tests
        const test_crypto_buffer = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_crypto_buffer.zig", target, optimize);
        test_crypto_buffer.root_module.addImport("crypto_buffer", conn_crypto_buffer_mod);
        const run_test_crypto_buffer = b.addRunArtifact(test_crypto_buffer);
        test_step.dependOn(&run_test_crypto_buffer.step);

        const test_conn_ack = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_ack.zig", target, optimize);
        test_conn_ack.root_module.addImport("ack", conn_ack_mod);
        test_conn_ack.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_conn_ack = b.addRunArtifact(test_conn_ack);
        test_step.dependOn(&run_test_conn_ack.step);

        const test_conn_stream = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_stream.zig", target, optimize);
        test_conn_stream.root_module.addImport("stream", conn_stream_mod);
        const run_test_conn_stream = b.addRunArtifact(test_conn_stream);
        test_step.dependOn(&run_test_conn_stream.step);

        const test_rx_ready_notifier = addTst(b, testlog_mod, compat_mod, "tests/test_rx_ready_notifier.zig", target, optimize);
        test_rx_ready_notifier.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_rx_ready_notifier = b.addRunArtifact(test_rx_ready_notifier);
        test_step.dependOn(&run_test_rx_ready_notifier.step);

        const test_connection_id_module = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_connection_id.zig", target, optimize);
        test_connection_id_module.root_module.addImport("connection_id", conn_connection_id_mod);
        test_connection_id_module.root_module.addImport("types", conn_types_mod);
        const run_test_connection_id_module = b.addRunArtifact(test_connection_id_module);
        test_step.dependOn(&run_test_connection_id_module.step);

        const test_conn_handshake = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_handshake.zig", target, optimize);
        test_conn_handshake.root_module.addImport("handshake", conn_handshake_mod);
        const run_test_conn_handshake = b.addRunArtifact(test_conn_handshake);
        test_step.dependOn(&run_test_conn_handshake.step);

        const test_conn_path = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_path.zig", target, optimize);
        test_conn_path.root_module.addImport("path", conn_path_mod);
        const run_test_conn_path = b.addRunArtifact(test_conn_path);
        test_step.dependOn(&run_test_conn_path.step);

        const test_conn_amplification = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_amplification.zig", target, optimize);
        test_conn_amplification.root_module.addImport("amplification", conn_amplification_mod);
        const run_test_conn_amplification = b.addRunArtifact(test_conn_amplification);
        test_step.dependOn(&run_test_conn_amplification.step);

        const test_conn_pmtud = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_pmtud.zig", target, optimize);
        test_conn_pmtud.root_module.addImport("pmtud", conn_pmtud_mod);
        const run_test_conn_pmtud = b.addRunArtifact(test_conn_pmtud);
        test_step.dependOn(&run_test_conn_pmtud.step);

        const test_conn_limits = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_limits.zig", target, optimize);
        test_conn_limits.root_module.addImport("limits", conn_limits_mod);
        const run_test_conn_limits = b.addRunArtifact(test_conn_limits);
        test_step.dependOn(&run_test_conn_limits.step);

        const test_conn_flow_control = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_flow_control.zig", target, optimize);
        test_conn_flow_control.root_module.addImport("flow_control", conn_flow_control_mod);
        const run_test_conn_flow_control = b.addRunArtifact(test_conn_flow_control);
        test_step.dependOn(&run_test_conn_flow_control.step);

        const test_conn_error = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_error.zig", target, optimize);
        test_conn_error.root_module.addImport("error", conn_error_mod);
        const run_test_conn_error = b.addRunArtifact(test_conn_error);
        test_step.dependOn(&run_test_conn_error.step);

        const test_conn_idle = addTst(b, testlog_mod, compat_mod, "tests/unit/connection/test_idle.zig", target, optimize);
        test_conn_idle.root_module.addImport("idle", conn_idle_mod);
        const run_test_conn_idle = b.addRunArtifact(test_conn_idle);
        test_step.dependOn(&run_test_conn_idle.step);

        // Frame module tests
        const test_frame_types = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_types.zig", target, optimize);
        test_frame_types.root_module.addImport("types", frame_types_mod);
        const run_test_frame_types = b.addRunArtifact(test_frame_types);
        test_step.dependOn(&run_test_frame_types.step);

        const test_frame_misc = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_misc.zig", target, optimize);
        test_frame_misc.root_module.addImport("misc", frame_misc_mod);
        test_frame_misc.root_module.addImport("types", frame_types_mod);
        const run_test_frame_misc = b.addRunArtifact(test_frame_misc);
        test_step.dependOn(&run_test_frame_misc.step);

        const test_frame_crypto = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_crypto.zig", target, optimize);
        test_frame_crypto.root_module.addImport("crypto", frame_crypto_mod);
        test_frame_crypto.root_module.addImport("types", frame_types_mod);
        const run_test_frame_crypto = b.addRunArtifact(test_frame_crypto);
        test_step.dependOn(&run_test_frame_crypto.step);

        const test_frame_stream = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_stream.zig", target, optimize);
        test_frame_stream.root_module.addImport("stream", frame_stream_mod);
        test_frame_stream.root_module.addImport("types", frame_types_mod);
        const run_test_frame_stream = b.addRunArtifact(test_frame_stream);
        test_step.dependOn(&run_test_frame_stream.step);

        const test_frame_ack = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_ack.zig", target, optimize);
        test_frame_ack.root_module.addImport("ack", frame_ack_mod);
        test_frame_ack.root_module.addImport("types", frame_types_mod);
        const run_test_frame_ack = b.addRunArtifact(test_frame_ack);
        test_step.dependOn(&run_test_frame_ack.step);

        const test_frame_path = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_path.zig", target, optimize);
        test_frame_path.root_module.addImport("path", frame_path_mod);
        test_frame_path.root_module.addImport("types", frame_types_mod);
        const run_test_frame_path = b.addRunArtifact(test_frame_path);
        test_step.dependOn(&run_test_frame_path.step);

        const test_frame_connection_mgmt = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_connection_mgmt.zig", target, optimize);
        test_frame_connection_mgmt.root_module.addImport("connection_mgmt", frame_connection_mgmt_mod);
        test_frame_connection_mgmt.root_module.addImport("types", frame_types_mod);
        const run_test_frame_connection_mgmt = b.addRunArtifact(test_frame_connection_mgmt);
        test_step.dependOn(&run_test_frame_connection_mgmt.step);

        const test_frame_flow_control = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_flow_control.zig", target, optimize);
        test_frame_flow_control.root_module.addImport("flow_control", frame_flow_control_mod);
        test_frame_flow_control.root_module.addImport("types", frame_types_mod);
        const run_test_frame_flow_control = b.addRunArtifact(test_frame_flow_control);
        test_step.dependOn(&run_test_frame_flow_control.step);

        const test_frame_datagram = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_datagram.zig", target, optimize);
        test_frame_datagram.root_module.addImport("datagram", frame_datagram_mod);
        test_frame_datagram.root_module.addImport("types", frame_types_mod);
        const run_test_frame_datagram = b.addRunArtifact(test_frame_datagram);
        test_step.dependOn(&run_test_frame_datagram.step);

        const test_frame_coalescing = addTst(b, testlog_mod, compat_mod, "tests/unit/frame/test_ack_stream_coalescing.zig", target, optimize);
        test_frame_coalescing.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_frame_coalescing = b.addRunArtifact(test_frame_coalescing);
        test_step.dependOn(&run_test_frame_coalescing.step);

        // Packet module tests
        const test_packet_types = addTst(b, testlog_mod, compat_mod, "tests/unit/packet/test_types.zig", target, optimize);
        test_packet_types.root_module.addImport("types", packet_types_mod);
        const run_test_packet_types = b.addRunArtifact(test_packet_types);
        test_step.dependOn(&run_test_packet_types.step);

        const test_packet_header = addTst(b, testlog_mod, compat_mod, "tests/unit/packet/test_header.zig", target, optimize);
        test_packet_header.root_module.addImport("header", packet_header_mod);
        test_packet_header.root_module.addImport("types", packet_types_mod);
        const run_test_packet_header = b.addRunArtifact(test_packet_header);
        test_step.dependOn(&run_test_packet_header.step);

        const test_packet_packet = addTst(b, testlog_mod, compat_mod, "tests/unit/packet/test_packet.zig", target, optimize);
        test_packet_packet.root_module.addImport("packet", quic_packet_mod);
        const run_test_packet_packet = b.addRunArtifact(test_packet_packet);
        test_step.dependOn(&run_test_packet_packet.step);

        // Version module tests
        const test_version = addTst(b, testlog_mod, compat_mod, "tests/unit/version/test_version.zig", target, optimize);
        test_version.root_module.addImport("version", quic_version_mod);
        const run_test_version = b.addRunArtifact(test_version);
        test_step.dependOn(&run_test_version.step);

        // Recovery module tests
        const test_recovery_types = addTst(b, testlog_mod, compat_mod, "tests/unit/recovery/test_types.zig", target, optimize);
        test_recovery_types.root_module.addImport("types", recovery_types_mod);
        const run_test_recovery_types = b.addRunArtifact(test_recovery_types);
        test_step.dependOn(&run_test_recovery_types.step);

        const test_recovery_rtt = addTst(b, testlog_mod, compat_mod, "tests/unit/recovery/test_rtt.zig", target, optimize);
        test_recovery_rtt.root_module.addImport("rtt", recovery_rtt_mod);
        const run_test_recovery_rtt = b.addRunArtifact(test_recovery_rtt);
        test_step.dependOn(&run_test_recovery_rtt.step);

        const test_recovery_loss_detection = addTst(b, testlog_mod, compat_mod, "tests/unit/recovery/test_loss_detection.zig", target, optimize);
        test_recovery_loss_detection.root_module.addImport("loss_detection", recovery_loss_detection_mod);
        test_recovery_loss_detection.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery_loss_detection = b.addRunArtifact(test_recovery_loss_detection);
        test_step.dependOn(&run_test_recovery_loss_detection.step);

        const test_recovery_congestion = addTst(b, testlog_mod, compat_mod, "tests/unit/recovery/test_congestion.zig", target, optimize);
        test_recovery_congestion.root_module.addImport("congestion", recovery_congestion_mod);
        const run_test_recovery_congestion = b.addRunArtifact(test_recovery_congestion);
        test_step.dependOn(&run_test_recovery_congestion.step);

        const test_recovery_recovery = addTst(b, testlog_mod, compat_mod, "tests/unit/recovery/test_recovery.zig", target, optimize);
        test_recovery_recovery.root_module.addImport("recovery", quic_recovery_mod);
        test_recovery_recovery.root_module.addImport("frame", quic_frame_mod);
        const run_test_recovery_recovery = b.addRunArtifact(test_recovery_recovery);
        test_step.dependOn(&run_test_recovery_recovery.step);

        // ====================================================================
        // Algorithm Module Tests (Geode Extraction)
        // ====================================================================
        // Inline tests in each algorithm source file
        const test_algo_drr = addTst(b, testlog_mod, compat_mod, "src/quic/algorithms/drr.zig", target, optimize);
        const run_test_algo_drr = b.addRunArtifact(test_algo_drr);
        test_step.dependOn(&run_test_algo_drr.step);

        const test_algo_congestion = addTst(b, testlog_mod, compat_mod, "src/quic/algorithms/congestion_newreno.zig", target, optimize);
        const run_test_algo_congestion = b.addRunArtifact(test_algo_congestion);
        test_step.dependOn(&run_test_algo_congestion.step);

        const test_algo_loss = addTst(b, testlog_mod, compat_mod, "src/quic/algorithms/loss_recovery.zig", target, optimize);
        const run_test_algo_loss = b.addRunArtifact(test_algo_loss);
        test_step.dependOn(&run_test_algo_loss.step);

        const test_algo_timer = addTst(b, testlog_mod, compat_mod, "src/quic/algorithms/timer_heap.zig", target, optimize);
        const run_test_algo_timer = b.addRunArtifact(test_algo_timer);
        test_step.dependOn(&run_test_algo_timer.step);

        const test_algo_shard = addTst(b, testlog_mod, compat_mod, "src/quic/algorithms/sharding.zig", target, optimize);
        const run_test_algo_shard = b.addRunArtifact(test_algo_shard);
        test_step.dependOn(&run_test_algo_shard.step);

        // Stream scheduler (inline tests)
        const test_stream_sched = addTst(b, testlog_mod, compat_mod, "src/quic/stream_scheduler.zig", target, optimize);
        const run_test_stream_sched = b.addRunArtifact(test_stream_sched);
        test_step.dependOn(&run_test_stream_sched.step);

        // Connection manager (inline tests, needs algorithm imports)
        const test_conn_mgr = addTst(b, testlog_mod, compat_mod, "src/quic/connection_manager.zig", target, optimize);
        test_conn_mgr.root_module.addImport("drr", algo_drr_mod);
        test_conn_mgr.root_module.addImport("congestion", algo_congestion_mod);
        test_conn_mgr.root_module.addImport("loss_recovery", algo_loss_recovery_mod);
        test_conn_mgr.root_module.addImport("timer_heap", algo_timer_heap_mod);
        test_conn_mgr.root_module.addImport("sharding", algo_sharding_mod);
        const run_test_conn_mgr = b.addRunArtifact(test_conn_mgr);
        test_step.dependOn(&run_test_conn_mgr.step);

        // Integration test for all algorithms working together
        const test_algo_integration = addTst(b, testlog_mod, compat_mod, "tests/integration/test_algorithms_integration.zig", target, optimize);
        test_algo_integration.root_module.addImport("drr", algo_drr_mod);
        test_algo_integration.root_module.addImport("congestion", algo_congestion_mod);
        test_algo_integration.root_module.addImport("loss_recovery", algo_loss_recovery_mod);
        test_algo_integration.root_module.addImport("timer_heap", algo_timer_heap_mod);
        test_algo_integration.root_module.addImport("sharding", algo_sharding_mod);
        test_algo_integration.root_module.addImport("connection_manager", connection_manager_mod);
        const run_test_algo_integration = b.addRunArtifact(test_algo_integration);
        test_step.dependOn(&run_test_algo_integration.step);

        const test_tls_record = addTst(b, testlog_mod, compat_mod, "tests/test_tls_record_layer.zig", target, optimize);
        test_tls_record.root_module.addImport("tls_record", tls_record_mod);
        const run_test_tls_record = b.addRunArtifact(test_tls_record);
        test_step.dependOn(&run_test_tls_record.step);

        const test_tls_context = addTst(b, testlog_mod, compat_mod, "tests/test_tls_handshake_context.zig", target, optimize);
        test_tls_context.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_context.root_module.addImport("quic_tls", quic_tls_mod);
        test_tls_context.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        test_tls_context.root_module.addImport("test_certs", test_certs_mod);
        const run_test_tls_context = b.addRunArtifact(test_tls_context);
        test_step.dependOn(&run_test_tls_context.step);

        const test_tls_server_flight = addTst(b, testlog_mod, compat_mod, "tests/test_tls_server_handshake_flight.zig", target, optimize);
        test_tls_server_flight.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_tls_server_flight = b.addRunArtifact(test_tls_server_flight);
        test_step.dependOn(&run_test_tls_server_flight.step);

        const test_tls = addTst(b, testlog_mod, compat_mod, "tests/test_tls_key_schedule.zig", target, optimize);
        test_tls.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls = b.addRunArtifact(test_tls);
        test_step.dependOn(&run_test_tls.step);

        const test_tls_hs = addTst(b, testlog_mod, compat_mod, "tests/test_tls_handshake_secrets.zig", target, optimize);
        const test_tls_keyupdate = addTst(b, testlog_mod, compat_mod, "tests/test_tls_key_update_exporter.zig", target, optimize);
        test_tls_keyupdate.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_keyupdate.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_keyupdate = b.addRunArtifact(test_tls_keyupdate);
        test_step.dependOn(&run_test_tls_keyupdate.step);
        test_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_hs = b.addRunArtifact(test_tls_hs);
        test_step.dependOn(&run_test_tls_hs.step);

        const test_tls_integration = addTst(b, testlog_mod, compat_mod, "tests/test_tls_integration.zig", target, optimize);
        test_tls_integration.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_integration.root_module.addImport("alert", alert_mod);
        test_tls_integration.root_module.addImport("zero_rtt", zero_rtt_mod);
        const run_test_tls_integration = b.addRunArtifact(test_tls_integration);
        test_step.dependOn(&run_test_tls_integration.step);

        const test_initial = addTst(b, testlog_mod, compat_mod, "tests/test_initial_protect.zig", target, optimize);
        test_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_initial.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_initial = b.addRunArtifact(test_initial);
        test_step.dependOn(&run_test_initial.step);

        const test_rfc_a1 = addTst(b, testlog_mod, compat_mod, "tests/test_rfc9001_a1_initial.zig", target, optimize);
        test_rfc_a1.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a1.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a1.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a1 = b.addRunArtifact(test_rfc_a1);
        test_step.dependOn(&run_test_rfc_a1.step);

        const test_rfc_a3 = addTst(b, testlog_mod, compat_mod, "tests/test_rfc9001_a3_server_initial.zig", target, optimize);
        test_rfc_a3.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a3.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a3.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a3 = b.addRunArtifact(test_rfc_a3);
        test_step.dependOn(&run_test_rfc_a3.step);

        const test_crypto_extract = addTst(b, testlog_mod, compat_mod, "tests/test_crypto_extract.zig", target, optimize);
        test_crypto_extract.root_module.addImport("quic_tls", quic_tls_mod);
        test_crypto_extract.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_crypto_extract.root_module.addImport("quic_packet", quic_packet_mod);
        test_crypto_extract.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_crypto_extract = b.addRunArtifact(test_crypto_extract);
        test_step.dependOn(&run_test_crypto_extract.step);

        const test_recovery = addTst(b, testlog_mod, compat_mod, "tests/test_recovery.zig", target, optimize);
        test_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
        test_recovery.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery = b.addRunArtifact(test_recovery);
        test_step.dependOn(&run_test_recovery.step);

        const test_loop = addTst(b, testlog_mod, compat_mod, "tests/test_initial_handshake_loop.zig", target, optimize);
        test_loop.root_module.addImport("quic_tls", quic_tls_mod);
        test_loop.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_loop.root_module.addImport("quic_packet", quic_packet_mod);
        test_loop.root_module.addImport("quic_frame", quic_frame_mod);
        test_loop.root_module.addImport("quic_tls13", tls13_mod);
        test_loop.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_loop = b.addRunArtifact(test_loop);
        test_step.dependOn(&run_test_loop.step);

        const test_server_initial = addTst(b, testlog_mod, compat_mod, "tests/test_server_initial_response.zig", target, optimize);
        test_server_initial.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_initial.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_initial.root_module.addImport("quic_api", quic_api_mod);
        test_server_initial.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_initial.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_initial.root_module.addImport("quic_varint", quic_varint_mod);
        test_server_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_initial.root_module.addImport("config.zig", quic_config_mod);
        test_server_initial.root_module.addImport("test_certs", test_certs_mod);
        const run_test_server_initial = b.addRunArtifact(test_server_initial);
        test_step.dependOn(&run_test_server_initial.step);

        const test_server_processing = addTst(b, testlog_mod, compat_mod, "tests/test_server_initial_processing.zig", target, optimize);
        test_server_processing.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_processing.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_processing.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_processing.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_processing.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_processing.root_module.addImport("config.zig", quic_config_mod);
        test_server_processing.root_module.addImport("test_certs", test_certs_mod);
        const run_test_server_processing = b.addRunArtifact(test_server_processing);
        test_step.dependOn(&run_test_server_processing.step);

        const test_sh = addTst(b, testlog_mod, compat_mod, "tests/test_shortrtt_roundtrip.zig", target, optimize);
        test_sh.root_module.addImport("quic_tls13", tls13_mod);
        test_sh.root_module.addImport("quic_packet", quic_packet_mod);
        test_sh.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_sh = b.addRunArtifact(test_sh);
        test_step.dependOn(&run_test_sh.step);

        // Regression test for RFC 8446 transcript hash handling in 1-RTT key derivation
        const test_transcript = addTst(b, testlog_mod, compat_mod, "tests/test_transcript_hash.zig", target, optimize);
        test_transcript.root_module.addImport("quic_tls13", tls13_mod);
        test_transcript.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_transcript = b.addRunArtifact(test_transcript);
        test_step.dependOn(&run_test_transcript.step);

        const test_pn = addTst(b, testlog_mod, compat_mod, "tests/test_pn_expansion.zig", target, optimize);
        test_pn.root_module.addImport("quic_tls13", tls13_mod);
        test_pn.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_pn = b.addRunArtifact(test_pn);
        test_step.dependOn(&run_test_pn.step);

        const test_tp = addTst(b, testlog_mod, compat_mod, "tests/test_transport_params.zig", target, optimize);
        test_tp.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_tp = b.addRunArtifact(test_tp);
        test_step.dependOn(&run_test_tp.step);

        const test_timers = addTst(b, testlog_mod, compat_mod, "tests/test_timers.zig", target, optimize);
        test_timers.root_module.addImport("quic_api", quic_api_mod);
        test_timers.root_module.addImport("quic_conn", quic_conn_mod);
        test_timers.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_timers = b.addRunArtifact(test_timers);
        test_step.dependOn(&run_test_timers.step);

        const test_vn = addTst(b, testlog_mod, compat_mod, "tests/test_version_negotiation.zig", target, optimize);
        test_vn.root_module.addImport("quic_packet", quic_packet_mod);
        test_vn.root_module.addImport("quic_conn", quic_conn_mod);
        test_vn.root_module.addImport("incoming", endpoint_incoming_mod);
        test_vn.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_vn.root_module.addImport("config", quic_config_mod);
        test_vn.root_module.addImport("quic_api", quic_api_mod);
        test_vn.root_module.addImport("test_certs", test_certs_mod);
        const run_test_vn = b.addRunArtifact(test_vn);
        test_step.dependOn(&run_test_vn.step);

        // Zero-length connection ID tests (RFC 9000 §12.2 / TLS Error 266 regression)
        const test_zero_scid = addTst(b, testlog_mod, compat_mod, "tests/test_zero_length_scid_coalescing.zig", target, optimize);
        test_zero_scid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid.root_module.addImport("quic_frame", quic_frame_mod);
        test_zero_scid.root_module.addImport("quic_varint", quic_varint_mod);
        test_zero_scid.root_module.addImport("quic_tls", quic_tls_mod);
        test_zero_scid.root_module.addImport("config.zig", quic_config_mod);
        test_zero_scid.root_module.addImport("test_certs", test_certs_mod);
        const run_test_zero_scid = b.addRunArtifact(test_zero_scid);
        test_step.dependOn(&run_test_zero_scid.step);

        const test_pto_zero_dcid = addTst(b, testlog_mod, compat_mod, "tests/test_pto_probe_zero_length_dcid.zig", target, optimize);
        test_pto_zero_dcid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_pto_zero_dcid.root_module.addImport("quic_conn", quic_conn_mod);
        test_pto_zero_dcid.root_module.addImport("quic_packet", quic_packet_mod);
        test_pto_zero_dcid.root_module.addImport("quic_frame", quic_frame_mod);
        test_pto_zero_dcid.root_module.addImport("quic_tls", quic_tls_mod);
        test_pto_zero_dcid.root_module.addImport("config.zig", quic_config_mod);
        test_pto_zero_dcid.root_module.addImport("test_certs", test_certs_mod);
        const run_test_pto_zero_dcid = b.addRunArtifact(test_pto_zero_dcid);
        test_step.dependOn(&run_test_pto_zero_dcid.step);

        // New: Retry issuance and amplification gating tests
        const test_retry = addTst(b, testlog_mod, compat_mod, "tests/test_retry.zig", target, optimize);
        test_retry.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry.root_module.addImport("quic_frame", quic_frame_mod);
        test_retry.root_module.addImport("test_certs", test_certs_mod);
        test_retry.root_module.addImport("config.zig", quic_config_mod);
        const run_test_retry = b.addRunArtifact(test_retry);
        test_step.dependOn(&run_test_retry.step);

        const test_retry_tamper = addTst(b, testlog_mod, compat_mod, "tests/test_retry_tamper.zig", target, optimize);
        test_retry_tamper.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry_tamper.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry_tamper.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry_tamper.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry_tamper.root_module.addImport("quic_frame", quic_frame_mod);
        test_retry_tamper.root_module.addImport("test_certs", test_certs_mod);
        test_retry_tamper.root_module.addImport("config.zig", quic_config_mod);
        const run_test_retry_tamper = b.addRunArtifact(test_retry_tamper);
        test_step.dependOn(&run_test_retry_tamper.step);

        const test_amp = addTst(b, testlog_mod, compat_mod, "tests/test_amplification.zig", target, optimize);
        test_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_amp.root_module.addImport("quic_packet", quic_packet_mod);
        test_amp.root_module.addImport("quic_varint", quic_varint_mod);
        test_amp.root_module.addImport("quic_tls", quic_tls_mod);
        test_amp.root_module.addImport("quic_frame", quic_frame_mod);
        test_amp.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_amp = b.addRunArtifact(test_amp);
        test_step.dependOn(&run_test_amp.step);

        // ALPN enforcement and getter tests
        const test_alpn = addTst(b, testlog_mod, compat_mod, "tests/test_alpn.zig", target, optimize);
        test_alpn.root_module.addImport("quic_api", quic_api_mod);
        test_alpn.root_module.addImport("quic_conn", quic_conn_mod);
        test_alpn.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_alpn = b.addRunArtifact(test_alpn);
        test_step.dependOn(&run_test_alpn.step);

        const test_conn_metadata = addTst(b, testlog_mod, compat_mod, "tests/test_conn_metadata.zig", target, optimize);
        test_conn_metadata.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_metadata.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_conn_metadata = b.addRunArtifact(test_conn_metadata);
        test_step.dependOn(&run_test_conn_metadata.step);

        const test_conn_server_name = addTst(b, testlog_mod, compat_mod, "tests/test_connection_server_name.zig", target, optimize);
        test_conn_server_name.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_server_name.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_conn_server_name = b.addRunArtifact(test_conn_server_name);
        test_step.dependOn(&run_test_conn_server_name.step);

        // Regression test for TLS Error 266 (zero-length SCID in 1-RTT packets)
        const test_zero_scid_1rtt = addTst(b, testlog_mod, compat_mod, "tests/test_zero_length_scid_1rtt.zig", target, optimize);
        test_zero_scid_1rtt.root_module.addImport("quic_api", quic_api_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_zero_scid_1rtt = b.addRunArtifact(test_zero_scid_1rtt);
        test_step.dependOn(&run_test_zero_scid_1rtt.step);

        // TLS SNI negative/allow_insecure tests
        const test_tls_sni = addTst(b, testlog_mod, compat_mod, "tests/test_tls_sni.zig", target, optimize);
        test_tls_sni.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_sni = b.addRunArtifact(test_tls_sni);
        test_step.dependOn(&run_test_tls_sni.step);

        // TLS validity window KATs
        const test_tls_validity = addTst(b, testlog_mod, compat_mod, "tests/test_tls_validity.zig", target, optimize);
        test_tls_validity.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_validity = b.addRunArtifact(test_tls_validity);
        test_step.dependOn(&run_test_tls_validity.step);

        // 0-RTT tests
        const test_0rtt = addTst(b, testlog_mod, compat_mod, "tests/test_0rtt.zig", target, optimize);
        test_0rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_0rtt.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_0rtt.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_0rtt = b.addRunArtifact(test_0rtt);
        test_step.dependOn(&run_test_0rtt.step);

        // Session resumption tests
        const test_resumption = addTst(b, testlog_mod, compat_mod, "tests/test_resumption.zig", target, optimize);
        test_resumption.root_module.addImport("quic_tls13", tls13_mod);
        test_resumption.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_resumption = b.addRunArtifact(test_resumption);
        test_step.dependOn(&run_test_resumption.step);

        // Connection migration tests
        const test_conn_migration = addTst(b, testlog_mod, compat_mod, "tests/test_connection_migration.zig", target, optimize);
        test_conn_migration.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_conn_migration.root_module.addImport("quic_frame", quic_frame_mod);
        test_conn_migration.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_conn_migration = b.addRunArtifact(test_conn_migration);
        test_step.dependOn(&run_test_conn_migration.step);

        // Preferred address tests
        const test_pref_addr = addTst(b, testlog_mod, compat_mod, "tests/test_preferred_address.zig", target, optimize);
        test_pref_addr.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_pref_addr = b.addRunArtifact(test_pref_addr);
        test_step.dependOn(&run_test_pref_addr.step);

        // TLS KU/EKU and malformed DER tests
        const test_kus_ekus = addTst(b, testlog_mod, compat_mod, "tests/test_tls_kus_ekus.zig", target, optimize);
        test_kus_ekus.root_module.addImport("quic_x509", x509_mod);
        const run_test_kus_ekus = b.addRunArtifact(test_kus_ekus);
        test_step.dependOn(&run_test_kus_ekus.step);

        // AEAD/HP KATs
        const test_hp_aead = addTst(b, testlog_mod, compat_mod, "tests/test_hp_aead_kats.zig", target, optimize);
        test_hp_aead.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_hp_aead.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_hp_aead = b.addRunArtifact(test_hp_aead);
        test_step.dependOn(&run_test_hp_aead.step);

        // ECN longitudinal multi-ACK across spaces
        const test_ecn_long = addTst(b, testlog_mod, compat_mod, "tests/test_ecn_longitudinal.zig", target, optimize);
        test_ecn_long.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_ecn_long.root_module.addImport("quic_packet", quic_packet_mod);
        test_ecn_long.root_module.addImport("quic_frame", quic_frame_mod);
        test_ecn_long.root_module.addImport("quic_tls", quic_tls_mod);
        test_ecn_long.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_ecn_long.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_ecn_long = b.addRunArtifact(test_ecn_long);
        test_step.dependOn(&run_test_ecn_long.step);

        // RX Key Update acceptance tests
        const test_rx_ku = addTst(b, testlog_mod, compat_mod, "tests/test_rx_key_update_accept.zig", target, optimize);
        test_rx_ku.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_rx_ku.root_module.addImport("quic_packet", quic_packet_mod);
        test_rx_ku.root_module.addImport("quic_tls13", tls13_mod);
        test_rx_ku.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_rx_ku = b.addRunArtifact(test_rx_ku);
        test_step.dependOn(&run_test_rx_ku.step);

        // Key update lifecycle (RFC 9001 §5.4 / §6 / §6.6) -- closes the
        // executable-coverage half of GAP-0013 against deriveNextTrafficSecret,
        // setAeadUsageLimits, and maybeTriggerKeyUpdateOnSend.
        const test_ku_lifecycle = addTst(b, testlog_mod, compat_mod, "tests/test_key_update_lifecycle.zig", target, optimize);
        test_ku_lifecycle.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_ku_lifecycle.root_module.addImport("quic_packet", quic_packet_mod);
        test_ku_lifecycle.root_module.addImport("quic_tls", quic_tls_mod);
        test_ku_lifecycle.root_module.addImport("quic_key_update", conn_key_update_mod);
        const run_test_ku_lifecycle = b.addRunArtifact(test_ku_lifecycle);
        test_step.dependOn(&run_test_ku_lifecycle.step);

        // PMTUD/DPLPMTUD probe sizing + ICMP clamp tests
        const test_pmtud = addTst(b, testlog_mod, compat_mod, "tests/test_pmtud.zig", target, optimize);
        test_pmtud.root_module.addImport("quic_api", quic_api_mod);
        test_pmtud.root_module.addImport("quic_conn", quic_conn_mod);
        test_pmtud.root_module.addImport("quic_packet", quic_packet_mod);
        test_pmtud.root_module.addImport("quic_frame", quic_frame_mod);
        test_pmtud.root_module.addImport("quic_tls13", tls13_mod);
        test_pmtud.root_module.addImport("quic_tls", quic_tls_mod);
        test_pmtud.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_pmtud = b.addRunArtifact(test_pmtud);
        test_step.dependOn(&run_test_pmtud.step);

        // ========================================================================
        // Phase 14: Integration Tests (RFC 9000 Tier 1)
        // ========================================================================

        // RFC 9000 Section 7 - Connection Establishment (26 tests)
        const test_rfc9000_section7 = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9000_section7.zig", target, optimize);
        test_rfc9000_section7.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_section7.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_section7.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_section7.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        // Note: harness is available through scenarios and connection_pair imports
        const run_test_rfc9000_section7 = b.addRunArtifact(test_rfc9000_section7);
        test_step.dependOn(&run_test_rfc9000_section7.step);

        // RFC 9000 Section 8 - Address Validation (Tier 2 Step 4 - 30 tests)
        const test_rfc9000_section8 = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9000_section8.zig", target, optimize);
        test_rfc9000_section8.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_section8.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_section8.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_section8.root_module.addImport("loopback", loopback_mod);
        test_rfc9000_section8.root_module.addImport("quic_conn", quic_conn_mod);
        test_rfc9000_section8.root_module.addImport("quic_connection_amplification", conn_amplification_mod);
        const run_test_rfc9000_section8 = b.addRunArtifact(test_rfc9000_section8);
        test_step.dependOn(&run_test_rfc9000_section8.step);

        // RFC 9000 Section 4 - Flow Control (Tier 2 Step 6 - 54 tests)
        const test_flow_control = addTst(b, testlog_mod, compat_mod, "tests/integration/flow_control.zig", target, optimize);
        test_flow_control.root_module.addImport("scenarios", scenarios_mod);
        test_flow_control.root_module.addImport("connection_pair", connection_pair_mod);
        test_flow_control.root_module.addImport("harness", integration_harness_mod);
        test_flow_control.root_module.addImport("loopback", loopback_mod);
        const run_test_flow_control = b.addRunArtifact(test_flow_control);
        test_step.dependOn(&run_test_flow_control.step);

        // RFC 9000 Section 9 - Connection Migration (Tier 2 Step 5 - 46 tests)
        const test_migration = addTst(b, testlog_mod, compat_mod, "tests/integration/migration.zig", target, optimize);
        test_migration.root_module.addImport("scenarios", scenarios_mod);
        test_migration.root_module.addImport("connection_pair", connection_pair_mod);
        test_migration.root_module.addImport("harness", integration_harness_mod);
        test_migration.root_module.addImport("loopback", loopback_mod);
        const run_test_migration = b.addRunArtifact(test_migration);
        test_step.dependOn(&run_test_migration.step);

        // RFC 9000 - Packet Processing Tests (Phase 21.3)
        const test_rfc9000_packets = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9000_packets.zig", target, optimize);
        test_rfc9000_packets.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_packets.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_packets.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_packets.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_packets.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_packets = b.addRunArtifact(test_rfc9000_packets);
        test_step.dependOn(&run_test_rfc9000_packets.step);

        // RFC 9002 - Loss Recovery Tests (Phase 21.4)
        const test_rfc9002_recovery = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9002_recovery.zig", target, optimize);
        test_rfc9002_recovery.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9002_recovery.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9002_recovery.root_module.addImport("loss_recovery_helpers", loss_recovery_helpers_mod);
        test_rfc9002_recovery.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9002_recovery.root_module.addImport("harness", integration_harness_mod);
        test_rfc9002_recovery.root_module.addImport("loopback", loopback_mod);
        test_rfc9002_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
        test_rfc9002_recovery.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_rfc9002_recovery = b.addRunArtifact(test_rfc9002_recovery);
        test_step.dependOn(&run_test_rfc9002_recovery.step);

        // RFC 9000 - Advanced Features Tests (Phase 21.5)
        const test_rfc9000_advanced = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9000_advanced.zig", target, optimize);
        test_rfc9000_advanced.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_advanced.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_advanced.root_module.addImport("advanced_features_helpers", advanced_features_helpers_mod);
        test_rfc9000_advanced.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_advanced.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_advanced.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_advanced = b.addRunArtifact(test_rfc9000_advanced);
        test_step.dependOn(&run_test_rfc9000_advanced.step);

        // RFC 9000 - Medium Priority Features Tests (Phase 22)
        const test_rfc9000_medium = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9000_medium.zig", target, optimize);
        test_rfc9000_medium.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_medium.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_medium.root_module.addImport("medium_priority_helpers", medium_priority_helpers_mod);
        test_rfc9000_medium.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_medium.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_medium.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_medium = b.addRunArtifact(test_rfc9000_medium);
        test_step.dependOn(&run_test_rfc9000_medium.step);

        // RFC 9001 - Advanced TLS Features Tests (Phase 23)
        const test_rfc9001_advanced = addTst(b, testlog_mod, compat_mod, "tests/integration/rfc9001_advanced.zig", target, optimize);
        test_rfc9001_advanced.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9001_advanced.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9001_advanced.root_module.addImport("low_priority_helpers", low_priority_helpers_mod);
        test_rfc9001_advanced.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9001_advanced.root_module.addImport("harness", integration_harness_mod);
        test_rfc9001_advanced.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9001_advanced = b.addRunArtifact(test_rfc9001_advanced);
        test_step.dependOn(&run_test_rfc9001_advanced.step);

        // RFC 9001 §6 - Key Update Tests (Tier 3 Step 7 - 61 tests)
        const test_key_update = addTst(b, testlog_mod, compat_mod, "tests/integration/key_update.zig", target, optimize);
        test_key_update.root_module.addImport("scenarios", scenarios_mod);
        test_key_update.root_module.addImport("connection_pair", connection_pair_mod);
        test_key_update.root_module.addImport("harness", integration_harness_mod);
        test_key_update.root_module.addImport("loopback", loopback_mod);
        const run_test_key_update = b.addRunArtifact(test_key_update);
        test_step.dependOn(&run_test_key_update.step);

        // RFC 9001 §4.6 - 0-RTT and Session Resumption Tests (Tier 3 Step 8 - 72 tests)
        const test_zero_rtt = addTst(b, testlog_mod, compat_mod, "tests/integration/zero_rtt.zig", target, optimize);
        test_zero_rtt.root_module.addImport("scenarios", scenarios_mod);
        test_zero_rtt.root_module.addImport("connection_pair", connection_pair_mod);
        test_zero_rtt.root_module.addImport("harness", integration_harness_mod);
        test_zero_rtt.root_module.addImport("loopback", loopback_mod);
        const run_test_zero_rtt = b.addRunArtifact(test_zero_rtt);
        test_step.dependOn(&run_test_zero_rtt.step);

        // Stress and Performance Tests (Tier 3 Step 9 - 46 tests)
        const test_stress = addTst(b, testlog_mod, compat_mod, "tests/integration/stress/stress.zig", target, optimize);
        test_stress.root_module.addImport("scenarios", scenarios_mod);
        test_stress.root_module.addImport("connection_pair", connection_pair_mod);
        test_stress.root_module.addImport("harness", integration_harness_mod);
        const run_test_stress = b.addRunArtifact(test_stress);
        test_step.dependOn(&run_test_stress.step);

        // Fault Injection Tests (Tier 3 Step 9 - 62 tests)
        const test_fault = addTst(b, testlog_mod, compat_mod, "tests/integration/fault/fault.zig", target, optimize);
        test_fault.root_module.addImport("scenarios", scenarios_mod);
        test_fault.root_module.addImport("connection_pair", connection_pair_mod);
        test_fault.root_module.addImport("harness", integration_harness_mod);
        test_fault.root_module.addImport("loopback", loopback_mod);
        const run_test_fault = b.addRunArtifact(test_fault);
        test_step.dependOn(&run_test_fault.step);

        // Interoperability Tests (Tier 3 Step 10 - 48 tests)
        const test_interop = addTst(b, testlog_mod, compat_mod, "tests/integration/interop/interop.zig", target, optimize);
        test_interop.root_module.addImport("scenarios", scenarios_mod);
        test_interop.root_module.addImport("harness", integration_harness_mod);
        const run_test_interop = b.addRunArtifact(test_interop);
        test_step.dependOn(&run_test_interop.step);

        // CI/CD Helpers Unit Tests (Phase 24)
        const test_ci_helpers = addTst(b, testlog_mod, compat_mod, "tests/integration/ci_helpers.zig", target, optimize);
        const run_test_ci_helpers = b.addRunArtifact(test_ci_helpers);
        test_step.dependOn(&run_test_ci_helpers.step);

        // GAP-0200: Thread-Safety Unit Tests
        const test_thread_safety = addTst(b, testlog_mod, compat_mod, "tests/test_thread_safety.zig", target, optimize);
        test_thread_safety.root_module.addImport("quic", quic_api_mod);
        test_thread_safety.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_thread_safety.root_module.addImport("quic_conn", quic_conn_mod);
        test_thread_safety.root_module.addImport("quic_config", quic_config_mod);
        const run_test_thread_safety = b.addRunArtifact(test_thread_safety);
        test_step.dependOn(&run_test_thread_safety.step);

        // Concurrent load tests for thread-safety validation
        const test_concurrent_load = addTst(b, testlog_mod, compat_mod, "tests/test_concurrent_load.zig", target, optimize);
        test_concurrent_load.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_concurrent_load.root_module.addImport("quic_conn", quic_conn_mod);
        test_concurrent_load.root_module.addImport("quic_config", quic_config_mod);
        const run_test_concurrent_load = b.addRunArtifact(test_concurrent_load);
        test_step.dependOn(&run_test_concurrent_load.step);

        const test_high_parallel = addTst(b, testlog_mod, compat_mod, "tests/test_high_parallel_stream_progress.zig", target, optimize);
        test_high_parallel.root_module.addImport("quic_api", quic_api_mod);
        test_high_parallel.root_module.addImport("quic_config", quic_config_mod);
        test_high_parallel.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_high_parallel = b.addRunArtifact(test_high_parallel);
        test_step.dependOn(&run_test_high_parallel.step);

        // Poll loop performance regression tests
        const test_poll_perf = addTst(b, testlog_mod, compat_mod, "tests/test_poll_perf.zig", target, optimize);
        test_poll_perf.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_poll_perf.root_module.addImport("quic_conn", quic_conn_mod);
        test_poll_perf.root_module.addImport("quic_config", quic_config_mod);
        const run_test_poll_perf = b.addRunArtifact(test_poll_perf);
        test_step.dependOn(&run_test_poll_perf.step);

        // Endpoint mutex contention load tests (Geode poll() contention pattern)
        const test_contention_load = addTst(b, testlog_mod, compat_mod, "tests/test_contention_load.zig", target, optimize);
        test_contention_load.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_contention_load.root_module.addImport("quic_conn", quic_conn_mod);
        test_contention_load.root_module.addImport("quic_config", quic_config_mod);
        const run_test_contention_load = b.addRunArtifact(test_contention_load);
        test_step.dependOn(&run_test_contention_load.step);

        // Geode transport-compat coverage for high-level transport API parity.
        const test_transport_geode_compat = addTst(b, testlog_mod, compat_mod, "tests/test_transport_geode_compat.zig", target, optimize);
        test_transport_geode_compat.root_module.addImport("transport", transport_public);
        const run_test_transport_geode_compat = b.addRunArtifact(test_transport_geode_compat);
        test_step.dependOn(&run_test_transport_geode_compat.step);

        // QUIC-H3-001..004: resetStream API, datagram plumbing, pollReady, writable signals
        const test_reset_stream_api = addTst(b, testlog_mod, compat_mod, "tests/test_reset_stream_api.zig", target, optimize);
        test_reset_stream_api.root_module.addImport("quic_api", quic_api_mod);
        test_reset_stream_api.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_reset_stream_api = b.addRunArtifact(test_reset_stream_api);
        test_step.dependOn(&run_test_reset_stream_api.step);
    } else if (!legacy_tests) {
        // Fast default graph: grouped smoke suite keeps `zig build test` responsive.
        // Use `zig build -Dfull-test-graph=true test` for full per-file coverage.
        const test_smoke = addTst(b, testlog_mod, compat_mod, "tests/smoke.zig", target, optimize);
        test_smoke.root_module.addImport("quic", quic_mod);
        test_smoke.root_module.addImport("transport", transport_public);
        test_smoke.root_module.addImport("byteorder", byteorder_mod);
        test_smoke.root_module.addImport("version", quic_version_mod);
        const run_test_smoke = b.addRunArtifact(test_smoke);
        test_step.dependOn(&run_test_smoke.step);

        // RFC 9001 §4.9.2: the client keeps its Handshake keys and the
        // retransmit copy of its Finished until HANDSHAKE_DONE.
        const test_client_hs_keys = addTst(b, testlog_mod, compat_mod, "tests/test_client_hs_key_retention.zig", target, optimize);
        test_client_hs_keys.root_module.addImport("quic_endpoint_handshake_integration", endpoint_handshake_integration_mod);
        test_client_hs_keys.root_module.addImport("quic_conn", quic_conn_mod);
        test_client_hs_keys.root_module.addImport("vendor_ztls_key_schedule", quic_tls_mod);
        const run_test_client_hs_keys = b.addRunArtifact(test_client_hs_keys);
        test_step.dependOn(&run_test_client_hs_keys.step);

        // FIPS-140-3 seam test: proves the crypto_backend seam is reachable
        // and resolves an approved SHA-256 KAT in BOTH -Dfips modes.
        const test_fips_seam = addTst(b, testlog_mod, compat_mod, "tests/fips_seam_test.zig", target, optimize);
        test_fips_seam.root_module.addImport("crypto_backend", crypto_backend_mod);
        const run_test_fips_seam = b.addRunArtifact(test_fips_seam);
        test_step.dependOn(&run_test_fips_seam.step);

        // Token HMAC seam test: the address-validation HMAC now routes through
        // crypto_backend.Mac. A dedicated test file imports the token module by
        // name and pins the seam HMAC round-trip in BOTH -Dfips modes.
        const test_token_seam = addTst(b, testlog_mod, compat_mod, "tests/test_fips_token.zig", target, optimize);
        test_token_seam.root_module.addImport("quic_token", quic_token_mod);
        const run_test_token_seam = b.addRunArtifact(test_token_seam);
        test_step.dependOn(&run_test_token_seam.step);

        // FIPS AEAD selection test: AES-GCM routes through the seam; under
        // -Dfips=true ChaCha20-Poly1305 is rejected (error.Unsupported);
        // under -Dfips=false ChaCha still works. Also covers the parallel
        // header-mask path (Task 4) in both modes.
        const test_fips_aead = addTst(b, testlog_mod, compat_mod, "tests/test_fips_aead_select.zig", target, optimize);
        test_fips_aead.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_fips_aead.root_module.addImport("crypto_backend", crypto_backend_mod);
        if (parallel_mod) |pm| test_fips_aead.root_module.addImport("parallel", pm);
        const run_test_fips_aead = b.addRunArtifact(test_fips_aead);
        test_step.dependOn(&run_test_fips_aead.step);

        // FIPS provider self-test assertion is reachable through the seam in
        // both modes (no-op when off; verifies the provider when on).
        const test_fips_assert = addTst(b, testlog_mod, compat_mod, "tests/test_fips_assert_active.zig", target, optimize);
        test_fips_assert.root_module.addImport("crypto_backend", crypto_backend_mod);
        const run_test_fips_assert = b.addRunArtifact(test_fips_assert);
        test_step.dependOn(&run_test_fips_assert.step);

        // Observability seam tests. The disabled-mode test runs under
        // both flag values (skip-guarded internally). The enabled-mode
        // test compiles cleanly under both flags too — its
        // otel-namespace identifiers sit behind `comptime if (enabled)`.
        const observability_disabled_tests = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/observability_disabled_test.zig",
            target,
            optimize,
        );
        observability_disabled_tests.root_module.addImport("quic", quic_mod);
        observability_disabled_tests.root_module.addImport("build_options", build_options_mod);
        const run_observability_disabled_tests = b.addRunArtifact(observability_disabled_tests);
        test_step.dependOn(&run_observability_disabled_tests.step);

        const observability_enabled_tests = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/observability_enabled_test.zig",
            target,
            optimize,
        );
        observability_enabled_tests.root_module.addImport("quic", quic_mod);
        observability_enabled_tests.root_module.addImport("build_options", build_options_mod);
        if (with_otel) {
            // Re-resolve the otel module under the same `with_otel`
            // guard so the smoke test reaches `@import("otel")`.
            const otel_dep = b.lazyDependency("otel", .{
                .target = target,
                .optimize = optimize,
            }) orelse return;
            observability_enabled_tests.root_module.addImport("otel", otel_dep.module("otel"));
        }
        const run_observability_enabled_tests = b.addRunArtifact(observability_enabled_tests);
        test_step.dependOn(&run_observability_enabled_tests.step);

        // Regression: Endpoint.mu <-> poll-worker teardown deadlock (quic
        // v0.1.44, gdb-captured at conn.zig beginEndpointDestroy /
        // endpoint.zig destroyConnections). Pre-fix the forced interleaving
        // hangs; the test fails on a 10 s deadline instead. Lives in the
        // default test graph so every `zig build test` gates it.
        const test_teardown_deadlock = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_endpoint_teardown_deadlock_regression.zig",
            target,
            optimize,
        );
        test_teardown_deadlock.root_module.addImport("quic_api", quic_api_mod);
        test_teardown_deadlock.root_module.addImport("quic_conn", quic_conn_mod);
        test_teardown_deadlock.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_teardown_deadlock = b.addRunArtifact(test_teardown_deadlock);
        test_step.dependOn(&run_test_teardown_deadlock.step);

        // Regression: Phase 4.5 pending-handshake retry used snapshotted
        // connection pointers without mu or an RX pin, so a concurrent
        // destroyBatch could free a connection mid-retry (use-after-free).
        const test_pending_hs_retry_destroy = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_pending_hs_retry_destroy_regression.zig",
            target,
            optimize,
        );
        test_pending_hs_retry_destroy.root_module.addImport("quic_api", quic_api_mod);
        test_pending_hs_retry_destroy.root_module.addImport("quic_conn", quic_conn_mod);
        test_pending_hs_retry_destroy.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_pending_hs_retry_destroy = b.addRunArtifact(test_pending_hs_retry_destroy);
        test_step.dependOn(&run_test_pending_hs_retry_destroy.step);

        // Regression: concurrent-HELLO NoHandshakeKeys race pinned by
        // commit 4b246b2 ("fix(handshake): drive TLS state machine
        // before checking hs_tx_keys"). N=10 client threads fan into
        // one server endpoint; pre-fix ~12/16 such handshakes hit
        // error.NoHandshakeKeys and never recovered. Lives in the
        // default test graph (not behind --full-test-graph) so the
        // regression is gated on every `zig build test` run.
        const test_concurrent_handshake_race = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_concurrent_handshake_race.zig",
            target,
            optimize,
        );
        test_concurrent_handshake_race.root_module.addImport("quic_api", quic_api_mod);
        test_concurrent_handshake_race.root_module.addImport("quic_config", quic_config_mod);
        const run_test_concurrent_handshake_race = b.addRunArtifact(test_concurrent_handshake_race);
        test_step.dependOn(&run_test_concurrent_handshake_race.step);

        // Regression: server-side `pending_hs_send` retry path that pins
        // the host-haleth fix for the
        //   `ERROR: processInitial: sendHandshakePackets failed: NoHandshakeKeys`
        // connection-stranding race. Pre-fix: processInitial logged the
        // error and dropped the handshake-flight emission with no retry,
        // so a single first-tick miss left the connection stalled past
        // the QUIC idle timeout. Post-fix: processInitial sets
        // `conn.pending_hs_send = true` and the endpoint poll loop's
        // Phase 4.5 drain retries `sendHandshakePackets` on subsequent
        // ticks. Lives in the default test graph (not behind
        // --full-test-graph) so the regression is gated on every
        // `zig build test` invocation.
        const test_pending_hs_send = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_pending_hs_send_retry.zig",
            target,
            optimize,
        );
        test_pending_hs_send.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_pending_hs_send.root_module.addImport("quic_conn", quic_conn_mod);
        test_pending_hs_send.root_module.addImport("quic_packet", quic_packet_mod);
        test_pending_hs_send.root_module.addImport("quic_frame", quic_frame_mod);
        test_pending_hs_send.root_module.addImport("quic_tls", quic_tls_mod);
        test_pending_hs_send.root_module.addImport("config.zig", quic_config_mod);
        test_pending_hs_send.root_module.addImport("test_certs", test_certs_mod);
        // FIPS seam: the test's hardcoded x25519-only ClientHello is a
        // non-FIPS key-share; under -Dfips the server CORRECTLY rejects it
        // (UnsupportedKeyShareGroup — X25519 alone is not FIPS-approved, only
        // the X25519MLKEM768 hybrid is). The pending_hs_send retry mechanics
        // under test are crypto-agnostic and fully covered by the -Dfips=false
        // gate, so the test skips under -Dfips=true.
        test_pending_hs_send.root_module.addImport("quic_build_options", build_options_mod);
        const run_test_pending_hs_send = b.addRunArtifact(test_pending_hs_send);
        test_step.dependOn(&run_test_pending_hs_send.step);

        // Regression: long server-initiated response stream stall pinned
        // by docs/BUG_LONG_RESPONSE_STREAM_STALL.md. A server writing
        // >20 KiB on a single bidi stream stalls because cwnd never
        // grows past its initial value once bytes_in_flight catches up.
        // The pre-fix symptom is that the client only reads ~12-18 KiB
        // and never observes FIN. Lives in the default test graph
        // (not gated on --full-test-graph) so the regression is caught
        // on every `zig build test` run.
        const test_long_response_stream_stall = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_long_response_stream_stall.zig",
            target,
            optimize,
        );
        test_long_response_stream_stall.root_module.addImport("quic_api", quic_api_mod);
        test_long_response_stream_stall.root_module.addImport("quic_config", quic_config_mod);
        test_long_response_stream_stall.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_long_response_stream_stall = b.addRunArtifact(test_long_response_stream_stall);
        test_step.dependOn(&run_test_long_response_stream_stall.step);

        // Regression: bulk (1 MiB) single-stream transfer with the
        // receiver's SO_RCVBUF clamped to the Docker/AWS default
        // (~212 KB). Datagram loss at the receiver socket must be
        // recovered; pre-fix the transfer stalled (geode backup create).
        const test_small_rcvbuf_bulk_stream = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_small_rcvbuf_bulk_stream.zig",
            target,
            optimize,
        );
        test_small_rcvbuf_bulk_stream.root_module.addImport("quic_api", quic_api_mod);
        test_small_rcvbuf_bulk_stream.root_module.addImport("quic_config", quic_config_mod);
        test_small_rcvbuf_bulk_stream.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_small_rcvbuf_bulk_stream.root_module.addImport("test_certs", test_certs_mod);
        test_small_rcvbuf_bulk_stream.root_module.addImport("quic_build_options", build_options_mod);
        const run_test_small_rcvbuf_bulk_stream = b.addRunArtifact(test_small_rcvbuf_bulk_stream);
        test_step.dependOn(&run_test_small_rcvbuf_bulk_stream.step);

        // Regression: a client Finished refused with error.WouldBlock is
        // kept and retried through the pending-handshake queue instead of
        // being freed, which stalled the handshake until the idle timeout.
        const test_client_finished_wouldblock = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_client_finished_wouldblock.zig",
            target,
            optimize,
        );
        test_client_finished_wouldblock.root_module.addImport("quic_api", quic_api_mod);
        test_client_finished_wouldblock.root_module.addImport("quic_config", quic_config_mod);
        test_client_finished_wouldblock.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_client_finished_wouldblock.root_module.addImport("test_certs", test_certs_mod);
        test_client_finished_wouldblock.root_module.addImport("quic_build_options", build_options_mod);
        const run_test_client_finished_wouldblock = b.addRunArtifact(test_client_finished_wouldblock);
        test_step.dependOn(&run_test_client_finished_wouldblock.step);

        const test_high_parallel_stream_progress = addTst(
            b,
            testlog_mod,
            compat_mod,
            "tests/test_high_parallel_stream_progress.zig",
            target,
            optimize,
        );
        test_high_parallel_stream_progress.root_module.addImport("quic_api", quic_api_mod);
        test_high_parallel_stream_progress.root_module.addImport("quic_config", quic_config_mod);
        test_high_parallel_stream_progress.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_high_parallel_stream_progress = b.addRunArtifact(test_high_parallel_stream_progress);
        test_step.dependOn(&run_test_high_parallel_stream_progress.step);
    } else {
        const test_quic = addTst(b, testlog_mod, compat_mod, "quic.zig", target, optimize);
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

    // ========================================================================
    // Benchmark suite (benchmarks/ directory)
    //
    const test_receive_accounting = addTst(b, testlog_mod, compat_mod, "tests/test_receive_accounting.zig", target, optimize);
    test_receive_accounting.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    test_receive_accounting.root_module.addImport("transport", endpoint_transport_mod);
    test_receive_accounting.root_module.addImport("config.zig", quic_config_mod);
    const run_receive_accounting = b.addRunArtifact(test_receive_accounting);
    test_step.dependOn(&run_receive_accounting.step);
    b.step("test-receive-accounting", "Run deterministic bounded receive-accounting regressions").dependOn(&run_receive_accounting.step);

    // Phase 3 rewire: the legacy `bench/` directory (quic-bench, bench_tls_*,
    // udp_batch_bench) and its independent v1 scaffolds (poll_bench, scale_bench,
    // throughput_bench, handshake_bench) have been retired. All measurement
    // logic now lives under benchmarks/{micro,integration}/ and is dispatched
    // by benchmarks/bench_runner.zig via --suite=<tier>|<scenario>|all.
    //
    // Step names exposed:
    //   bench                -- primary (was bench-v2). Accepts --list,
    //                           --suite=<filter>, --output=<path> via `-- ...`.
    //   bench-micro          -- shortcut for --suite=micro
    //   bench-integration    -- shortcut for --suite=integration
    //   bench-external       -- shortcut for --suite=external
    //   bench-v2             -- DEPRECATED alias to bench.
    //   bench-poll           -- DEPRECATED alias to --suite=poll_overhead.
    //   bench-scale          -- DEPRECATED alias to --suite=conn_scale.
    //   bench-throughput     -- DEPRECATED alias to --suite=stream_throughput
    //                           (scenario is scheduled for Phase 5 Task 5.2;
    //                           until then the alias exits with "no scenarios
    //                           matched suite='stream_throughput'" (rc=3)).
    //   bench-handshake      -- DEPRECATED alias to --suite=handshake_e2e
    //                           (scheduled for Phase 5 Task 5.1; same behavior
    //                           as bench-throughput until it lands).
    //   bench-compare        -- regression comparator (reads ResultDocument JSON).
    //   test-bench-common    -- bench harness unit tests.
    //   test-bench-compare   -- bench comparator unit tests.
    // ========================================================================

    const bench_common_mod = b.createModule(.{
        .root_source_file = b.path("benchmarks/common.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });

    // Bench harness unit tests
    const bench_common_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/test_bench_common.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_common_test_mod.addImport("bench_common", bench_common_mod);
    const bench_common_test = b.addTest(.{ .root_module = bench_common_test_mod });
    const run_bench_common_test = b.addRunArtifact(bench_common_test);
    const bench_common_test_step = b.step("test-bench-common", "Run bench harness tests");
    bench_common_test_step.dependOn(&run_bench_common_test.step);

    // Regression comparison tool (tier-aware -- reads ResultDocument JSON)
    const bench_compare = addExe(b, "bench-compare", "benchmarks/compare.zig", target, .ReleaseFast);
    bench_compare.root_module.addImport("bench_common", bench_common_mod);
    const install_bench_compare = b.addInstallArtifact(bench_compare, .{});
    const run_bench_compare = b.addRunArtifact(bench_compare);
    if (b.args) |args| run_bench_compare.addArgs(args);
    const bench_compare_step = b.step("bench-compare", "Compare benchmark results against baseline");
    bench_compare_step.dependOn(&install_bench_compare.step);
    bench_compare_step.dependOn(&run_bench_compare.step);

    // Bench comparator unit tests -- exposes compare.zig's helpers (Tier,
    // classify, pctChange) via a module import because Zig 0.16 rejects the
    // direct cross-module `@import("../benchmarks/compare.zig")` form.
    const bench_compare_mod = b.createModule(.{
        .root_source_file = b.path("benchmarks/compare.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_compare_mod.addImport("bench_common", bench_common_mod);
    const bench_compare_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/test_bench_compare.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_compare_test_mod.addImport("bench_compare", bench_compare_mod);
    bench_compare_test_mod.addImport("bench_common", bench_common_mod);
    const bench_compare_test = b.addTest(.{ .root_module = bench_compare_test_mod });
    const run_bench_compare_test = b.addRunArtifact(bench_compare_test);
    const bench_compare_test_step = b.step("test-bench-compare", "Run bench comparator tests");
    bench_compare_test_step.dependOn(&run_bench_compare_test.step);
    // SONNY-4381: a row that could not be measured, on either side, fails the
    // gate (exit 1) instead of comparing placeholder numbers.
    for ([_][2][]const u8{
        .{ "tests/fixtures/bench/measured.json", "tests/fixtures/bench/not_measured.json" },
        .{ "tests/fixtures/bench/not_measured.json", "tests/fixtures/bench/measured.json" },
    }) |pair| {
        const gate_run = b.addRunArtifact(bench_compare);
        gate_run.addArg("--baseline");
        gate_run.addFileArg(b.path(pair[0]));
        gate_run.addArg("--current");
        gate_run.addFileArg(b.path(pair[1]));
        gate_run.expectExitCode(1);
        bench_compare_test_step.dependOn(&gate_run.step);
    }

    // Benchmark suite dispatcher. Scenarios are registered in
    // benchmarks/bench_runner.zig's `registry`; each registry entry picks a
    // tier ("micro"|"integration"|"external") and a list of ScenarioSpec.
    const bench_runner = addExe(b, "bench", "benchmarks/bench_runner.zig", target, .ReleaseFast);
    bench_runner.root_module.addImport("bench_common", bench_common_mod);
    bench_runner.root_module.addImport("quic_varint", quic_varint_mod);
    bench_runner.root_module.addImport("quic_recovery", quic_recovery_mod);
    bench_runner.root_module.addImport("quic_crypto", quic_crypto_mod);
    bench_runner.root_module.addImport("quic_packet", quic_packet_mod);
    bench_runner.root_module.addImport("quic_frame", quic_frame_mod);
    bench_runner.root_module.addImport("compat", compat_mod);
    bench_runner.root_module.addImport("quic_tls", quic_tls_mod);
    bench_runner.root_module.addImport("quic_tls13", tls13_mod);
    bench_runner.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    bench_runner.root_module.addImport("quic_conn", quic_conn_mod);
    bench_runner.root_module.addImport("quic_config", quic_config_mod);
    bench_runner.root_module.addImport("quic_api", quic_api_mod);
    const install_bench_runner = b.addInstallArtifact(bench_runner, .{});

    // Primary `bench` step. User-supplied args (via `zig build bench -- ...`)
    // are forwarded verbatim so --list/--suite=<filter>/--output=<path> work.
    const run_bench_runner = b.addRunArtifact(bench_runner);
    if (b.args) |args| run_bench_runner.addArgs(args);
    const bench_step = b.step("bench", "Run benchmark suite (--suite=all|micro|integration|external|<scenario>, --list, --output=<path>)");
    bench_step.dependOn(&install_bench_runner.step);
    bench_step.dependOn(&run_bench_runner.step);

    // DEPRECATED alias: bench-v2 -> bench. Kept for one release so existing
    // MRs / tooling referencing the pre-rename name keep working.
    const run_bench_v2_alias = b.addRunArtifact(bench_runner);
    if (b.args) |args| run_bench_v2_alias.addArgs(args);
    const bench_v2_step = b.step("bench-v2", "DEPRECATED: use 'bench'. Alias to bench.");
    bench_v2_step.dependOn(&install_bench_runner.step);
    bench_v2_step.dependOn(&run_bench_v2_alias.step);

    // Tier shortcuts -- invoke the runner with a fixed --suite filter.
    const bench_micro_run = b.addRunArtifact(bench_runner);
    bench_micro_run.addArgs(&.{"--suite=micro"});
    const bench_micro_step = b.step("bench-micro", "Run micro-tier benchmarks");
    bench_micro_step.dependOn(&install_bench_runner.step);
    bench_micro_step.dependOn(&bench_micro_run.step);

    const bench_integration_run = b.addRunArtifact(bench_runner);
    bench_integration_run.addArgs(&.{"--suite=integration"});
    const bench_integration_step = b.step("bench-integration", "Run integration-tier benchmarks");
    bench_integration_step.dependOn(&install_bench_runner.step);
    bench_integration_step.dependOn(&bench_integration_run.step);

    const bench_external_run = b.addRunArtifact(bench_runner);
    bench_external_run.addArgs(&.{"--suite=external"});
    const bench_external_step = b.step("bench-external", "Run external-impl compare benchmarks");
    bench_external_step.dependOn(&install_bench_runner.step);
    bench_external_step.dependOn(&bench_external_run.step);

    // `bench-isolated`: micro suites, one executable per suite
    // (benchmarks/micro_main.zig), run and merged by
    // benchmarks/isolated_runner.zig. A change to unrelated code (endpoint,
    // connection, integration benches) cannot move a micro suite's hot loops,
    // so the paired perf gate measures only the code each suite calls.
    // scripts/perf-gate.sh uses this step when both compared commits have it.
    const isolated_runner = addExe(b, "bench-isolated", "benchmarks/isolated_runner.zig", target, .ReleaseFast);
    isolated_runner.root_module.addImport("bench_common", bench_common_mod);
    const run_isolated_runner = b.addRunArtifact(isolated_runner);
    // Registry order (benchmarks/bench_runner.zig), so rows come out in the
    // same order as `zig build bench`.
    const isolated_micro_suites = [_][]const u8{
        "varint",
        "pacing",
        "header_protection",
        "aead",
        "tls_keygen",
        "frame_serialization",
        "connection_lookup",
        "loss_detection_scan",
        "send_buffer_alloc",
    };
    var bench_micro_exes: std.ArrayList(*std.Build.Step.Compile) = .empty;
    for (isolated_micro_suites) |suite_name| {
        const suite_mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("benchmarks/micro/{s}.zig", .{suite_name})),
            .target = target,
            .optimize = .ReleaseFast,
        });
        // Same imports the runner provides; Zig only compiles what the
        // suite actually references.
        suite_mod.addImport("bench_common", bench_common_mod);
        suite_mod.addImport("quic_varint", quic_varint_mod);
        suite_mod.addImport("quic_recovery", quic_recovery_mod);
        suite_mod.addImport("quic_crypto", quic_crypto_mod);
        suite_mod.addImport("quic_packet", quic_packet_mod);
        suite_mod.addImport("quic_frame", quic_frame_mod);
        suite_mod.addImport("compat", compat_mod);
        suite_mod.addImport("quic_tls", quic_tls_mod);
        suite_mod.addImport("quic_tls13", tls13_mod);
        suite_mod.addImport("quic_endpoint", quic_endpoint_mod);
        suite_mod.addImport("quic_conn", quic_conn_mod);
        suite_mod.addImport("quic_config", quic_config_mod);
        suite_mod.addImport("quic_api", quic_api_mod);
        const suite_exe = addExe(b, b.fmt("bench-micro-{s}", .{suite_name}), "benchmarks/micro_main.zig", target, .ReleaseFast);
        suite_exe.root_module.addImport("bench_common", bench_common_mod);
        suite_exe.root_module.addImport("micro_suite", suite_mod);
        run_isolated_runner.addPrefixedArtifactArg(b.fmt("--micro-exe=micro/{s}=", .{suite_name}), suite_exe);
        bench_micro_exes.append(b.allocator, suite_exe) catch @panic("OOM");
    }
    if (b.args) |args| run_isolated_runner.addArgs(args);
    const bench_isolated_step = b.step("bench-isolated", "Run micro benchmarks, one executable per suite (--suite=micro|<scenario>, --output=<path>)");
    bench_isolated_step.dependOn(&run_isolated_runner.step);

    // `bench-build` (SONNY-6669): compile every bench executable without
    // running it, for any -Dtarget. scripts/bench_cross_compile.sh runs it
    // for each release target so the suite cannot stop compiling for macOS
    // or Windows unnoticed again (it did once std.time.Timer was removed).
    const bench_build_step = b.step("bench-build", "Compile the bench suite (runner, isolated micro suites, comparator) without running it");
    bench_build_step.dependOn(&install_bench_runner.step);
    bench_build_step.dependOn(&install_bench_compare.step);
    bench_build_step.dependOn(&b.addInstallArtifact(isolated_runner, .{}).step);
    for (bench_micro_exes.items) |exe| bench_build_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

    // DEPRECATED retired-name aliases. Each invokes the runner with a fixed
    // --suite=<scenario_short_name>. bench-throughput and bench-handshake
    // point at scenarios that will be introduced by Phase 5 Tasks 5.1/5.2;
    // until then they exit cleanly with rc=3 "no scenarios matched" (benign
    // failure preferred over a missing alias that breaks external callers).
    const bench_poll_run = b.addRunArtifact(bench_runner);
    bench_poll_run.addArgs(&.{"--suite=poll_overhead"});
    const bench_poll_step = b.step("bench-poll", "DEPRECATED: use 'bench -- --suite=poll_overhead'");
    bench_poll_step.dependOn(&install_bench_runner.step);
    bench_poll_step.dependOn(&bench_poll_run.step);

    const bench_scale_run = b.addRunArtifact(bench_runner);
    bench_scale_run.addArgs(&.{"--suite=conn_scale"});
    const bench_scale_step = b.step("bench-scale", "DEPRECATED: use 'bench -- --suite=conn_scale'");
    bench_scale_step.dependOn(&install_bench_runner.step);
    bench_scale_step.dependOn(&bench_scale_run.step);

    const bench_throughput_run = b.addRunArtifact(bench_runner);
    bench_throughput_run.addArgs(&.{"--suite=stream_throughput"});
    const bench_throughput_step = b.step("bench-throughput", "DEPRECATED: use 'bench -- --suite=stream_throughput' (scenario pending Phase 5)");
    bench_throughput_step.dependOn(&install_bench_runner.step);
    bench_throughput_step.dependOn(&bench_throughput_run.step);

    const bench_handshake_run = b.addRunArtifact(bench_runner);
    bench_handshake_run.addArgs(&.{"--suite=handshake_e2e"});
    const bench_handshake_step = b.step("bench-handshake", "DEPRECATED: use 'bench -- --suite=handshake_e2e' (scenario pending Phase 5)");
    bench_handshake_step.dependOn(&install_bench_runner.step);
    bench_handshake_step.dependOn(&bench_handshake_run.step);

    // ========================================================================
    // Cross-platform compile smoke test
    // Used by scripts/cross_platform_udp_batch_smoke.sh
    // Compile-only (addObject, no linking) so cross-targets work without
    // system libraries (OpenSSL, ws2_32, etc.).
    //
    // Only defined when quic is built as the root package. When consumed as a
    // dependency (e.g. by geode), creating additional modules rooted at
    // src/quic/endpoint{,/transport,/udp_transport}.zig produces diamond
    // "file exists in modules 'X' and 'X0'" errors in Zig 0.16 because the
    // same source files also root the public `quic_endpoint_mod` /
    // `endpoint_transport_mod` / `endpoint_udp_transport_mod` that downstream
    // consumers import. Skipping the step under a dep prefix keeps the graph
    // clean without blocking quic's own cross-smoke CI script.
    // ========================================================================
    if (b.dep_prefix.len == 0) {
        const cross_smoke_step = b.step("cross-smoke", "Compile-only cross-platform transport smoke test");

        // endpoint/transport.zig
        {
            const mod = b.createModule(.{
                .root_source_file = b.path("src/quic/endpoint/transport.zig"),
                .target = target,
                .optimize = optimize,
            });
            mod.addImport("quic_conn", quic_conn_mod);
            const obj = b.addObject(.{ .name = "cross-smoke-transport", .root_module = mod });
            cross_smoke_step.dependOn(&obj.step);
        }

        // endpoint/udp_transport.zig
        {
            const mod = b.createModule(.{
                .root_source_file = b.path("src/quic/endpoint/udp_transport.zig"),
                .target = target,
                .optimize = optimize,
            });
            mod.addImport("transport.zig", endpoint_transport_mod);
            mod.addImport("conn.zig", quic_conn_mod);
            mod.addImport("quic_logger", quic_logger_mod);
            const obj = b.addObject(.{ .name = "cross-smoke-udp-transport", .root_module = mod });
            cross_smoke_step.dependOn(&obj.step);
        }

        // endpoint.zig (full module graph — mirrors quic_endpoint_mod imports)
        {
            const mod = b.createModule(.{
                .root_source_file = b.path("src/quic/endpoint.zig"),
                .target = target,
                .optimize = optimize,
            });
            mod.addImport("types", endpoint_types_mod);
            mod.addImport("quic_conn", quic_conn_mod);
            mod.addImport("quic_packet", quic_packet_mod);
            mod.addImport("quic_frame", quic_frame_mod);
            mod.addImport("quic_tls13", tls13_mod);
            mod.addImport("quic_crypto", quic_crypto_mod);
            mod.addImport("quic_varint", quic_varint_mod);
            mod.addImport("quic_tls", quic_tls_mod);
            mod.addImport("sig", sig_mod);
            mod.addImport("x509", x509_mod);
            mod.addImport("quic_recovery", quic_recovery_mod);
            mod.addImport("config.zig", quic_config_mod);
            mod.addImport("loop_backend.zig", loop_backend_mod);
            mod.addImport("quic_transport_params", quic_transport_params_mod);
            mod.addImport("quic_logger", quic_logger_mod);
            mod.addImport("byteorder", byteorder_mod);
            mod.addImport("quic_version", quic_version_mod);
            mod.addImport("quic_token", quic_token_mod);
            mod.addImport("endpoint/utils.zig", endpoint_utils_mod);
            mod.addImport("endpoint/transport.zig", endpoint_transport_mod);
            mod.addImport("endpoint/udp_transport.zig", endpoint_udp_transport_mod);
            mod.addImport("endpoint/incoming.zig", endpoint_incoming_mod);
            mod.addImport("endpoint/frame_handler.zig", endpoint_frame_handler_mod);
            mod.addImport("endpoint/lookup.zig", endpoint_lookup_mod);
            mod.addImport("endpoint/pto.zig", endpoint_pto_mod);
            mod.addImport("endpoint/lifecycle.zig", endpoint_lifecycle_mod);
            mod.addImport("endpoint/handshake_integration.zig", endpoint_handshake_integration_mod);
            mod.addImport("endpoint/client.zig", endpoint_client_mod);
            mod.addImport("endpoint/server.zig", endpoint_server_mod);
            mod.addImport("quic_build_options", build_options_mod);
            if (parallel_mod) |pm| mod.addImport("parallel", pm);
            const obj = b.addObject(.{ .name = "cross-smoke-endpoint", .root_module = mod });
            cross_smoke_step.dependOn(&obj.step);
        }
    }
}
