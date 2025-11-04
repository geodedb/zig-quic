// Helper for setting up the QUIC library as a vendor dependency
//
// Usage in your build.zig:
// ```zig
// const quic_vendor_setup = @import("vendor/quic/vendor_setup.zig");
//
// pub fn build(b: *std.Build) void {
//     const target = b.standardTargetOptions(.{});
//     const optimize = b.standardOptimizeOption(.{});
//
//     // Setup QUIC modules
//     const quic_modules = quic_vendor_setup.setupModules(b, "vendor/quic", target, optimize);
//
//     // Add to your exe/lib
//     exe.root_module.addImport("quic", quic_modules.quic_api);
//     exe.root_module.addImport("quic_endpoint", quic_modules.quic_endpoint);
//     exe.root_module.addImport("quic_conn", quic_modules.quic_conn);
//     // ... add other modules as needed
// }
// ```

const std = @import("std");

pub const QuicModules = struct {
    byteorder: *std.Build.Module,
    quic_api: *std.Build.Module,
    quic_endpoint: *std.Build.Module,
    quic_conn: *std.Build.Module,
    quic_packet: *std.Build.Module,
    quic_frame: *std.Build.Module,
    quic_varint: *std.Build.Module,
    quic_tls: *std.Build.Module,
    quic_tls13: *std.Build.Module,
    quic_crypto: *std.Build.Module,
    quic_recovery: *std.Build.Module,
    quic_transport_params: *std.Build.Module,
    quic_logger: *std.Build.Module,
    config: *std.Build.Module,
    loop_backend: *std.Build.Module,
    asn1: *std.Build.Module,
    sig: *std.Build.Module,
    x509: *std.Build.Module,
    token: *std.Build.Module,
};

pub fn setupModules(
    b: *std.Build,
    quic_path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) QuicModules {
    _ = target;
    _ = optimize;

    const mkModule = struct {
        fn mk(builder: *std.Build, root_path: []const u8, sub_path: []const u8) *std.Build.Module {
            const full_path = builder.pathJoin(&.{ root_path, sub_path });
            return builder.addModule("mod", .{
                .root_source_file = builder.path(full_path),
            });
        }
    }.mk;

    // Core byteorder module - REQUIRED by multiple QUIC modules
    const byteorder_mod = mkModule(b, quic_path, "src/byteorder/byteorder.zig");

    // TLS/crypto modules
    const quic_tls_mod = mkModule(b, quic_path, "src/quic/tls/key_schedule.zig");
    const quic_crypto_mod = mkModule(b, quic_path, "src/quic/crypto_quic.zig");
    const asn1_mod = mkModule(b, quic_path, "src/quic/tls/asn1.zig");
    const sig_mod = mkModule(b, quic_path, "src/quic/tls/sig.zig");
    const x509_mod = mkModule(b, quic_path, "src/quic/tls/x509.zig");
    const quic_tls13_mod = mkModule(b, quic_path, "src/quic/tls/tls13.zig");

    // Core QUIC modules
    const quic_logger_mod = mkModule(b, quic_path, "src/quic/logger.zig");
    const config_mod = mkModule(b, quic_path, "src/quic/config.zig");
    const loop_backend_mod = mkModule(b, quic_path, "src/quic/loop_backend.zig");
    const token_mod = mkModule(b, quic_path, "src/quic/token.zig");

    // Varint and frame
    const quic_varint_mod = mkModule(b, quic_path, "src/quic/varint.zig");
    quic_varint_mod.addImport("byteorder", byteorder_mod);

    const quic_frame_mod = mkModule(b, quic_path, "src/quic/frame.zig");
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);

    // Transport parameters
    const quic_transport_params_mod = mkModule(b, quic_path, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);

    // Packet module
    const quic_packet_mod = mkModule(b, quic_path, "src/quic/packet.zig");
    quic_packet_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_packet_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_mod.addImport("quic_logger", quic_logger_mod);

    // Recovery module
    const quic_recovery_mod = mkModule(b, quic_path, "src/quic/recovery.zig");
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);

    // Connection module
    const quic_conn_mod = mkModule(b, quic_path, "src/quic/conn.zig");
    quic_conn_mod.addImport("quic_tls13", quic_tls13_mod);
    quic_conn_mod.addImport("quic_packet", quic_packet_mod);
    quic_conn_mod.addImport("quic_frame", quic_frame_mod);
    quic_conn_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_conn_mod.addImport("quic_tls", quic_tls_mod);
    quic_conn_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_conn_mod.addImport("quic_logger", quic_logger_mod);
    quic_conn_mod.addImport("byteorder", byteorder_mod);  // IMPORTANT: conn.zig needs byteorder

    // Endpoint module
    const quic_endpoint_mod = mkModule(b, quic_path, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("config.zig", config_mod);
    quic_endpoint_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_endpoint_mod.addImport("quic_conn", quic_conn_mod);
    quic_endpoint_mod.addImport("quic_packet", quic_packet_mod);
    quic_endpoint_mod.addImport("quic_frame", quic_frame_mod);
    quic_endpoint_mod.addImport("quic_tls", quic_tls_mod);
    quic_endpoint_mod.addImport("sig", sig_mod);
    quic_endpoint_mod.addImport("x509", x509_mod);
    quic_endpoint_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_endpoint_mod.addImport("quic_varint", quic_varint_mod);
    quic_endpoint_mod.addImport("token.zig", token_mod);
    quic_endpoint_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_endpoint_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_endpoint_mod.addImport("quic_logger", quic_logger_mod);
    quic_endpoint_mod.addImport("byteorder", byteorder_mod);  // IMPORTANT: endpoint.zig needs byteorder

    // TLS13 module dependencies
    quic_tls13_mod.addImport("quic_tls", quic_tls_mod);
    quic_tls13_mod.addImport("asn1", asn1_mod);
    quic_tls13_mod.addImport("sig", sig_mod);
    quic_tls13_mod.addImport("x509", x509_mod);
    quic_tls13_mod.addImport("quic_logger", quic_logger_mod);

    // Signature module dependencies
    sig_mod.addImport("asn1", asn1_mod);

    // X509 module dependencies
    x509_mod.addImport("asn1", asn1_mod);
    x509_mod.addImport("sig", sig_mod);

    // Crypto module dependencies
    quic_crypto_mod.addImport("quic_logger", quic_logger_mod);
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // Token module dependencies
    token_mod.addImport("byteorder", byteorder_mod);  // IMPORTANT: token.zig needs byteorder

    // API module (main entry point)
    const quic_api_mod = mkModule(b, quic_path, "src/quic/api.zig");
    quic_api_mod.addImport("config.zig", config_mod);
    quic_api_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_api_mod.addImport("quic_conn", quic_conn_mod);
    quic_api_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_api_mod.addImport("quic_packet", quic_packet_mod);
    quic_api_mod.addImport("quic_frame", quic_frame_mod);
    quic_api_mod.addImport("quic_tls", quic_tls_mod);
    quic_api_mod.addImport("quic_tls13", quic_tls13_mod);
    quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_api_mod.addImport("quic_varint", quic_varint_mod);
    quic_api_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_api_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_api_mod.addImport("quic_logger", quic_logger_mod);
    quic_api_mod.addImport("byteorder", byteorder_mod);
    quic_api_mod.addImport("token.zig", token_mod);
    quic_api_mod.addImport("asn1", asn1_mod);
    quic_api_mod.addImport("sig", sig_mod);
    quic_api_mod.addImport("x509", x509_mod);

    return .{
        .byteorder = byteorder_mod,
        .quic_api = quic_api_mod,
        .quic_endpoint = quic_endpoint_mod,
        .quic_conn = quic_conn_mod,
        .quic_packet = quic_packet_mod,
        .quic_frame = quic_frame_mod,
        .quic_varint = quic_varint_mod,
        .quic_tls = quic_tls_mod,
        .quic_tls13 = quic_tls13_mod,
        .quic_crypto = quic_crypto_mod,
        .quic_recovery = quic_recovery_mod,
        .quic_transport_params = quic_transport_params_mod,
        .quic_logger = quic_logger_mod,
        .config = config_mod,
        .loop_backend = loop_backend_mod,
        .asn1 = asn1_mod,
        .sig = sig_mod,
        .x509 = x509_mod,
        .token = token_mod,
    };
}