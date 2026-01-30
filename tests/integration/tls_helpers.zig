//! TLS Test Helpers for Integration Testing
//!
//! Provides utilities for TLS testing including:
//! - Self-signed certificate generation
//! - Test key pair creation
//! - TLS configuration helpers
//! - Handshake verification
//!
//! RFC References:
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3

const std = @import("std");

/// Test certificate configuration
pub const TestCertConfig = struct {
    /// Subject common name
    common_name: []const u8 = "localhost",

    /// Subject alternative names
    san_list: []const []const u8 = &[_][]const u8{"localhost"},

    /// Certificate validity in days
    validity_days: u32 = 365,

    /// Key size in bits
    key_size: u16 = 2048,
};

/// Test certificate and key pair
pub const TestCertKeyPair = struct {
    /// Certificate in PEM format
    cert_pem: []const u8,

    /// Private key in PEM format
    key_pem: []const u8,

    /// Allocator used for the data
    allocator: std.mem.Allocator,

    /// Clean up certificate and key
    pub fn deinit(self: *TestCertKeyPair) void {
        self.allocator.free(self.cert_pem);
        self.allocator.free(self.key_pem);
    }
};

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn runOpenSsl(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) {
        return error.TestCertsUnavailable;
    }
}

/// Ensure test certificate files exist on disk, generating them with OpenSSL if missing.
pub fn ensureTestCertFiles(allocator: std.mem.Allocator) !void {
    const cert_path = "tests/certs/cert.pem";
    const key_path = "tests/certs/key.pem";
    const rsa_cert_path = "tests/certs/server-rsa.crt";
    const rsa_key_path = "tests/certs/server-rsa.key";

    const cert_exists = pathExists(cert_path);
    const key_exists = pathExists(key_path);
    const rsa_cert_exists = pathExists(rsa_cert_path);
    const rsa_key_exists = pathExists(rsa_key_path);

    if (cert_exists and key_exists and rsa_cert_exists and rsa_key_exists) return;

    std.fs.cwd().makePath("tests/certs") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    if (!(cert_exists and key_exists)) {
        try runOpenSsl(allocator, &[_][]const u8{
            "openssl",
            "ecparam",
            "-genkey",
            "-name",
            "prime256v1",
            "-out",
            key_path,
        });
        try runOpenSsl(allocator, &[_][]const u8{
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            key_path,
            "-out",
            cert_path,
            "-days",
            "365",
            "-subj",
            "/CN=localhost/O=Test/C=US",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        });
    }

    if (!(rsa_cert_exists and rsa_key_exists)) {
        try runOpenSsl(allocator, &[_][]const u8{
            "openssl",
            "genrsa",
            "-out",
            rsa_key_path,
            "2048",
        });
        try runOpenSsl(allocator, &[_][]const u8{
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            rsa_key_path,
            "-out",
            rsa_cert_path,
            "-days",
            "365",
            "-subj",
            "/CN=localhost/O=Test/C=US",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        });
    }
}

/// Generate a self-signed certificate and key pair for testing
///
/// This is a placeholder implementation that uses pre-generated test certificates.
/// In production, you would use OpenSSL or another crypto library to generate
/// certificates on the fly.
pub fn generateSelfSignedCert(
    allocator: std.mem.Allocator,
    config: TestCertConfig,
) !TestCertKeyPair {
    _ = config;

    try ensureTestCertFiles(allocator);

    // For now, use the existing test certificates
    // In a full implementation, this would call OpenSSL to generate certs
    const cert_path = "tests/certs/cert.pem";
    const key_path = "tests/certs/key.pem";

    // Read existing test certificate
    const cert_file = try std.fs.cwd().openFile(cert_path, .{});
    defer cert_file.close();
    const cert_pem = try cert_file.readToEndAlloc(allocator, 16 * 1024);
    errdefer allocator.free(cert_pem);

    // Read existing test key
    const key_file = try std.fs.cwd().openFile(key_path, .{});
    defer key_file.close();
    const key_pem = try key_file.readToEndAlloc(allocator, 16 * 1024);
    errdefer allocator.free(key_pem);

    return TestCertKeyPair{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .allocator = allocator,
    };
}

/// Write certificate and key to temporary files
pub fn writeCertKeyToFiles(
    pair: *const TestCertKeyPair,
    cert_path: []const u8,
    key_path: []const u8,
) !void {
    // Write certificate
    const cert_file = try std.fs.cwd().createFile(cert_path, .{});
    defer cert_file.close();
    try cert_file.writeAll(pair.cert_pem);

    // Write key
    const key_file = try std.fs.cwd().createFile(key_path, .{});
    defer key_file.close();
    try key_file.writeAll(pair.key_pem);
}

/// TLS configuration for testing
pub const TlsTestConfig = struct {
    /// ALPN protocols
    alpn: []const []const u8 = &[_][]const u8{"test"},

    /// Allow insecure (for self-signed certs)
    allow_insecure: bool = true,

    /// Certificate path (for server)
    cert_path: ?[]const u8 = null,

    /// Key path (for server)
    key_path: ?[]const u8 = null,

    /// Require client certificate
    require_client_cert: bool = false,

    /// Enable 0-RTT
    enable_0rtt: bool = false,

    /// Session ticket storage
    session_ticket_store: ?[]const u8 = null,
};

/// Create a server TLS configuration for testing
pub fn createServerTlsConfig(
    allocator: std.mem.Allocator,
    tls_config: TlsTestConfig,
) !ServerTlsConfig {
    if (tls_config.cert_path == null or tls_config.key_path == null) {
        try ensureTestCertFiles(allocator);
    }

    return ServerTlsConfig{
        .cert_path = tls_config.cert_path orelse "tests/certs/cert.pem",
        .key_path = tls_config.key_path orelse "tests/certs/key.pem",
        .alpn = tls_config.alpn,
        .require_client_cert = tls_config.require_client_cert,
        .enable_0rtt = tls_config.enable_0rtt,
    };
}

/// Create a client TLS configuration for testing
pub fn createClientTlsConfig(
    allocator: std.mem.Allocator,
    tls_config: TlsTestConfig,
) !ClientTlsConfig {
    _ = allocator;

    return ClientTlsConfig{
        .alpn = tls_config.alpn,
        .allow_insecure = tls_config.allow_insecure,
        .cert_path = tls_config.cert_path,
        .key_path = tls_config.key_path,
        .enable_0rtt = tls_config.enable_0rtt,
        .session_ticket_store = tls_config.session_ticket_store,
    };
}

/// Server TLS configuration
pub const ServerTlsConfig = struct {
    cert_path: []const u8,
    key_path: []const u8,
    alpn: []const []const u8,
    require_client_cert: bool,
    enable_0rtt: bool,
};

/// Client TLS configuration
pub const ClientTlsConfig = struct {
    alpn: []const []const u8,
    allow_insecure: bool,
    cert_path: ?[]const u8,
    key_path: ?[]const u8,
    enable_0rtt: bool,
    session_ticket_store: ?[]const u8,
};

/// Handshake verification helper
pub const HandshakeVerifier = struct {
    /// Expected ALPN protocol
    expected_alpn: ?[]const u8 = null,

    /// Expected cipher suite
    expected_cipher: ?CipherSuite = null,

    /// Require forward secrecy
    require_forward_secrecy: bool = true,

    /// Verify handshake completed successfully
    pub fn verify(self: *const HandshakeVerifier, result: HandshakeResult) !void {
        // Verify ALPN if specified
        if (self.expected_alpn) |alpn| {
            if (result.negotiated_alpn) |negotiated| {
                if (!std.mem.eql(u8, alpn, negotiated)) {
                    return error.AlpnMismatch;
                }
            } else {
                return error.AlpnNotNegotiated;
            }
        }

        // Verify cipher suite if specified
        if (self.expected_cipher) |cipher| {
            if (result.cipher_suite != cipher) {
                return error.CipherSuiteMismatch;
            }
        }

        // Verify forward secrecy if required
        if (self.require_forward_secrecy) {
            if (!result.has_forward_secrecy) {
                return error.NoForwardSecrecy;
            }
        }

        // Verify handshake was successful
        if (!result.success) {
            return error.HandshakeFailed;
        }
    }
};

/// Result of a TLS handshake
pub const HandshakeResult = struct {
    /// Handshake succeeded
    success: bool,

    /// Negotiated ALPN protocol
    negotiated_alpn: ?[]const u8,

    /// Selected cipher suite
    cipher_suite: CipherSuite,

    /// Handshake has forward secrecy
    has_forward_secrecy: bool,

    /// Handshake used 0-RTT
    used_0rtt: bool,

    /// Session was resumed
    session_resumed: bool,
};

/// TLS 1.3 cipher suites
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
};

/// Extract handshake information from a connection (placeholder)
pub fn extractHandshakeInfo(conn: anytype) HandshakeResult {
    // This is a placeholder - in real implementation, extract from conn.tls
    _ = conn;

    return .{
        .success = true,
        .negotiated_alpn = "test",
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .has_forward_secrecy = true,
        .used_0rtt = false,
        .session_resumed = false,
    };
}

/// Create a test certificate authority (for mutual TLS)
pub const TestCA = struct {
    /// CA certificate
    ca_cert: TestCertKeyPair,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize test CA
    pub fn init(allocator: std.mem.Allocator) !*TestCA {
        const self = try allocator.create(TestCA);
        errdefer allocator.destroy(self);

        const config = TestCertConfig{
            .common_name = "Test CA",
            .san_list = &[_][]const u8{},
            .validity_days = 3650, // 10 years for CA
        };

        self.* = .{
            .ca_cert = try generateSelfSignedCert(allocator, config),
            .allocator = allocator,
        };

        return self;
    }

    /// Clean up test CA
    pub fn deinit(self: *TestCA) void {
        self.ca_cert.deinit();
        self.allocator.destroy(self);
    }

    /// Issue a certificate signed by this CA
    pub fn issueCertificate(
        self: *TestCA,
        allocator: std.mem.Allocator,
        config: TestCertConfig,
    ) !TestCertKeyPair {
        // For now, just return a self-signed cert
        // In full implementation, would sign with CA key
        _ = self;
        return generateSelfSignedCert(allocator, config);
    }
};

/// Session ticket store for testing 0-RTT
pub const TestSessionStore = struct {
    /// Stored session tickets (indexed by server name)
    tickets: std.StringHashMap([]const u8),

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize session store
    pub fn init(allocator: std.mem.Allocator) TestSessionStore {
        return .{
            .tickets = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Clean up session store
    pub fn deinit(self: *TestSessionStore) void {
        var it = self.tickets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tickets.deinit();
    }

    /// Store a session ticket
    pub fn storeTicket(
        self: *TestSessionStore,
        server_name: []const u8,
        ticket: []const u8,
    ) !void {
        const name_copy = try self.allocator.dupe(u8, server_name);
        errdefer self.allocator.free(name_copy);

        const ticket_copy = try self.allocator.dupe(u8, ticket);
        errdefer self.allocator.free(ticket_copy);

        try self.tickets.put(name_copy, ticket_copy);
    }

    /// Retrieve a session ticket
    pub fn getTicket(self: *TestSessionStore, server_name: []const u8) ?[]const u8 {
        return self.tickets.get(server_name);
    }

    /// Clear all stored tickets
    pub fn clear(self: *TestSessionStore) void {
        var it = self.tickets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tickets.clearRetainingCapacity();
    }
};

// Tests

test "TLS helpers - generate self-signed cert" {
    const allocator = std.testing.allocator;

    const config = TestCertConfig{};
    var pair = generateSelfSignedCert(allocator, config) catch |err| {
        if (err == error.SkipZigTest) return error.SkipZigTest;
        return err;
    };
    defer pair.deinit();

    try std.testing.expect(pair.cert_pem.len > 0);
    try std.testing.expect(pair.key_pem.len > 0);

    // Verify PEM format markers
    try std.testing.expect(std.mem.indexOf(u8, pair.cert_pem, "BEGIN CERTIFICATE") != null);
    try std.testing.expect(std.mem.indexOf(u8, pair.key_pem, "BEGIN") != null);
}

test "TLS helpers - create server TLS config" {
    const allocator = std.testing.allocator;

    const tls_config = TlsTestConfig{
        .alpn = &[_][]const u8{"h3"},
        .require_client_cert = true,
    };

    const server_config = try createServerTlsConfig(allocator, tls_config);

    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{"h3"}, server_config.alpn);
    try std.testing.expect(server_config.require_client_cert);
}

test "TLS helpers - create client TLS config" {
    const allocator = std.testing.allocator;

    const tls_config = TlsTestConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = false,
    };

    const client_config = try createClientTlsConfig(allocator, tls_config);

    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{"h3"}, client_config.alpn);
    try std.testing.expect(!client_config.allow_insecure);
}

test "TLS helpers - handshake verifier success" {
    const verifier = HandshakeVerifier{
        .expected_alpn = "test",
        .expected_cipher = .TLS_AES_128_GCM_SHA256,
    };

    const result = HandshakeResult{
        .success = true,
        .negotiated_alpn = "test",
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .has_forward_secrecy = true,
        .used_0rtt = false,
        .session_resumed = false,
    };

    try verifier.verify(result);
}

test "TLS helpers - handshake verifier ALPN mismatch" {
    const verifier = HandshakeVerifier{
        .expected_alpn = "h3",
    };

    const result = HandshakeResult{
        .success = true,
        .negotiated_alpn = "h2",
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .has_forward_secrecy = true,
        .used_0rtt = false,
        .session_resumed = false,
    };

    try std.testing.expectError(error.AlpnMismatch, verifier.verify(result));
}

test "TLS helpers - session store basic operations" {
    const allocator = std.testing.allocator;

    var store = TestSessionStore.init(allocator);
    defer store.deinit();

    // Store a ticket
    try store.storeTicket("example.com", "test_ticket_data");

    // Retrieve the ticket
    const ticket = store.getTicket("example.com");
    try std.testing.expect(ticket != null);
    try std.testing.expectEqualSlices(u8, "test_ticket_data", ticket.?);

    // Non-existent ticket
    const missing = store.getTicket("other.com");
    try std.testing.expect(missing == null);
}

test "TLS helpers - session store clear" {
    const allocator = std.testing.allocator;

    var store = TestSessionStore.init(allocator);
    defer store.deinit();

    try store.storeTicket("example.com", "ticket1");
    try store.storeTicket("test.com", "ticket2");

    store.clear();

    try std.testing.expect(store.getTicket("example.com") == null);
    try std.testing.expect(store.getTicket("test.com") == null);
}

test "TLS helpers - cipher suite enum values" {
    try std.testing.expectEqual(@as(u16, 0x1301), @intFromEnum(CipherSuite.TLS_AES_128_GCM_SHA256));
    try std.testing.expectEqual(@as(u16, 0x1302), @intFromEnum(CipherSuite.TLS_AES_256_GCM_SHA384));
    try std.testing.expectEqual(@as(u16, 0x1303), @intFromEnum(CipherSuite.TLS_CHACHA20_POLY1305_SHA256));
}
