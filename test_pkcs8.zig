const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Read the test key
    const key_file = try std.fs.cwd().openFile("tests/certs/valid/key.pem", .{});
    defer key_file.close();
    const key_pem = try key_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(key_pem);

    std.debug.print("PEM key contents ({d} bytes):\n{s}\n", .{key_pem.len, key_pem});

    // Find the base64 content between headers
    const start_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    const start_idx = std.mem.indexOf(u8, key_pem, start_marker) orelse {
        std.debug.print("ERROR: Could not find BEGIN marker\n", .{});
        return;
    };
    const content_start = start_idx + start_marker.len;

    const end_idx = std.mem.indexOf(u8, key_pem[content_start..], end_marker) orelse {
        std.debug.print("ERROR: Could not find END marker\n", .{});
        return;
    };

    const base64_content = key_pem[content_start..content_start + end_idx];
    std.debug.print("Base64 content ({d} bytes):\n{s}\n", .{base64_content.len, base64_content});

    // Remove newlines from base64
    var clean_base64 = std.ArrayList(u8){};
    defer clean_base64.deinit(allocator);

    for (base64_content) |c| {
        if (c != '\n' and c != '\r' and c != ' ') {
            try clean_base64.append(allocator, c);
        }
    }

    std.debug.print("Clean base64 ({d} bytes): {s}\n", .{clean_base64.items.len, clean_base64.items});

    // Decode base64
    const decoder = std.base64.standard.Decoder;
    const max_decoded_size = decoder.calcSizeForSlice(clean_base64.items) catch {
        std.debug.print("ERROR: Invalid base64 size\n", .{});
        return;
    };

    const decoded = try allocator.alloc(u8, max_decoded_size);
    defer allocator.free(decoded);

    decoder.decode(decoded, clean_base64.items) catch |err| {
        std.debug.print("ERROR: Base64 decode failed: {}\n", .{err});
        return;
    };

    // The decoder fills the entire buffer with the decoded data
    // For PKCS#8 EC keys, this should be 138 bytes
    const der_key = decoded;
    std.debug.print("DER key ({d} bytes):\n", .{der_key.len});

    // Hexdump the DER
    for (der_key, 0..) |b, i| {
        std.debug.print("{X:0>2} ", .{b});
        if ((i + 1) % 16 == 0) std.debug.print("\n", .{});
    }
    if (der_key.len % 16 != 0) std.debug.print("\n", .{});

    // Try to parse it
    std.debug.print("\n=== Parsing PKCS#8 structure ===\n", .{});

    if (der_key.len < 16) {
        std.debug.print("ERROR: Too short for PKCS#8\n", .{});
        return;
    }

    var i: usize = 0;

    // Check for SEQUENCE
    if (der_key[i] != 0x30) {
        std.debug.print("ERROR: Not a SEQUENCE at position {d}: 0x{X:0>2}\n", .{i, der_key[i]});
        return;
    }
    i += 1;

    // Read length
    const seq_len = if (der_key[i] < 0x80) blk: {
        const len = der_key[i];
        i += 1;
        break :blk len;
    } else blk: {
        const nbytes = der_key[i] & 0x7F;
        i += 1;
        if (nbytes > 2) {
            std.debug.print("ERROR: Length too long\n", .{});
            return;
        }
        var len: usize = 0;
        var j: usize = 0;
        while (j < nbytes) : (j += 1) {
            len = (len << 8) | der_key[i + j];
        }
        i += nbytes;
        break :blk len;
    };

    std.debug.print("SEQUENCE length: {d} bytes\n", .{seq_len});

    // Version INTEGER (expect 0)
    if (der_key[i] != 0x02) {
        std.debug.print("ERROR: Expected INTEGER for version at {d}: 0x{X:0>2}\n", .{i, der_key[i]});
        return;
    }
    i += 1;
    const ver_len = der_key[i];
    i += 1;
    if (ver_len != 1) {
        std.debug.print("ERROR: Version length should be 1, got {d}\n", .{ver_len});
        return;
    }
    const version = der_key[i];
    i += 1;
    std.debug.print("Version: {d}\n", .{version});

    // Algorithm SEQUENCE
    if (der_key[i] != 0x30) {
        std.debug.print("ERROR: Expected SEQUENCE for algorithm at {d}: 0x{X:0>2}\n", .{i, der_key[i]});
        return;
    }
    i += 1;
    const alg_len = der_key[i];
    i += 1;
    const alg_end = i + alg_len;
    std.debug.print("Algorithm SEQUENCE length: {d}\n", .{alg_len});

    // Skip algorithm details for now
    i = alg_end;

    // PrivateKey OCTET STRING
    if (der_key[i] != 0x04) {
        std.debug.print("ERROR: Expected OCTET STRING for private key at {d}: 0x{X:0>2}\n", .{i, der_key[i]});
        return;
    }
    i += 1;

    const pk_len = if (der_key[i] < 0x80) blk: {
        const len = der_key[i];
        i += 1;
        break :blk len;
    } else blk: {
        const nbytes = der_key[i] & 0x7F;
        i += 1;
        var len: usize = 0;
        var j: usize = 0;
        while (j < nbytes) : (j += 1) {
            len = (len << 8) | der_key[i + j];
        }
        i += nbytes;
        break :blk len;
    };

    std.debug.print("PrivateKey OCTET STRING length: {d}\n", .{pk_len});

    // The OCTET STRING contains ECPrivateKey
    const ec_priv = der_key[i..i + pk_len];
    std.debug.print("ECPrivateKey contents ({d} bytes):\n", .{ec_priv.len});
    for (ec_priv, 0..) |b, j| {
        std.debug.print("{X:0>2} ", .{b});
        if ((j + 1) % 16 == 0) std.debug.print("\n", .{});
    }
    if (ec_priv.len % 16 != 0) std.debug.print("\n", .{});

    // Parse ECPrivateKey
    var j: usize = 0;
    if (ec_priv[j] != 0x30) {
        std.debug.print("ERROR: ECPrivateKey not a SEQUENCE\n", .{});
        return;
    }
    j += 1;

    const ec_seq_len = ec_priv[j];
    j += 1;
    std.debug.print("ECPrivateKey SEQUENCE length: {d}\n", .{ec_seq_len});

    // Version (expect 1)
    if (ec_priv[j] != 0x02) {
        std.debug.print("ERROR: Expected INTEGER for ECPrivateKey version\n", .{});
        return;
    }
    j += 1;
    const ec_ver_len = ec_priv[j];
    j += 1;
    const ec_version = ec_priv[j];
    j += ec_ver_len;
    std.debug.print("ECPrivateKey version: {d}\n", .{ec_version});

    // Private key OCTET STRING
    if (ec_priv[j] != 0x04) {
        std.debug.print("ERROR: Expected OCTET STRING for private scalar at {d}: 0x{X:0>2}\n", .{j, ec_priv[j]});
        return;
    }
    j += 1;
    const scalar_len = ec_priv[j];
    j += 1;
    std.debug.print("Private scalar length: {d}\n", .{scalar_len});

    if (scalar_len != 32) {
        std.debug.print("ERROR: Expected 32-byte scalar for P-256\n", .{});
        return;
    }

    const scalar = ec_priv[j..j + 32];
    std.debug.print("Private scalar (32 bytes):\n", .{});
    for (scalar) |b| {
        std.debug.print("{X:0>2} ", .{b});
    }
    std.debug.print("\n", .{});

    std.debug.print("\n=== SUCCESS: Parsed PKCS#8 P-256 key ===\n", .{});
}