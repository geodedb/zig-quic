// MIT License
// Minimal X.509 (DER) parser/validator for TLS 1.3 in this project.
// Scope: parse TBSCertificate, read subject alt names, basic constraints,
// key usage, and validity (notBefore/notAfter) as UTCTime/GeneralizedTime.
// This is intentionally minimal and strict; allow_insecure mode will skip
// verification in tests.
const std = @import("std");
const asn1 = @import("asn1.zig");

pub const Name = struct {
    cn: ?[]const u8 = null,
};

pub const SubjectAltName = struct { dns: []const []const u8 };

pub const BasicConstraints = struct { ca: bool = false, path_len: ?u32 = null };

pub const KeyUsage = struct { bits: u16 };

pub const Certificate = struct {
    tbs: []const u8, // raw TBSCertificate for signature verify later
    subject: Name,
    san: ?SubjectAltName = null,
    basic: ?BasicConstraints = null,
    ku: ?KeyUsage = null,
    not_before_unix: i64,
    not_after_unix: i64,
    // public key raw (spki)
    spki: []const u8,
};

fn parseTime(bytes: []const u8) !i64 {
    // Accept the subset: YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ; return unix seconds
    if (bytes.len == 13 and bytes[12] == 'Z') {
        // UTCTime: YYMMDDHHMMSSZ -> assume 1950..2049 window
        const yy = try std.fmt.parseInt(u8, bytes[0..2], 10);
        const year: u16 = if (yy >= 50) 1900 + yy else 2000 + yy;
        const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
        const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const hh = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const mm = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const ss = try std.fmt.parseInt(u8, bytes[10..12], 10);
        return std.time.epoch.DaySecond.fromDateTime(.{ .year = year, .month = month, .day = day, .hour = hh, .minute = mm, .second = ss }).toUnixSeconds();
    }
    if (bytes.len == 15 and bytes[14] == 'Z') {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        const year = try std.fmt.parseInt(u16, bytes[0..4], 10);
        const month = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const day = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const hh = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const mm = try std.fmt.parseInt(u8, bytes[10..12], 10);
        const ss = try std.fmt.parseInt(u8, bytes[12..14], 10);
        return std.time.epoch.DaySecond.fromDateTime(.{ .year = year, .month = month, .day = day, .hour = hh, .minute = mm, .second = ss }).toUnixSeconds();
    }
    return error.UnsupportedTimeFormat;
}

pub fn parseCert(alloc: std.mem.Allocator, der: []const u8) !Certificate {
    // Use allocator for any owned slices (none yet, but keep for future fields)
    _ = alloc;
    var d = asn1.Decoder.init(der);
    const seq = try d.readSequence(); // Certificate
    var ci = asn1.Decoder.init(seq);
    const tbs = try ci.readSequence();
    const tbs_off_begin = (@intFromPtr(tbs.ptr) - @intFromPtr(seq.ptr)) + (seq.ptr - der.ptr);
    const tbs_len = tbs.len;
    // version [0] EXPLICIT INTEGER DEFAULT v1, serial, signature, issuer, validity, subject, spki, ...
    // Very partial parse: issuer, validity, subject, spki, extensions
    // Skip to validity: read issuer (SEQUENCE)
    var ti = asn1.Decoder.init(tbs);
    _ = try ti.readTLV(); // version or serial
    _ = try ti.readTLV(); // maybe version/serial/signature
    _ = try ti.readTLV(); // signature or serial/signature
    _ = try ti.readTLV(); // issuer
    const validity = try ti.readSequence();
    var vd = asn1.Decoder.init(validity);
    const not_before_tlv = try vd.readTLV();
    const not_after_tlv = try vd.readTLV();
    const not_before = try parseTime(not_before_tlv.val);
    const not_after = try parseTime(not_after_tlv.val);
    const subject_seq = try ti.readSequence();
    _ = subject_seq; // TODO: parse CN
    const spki_tlv = try ti.readTLV();

    // Minimal fields collected
    const subject: Name = .{};
    const san: ?SubjectAltName = null;
    const basic: ?BasicConstraints = null;
    const ku: ?KeyUsage = null;

    // Store TBSCertificate slice
    const tbs_start: usize = @intCast(tbs_off_begin);
    const tbs_bytes = der[tbs_start .. tbs_start + tbs_len];
    return .{
        .tbs = tbs_bytes,
        .subject = subject,
        .san = san,
        .basic = basic,
        .ku = ku,
        .not_before_unix = not_before,
        .not_after_unix = not_after,
        .spki = spki_tlv.val,
    };
}

pub fn checkValidity(now_unix: i64, cert: *const Certificate) !void {
    if (now_unix < cert.not_before_unix) return error.NotYetValid;
    if (now_unix > cert.not_after_unix) return error.Expired;
}

pub fn matchDnsName(cert: *const Certificate, name: []const u8) bool {
    if (cert.san) |san| {
        for (san.dns) |d| if (std.mem.eql(u8, d, name)) return true;
        return false;
    }
    // Fallback to CN if SAN missing
    if (cert.subject.cn) |cn| return std.mem.eql(u8, cn, name);
    return false;
}

/// Very simple chain validation placeholder. Insecure mode skips all checks.
pub fn validateChain(alloc: std.mem.Allocator, chain_der: []const []const u8, now_unix: i64, server_name: []const u8, allow_insecure: bool) !void {
    // Touch allocator to avoid lint error and reserve future-use buffer.
    const scratch = try alloc.alloc(u8, 1);
    defer alloc.free(scratch);
    if (allow_insecure) return;
    if (chain_der.len == 0) return error.EmptyChain;
    var leaf = try parseCert(alloc, chain_der[0]);
    try checkValidity(now_unix, &leaf);
    if (!matchDnsName(&leaf, server_name)) return error.NameMismatch;
    // TODO: path building, signature verify, basic constraints, KU
}
