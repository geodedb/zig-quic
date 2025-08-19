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

fn isLeap(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

fn daysBeforeMonth(year: u16, month: u8) i64 {
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var d: i64 = 0;
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        if (m == 2 and isLeap(year)) d += 29 else d += mdays[m - 1];
    }
    return d;
}

fn unixSecondsFromYMDHMS(year: u16, month: u8, day: u8, hh: u8, mm: u8, ss: u8) i64 {
    if (year < 1970) return 0; // clamp for simplicity
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) days += if (isLeap(y)) 366 else 365;
    days += daysBeforeMonth(year, month);
    days += (@as(i64, day) - 1);
    return days * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + @as(i64, ss);
}

fn parseTime(bytes: []const u8) !i64 {
    // Accept the subset: YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ; return unix seconds
    if (bytes.len == 13 and bytes[12] == 'Z') {
        // UTCTime: YYMMDDHHMMSSZ -> assume 1950..2049 window
        const yy = try std.fmt.parseInt(u8, bytes[0..2], 10);
        const year: u16 = if (yy >= 50) (@as(u16, 1900) + @as(u16, yy)) else (@as(u16, 2000) + @as(u16, yy));
        const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
        const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const hh = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const mm = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const ss = try std.fmt.parseInt(u8, bytes[10..12], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
    }
    if (bytes.len == 15 and bytes[14] == 'Z') {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        const year = try std.fmt.parseInt(u16, bytes[0..4], 10);
        const month = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const day = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const hh = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const mm = try std.fmt.parseInt(u8, bytes[10..12], 10);
        const ss = try std.fmt.parseInt(u8, bytes[12..14], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
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
    const issuer = try ti.readTLV();
    _ = issuer;
    const validity = try ti.readSequence();
    var vd = asn1.Decoder.init(validity);
    const not_before_tlv = try vd.readTLV();
    const not_after_tlv = try vd.readTLV();
    const not_before = try parseTime(not_before_tlv.val);
    const not_after = try parseTime(not_after_tlv.val);
    const subject_seq = try ti.readSequence();
    // Parse subject for CN (very shallow: look for UTF8String in RDNs)
    var subj_cn: ?[]const u8 = null;
    {
        var sdec = asn1.Decoder.init(subject_seq);
        // subject is a sequence of sets of sequences; we do a simple scan for any UTF8String
        while (true) {
            const tlv = sdec.readTLV() catch break;
            if (asn1.tagClass(tlv.tag) == .universal and asn1.tagNumber(tlv.tag) == 12) {
                subj_cn = tlv.val;
                break;
            }
        }
    }
    const spki_tlv = try ti.readTLV();

    // Try to find extensions sequence and parse SAN if present
    var san_result: ?SubjectAltName = null;
    while (true) {
        const tlv = ti.readTLV() catch break;
        // Look for [3] EXPLICIT Extensions (context-specific constructed)
        if (asn1.tagClass(tlv.tag) == .context and asn1.isConstructed(tlv.tag)) {
            var ed = asn1.Decoder.init(tlv.val);
            const exts_seq = ed.readSequence() catch continue;
            var exd = asn1.Decoder.init(exts_seq);
            while (true) {
                const ext = exd.readSequence() catch break;
                var one = asn1.Decoder.init(ext);
                const oid = one.readOID() catch continue;
                const critical_or_val = one.readTLV() catch continue;
                var val = critical_or_val.val;
                // If next is value, adjust
                if (one.readTLV() catch null) |v2| val = v2.val;
                // id-ce-subjectAltName = 2.5.29.17 (we match by length/prefix loosely)
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x11) {
                    var vd2 = asn1.Decoder.init(val);
                    const san_seq = vd2.readSequence() catch continue;
                    var dns_list: [8][]const u8 = undefined;
                    var dns_len: usize = 0;
                    var s2 = asn1.Decoder.init(san_seq);
                    while (dns_len < dns_list.len) {
                        const gn = s2.readTLV() catch break;
                        // dNSName is [2] IA5String; context-specific primitive tag 2
                        if (asn1.tagClass(gn.tag) == .context and asn1.tagNumber(gn.tag) == 2) {
                            dns_list[dns_len] = gn.val;
                            dns_len += 1;
                        }
                    }
                    if (dns_len > 0) san_result = .{ .dns = dns_list[0..dns_len] };
                }
            }
        }
    }

    const subject: Name = .{ .cn = subj_cn };
    const san: ?SubjectAltName = san_result;
    const basic: ?BasicConstraints = null;
    const ku: ?KeyUsage = null;

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
