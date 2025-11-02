const std = @import("std");

// TLS 1.3 test harness scaffolding — lays out future suites per RFC 8446 sections.
// Each placeholder returns error.SkipZigTest to document intended coverage without
// impacting current pass/fail status. Replace these skips with real assertions as
// corresponding functionality lands.

// Unit test suites ----------------------------------------------------------

test "tls.unit.handshake.transcript_invariants (RFC 8446 §4.4.1)" {
    return error.SkipZigTest;
}

test "tls.unit.key_schedule.traffic_secret_vectors (RFC 8446 §7.1)" {
    return error.SkipZigTest;
}

test "tls.unit.record_layer.aead_limits (RFC 8446 §5.5)" {
    return error.SkipZigTest;
}

// Integration test suites ---------------------------------------------------

test "tls.integration.handshake_loopback (RFC 8446 §4, RFC 9001 §4.1.4)" {
    return error.SkipZigTest;
}

test "tls.integration.key_update (RFC 8446 §7.2, RFC 9001 §6)" {
    return error.SkipZigTest;
}

// Fuzz harness placeholders -------------------------------------------------

test "tls.fuzz.record_decode (RFC 8446 §5)" {
    return error.SkipZigTest;
}

test "tls.fuzz.handshake_message_parse (RFC 8446 §4.1)" {
    return error.SkipZigTest;
}
