const std = @import("std");
const conn_mod = @import("quic_conn");

// Ensure amplification gating uses overflow-safe math:
// with extremely large RX, the helper must not overflow and must allow send up to 3x.
test "amplification gating uses overflow-safe math" {
    var c = conn_mod.Connection{};
    // Unvalidated path
    c.address_validated = false;
    // Simulate extremely large RX bytes near max u64; pick a value where rx*3 would overflow.
    c.bytes_rx_unvalidated = 0xffffffffffffffff; // max
    c.bytes_tx_unvalidated = 0xffffffffffffffff; // equal to rx (<= 3x)
    try std.testing.expect(c.canSendUnderAmplification());

    // Now set tx to greater than 3x rx by division logic: let tx/3 > rx.
    // For rx = max, any increase still floor-divides to 0xffffffffffffffff / 3 = 0x5555...., so craft a case more controlled.
    // Use a finite rx where 3*rx would overflow if multiplied, but division-based compare remains correct.
    c.bytes_rx_unvalidated = 0x8000_0000_0000_0000; // 2^63
    // 3*rx would overflow, but set tx to 3*rx + 1 conceptually; emulate by ensuring (tx/3) > rx.
    // Choose tx = (rx + 1) * 3 which is representable (will overflow if multiplied naïvely in compare).
    // Compute (rx + 1) * 3 in pieces without overflow: use wrapping add on u64 then wrapping mul, but assign a known literal.
    // Here we directly pick a value: (2^63 + 1) * 3 = 0x18000000000000003 which wraps; instead, test logic via division threshold.
    // Set tx so that tx/3 = rx + 1 to guarantee over limit.
    c.bytes_tx_unvalidated = (c.bytes_rx_unvalidated + 1) * 3;
    try std.testing.expect(c.overAmplification());
}

// Sanity: when address is validated, gating always allows send, irrespective of counters.
test "amplification gating ignored when validated" {
    var c = conn_mod.Connection{};
    c.address_validated = true;
    c.bytes_rx_unvalidated = 0;
    c.bytes_tx_unvalidated = std.math.maxInt(u64);
    try std.testing.expect(c.canSendUnderAmplification());
    try std.testing.expect(!c.overAmplification());
}
