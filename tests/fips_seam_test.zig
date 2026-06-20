// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const backend = @import("crypto_backend");

test "seam exposes a backend-agnostic crypto surface" {
    // fips_enabled tracks -Dfips; default build is false (std shim).
    _ = backend.fips_enabled;
    // assertActive must be callable in both modes (no-op when off).
    backend.assertActive();
    // A representative approved digest resolves through the seam.
    var out: [32]u8 = undefined;
    _ = try backend.Hash.digest(.sha256, "abc", &out);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
