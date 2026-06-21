// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const backend = @import("crypto_backend");

test "assertActive is callable from the quic seam (no-op when fips off)" {
    // Under -Dfips=false this is a comptime no-op; under -Dfips=true it
    // verifies the loaded FIPS provider self-tested. Either way it must
    // not error/panic when the provider is present.
    backend.assertActive();
}
