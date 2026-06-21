# FIPS-140-3 / PQC mode (quic)

`zig build -Dfips=true` routes quic's security crypto through the linked
OpenSSL 3.x FIPS provider via the `crypto_backend` seam. Off by default
with zero overhead (std.crypto shim).

## What changes under -Dfips=true

| Surface | Default (-Dfips=false) | FIPS (-Dfips=true) |
|---|---|---|
| Packet AEAD | AES-GCM **and** ChaCha20-Poly1305 | **AES-GCM only** (ChaCha20-Poly1305 → `error.Unsupported`) |
| Header protection | AES-ECB mask + ChaCha20 mask | AES-ECB mask only (ChaCha arm rejected) |
| Address-validation token | HMAC-SHA256 (std) | HMAC-SHA256 via FIPS provider |
| CSPRNG | std.crypto.random | SP 800-90A DRBG (inherited via seam) |

## Inherited via tls / quic_tls

HKDF (key schedule, key update, stateless-reset token) and ALL PQC
(hybrid ML-KEM key exchange, ML-DSA handshake/cert signatures) reach quic
through the `quic_tls` key schedule, which routes through the same seam in
the `tls` package. quic adds no PQC code of its own.

## fips-exempt (non-security) uses

- `std.crypto.timing_safe.eql` — constant-time compares (token, packet tag, reset token).
- `std.crypto.secureZero` — key-material zeroization.
- `std.crypto.core.aes` ECB in header protection — RFC 9001 §5.4 mask; AES is FIPS-approved.

## Runtime self-test

Endpoint construction (`Endpoint.init` / `Endpoint.initWithTransport`) calls
`crypto_backend.assertActive()`, which hard-fails if the FIPS provider is not
loaded + self-tested under `-Dfips=true` (no-op under `-Dfips=false`).

## Build wiring

- One `build_options` instance carries `fips`; threaded into every compile
  unit (GAP-0020 single-instance discipline).
- The non-fips backend is vendored locally at `src/fips_backend/std_shim.zig`
  (+ its sibling `src/fips_backend/policy.zig`), so `-Dfips=false` pulls the
  `fips` dependency NOT AT ALL — no fetch, no OpenSSL link.
- The `fips` backend is resolved only under `-Dfips=true` via
  `b.dependency("fips", ...)`. The dependency is currently a LOCAL PATH entry
  in `build.zig.zon` (the `fips` package has no git remote yet); the eventual
  published `git+https` lazy form is documented inline there.

## Provisioning

CI builds the provider via the `fips` package's
`scripts/install-openssl-fips.sh` (or the ci-catalog `zig-fips-build`
component). Pass `-Dopenssl_path=/usr/local/ssl` and set
`OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf`.
