# Interop Harness (manual)

This directory contains a manual interop harness to test this Zig QUIC stack against quic-go in both directions.

Scope:

- Developer-run; not part of CI.
- Localhost only (127.0.0.1:4433).
- Insecure mode (test certs) acceptable.

Quick start:

- Generate self-signed certs: `bash ./examples/interop/certs/generate.sh`
- Build Zig CLIs/tools: `zig build cli tools`
- Prime Go deps: `cd examples/interop && go mod tidy`
- Run helper: `bash ./examples/interop/run.sh`

Scenarios:

1. Zig server, Go client (quic-go):

   - Start Zig server: `./zig-out/bin/quic-server --bind 127.0.0.1:4433 --cert ./examples/interop/certs/cert.pem --key ./examples/interop/certs/key.pem --alpn h3 --insecure`.
   - Run Go client: `go run ./examples/interop/go-client --addr 127.0.0.1:4433 --alpn h3 --sni test.local --insecure`.
   - Expect: handshake success; send STREAM payload; echo.

2. Go server, Zig client:
   - Start Go server: `go run ./examples/interop/go-server --addr 127.0.0.1:4433 --alpn h3 --cert ./examples/interop/certs/cert.pem --key ./examples/interop/certs/key.pem`.
   - Run Zig client: `./zig-out/bin/quic-client --connect 127.0.0.1:4433 --sni test.local --alpn h3 --insecure`.
   - Expect: handshake success; send STREAM payload; echo.

Notes:

- The Go module uses `replace github.com/quic-go/quic-go => ../quic-go` so the vendored quic-go under examples is used offline.
- Place test certificates as `examples/interop/certs/{cert.pem,key.pem}` or pass paths on CLI.
- Requires Go >= 1.21 for quic-go.
- Until TLS interop lands in the Zig stack, these may not succeed; keep as future harness.
