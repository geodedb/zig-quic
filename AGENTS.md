# Repository Guidelines

## Project Structure & Module Organization
- Zig sources live in `src/` (`src/quic/*` for core transport, `src/h3/` for HTTP/3, `quic.zig` as top-level lib) with helper binaries in `cmd/` and examples in `examples/`.
- Tests are split between `tests/` and root-level `test_*.zig`/`*.py`/`*.go` files for focused scenarios (interop, TLS vectors). Scripts for diagnostics and interop sit in `scripts/` and `tools/`.
- Docs and investigation notes reside in `docs/` plus topic-specific markdown files in the repo root; keep new docs in one of those locations.
- Build configuration is `build.zig` and dependencies are pinned in `build.zig.zon`; Go helpers use `go.mod`.

## Build, Test, and Development Commands
- Default debug build: `zig build`; release: `zig build -Drelease-safe=true` (target Zig 0.15.1).
- Unit/integration tests: `zig build test`; filter a single suite: `zig build -Dtest-filter=<name> test` (e.g., `tls_key_schedule_kat`).
- CLI/tools/examples: `zig build tools`, `zig build examples`, `zig build bench`, `zig build fuzz`; run benches with `./zig-out/bin/quic-bench --grid` or single scenarios.
- Interop/regression smoke: `./test_interop.sh` (Zig↔Zig), `./scripts/interop_test.sh` (quick matrix), `./scripts/interop_verify.sh` (core), `./scripts/interop_full.sh quick` (broad; slower).

## Coding Style & Naming Conventions
- Run `zig fmt` on all Zig changes; 4-space indent, no tabs. Prefer descriptive identifiers (`lower_snake_case` for vars/functions, `UpperCamelCase` for types) to match existing code.
- Keep public APIs documented; doccheck in CI expects exported symbols to have comments.
- Go helpers should pass `go fmt`/`go test ./...`; Python scripts should be `black`/`ruff` friendly when touched.
- File/branch names: short, kebab-case (`feature-h3-flow-control`); avoid spaces.

## Testing Guidelines
- Add or extend `test_*.zig` in root/tests for new behaviors; mirror naming on the function or RFC section exercised.
- When fixing a bug, add the minimal repro in a dedicated test file near related code (e.g., `test_handshake_*`, `test_aead_*`).
- Capture interop or CLI repro scripts under `scripts/` with clear usage strings; keep logs out of the repo.

## Commit & Pull Request Guidelines
- Commit messages follow a short prefix pattern seen in history (`fix:`, `quic:`, `docs:`) plus an imperative summary; group related changes per commit.
- PRs should include: scope/impact summary, links to relevant issues/TLS-RFC sections, test commands run (paste key logs/output snippets), and notes on interop coverage if applicable.
- Ensure `zig fmt` (and `go fmt`/`black` where touched) and `zig build test` pass before requesting review; avoid committing generated artifacts under `zig-out/`.

## Security & Configuration Tips
- Reuse test certificates from `certs/` for local runs; do not add private keys or secrets. Prefer environment variables or `.env` (gitignored) for credentials when integrating external tooling.
- If changing TLS/crypto code, call out compatibility implications (version negotiation, ALPN, replay safety) in the PR description and add a targeted regression test.
