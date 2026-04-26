# Security Review Notes

Last updated: 2026-04-26

## Orientation

- Repo root: `/home/benji/src/devnw/zig/quic`
- Branch: `main`
- HEAD at review start: `18d49c8`
- Remote: `origin git@gitlab.com:devnw/zig/quic.git`
- `glab repo view`: succeeded for `devnw/zig/quic`
- Worktree status at review start: clean
- File inventory snapshots:
  - `find . -maxdepth 3 -type f` -> `/tmp/security_review_find_maxdepth3_20260426.txt` (`13021` entries; includes ignored/generated files)
  - `git ls-files` -> `/tmp/security_review_git_ls_files_20260426.txt` (`568` tracked files)
  - build/deploy inventory -> `/tmp/security_review_build_deploy_files_20260426.txt`

## Tooling Inventory

Raw capture: `/tmp/security_review_tool_versions_20260426.txt`

- `gitleaks`: `/usr/local/bin/gitleaks` (`8.30.0`)
- `trufflehog`: `/usr/local/bin/trufflehog` (legacy CLI; `--version` prints usage)
- `osv-scanner`: `/usr/local/bin/osv-scanner` (`1.9.2`)
- `trivy`: `/home/benji/.local/bin/trivy` (`0.69.0`)
- `grype`: `/home/benji/.local/bin/grype` (`0.107.0`)
- `syft`: `/home/benji/.local/bin/syft` (`1.41.1`)
- `semgrep`: `/home/benji/.local/bin/semgrep` (`1.150.0`)
- `shellcheck`: `/home/benji/.local/bin/shellcheck` (`0.9.0`)
- `hadolint`: `/home/benji/.local/bin/hadolint` (`2.14.0`)
- `checkov`: `/home/benji/.local/bin/checkov` (`3.2.499`)
- `bandit`: `/home/benji/.local/bin/bandit` (`1.9.3`)
- `safety`: `/home/benji/.local/bin/safety` (`3.7.0`)
- `cargo-audit`: `/home/benji/.cargo/bin/cargo-audit` (`0.22.0`)
- `govulncheck`: `/home/benji/go/bin/govulncheck` (`v1.1.4`, local Go `1.23.4`)
- `snyk`: missing; not run

## Telemetry / Network Controls

- Semgrep `auto` was not run with telemetry enabled. `semgrep scan --config auto --metrics=off` failed because this Semgrep version requires metrics for auto config creation, so named configs were used instead.
- Trivy downloaded its vulnerability DB locally.
- Snyk was skipped because it is not installed and would require SaaS/auth setup.
- No scanner output containing secret values was copied into repository docs.

## Automated Scan Runs

All raw reports were written to `/tmp`.

### Secrets

- `gitleaks detect --source . --redact --report-format json --report-path /tmp/gitleaks_20260426.json`
  - Exit `0`; no leaks found.
- `trufflehog --json file://$PWD > /tmp/trufflehog_20260426.json`
  - Exit `1`; `179` high-entropy-only records.
  - Manual summary showed lockfile hashes and historical/test certificate paths; values were not printed.
- `trivy fs ... --skip-dirs ... --format json -o /tmp/trivy_fs_trackedish_20260426.json`
  - Exit `0`; reported `10` private-key findings in public RFC spec files.
- `semgrep scan --config p/security-audit --config p/secrets --metrics=off --json -o /tmp/semgrep_20260426.json`
  - Exit `0`; reported `13` findings, including `10` private-key findings in public RFC spec files.

### SBOM / Dependency

- `syft dir:. -o cyclonedx-json=/tmp/sbom_20260426.cdx.json`
  - Exit `0`; broad scan included generated/ignored files and was treated as triage-only.
- `syft dir:. --exclude './.git/**' --exclude './.zig-cache/**' --exclude './.claude/**' --exclude './zig-out/**' --exclude './quic-test/**' --exclude './test-clients/*/target/**' --exclude './clients/*/target/**' -o cyclonedx-json=/tmp/sbom_trackedish_20260426.cdx.json`
  - Exit `0`; used for Grype follow-up.
- `grype sbom:/tmp/sbom_trackedish_20260426.cdx.json -o json > /tmp/grype_trackedish_20260426.json`
  - Exit `0`; reported Go binary/runtime advisories on tracked committed test-client binaries.
- `osv-scanner scan -r --format json . > /tmp/osv_20260426.json`
  - Exit `1`; JSON produced. Call analysis failed for one legacy Go package layout and local Go 1.23.4 was older than some checked-in Go dependencies require.
- `trivy fs ... --skip-dirs ... --format json -o /tmp/trivy_fs_trackedish_20260426.json`
  - Exit `0`; reported Rust low-severity advisories and RFC spec private-key false positives.

### SAST / IaC / Lint

- `bandit` over tracked Python files:
  - Exit `123`; `8` low-severity findings in interop Python wrapper code.
- `git ls-files '*.sh' | xargs -r shellcheck -x`
  - Exit `123`; info/warning output stored in `/tmp/shellcheck_20260426.txt`; SC2086 command-variable findings were carried forward as a suspected shell hardening gap.
- `git ls-files '*Dockerfile*' | xargs -r hadolint`
  - Exit `0`; no findings.
- `checkov -d . -o json > /tmp/checkov_20260426.json`
  - Exit `1`; Dockerfile checks only. Docker tag pinning is intentionally not tracked as a repo-local gap per governance boundary; runtime user check overlaps GAP-0056.
- `trivy config ... --skip-dirs ... --format json -o /tmp/trivy_config_trackedish_20260426.json`
  - Exit `0`; `DS-0002` on `examples/interop/zig-qns/Dockerfile`, matching GAP-0056.

### Language-Specific Audits

- `safety scan --json`
  - Exit `1`; failed with interactive EOF.
- Fallback `safety check --full-report -r clients/python/requirements.txt -r test-clients/aioquic-client/requirements.txt -r test-clients/legacy-clients/python/requirements.txt`
  - Exit `0`; `0` reported vulnerabilities, but warned that unpinned `aioquic`, `pytest`, and `pytest-asyncio` are not fully reported by default and ignored one pytest advisory due unpinned ranges.
- Per-lock `cargo audit --json`
  - `clients/rust`: exit `1`, `RUSTSEC-2026-0104` on `rustls-webpki 0.103.12`.
  - `test-clients/legacy-clients/rust`: exit `1`, `RUSTSEC-2026-0104` on `rustls-webpki 0.103.12`.
  - `test-clients/quinn-client`: exit `1`, `RUSTSEC-2026-0104`, `RUSTSEC-2026-0099`, and `RUSTSEC-2026-0098` on `rustls-webpki 0.103.10`.
- Per-module `govulncheck -json ./...`
  - `examples/interop`, `test-clients/legacy-clients/go`, `test-clients/quic-go-client`, and `test-clients/quic-test-legacy/xnet-quic`: exit `0`.
  - `test-clients/quic-test-legacy`: exit `1`, package load failed because multiple standalone `main` files live in one directory.

## Manual Verification Highlights

- Confirmed tracked committed ELF binaries under `test-clients` and reopened #157.
- Confirmed current Go module/toolchain/security-scan drift and reopened #59.
- Confirmed unpinned Python dependency specs and reopened #57.
- Confirmed developer shell secret export persists in `scripts/devshell_auth.sh` and reopened #43.
- Confirmed QNS runtime-user verification remains open and commented on #191.
- Created #195 for Rust test-client advisories and missing `quinn-client` CI cargo-audit coverage.
- Created #196 for interop/test clients that disable TLS verification and write TLS key logs by default.
- Created #197 for secret-scanner false positives on public RFC private-key examples.
- Created #198 for suspected shell command-variable word splitting in interop scripts.

## Closure Update

The implementation pass following this review closed the actionable security/delivery findings above:

- #157: removed tracked Go ELF binaries and added `scripts/check-no-committed-binaries.sh` plus CI enforcement.
- #59: aligned Go module toolchain metadata with CI and runs govulncheck through `go run` under `GOTOOLCHAIN=go1.26.2`, with binary-mode coverage for standalone Go clients.
- #57: pinned tracked Python requirement specs and added Safety coverage in CI.
- #195: bumped Rust client lockfiles to `rustls-webpki 0.103.13` and added `test-clients/quinn-client` to cargo-audit CI.
- #196: made insecure TLS verification and TLS key logging explicit opt-ins in Go/Python interop clients.
- #197: added narrow Semgrep and Trivy allowlists for public RFC PEM examples only.
- #191 / GAP-0056: added a QNS runtime privilege-drop check and fail-closed `setpriv` handling.
- #198: replaced the interop Compose command string with a Bash array.
- #43: added explicit token-in-environment warnings to the dev shell helper.

Closure evidence is mirrored in `docs/GAP_ANALYSIS_RESOLVED.md`; current open gaps remain in `docs/GAP_ANALYSIS.md`.

## Governance Boundaries

- CI external-tool hash/toolchain pinning, Docker tag/digest pinning, and pre-commit hook enforcement remain documented as external-control / won't-do boundaries from prior direction. This review did not reopen those as repo-local gaps.
