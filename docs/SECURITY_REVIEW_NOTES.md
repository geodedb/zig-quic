# Security Review Notes

Last updated: 2026-02-16

## Orientation

- Repo root: `/home/benji/src/devnw/zig/quic`
- Branch: `main`
- HEAD: `da48742`
- Remote: `origin git@gitlab.com:devnw/zig/quic.git`
- `glab repo view`: succeeded
- Worktree status: **dirty** (large pre-existing change set present before this review)
- File inventory snapshots:
  - `find . -maxdepth 3 -type f` -> `/tmp/quic_find_maxdepth3.txt` (4542 entries)
  - `git ls-files` -> `/tmp/quic_git_ls_files.txt` (482 tracked files)

## Tooling Inventory (command -v + version)

- `gitleaks`: `/usr/bin/gitleaks` (`version is set by build process`)
- `trufflehog`: `/usr/local/bin/trufflehog` (`3.92.5`)
- `osv-scanner`: `/usr/local/bin/osv-scanner` (`2.3.2`)
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
- `govulncheck`: `/home/benji/go/bin/govulncheck` (`v1.1.4`, Go `1.25.6`)
- `snyk`: `/home/benji/.config/nvm/versions/node/v24.11.1/bin/snyk` (`1.1302.1`)
- `npm`: `/home/benji/.config/nvm/versions/node/v24.11.1/bin/npm` (`11.6.2`)
- `pnpm`: `/home/benji/.config/nvm/versions/node/v24.11.1/bin/pnpm` (`10.28.2`)
- `yarn`: not installed

Raw capture: `/tmp/security_tool_versions.txt`

## Telemetry / Network Controls

- `semgrep` run with `--metrics=off`.
- `trivy` run with `TRIVY_DISABLE_ANALYTICS=true`.
- `syft` run with `SYFT_CHECK_FOR_APP_UPDATE=false`.
- `grype` run with `GRYPE_CHECK_FOR_APP_UPDATE=false`.
- `trufflehog` rerun with `--no-update` after updater error.

## Automated Scan Runs (outputs in /tmp)

### Secrets

- `gitleaks detect --source . --redact --report-format json --report-path /tmp/gitleaks.json`
  - Result: exit 1, `14` findings (historical/private-key + test-fixture patterns).
- `trufflehog --no-update git file://$PWD --json > /tmp/trufflehog.json`
  - Result: exit 0, `8` unverified findings (historical private-key hits).

### SBOM / Dependency

- `syft dir:. -o cyclonedx-json=/tmp/sbom.cdx.json`
  - Result: success, CycloneDX components: `533`.
- `grype sbom:/tmp/sbom.cdx.json -o json > /tmp/grype.json`
  - Result: success, matches: `151` (`10 Critical`, `59 High`, `82 Medium`; 93 unique package+vuln tuples).
- `osv-scanner scan --recursive . --format json > /tmp/osv.json`
  - Result: exit 1 (govulncheck package-load failure on `test-clients/quic-test-legacy`), but JSON produced with vuln hits.
- `trivy fs . --format json -o /tmp/trivy-fs.json`
  - Result: success, vulnerabilities reported: `0`.
- `trivy config . --format json -o /tmp/trivy-config.json`
  - Result: success, misconfigurations: `2` (`DS-0002` on two Dockerfiles).

### SAST / IaC / Lint

- `semgrep scan --config auto --metrics=off --json -o /tmp/semgrep.json`
  - Result: failed (`auto` config requires metrics); fallback used.
- `semgrep scan --config p/default --metrics=off --json -o /tmp/semgrep.json`
  - Result: success, findings: `51`.
- `bandit -r . -f json -o /tmp/bandit.json`
  - Result: exit 1, findings: `8` (all Low).
- `checkov -d . -o json > /tmp/checkov.json`
  - Result: exit 1, failed checks: `3` (Dockerfile checks).
- `git ls-files '*.sh' | xargs -r shellcheck -x`
  - Result: exit 123, warnings/info in `/tmp/shellcheck.txt`.
- `git ls-files '*Dockerfile*' | xargs -r hadolint`
  - Result: exit 0.

### Language-Specific Audits

- `safety scan --json > /tmp/safety.json`
  - Result: failed (interactive/EOF in this environment).
- Fallback:
  - `safety check --full-report -r clients/python/requirements.txt`
  - `safety check --full-report -r test-clients/legacy-clients/python/requirements.txt`
  - `safety check --full-report -r test-clients/aioquic-client/requirements.txt`
  - Result: 0 vulnerabilities reported in all three files.
- `cargo audit --json > /tmp/cargo-audit-root.json`
  - Result: failed at repo root (no root Cargo.lock); per-lock fallback used:
    - `cargo audit --file clients/rust/Cargo.lock --json` -> warns `RUSTSEC-2025-0134` (unmaintained `rustls-pemfile`).
    - `cargo audit --file test-clients/quinn-client/Cargo.lock --json` -> no advisories.
    - `cargo audit --file test-clients/legacy-clients/rust/Cargo.lock --json` -> no advisories.
- `govulncheck -json ./... > /tmp/govulncheck-root.json`
  - Result: failed at repo root (no root go.mod); per-module fallback used:
    - `examples/interop` -> success, no findings
    - `test-clients/quic-go-client` -> success, no findings
    - `test-clients/quic-test-legacy/xnet-quic` -> success, no findings
    - `test-clients/legacy-clients/go` -> success, no findings
    - `test-clients/quic-test-legacy` -> fails package load (`main redeclared`)
- `snyk auth list`
  - Result: interactive OAuth/login required; `snyk test` not run.

## Manual Verification Highlights

- Confirmed secret-history exposure persists (historical commits detectable by gitleaks/trufflehog).
- Confirmed and implemented `#59` remediation:
  - Upgraded `test-clients/quic-test-legacy/go.mod` to `go 1.25.0` with `toolchain go1.25.7`.
  - Added explicit binary-mode govulncheck coverage for legacy standalone mains in `.gitlab-ci.yml`.
- Confirmed and implemented `#58` remediation:
  - Removed `rustls-pemfile` from `clients/rust/Cargo.toml`.
  - Removed CI audit suppression (`--ignore RUSTSEC-2025-0134`) from `.gitlab-ci.yml`.
- Applied policy decision for `#54`:
  - Closed as won't-do under external controls (same governance boundary as digest/tag pinning and pre-commit enforcement).
- Applied policy decision for `#36`:
  - Closed as won't-do under external governance controls (same ownership boundary as CI/toolchain hash pinning and mutable image-tag pinning).

## Files Updated by This Review

- `docs/GAP_ANALYSIS.md`
- `docs/SECURITY_REVIEW_NOTES.md`
