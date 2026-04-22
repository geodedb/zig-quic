# QUIC System-Level Tuning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship canonical UDP / network sysctl tuning for zig-quic, unconditionally applied by geode's packaging and developer `make install`.

**Architecture:** zig-quic carries the source-of-truth drop-in + helper script + operator doc; geode vendors them verbatim and invokes them from postinstall and Makefile. Runtime apply is "only raise, never lower" on bounded values; the drop-in persists across reboots via `/etc/sysctl.d/`. No `.zig` code changes.

**Tech Stack:** Bash, sysctl, systemd, Make.

**Spec:** `docs/superpowers/specs/2026-04-22-quic-system-tuning-design.md`

**Repos:** `zig-quic` at `/home/benji/src/devnw/zig/quic`, `geode` at `/home/benji/src/devnw/codepros/geode/geode`.

---

## File Structure

### zig-quic (create)

- `config/sysctl.d/99-zig-quic.conf` — canonical drop-in (10 knobs)
- `scripts/tune-system.sh` — `apply | revert | check` helper
- `docs/SYSTEM_TUNING.md` — operator doc
- `scripts/test_tune_system.sh` — bash unit tests

### zig-quic (modify)

- `README.md` — add "System tuning" pointer under `## Docs`
- `CLAUDE.md` — add one-liner under `## Quick Commands`

### geode (create)

- `deployment/sysctl.d/99-geode-quic.conf` — superset-identical to zig-quic drop-in
- `deployment/scripts/tune-system.sh` — vendored copy

### geode (modify)

- `deployment/scripts/postinstall.sh` — extend sysctl block from 2 knobs to 10, install drop-in
- `deployment/systemd/geode.service:42-50` — drop stale `QUIC_GO_DISABLE_GSO` comment
- `deployment/config/geode.conf:33-46` — purge stale quic-go references
- `deployment/README.md:254-320` — rewrite "QUIC Performance Optimizations" section
- `Makefile:196-202` — add `install-tuning` target and wire it into `install`

---

## Task 1: zig-quic — sysctl.d drop-in

**Files:** Create `config/sysctl.d/99-zig-quic.conf`

- [ ] **Step 1: Create the drop-in**

```conf
# zig-quic — system-level tuning for QUIC/UDP workloads
# Authoritative reference: docs/SYSTEM_TUNING.md
# Apply via: sudo scripts/tune-system.sh apply
# Revert via: sudo scripts/tune-system.sh revert

# --- UDP socket buffers (per-socket ceilings) ---
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032

# --- UDP socket buffers (per-socket defaults) ---
net.core.rmem_default = 2500000
net.core.wmem_default = 2500000

# --- NIC -> kernel softirq queue depth ---
net.core.netdev_max_backlog = 5000

# --- System-wide UDP memory (pages) ---
net.ipv4.udp_mem = 262144 524288 1048576

# --- Per-socket UDP memory floor under pressure ---
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- Client-side ephemeral port range ---
net.ipv4.ip_local_port_range = 1024 65535

# --- Pacing-aware qdisc ---
net.core.default_qdisc = fq

# --- Kernel-wide file descriptor ceiling ---
fs.file-max = 1048576
```

- [ ] **Step 2: Verify lines parse as `key = value`**

Run: `grep -vE '^\s*(#|$)' config/sysctl.d/99-zig-quic.conf | awk -F= '{print NF}' | sort -u`
Expected: `2` (every non-comment line is a single `key = value` pair).

- [ ] **Step 3: Commit**

```bash
cd /home/benji/src/devnw/zig/quic
git add config/sysctl.d/99-zig-quic.conf
git commit -m "feat(tuning): add canonical sysctl drop-in (99-zig-quic.conf)"
```

---

## Task 2: zig-quic — `tune-system.sh` helper + tests

**Files:** Create `scripts/tune-system.sh` and `scripts/test_tune_system.sh`

- [ ] **Step 1: Write the failing test harness**

Create `scripts/test_tune_system.sh`:

```bash
#!/usr/bin/env bash
# Shell tests for tune-system.sh — dry-run only, no sudo required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TUNE="$SCRIPT_DIR/tune-system.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

[ -x "$TUNE" ] || fail "tune-system.sh missing or not executable"

# 1. --help exits 0
"$TUNE" --help >/dev/null 2>&1 || fail "--help should exit 0"
pass "--help exits 0"

# 2. Unknown subcommand exits non-zero
if "$TUNE" bogus >/dev/null 2>&1; then fail "unknown subcommand should exit non-zero"; fi
pass "unknown subcommand rejected"

# 3. --dry-run apply covers all 10 knob names
out=$("$TUNE" apply --dry-run 2>&1)
for key in rmem_max wmem_max rmem_default wmem_default netdev_max_backlog udp_mem udp_rmem_min udp_wmem_min ip_local_port_range default_qdisc file-max; do
    echo "$out" | grep -q "$key" || fail "dry-run missing knob: $key"
done
pass "dry-run covers all knobs"

# 4. check subcommand reads current values
"$TUNE" check >/dev/null 2>&1 || fail "check should exit 0"
pass "check exits 0"

echo "ALL PASS"
```

Make executable: `chmod +x scripts/test_tune_system.sh`

- [ ] **Step 2: Run to confirm test fails (script does not exist yet)**

Run: `scripts/test_tune_system.sh`
Expected: FAIL with "tune-system.sh missing or not executable".

- [ ] **Step 3: Write `scripts/tune-system.sh`**

Create `scripts/tune-system.sh`:

```bash
#!/usr/bin/env bash
# tune-system.sh — apply / revert / check the zig-quic canonical sysctl drop-in.
#
# Usage:
#   tune-system.sh apply [--dry-run]   # raise kernel values to recommendations
#   tune-system.sh revert [--dry-run]  # remove drop-in and reload
#   tune-system.sh check               # print current vs. recommended, no writes
#   tune-system.sh --help
#
# Semantics:
#   * "only raise, never lower" on rmem_max, wmem_max, rmem_default, wmem_default,
#     netdev_max_backlog, udp_rmem_min, udp_wmem_min, file-max.
#   * udp_mem, ip_local_port_range, default_qdisc are written verbatim.
#   * Missing sysctl / read-only rootfs / no CAP_NET_ADMIN: log and continue.
#   * Linux-only. On macOS / BSD, prints kern.ipc.maxsockbuf guidance and exits 0.

set -u

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly CONF_SRC="${TUNE_CONF:-$SCRIPT_DIR/../config/sysctl.d/99-zig-quic.conf}"
readonly CONF_DEST="${TUNE_DEST:-/etc/sysctl.d/99-zig-quic.conf}"

log()  { printf '[tune-system] %s\n' "$*"; }
warn() { printf '[tune-system] WARN: %s\n' "$*" >&2; }

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

parse_conf() {
    [ -f "$CONF_SRC" ] || { warn "missing $CONF_SRC"; return 1; }
    sed -E 's/#.*$//' "$CONF_SRC" \
        | awk -F= 'NF==2 {
            key=$1; val=$2;
            gsub(/^[ \t]+|[ \t]+$/, "", key);
            gsub(/^[ \t]+|[ \t]+$/, "", val);
            if (key!="" && val!="") printf "%s\t%s\n", key, val;
          }'
}

should_raise() {
    local key="$1" cur="$2" new="$3"
    case "$key" in
        net.ipv4.udp_mem|net.ipv4.ip_local_port_range|net.core.default_qdisc) return 1 ;;
    esac
    [[ "$cur" =~ ^[0-9]+$ && "$new" =~ ^[0-9]+$ ]] || return 1
    (( new > cur ))
}

read_cur() { sysctl -n "$1" 2>/dev/null || echo ""; }

cmd_check() {
    [ -f "$CONF_SRC" ] || { warn "missing $CONF_SRC"; return 0; }
    printf '%-40s  %-24s  %s\n' "KNOB" "CURRENT" "RECOMMENDED"
    local knob val cur
    while IFS=$'\t' read -r knob val; do
        cur=$(read_cur "$knob")
        printf '%-40s  %-24s  %s\n' "$knob" "${cur:-<unset>}" "$val"
    done < <(parse_conf)
}

cmd_apply() {
    local dry="$1" knob val cur

    if [ "$(uname -s)" != "Linux" ]; then
        log "non-Linux ($(uname -s)); see docs/SYSTEM_TUNING.md for BSD/macOS guidance"
        return 0
    fi
    [ -f "$CONF_SRC" ] || { warn "missing $CONF_SRC"; return 1; }

    while IFS=$'\t' read -r knob val; do
        cur=$(read_cur "$knob")
        case "$knob" in
            net.ipv4.udp_mem|net.ipv4.ip_local_port_range|net.core.default_qdisc)
                log "set $knob = $val"
                [ "$dry" = "1" ] || sysctl -w "$knob=$val" >/dev/null 2>&1 \
                    || warn "failed to set $knob (continuing)"
                ;;
            *)
                if should_raise "$knob" "$cur" "$val"; then
                    log "raise $knob: $cur -> $val"
                    [ "$dry" = "1" ] || sysctl -w "$knob=$val" >/dev/null 2>&1 \
                        || warn "failed to set $knob (continuing)"
                else
                    log "keep  $knob: $cur (>= $val)"
                fi
                ;;
        esac
    done < <(parse_conf)

    if [ -d /etc/sysctl.d ]; then
        if [ "$dry" = "1" ]; then
            log "would install $CONF_DEST"
        else
            install -m 0644 "$CONF_SRC" "$CONF_DEST" 2>/dev/null \
                && log "installed $CONF_DEST" \
                || warn "could not install $CONF_DEST (continuing)"
            sysctl --system >/dev/null 2>&1 || warn "sysctl --system failed (continuing)"
        fi
    else
        warn "/etc/sysctl.d not present; skipped persistent drop-in"
    fi
}

cmd_revert() {
    local dry="$1"
    if [ -f "$CONF_DEST" ]; then
        if [ "$dry" = "1" ]; then
            log "would remove $CONF_DEST"
        else
            rm -f "$CONF_DEST" && log "removed $CONF_DEST"
            sysctl --system >/dev/null 2>&1 || warn "sysctl --system failed (continuing)"
        fi
    else
        log "no drop-in at $CONF_DEST; nothing to revert"
    fi
}

main() {
    local sub="${1:-}"
    case "$sub" in
        --help|-h) usage; return 0 ;;
        "") usage; return 1 ;;
        apply)  shift; [ "${1:-}" = "--dry-run" ] && cmd_apply 1 || cmd_apply 0 ;;
        revert) shift; [ "${1:-}" = "--dry-run" ] && cmd_revert 1 || cmd_revert 0 ;;
        check)  cmd_check ;;
        *) usage; return 1 ;;
    esac
}

main "$@"
```

Make executable: `chmod +x scripts/tune-system.sh`

- [ ] **Step 4: Run tests**

Run: `scripts/test_tune_system.sh`
Expected: `ALL PASS`.

- [ ] **Step 5: Smoke-test `check` and `apply --dry-run`**

Run: `scripts/tune-system.sh check`
Expected: table with 11 knob rows (`udp_mem`, etc.); exit 0.

Run: `scripts/tune-system.sh apply --dry-run`
Expected: `raise ...` or `keep ...` lines + `would install ...`; exit 0; no writes.

- [ ] **Step 6: Commit**

```bash
cd /home/benji/src/devnw/zig/quic
git add scripts/tune-system.sh scripts/test_tune_system.sh
git commit -m "feat(tuning): add tune-system.sh apply/revert/check + tests"
```

---

## Task 3: zig-quic — `docs/SYSTEM_TUNING.md`

**Files:** Create `docs/SYSTEM_TUNING.md`

- [ ] **Step 1: Write the operator doc**

```markdown
# System Tuning for zig-quic

Source-of-truth for OS-level knobs that bound zig-quic throughput on Linux. Downstream consumers (e.g. `geode`) vendor the same values and helper.

## TL;DR

```

scripts/tune-system.sh check              # current vs. recommended
sudo scripts/tune-system.sh apply         # raise + persist
sudo scripts/tune-system.sh revert        # undo

```text

## What `apply` does

1. For each knob in `config/sysctl.d/99-zig-quic.conf`:
   - Numeric and `current < recommended`: raise via `sysctl -w`.
   - Already `>= recommended`: leave untouched.
   - Multi-value / non-numeric (`udp_mem`, `ip_local_port_range`, `default_qdisc`): write verbatim.
2. Install `/etc/sysctl.d/99-zig-quic.conf` for reboot persistence.
3. Run `sysctl --system` to reload drop-ins in precedence order.

Individual failures are logged and ignored — tuning is best-effort.

## The knobs

| Knob | Value | Why |
|---|---|---|
| `net.core.rmem_max` | 7340032 (7 MB) | Per-socket `SO_RCVBUF` ceiling. Matches quic-go recommendation. |
| `net.core.wmem_max` | 7340032 (7 MB) | Per-socket `SO_SNDBUF` ceiling. |
| `net.core.rmem_default` | 2500000 | Default recv buffer when process does not `setsockopt`. |
| `net.core.wmem_default` | 2500000 | Symmetric. |
| `net.core.netdev_max_backlog` | 5000 | NIC -> softirq queue. Prevents drops at 10 G+ bursts. |
| `net.ipv4.udp_mem` | `262144 524288 1048576` | System-wide UDP memory pages (min / pressure / max). |
| `net.ipv4.udp_rmem_min` | 16384 | Per-socket recv floor under memory pressure. |
| `net.ipv4.udp_wmem_min` | 16384 | Symmetric. |
| `net.ipv4.ip_local_port_range` | `1024 65535` | Ephemeral port range for clients. |
| `net.core.default_qdisc` | `fq` | Pacing-aware qdisc; requires `sch_fq` module (ubiquitous). |
| `fs.file-max` | 1048576 | Kernel-wide fd ceiling, aligns with `LimitNOFILE=65536`. |

## Precedence and local overrides

`/etc/sysctl.d/` files load in lexical order. For higher local values, use a later-sorting filename (e.g. `99-zzz-local.conf`). Our drop-in never touches files it did not write.

## Verifying

```

sysctl net.core.rmem_max net.core.wmem_max net.core.default_qdisc

```text

After reboot, re-run `scripts/tune-system.sh check`.

## Containers

```

docker run --sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032 ...

```text

Unprivileged containers without `CAP_NET_ADMIN` cannot set sysctls at runtime — tune the host instead.

## BSD / macOS

No automated apply. Manual equivalent:

```

sudo sysctl -w kern.ipc.maxsockbuf=8441037   # ~7 MB + 15% padding

```text

`fq`, `udp_mem`, `ip_local_port_range` have no direct BSD equivalents.

## Deliberately not tuned

- `net.core.busy_poll` / `busy_read` — CPU-at-idle tradeoff not justified by workload data.
- `somaxconn` — QUIC is UDP; listen-backlog does not apply.
- Conntrack UDP timeouts — tune per-deployment behind stateful NAT.
- GSO / GRO — zig-quic does not use GSO today (tracked under issue #109).

## Spec

`docs/superpowers/specs/2026-04-22-quic-system-tuning-design.md`

```

- [ ] **Step 2: Verify the doc covers every knob in the conf**

Run:

```bash
diff \
  <(grep -oE '(net|fs)\.[a-z0-9._-]+' config/sysctl.d/99-zig-quic.conf | sort -u) \
  <(grep -oE '(net|fs)\.[a-z0-9._-]+' docs/SYSTEM_TUNING.md | sort -u)
```

Expected: no lines unique to the conf (every knob is documented).

- [ ] **Step 3: Commit**

```bash
cd /home/benji/src/devnw/zig/quic
git add docs/SYSTEM_TUNING.md
git commit -m "docs(tuning): add SYSTEM_TUNING.md operator reference"
```

---

## Task 4: zig-quic — README + CLAUDE pointers

**Files:** Modify `README.md` (Docs section) and `CLAUDE.md` (Quick Commands block)

- [ ] **Step 1: Append to `README.md` under `## Docs`**

After the existing bullet `- Design: \`docs/DESIGN.md\``, add:

```text
- System tuning (sysctl / UDP buffers): `docs/SYSTEM_TUNING.md` — apply via `sudo scripts/tune-system.sh apply`
```

- [ ] **Step 2: Append to `CLAUDE.md` `## Quick Commands` code block**

Inside the existing ` ```bash ... ``` ` block, before the closing fence, add:

```text
sudo scripts/tune-system.sh apply   # apply canonical UDP/network sysctl tuning (docs/SYSTEM_TUNING.md)
```

- [ ] **Step 3: Verify pointers present**

Run: `grep -n 'SYSTEM_TUNING' README.md CLAUDE.md`
Expected: ≥ 1 hit per file.

- [ ] **Step 4: Confirm no zig regression (pointers are docs-only, but sanity-check)**

Run: `zig build test 2>&1 | tail -5`
Expected: same pass/fail state as before the change. Per `CLAUDE.md` Known Issue #1, the `test_transport_geode_compat.zig:246` failure is pre-existing and tolerable; any NEW failure is a regression.

- [ ] **Step 5: Commit**

```bash
cd /home/benji/src/devnw/zig/quic
git add README.md CLAUDE.md
git commit -m "docs(tuning): reference SYSTEM_TUNING.md from README + CLAUDE.md"
```

---

## Task 5: geode — vendor sysctl drop-in

**Files:** Create `/home/benji/src/devnw/codepros/geode/geode/deployment/sysctl.d/99-geode-quic.conf`

- [ ] **Step 1: Create with geode-specific header**

```conf
# geode — system-level tuning for QUIC/UDP workloads
# Sourced from devnw/zig/quic: docs/SYSTEM_TUNING.md (2026-04-22 spec)
# Apply via: sudo deployment/scripts/tune-system.sh apply
# Also applied at install time by deployment/scripts/postinstall.sh and `make install`.

# --- UDP socket buffers (per-socket ceilings) ---
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032

# --- UDP socket buffers (per-socket defaults) ---
net.core.rmem_default = 2500000
net.core.wmem_default = 2500000

# --- NIC -> kernel softirq queue depth ---
net.core.netdev_max_backlog = 5000

# --- System-wide UDP memory (pages) ---
net.ipv4.udp_mem = 262144 524288 1048576

# --- Per-socket UDP memory floor under pressure ---
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- Client-side ephemeral port range ---
net.ipv4.ip_local_port_range = 1024 65535

# --- Pacing-aware qdisc ---
net.core.default_qdisc = fq

# --- Kernel-wide file descriptor ceiling ---
fs.file-max = 1048576
```

- [ ] **Step 2: Verify body matches zig-quic byte-for-byte (comments excluded)**

```bash
diff \
  <(grep -vE '^\s*(#|$)' /home/benji/src/devnw/zig/quic/config/sysctl.d/99-zig-quic.conf) \
  <(grep -vE '^\s*(#|$)' /home/benji/src/devnw/codepros/geode/geode/deployment/sysctl.d/99-geode-quic.conf)
```

Expected: empty diff.

---

## Task 6: geode — vendor `tune-system.sh`

**Files:** Create `/home/benji/src/devnw/codepros/geode/geode/deployment/scripts/tune-system.sh`

- [ ] **Step 1: Copy from zig-quic, change defaults**

Copy `/home/benji/src/devnw/zig/quic/scripts/tune-system.sh` verbatim to the geode path above, then change the two default-path lines near the top:

From:

```bash
readonly CONF_SRC="${TUNE_CONF:-$SCRIPT_DIR/../config/sysctl.d/99-zig-quic.conf}"
readonly CONF_DEST="${TUNE_DEST:-/etc/sysctl.d/99-zig-quic.conf}"
```

To:

```bash
readonly CONF_SRC="${TUNE_CONF:-$SCRIPT_DIR/../sysctl.d/99-geode-quic.conf}"
readonly CONF_DEST="${TUNE_DEST:-/etc/sysctl.d/99-geode-quic.conf}"
```

Make executable: `chmod +x deployment/scripts/tune-system.sh`

- [ ] **Step 2: Bash syntax check**

Run: `bash -n /home/benji/src/devnw/codepros/geode/geode/deployment/scripts/tune-system.sh`
Expected: exit 0, no output.

- [ ] **Step 3: Smoke-test `check`**

Run (from geode root): `./deployment/scripts/tune-system.sh check`
Expected: table with 11 rows, exit 0.

---

## Task 7: geode — extend `postinstall.sh`

**Files:** Modify `/home/benji/src/devnw/codepros/geode/geode/deployment/scripts/postinstall.sh:7-50`

- [ ] **Step 1: Replace the 2-knob tuning block**

Current lines 7-50 tune only `rmem_max` / `wmem_max` and write a 2-knob drop-in; also contain a stale `QUIC_GO_DISABLE_GSO` comment. Replace with a single invocation of the vendored `tune-system.sh`:

From (currently in postinstall.sh):

```bash
# Configure QUIC performance optimizations
# These settings significantly improve QUIC/UDP throughput for high-bandwidth connections
echo "Configuring QUIC performance optimizations..."

# Increase UDP buffer sizes for high-throughput QUIC transfers
# Default values are too small for high-bandwidth connections
RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
WMEM_MAX=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "0")
...
# Note: Generic Segmentation Offload (GSO) is automatically enabled by quic-go
# on Linux kernel 4.18+. To disable GSO (not recommended), set:
# Environment="QUIC_GO_DISABLE_GSO=true" in the systemd service file.
```

To:

```bash
# Configure QUIC / UDP system-level tuning.
# Source-of-truth: devnw/zig/quic docs/SYSTEM_TUNING.md.
# Applies 10 kernel knobs with "only raise, never lower" semantics and persists
# them to /etc/sysctl.d/99-geode-quic.conf. Best-effort — never blocks install.
echo "Applying QUIC/UDP system tuning..."

TUNE_SH="/usr/share/geode/deployment/scripts/tune-system.sh"
TUNE_CONF_PATH="/usr/share/geode/deployment/sysctl.d/99-geode-quic.conf"

# Fall back to the build tree when the helper has not been packaged yet (source install).
if [ ! -x "$TUNE_SH" ]; then
    for cand in "./deployment/scripts/tune-system.sh" "$(dirname "$0")/tune-system.sh"; do
        if [ -x "$cand" ]; then TUNE_SH="$cand"; break; fi
    done
fi
if [ ! -f "$TUNE_CONF_PATH" ]; then
    for cand in "./deployment/sysctl.d/99-geode-quic.conf" "$(dirname "$0")/../sysctl.d/99-geode-quic.conf"; do
        if [ -f "$cand" ]; then TUNE_CONF_PATH="$cand"; break; fi
    done
fi

if [ -x "$TUNE_SH" ] && [ -f "$TUNE_CONF_PATH" ]; then
    TUNE_CONF="$TUNE_CONF_PATH" "$TUNE_SH" apply || true
else
    echo "  Warning: tuning helper not found; skipping system tuning."
    echo "  See https://gitlab.com/devnw/zig/quic/-/blob/main/docs/SYSTEM_TUNING.md"
fi
```

Leave the rest (chown, cert gen, systemctl) unchanged.

- [ ] **Step 2: Bash syntax check**

Run: `bash -n deployment/scripts/postinstall.sh`
Expected: exit 0.

- [ ] **Step 3: Verify stale refs removed**

Run: `grep -c 'QUIC_GO\|quic-go' deployment/scripts/postinstall.sh`
Expected: `0`.

---

## Task 8: geode — `install-tuning` Makefile target

**Files:** Modify `/home/benji/src/devnw/codepros/geode/geode/Makefile`

- [ ] **Step 1: Extend the `.PHONY` line that lists `install`**

Locate the `.PHONY:` line near line 31 containing `install`:

```text
.PHONY: all build release install test integration-test ...
```

Change `install` to `install install-tuning`:

```text
.PHONY: all build release install install-tuning test integration-test ...
```

- [ ] **Step 2: Replace the `install` target at lines 196-202**

From:

```text
install: release
 @echo "=== Installing geode from current branch ==="
 sudo systemctl stop geode
 @sleep 2
 sudo cp zig-out/bin/geode /usr/bin/geode
 sudo systemctl start geode
 @echo "✓ geode installed and restarted"
```

To:

```text
install: release install-tuning
 @echo "=== Installing geode from current branch ==="
 sudo systemctl stop geode
 @sleep 2
 sudo cp zig-out/bin/geode /usr/bin/geode
 sudo systemctl start geode
 @echo "✓ geode installed and restarted"

# Apply the canonical zig-quic sysctl tuning. Unconditional on developer hosts;
# idempotent and only-raise. See deployment/sysctl.d/99-geode-quic.conf.
install-tuning:
 @echo "=== Applying QUIC/UDP system tuning ==="
 @sudo deployment/scripts/tune-system.sh apply
 @echo "✓ system tuning applied"
```

- [ ] **Step 3: Validate Makefile parses**

Run: `cd /home/benji/src/devnw/codepros/geode/geode && make -n install-tuning`
Expected: dry-run shows `sudo deployment/scripts/tune-system.sh apply`; exit 0.

Run: `cd /home/benji/src/devnw/codepros/geode/geode && make -n install 2>&1 | head -20`
Expected: dry-run shows both `deployment/scripts/tune-system.sh apply` and `cp zig-out/bin/geode /usr/bin/geode`.

---

## Task 9: geode — purge stale `quic-go` refs in service + config

**Files:**

- Modify: `deployment/systemd/geode.service:42-50`
- Modify: `deployment/config/geode.conf:33-46`

- [ ] **Step 1: Replace `geode.service` lines 42-50**

From:

```text
# QUIC Performance Optimizations
# GSO (Generic Segmentation Offload) is enabled by default on Linux 4.18+
# Uncomment the following line to disable GSO (not recommended):
# Environment="QUIC_GO_DISABLE_GSO=true"

# UDP buffer sizes should be configured via sysctl for optimal performance:
# sysctl -w net.core.rmem_max=7340032
# sysctl -w net.core.wmem_max=7340032
# See /etc/sysctl.d/99-geode-quic.conf for persistent configuration
```

To:

```text
# QUIC / UDP tuning is applied at install time via deployment/scripts/tune-system.sh
# and persisted to /etc/sysctl.d/99-geode-quic.conf. See devnw/zig/quic
# docs/SYSTEM_TUNING.md for per-knob rationale and rollback.
#
# The service runs with ProtectKernelTunables=true, so runtime sysctl writes from
# this process are (intentionally) blocked — tuning must be installed out-of-band.
```

- [ ] **Step 2: Replace `geode.conf` `[quic]` section lines 33-46**

From:

```text
# QUIC Performance Tuning
[quic]
# Path MTU Discovery (DPLPMTUD) - probes for optimal MTU size
# Enabled by default, reduces per-packet overhead on paths supporting >1200 byte MTUs
# enable_path_mtu_discovery = true

# UDP Buffer Sizes - Must be configured at OS level via sysctl:
#   sysctl -w net.core.rmem_max=7340032  (7MB receive buffer)
#   sysctl -w net.core.wmem_max=7340032  (7MB send buffer)
# For persistent settings, add to /etc/sysctl.d/99-geode-quic.conf

# Generic Segmentation Offload (GSO) - Linux 4.18+ only
# Enabled automatically by quic-go, batches UDP packets for reduced syscall overhead
# To disable (not recommended), set environment variable: QUIC_GO_DISABLE_GSO=true
```

To:

```text
# QUIC Performance Tuning
[quic]
# Path MTU Discovery (DPLPMTUD) — probes for optimal MTU size.
# Enabled by default in zig-quic; reduces per-packet overhead on paths
# supporting > 1200 byte MTUs.
# enable_path_mtu_discovery = true

# OS-level tuning (UDP buffers, udp_mem, netdev_max_backlog, qdisc=fq, ...)
# is applied out-of-band at install time via:
#   sudo deployment/scripts/tune-system.sh apply
# and persisted to /etc/sysctl.d/99-geode-quic.conf.
# See devnw/zig/quic docs/SYSTEM_TUNING.md for per-knob rationale.
```

- [ ] **Step 3: Verify no stale refs anywhere in deployment/**

Run:

```bash
grep -rn 'QUIC_GO\|quic-go' deployment/ 2>&1
```

Expected: no matches (grep exits 1).

---

## Task 10: geode — rewrite `deployment/README.md` QUIC section

**Files:** Modify `deployment/README.md:254-320`

- [ ] **Step 1: Replace the whole "QUIC Performance Optimizations" section**

Locate line `## QUIC Performance Optimizations` (≈ line 254). Replace from that heading through the end of the `### Docker Deployments` subsection (≈ line 320) with:

```markdown
## QUIC Performance Optimizations

Geode runs over `devnw/zig/quic`. The upstream `docs/SYSTEM_TUNING.md` is the source of truth for OS-level knobs; geode vendors the same values and applies them at install time.

### Applied automatically

Both `apt install geode` / `rpm -i geode` and `make install` run `deployment/scripts/tune-system.sh apply`, which:

1. Raises ten kernel knobs if the running value is lower than ours (never lowers — protects operators who tuned higher).
2. Installs `/etc/sysctl.d/99-geode-quic.conf` for persistence.
3. Runs `sysctl --system` to reload drop-ins in precedence order.

The knobs:

| Knob | Value |
|---|---|
| `net.core.rmem_max` | 7340032 (7 MB) |
| `net.core.wmem_max` | 7340032 (7 MB) |
| `net.core.rmem_default` | 2500000 |
| `net.core.wmem_default` | 2500000 |
| `net.core.netdev_max_backlog` | 5000 |
| `net.ipv4.udp_mem` | `262144 524288 1048576` |
| `net.ipv4.udp_rmem_min` | 16384 |
| `net.ipv4.udp_wmem_min` | 16384 |
| `net.ipv4.ip_local_port_range` | `1024 65535` |
| `net.core.default_qdisc` | `fq` |
| `fs.file-max` | 1048576 |

### Manually applying

```

./deployment/scripts/tune-system.sh check              # preview
sudo ./deployment/scripts/tune-system.sh apply         # apply + persist
sudo ./deployment/scripts/tune-system.sh revert        # undo

```text

### Overriding individual knobs

`/etc/sysctl.d/` loads in lexical order. Place local overrides in a later-sorting file:

```

echo 'net.core.rmem_max=16777216' | sudo tee /etc/sysctl.d/99-zzz-local.conf
sudo sysctl --system

```text

### BSD / macOS

No scripted apply. Manual approximation:

```

sudo sysctl -w kern.ipc.maxsockbuf=8441037   # ~7 MB + 15% padding

```text

`fq`, `udp_mem`, `ip_local_port_range` have no direct BSD equivalents.

### Docker Deployments

```

docker run \
  --sysctl net.core.rmem_max=7340032 \
  --sysctl net.core.wmem_max=7340032 \
  --sysctl net.core.rmem_default=2500000 \
  --sysctl net.core.wmem_default=2500000 \
  geode:latest

```text

Prefer tuning the host — containers inherit host sysctls unless overridden, and unprivileged containers cannot raise limits at runtime.

Upstream reference: [`devnw/zig/quic` docs/SYSTEM_TUNING.md](https://gitlab.com/devnw/zig/quic/-/blob/main/docs/SYSTEM_TUNING.md)

```

- [ ] **Step 2: Verify README has no stale refs and links upstream**

Run: `grep -c 'QUIC_GO\|quic-go' deployment/README.md`
Expected: `0`.

Run: `grep -c 'SYSTEM_TUNING' deployment/README.md`
Expected: `>= 1`.

---

## Task 11: geode — package the vendored assets

**Files:** Inspect packaging config; modify if needed.

- [ ] **Step 1: Locate packaging config**

Run:

```bash
ls /home/benji/src/devnw/codepros/geode/geode/release 2>/dev/null
ls /home/benji/src/devnw/codepros/geode/geode/.goreleaser*.yml 2>/dev/null
grep -rn 'postinstall\|deployment/scripts\|deployment/sysctl\|/usr/share' \
    /home/benji/src/devnw/codepros/geode/geode/.goreleaser*.yml \
    /home/benji/src/devnw/codepros/geode/geode/release 2>/dev/null | head -30
```

Expected: shows how `postinstall.sh` is currently referenced. Note whether `deployment/scripts/tune-system.sh` and `deployment/sysctl.d/99-geode-quic.conf` need to be added.

- [ ] **Step 2: If packaging config lacks them, extend `contents:`**

In `.goreleaser.yml` (or equivalent nfpms section), add:

```yaml
nfpms:
  - contents:
      - src: deployment/scripts/tune-system.sh
        dst: /usr/share/geode/deployment/scripts/tune-system.sh
        file_info:
          mode: 0755
      - src: deployment/sysctl.d/99-geode-quic.conf
        dst: /usr/share/geode/deployment/sysctl.d/99-geode-quic.conf
        file_info:
          mode: 0644
```

If the project uses a different packaging mechanism, replicate the same two file mappings there.

- [ ] **Step 3: Verify packaging via snapshot build**

Run: `cd /home/benji/src/devnw/codepros/geode/geode && make goreleaser-snapshot 2>&1 | tail -20`
Expected: snapshot build completes. (If `goreleaser` is missing locally, this step can be deferred to CI — note in the commit message.)

Run (if snapshot succeeded):

```bash
tar -tf dist/geode_*.tar.gz 2>/dev/null | grep -E 'tune-system|99-geode-quic' || \
find dist -name '*.deb' -exec dpkg -c {} \; 2>/dev/null | grep -E 'tune-system|99-geode-quic'
```

Expected: both files appear in the produced package.

- [ ] **Step 4: Confirm `make install` dev path works regardless of packaging**

Run: `cd /home/benji/src/devnw/codepros/geode/geode && make -n install-tuning`
Expected: `sudo deployment/scripts/tune-system.sh apply`.

---

## Task 12: geode — final verification + commit

**Files:** none (verification only)

- [ ] **Step 1: Confirm no `.zig` files changed**

Run: `cd /home/benji/src/devnw/codepros/geode/geode && git status --short`
Expected: modified files are all under `Makefile`, `deployment/`, and (optionally) `.goreleaser.yml` — no `.zig` files.

- [ ] **Step 2: Run geode test suite**

Run: `cd /home/benji/src/devnw/codepros/geode/geode && make test 2>&1 | tail -15`
Expected: same pass/fail state as before the change (packaging-only edits).

- [ ] **Step 3: Final grep sweep**

Run:

```bash
cd /home/benji/src/devnw/codepros/geode/geode
grep -rn 'QUIC_GO\|quic-go' deployment/ Makefile 2>&1
```

Expected: no matches.

- [ ] **Step 4: Commit geode changes as one coherent commit**

```bash
cd /home/benji/src/devnw/codepros/geode/geode
git add deployment/sysctl.d/ deployment/scripts/tune-system.sh deployment/scripts/postinstall.sh \
        deployment/systemd/geode.service deployment/config/geode.conf deployment/README.md \
        Makefile
# If Task 11 changed packaging:
# git add .goreleaser.yml
git commit -m "$(cat <<'EOF'
feat(deploy): adopt zig-quic canonical sysctl tuning (10 knobs)

- vendor 99-geode-quic.conf drop-in (superset-identical to zig-quic)
- vendor tune-system.sh apply/revert/check with only-raise semantics
- postinstall.sh now applies 10 knobs (was 2) via tune-system.sh
- Makefile: `make install` now invokes `install-tuning` on dev hosts
- purge stale quic-go / QUIC_GO_DISABLE_GSO refs (geode runs on zig-quic)
- deployment/README.md documents the full set + BSD/macOS fallback

Source of truth: devnw/zig/quic docs/SYSTEM_TUNING.md
EOF
)"
```

---

## Plan self-review

**Spec coverage:**

- Goals 1 (zig-quic source of truth) → Tasks 1-4.
- Goals 2 (geode vendors and applies unconditionally) → Tasks 5-8, 11.
- Goals 3 (idempotent, only-raise, reversible, persistent) → Task 2 (script + unit tests); end-to-end via Task 7 postinstall.
- Goals 4 (purge stale quic-go refs) → Tasks 9, 10, 12 Step 3.
- Non-goals (GSO, busy_poll, somaxconn, runtime auto-detection) → not implemented; Task 3 documents exclusions.
- Tuning set (10 knobs) → Task 1 (canonical) + Task 5 (geode vendor); byte-identical via Task 5 Step 2.
- Runtime semantics (only-raise, verbatim for multi-value) → Task 2 Step 3 (`should_raise` + special-case branch).
- Error handling (best-effort, never blocks install) → Task 2 Step 3 + Task 7 Step 1 (fallback paths, `|| true`).
- Testing → Task 2 Step 1 (unit tests), Tasks 4/8/12 (regression sweeps + Makefile dry-run).
- Rollout (zig-quic first, then geode) → Tasks 1-4 before Tasks 5-12.

No gaps.

**Placeholder scan:** None.

**Type consistency:** Subcommand names (`apply`, `revert`, `check`, `--dry-run`) identical across Tasks 2, 6, 7, 8, 10. File names (`99-zig-quic.conf`, `99-geode-quic.conf`) consistent. Env-var names (`TUNE_CONF`, `TUNE_DEST`) identical across zig-quic and geode scripts. `install-tuning` Makefile target name identical across Tasks 8, 11, 12.
