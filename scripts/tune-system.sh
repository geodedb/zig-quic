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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_DIR
readonly CONF_SRC="${TUNE_CONF:-$SCRIPT_DIR/../config/sysctl.d/99-zig-quic.conf}"
readonly CONF_DEST="${TUNE_DEST:-/etc/sysctl.d/99-zig-quic.conf}"

# Resolve sysctl binary. Package-manager postinstall and CI sandboxes can run
# with a restricted PATH that excludes /usr/sbin and /sbin, so fall back by path.
find_sysctl() {
    if command -v sysctl >/dev/null 2>&1; then command -v sysctl; return; fi
    for p in /usr/sbin/sysctl /sbin/sysctl /usr/local/sbin/sysctl; do
        [ -x "$p" ] && { printf '%s\n' "$p"; return; }
    done
    printf '\n'
}
SYSCTL="$(find_sysctl)"
readonly SYSCTL

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

read_cur() { [ -n "$SYSCTL" ] && "$SYSCTL" -n "$1" 2>/dev/null || echo ""; }

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
    if [ -z "$SYSCTL" ] && [ "$dry" != "1" ]; then
        warn "sysctl(8) not found on PATH or in /sbin /usr/sbin; skipping runtime apply"
    fi

    while IFS=$'\t' read -r knob val; do
        cur=$(read_cur "$knob")
        case "$knob" in
            net.ipv4.udp_mem|net.ipv4.ip_local_port_range|net.core.default_qdisc)
                log "set $knob = $val"
                if [ "$dry" != "1" ]; then
                    "$SYSCTL" -w "$knob=$val" >/dev/null 2>&1 \
                        || warn "failed to set $knob (continuing)"
                fi
                ;;
            *)
                if should_raise "$knob" "$cur" "$val"; then
                    log "raise $knob: $cur -> $val"
                    if [ "$dry" != "1" ]; then
                        sysctl -w "$knob=$val" >/dev/null 2>&1 \
                            || warn "failed to set $knob (continuing)"
                    fi
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
            if install -m 0644 "$CONF_SRC" "$CONF_DEST" 2>/dev/null; then
                log "installed $CONF_DEST"
            else
                warn "could not install $CONF_DEST (continuing)"
            fi
            "$SYSCTL" --system >/dev/null 2>&1 || warn "sysctl --system failed (continuing)"
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
            "$SYSCTL" --system >/dev/null 2>&1 || warn "sysctl --system failed (continuing)"
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
        apply)  shift; if [ "${1:-}" = "--dry-run" ]; then cmd_apply 1; else cmd_apply 0; fi ;;
        revert) shift; if [ "${1:-}" = "--dry-run" ]; then cmd_revert 1; else cmd_revert 0; fi ;;
        check)  cmd_check ;;
        *) usage; return 1 ;;
    esac
}

main "$@"
