#!/usr/bin/env bash
# Install Nix and direnv with resilient fallbacks (WSL/containers/macOS-friendly).
# - Avoids sudo if it's broken or unavailable
# - Multi-user Nix only when systemd+sudo are healthy
#
# SECURITY WARNING:
# This script downloads and executes code from the internet (nixos.org).
# Before running this script, you should:
# 1. Verify you trust the Nix project (https://nixos.org)
# 2. Review the installer manually: curl https://nixos.org/nix/install | less
# 3. Consider using your OS package manager instead if available
#
# Usage: ./install_pkgs.sh
# Env:
#   FORCE_SINGLE_USER=1  # Force single-user install of Nix
#   NO_SUDO=1            # Never attempt to use sudo
#   NONINTERACTIVE=1     # Auto-accept prompts where supported
#   SKIP_VERIFY=1        # Skip installer verification (not recommended)
#
# Re-run safe.

set -euo pipefail
umask 022

# ---------- utils ----------
log()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

ensure_line() {
  # ensure_line <file> <exact line>
  local f="$1" line="$2"
  mkdir -p "$(dirname "$f")"
  touch "$f"
  grep -Fqx "$line" "$f" || printf "%s\n" "$line" >> "$f"
}

# Environment detection
is_wsl()       { [[ -f /proc/version ]] && grep -qi microsoft /proc/version; }
has_systemd()  { [ -d /run/systemd/system ] && have systemctl; }
in_container() { grep -qaE 'docker|lxc|containerd|podman' /proc/1/cgroup 2>/dev/null || [ -f /.dockerenv ] || [ -f /run/.containerenv ]; }

# Sudo health checks (without invoking sudo unless optional)
sudo_files_broken() {
  local bad=0
  if [ -e /etc/sudoers ]; then
    local uid gid
    uid="$(ls -ln /etc/sudoers | awk '{print $3}')" || true
    gid="$(ls -ln /etc/sudoers | awk '{print $4}')" || true
    [[ "${uid:-0}" != "0" || "${gid:-0}" != "0" ]] && bad=1
  fi
  if [ -e /etc/sudo.conf ]; then
    local uid gid
    uid="$(ls -ln /etc/sudo.conf | awk '{print $3}')" || true
    gid="$(ls -ln /etc/sudo.conf | awk '{print $4}')" || true
    [[ "${uid:-0}" != "0" || "${gid:-0}" != "0" ]] && bad=1
  fi
  return "$bad"
}

sudo_ok() {
  [[ "${NO_SUDO:-0}" == "1" ]] && return 1
  have sudo || return 1
  sudo_files_broken && return 1
  # Optional runtime check; ignore output if sudo is locked down
  sudo -n true >/dev/null 2>&1 || return 1
  return 0
}

# If we happen to run as root, repair sudo file ownership/permissions safely
fix_sudo_files_if_root() {
  [ "$EUID" -eq 0 ] || return 0
  local changed=0
  if [ -e /etc/sudoers ]; then
    local uid gid
    uid="$(ls -ln /etc/sudoers | awk '{print $3}')" || true
    gid="$(ls -ln /etc/sudoers | awk '{print $4}')" || true
    if [[ "${uid:-0}" != "0" || "${gid:-0}" != "0" ]]; then
      warn "Repairing /etc/sudoers ownership (uid=$uid gid=$gid -> root:root)"
      chown root:root /etc/sudoers
      changed=1
    fi
    chmod 0440 /etc/sudoers || true
  fi
  if [ -e /etc/sudo.conf ]; then
    local uid gid
    uid="$(ls -ln /etc/sudo.conf | awk '{print $3}')" || true
    gid="$(ls -ln /etc/sudo.conf | awk '{print $4}')" || true
    if [[ "${uid:-0}" != "0" || "${gid:-0}" != "0" ]]; then
      warn "Repairing /etc/sudo.conf ownership (uid=$uid gid=$gid -> root:root)"
      chown root:root /etc/sudo.conf
      changed=1
    fi
    chmod 0444 /etc/sudo.conf || true
  fi
  if [ -d /etc/sudoers.d ]; then
    chown -R root:root /etc/sudoers.d || true
    chmod 0750 /etc/sudoers.d || true
    find /etc/sudoers.d -type f -exec chmod 0440 {} + 2>/dev/null || true
  fi
  if have visudo; then
    visudo -c || warn "visudo syntax check reported issues; review /etc/sudoers"
  fi
  (( changed )) && log "sudo files repaired."
}

# Source Nix profile for the current shell
source_nix_env() {
  for p in \
    /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh \
    "$HOME/.nix-profile/etc/profile.d/nix.sh" \
    /etc/profile.d/nix.sh
  do
    [ -r "$p" ] && . "$p" && return 0
  done
  return 1
}

# ---------- Nix install ----------
install_nix() {
  if have nix; then
    log "Nix already present: $(nix --version)"
    return 0
  fi

  warn "SECURITY: About to download installer from nixos.org"
  warn "Review the source at: https://github.com/NixOS/nix/blob/master/scripts/install-nix-from-closure.sh"

  local installer="/tmp/nix-install.$$"

  # Download the installer
  log "Downloading Nix installer..."
  curl -fsSL https://nixos.org/nix/install -o "$installer"
  trap 'rm -f "$installer"' EXIT

  # Basic sanity check: verify it looks like a shell script
  if ! head -1 "$installer" | grep -q "^#!"; then
    die "Downloaded file does not appear to be a shell script. Aborting for safety."
  fi

  # Verify it contains expected Nix installer markers
  if ! grep -q "nix-store" "$installer" || ! grep -q "NIX_" "$installer"; then
    die "Downloaded file does not appear to be the Nix installer. Aborting for safety."
  fi

  log "Basic installer verification passed"

  # Optional: Skip interactive confirmation in non-interactive mode
  if [[ "${NONINTERACTIVE:-0}" != "1" ]] && [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
    warn "You can review the installer at: $installer"
    warn "Press Enter to continue or Ctrl+C to abort..."
    read -r
  fi

  local nonint=()
  [[ "${NONINTERACTIVE:-0}" == "1" ]] && nonint+=(--yes)

  # Decide install mode
  local want_multi=1
  if [[ "${FORCE_SINGLE_USER:-0}" == "1" ]] || is_wsl || in_container || ! has_systemd; then
    want_multi=0
  fi
  if ! sudo_ok; then
    [[ $want_multi -eq 1 ]] && warn "sudo/systemd not healthy; falling back to single-user Nix."
    want_multi=0
  fi

  if (( want_multi )); then
    log "Installing Nix (multi-user)…"
    if [ "$EUID" -eq 0 ]; then
      sh "$installer" --daemon "${nonint[@]}"
    else
      sudo sh "$installer" --daemon "${nonint[@]}"
    fi
  else
    log "Installing Nix (single-user)…"
    sh "$installer" --no-daemon "${nonint[@]}"
  fi

  log "Loading Nix profile into this session…"
  source_nix_env || die "Nix installed but profile scripts not found."
  have nix || die "Nix installation did not complete properly."
}

persist_nix_in_shells() {
  # Ensure future shells load Nix (both modes)
  local daemon_line='[ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'
  local single_line='[ -e "$HOME/.nix-profile/etc/profile.d/nix.sh" ] && . "$HOME/.nix-profile/etc/profile.d/nix.sh"'
  ensure_line "$HOME/.bashrc" "$daemon_line"
  ensure_line "$HOME/.bashrc" "$single_line"
  ensure_line "$HOME/.zshrc"  "$daemon_line"
  ensure_line "$HOME/.zshrc"  "$single_line"
  ensure_line "$HOME/.profile" "$daemon_line"
  ensure_line "$HOME/.profile" "$single_line"
}

# ---------- direnv (+ nix-direnv) ----------
install_direnv() {
  log "Installing direnv + nix-direnv via Nix…"
  if nix profile install nixpkgs#direnv nixpkgs#nix-direnv; then
    :
  else
    warn "nix profile failed; trying channel + nix-env fallback."
    have nix-channel || die "nix-channel not available; update Nix or use flakes."
    nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs || true
    nix-channel --update
    nix-env -iA nixpkgs.direnv nixpkgs.nix-direnv
  fi
  log "direnv: $(~/.nix-profile/bin/direnv version 2>/dev/null || direnv version 2>/dev/null || echo installed)"
}

hook_direnv_into_shell() {
  # Only enable hooks if direnv exists in PATH at runtime (prevents noisy startups)
  ensure_line "$HOME/.bashrc" 'command -v direnv >/dev/null 2>&1 && eval "$(direnv hook bash)"'
  ensure_line "$HOME/.zshrc"  'command -v direnv >/dev/null 2>&1 && eval "$(direnv hook zsh)"'
  mkdir -p "$HOME/.config/fish"
  ensure_line "$HOME/.config/fish/config.fish" 'type -q direnv; and direnv hook fish | source'

  # nix-direnv integration: only source if present (prevents non-blocking errors)
  mkdir -p "$HOME/.config/direnv"
  if [[ ! -f "$HOME/.config/direnv/direnvrc" ]] || ! grep -q "nix-direnv/direnvrc" "$HOME/.config/direnv/direnvrc"; then
    cat >> "$HOME/.config/direnv/direnvrc" <<'EOF'
# nix-direnv integration (guarded)
if [ -f "$HOME/.nix-profile/share/nix-direnv/direnvrc" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.nix-profile/share/nix-direnv/direnvrc"
fi
EOF
  fi
}

# ---------- main ----------
main() {
  # If run as root (e.g., WSL root or container root), opportunistically repair sudo file ownership
  fix_sudo_files_if_root

  # Minimal prerequisite
  have curl || die "curl is required to bootstrap Nix."

  install_nix
  persist_nix_in_shells
  install_direnv
  hook_direnv_into_shell

  log "Done."
  printf "\nNext steps:\n"
  printf "  - Start a new shell (or run: exec \"\$SHELL\" -l)\n"
  printf "  - Verify: nix --version; direnv version\n"
  printf "  - In a project: create .envrc (e.g., 'use flake') and run: direnv allow\n"
}
main "$@"
