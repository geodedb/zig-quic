#!/usr/bin/env bash
set -euo pipefail

warn() {
  printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2
}

note() {
  printf '\033[1;34m[INFO]\033[0m %s\n' "$*" >&2
}

if command -v gh >/dev/null 2>&1; then
  if ! gh auth status >/dev/null 2>&1; then
    if [[ -r "$HOME/.github_token" ]]; then
      gh auth login --with-token < "$HOME/.github_token" >/dev/null 2>&1 || warn "GitHub login via ~/.github_token failed"
    else
      warn "gh is installed but no session or ~/.github_token found"
    fi
  fi
  GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
  export GITHUB_TOKEN
  [[ -n "${GITHUB_TOKEN:-}" ]] && note "GITHUB_TOKEN exported for this shell"
else
  warn "gh CLI not found; skipping GitHub token setup"
fi

if command -v vault >/dev/null 2>&1; then
  export VAULT_ADDR="${VAULT_ADDR:-https://pki.devnw.com}"
  if [[ -n "${GITHUB_TOKEN:-}" ]] && ! vault token lookup -no-print >/dev/null 2>&1; then
    vault login -no-print -method=github token="$GITHUB_TOKEN" >/dev/null 2>&1 || warn "Vault login failed"
  fi

  OPENAI_API_KEY="$(vault kv get -mount=secret -field=token /dev/openai/actions-primary 2>/dev/null || true)"
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    export OPENAI_API_KEY
    note "OPENAI_API_KEY loaded into environment"
  fi

  CACHIX_AUTH_TOKEN="$(vault kv get -mount=secret -field=token /cicd/gh/cachix 2>/dev/null || true)"
  if [[ -n "${CACHIX_AUTH_TOKEN:-}" ]]; then
    export CACHIX_AUTH_TOKEN
    note "CACHIX_AUTH_TOKEN loaded into environment"
    if command -v cachix >/dev/null 2>&1; then
      cachix authtoken "$CACHIX_AUTH_TOKEN" >/dev/null 2>&1 || warn "cachix authtoken failed"
      cachix use spyder >/dev/null 2>&1 || warn "cachix use spyder failed"
    fi
  fi
else
  warn "vault CLI not found; skipping secret retrieval"
fi
