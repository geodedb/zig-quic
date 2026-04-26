#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

missing_tool=0
for tool in git file; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    missing_tool=1
  fi
done
if [[ "$missing_tool" -ne 0 ]]; then
  exit 2
fi

failed=0
while IFS= read -r -d '' path; do
  [[ -f "$path" ]] || continue
  desc="$(file -b "$path")"
  case "$desc" in
    ELF*"executable"*|ELF*"shared object"*|Mach-O*"executable"*|Mach-O*"dynamically linked shared library"*|PE32+*"executable"*|PE32*"executable"*)
      printf 'committed native binary: %s (%s)\n' "$path" "$desc" >&2
      failed=1
      ;;
  esac
done < <(git ls-files -z)

if [[ "$failed" -ne 0 ]]; then
  cat >&2 <<'EOF'

Tracked native binaries are not allowed in this repository. Build test clients
from source during local runs or CI jobs and keep generated artifacts ignored.
EOF
  exit 1
fi
