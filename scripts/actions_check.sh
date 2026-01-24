#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: get-run-logs.sh [-r RUN_ID] [-w WORKFLOW] [-b BRANCH] [-R OWNER/REPO]
Fetch GitHub Actions logs and print to stdout.

- If RUN_ID is given, fetch that run's logs.
- Otherwise, fetch the latest run for BRANCH (defaults to current branch).
- Optionally filter by WORKFLOW file/name.
- Use -R to target a different repo.

Examples:
  get-run-logs.sh
  get-run-logs.sh -r 123456789
  get-run-logs.sh -w ci.yml -b main
  get-run-logs.sh -R owner/repo
EOF
}

# Requirements
if ! command -v gh >/dev/null 2>&1; then
  echo "Error: gh (GitHub CLI) not found. Install: https://cli.github.com/" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "Error: gh is not authenticated. Run: gh auth login" >&2
  exit 1
fi

# Disable pager so output goes straight to stdout
export GH_PAGER=cat

run_id=""
workflow=""
branch=""
repo=""

while getopts ":r:w:b:R:h" opt; do
  case "$opt" in
    r) run_id="$OPTARG" ;;
    w) workflow="$OPTARG" ;;
    b) branch="$OPTARG" ;;
    R) repo="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done

# If no run ID provided, find the latest run (by branch/workflow if given)
if [[ -z "$run_id" ]]; then
  if [[ -z "$branch" ]]; then
    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
      if [[ -n "$current_branch" && "$current_branch" != "HEAD" ]]; then
        branch="$current_branch"
      fi
    fi
  fi

  cmd=(gh run list --limit 1)
  if [[ -n "$branch" ]]; then
    cmd+=(--branch "$branch")
  fi
  if [[ -n "$workflow" ]]; then
    cmd+=(--workflow "$workflow")
  fi
  if [[ -n "$repo" ]]; then
    cmd+=(-R "$repo")
  fi

  run_id=$("${cmd[@]}" --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
  if [[ -z "$run_id" || "$run_id" == "null" ]]; then
    echo "No workflow runs found for the given filters." >&2
    exit 1
  fi
fi

view_cmd=(gh run view "$run_id" --log)
if [[ -n "$repo" ]]; then
  view_cmd+=(-R "$repo")
fi

# Print all logs to stdout
"${view_cmd[@]}"