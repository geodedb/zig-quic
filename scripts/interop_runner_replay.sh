#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

RUN_URL="https://interop.seemann.io/?run=2026-02-16T09:04"
RUNNER_DIR="${ROOT}/interop/quic-interop-runner"
RUNNER_REF="${QUIC_INTEROP_RUNNER_REF:-master}"
IMAGE_TAG="${INTEROP_IMAGE_TAG:-zig-quic:interop}"
DOCKER_PLATFORM="${INTEROP_DOCKER_PLATFORM:-linux/amd64}"
LOG_DIR=""
CLIENTS=""
SERVERS=""
MUST_INCLUDE="zig"
TESTS_OVERRIDE=""
NO_BUILD=0
NO_FETCH=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/interop_runner_replay.sh [options]

Options:
  --run-url URL_OR_TIMESTAMP    Interop run URL or timestamp (default: 2026-02-16T09:04)
  --runner-dir PATH             quic-interop-runner checkout dir
  --runner-ref REF              Runner git ref (default: master)
  --image-tag TAG               Local docker tag for zig endpoint image
  --docker-platform PLATFORM    Docker build platform (default: linux/amd64)
  --log-dir PATH                Runner log dir (default: interop/logs_<run>-zig)
  --client CSV                  Restrict clients (comma-separated)
  --server CSV                  Restrict servers (comma-separated)
  --must-include NAME           Require pairs to include implementation (default: zig)
  --tests CSV                   Override tests instead of deriving from run JSON
  --no-build                    Skip local image build
  --no-fetch                    Skip runner git fetch/reset
  --dry-run                     Print resolved command and exit
  -h, --help                    Show this help

Examples:
  scripts/interop_runner_replay.sh --client zig --server quic-go
  scripts/interop_runner_replay.sh --run-url 'https://interop.seemann.io/?run=2026-02-16T09:04' --must-include zig
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-url)
      RUN_URL="$2"
      shift 2
      ;;
    --runner-dir)
      RUNNER_DIR="$2"
      shift 2
      ;;
    --runner-ref)
      RUNNER_REF="$2"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="$2"
      shift 2
      ;;
    --docker-platform)
      DOCKER_PLATFORM="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
      shift 2
      ;;
    --client)
      CLIENTS="$2"
      shift 2
      ;;
    --server)
      SERVERS="$2"
      shift 2
      ;;
    --must-include)
      MUST_INCLUDE="$2"
      shift 2
      ;;
    --tests)
      TESTS_OVERRIDE="$2"
      shift 2
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --no-fetch)
      NO_FETCH=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

for cmd in git curl jq docker python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

extract_run_id() {
  local input="$1"
  if [[ "$input" == *"run="* ]]; then
    sed -E 's/.*run=([^&]+).*/\1/' <<<"$input"
    return
  fi
  echo "$input"
}

RUN_ID="$(extract_run_id "$RUN_URL")"
RUN_JSON="/tmp/interop-run-${RUN_ID}.json"
RUN_RESULT_URL="https://interop.seemann.io/logs/${RUN_ID}/result.json"

if ! curl -fsSL "$RUN_RESULT_URL" -o "$RUN_JSON"; then
  # Backward-compatible fallback format used by older pages.
  RUN_RESULT_URL="https://interop.seemann.io/logs/logs_${RUN_ID}/result.json"
  curl -fsSL "$RUN_RESULT_URL" -o "$RUN_JSON"
fi

RUN_TESTS="$(jq -r '.tests | to_entries | map(.value.name) | join(",")' "$RUN_JSON")"
RUN_MEASUREMENTS="$(jq -r 'if (.measurements|length) > 0 then (.measurements[0] | map(.name) | join(",")) else "" end' "$RUN_JSON")"
DERIVED_TESTS="$(printf '%s\n%s\n' "$RUN_TESTS" "$RUN_MEASUREMENTS" | tr ',' '\n' | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -)"
TESTS="${TESTS_OVERRIDE:-$DERIVED_TESTS}"

if [[ -z "$TESTS" ]]; then
  echo "No tests resolved from run metadata." >&2
  exit 1
fi

if [[ -z "$LOG_DIR" ]]; then
  LOG_DIR="${ROOT}/interop/logs_${RUN_ID}-zig"
  if [[ -e "$LOG_DIR" ]]; then
    LOG_DIR="${LOG_DIR}-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
fi
mkdir -p "$(dirname "$LOG_DIR")"

if [[ ! -d "$RUNNER_DIR/.git" ]]; then
  mkdir -p "$(dirname "$RUNNER_DIR")"
  git clone https://github.com/quic-interop/quic-interop-runner.git "$RUNNER_DIR"
fi

if [[ "$NO_FETCH" -eq 0 ]]; then
  git -C "$RUNNER_DIR" fetch origin --tags --prune
  git -C "$RUNNER_DIR" checkout --detach "$RUNNER_REF"
fi

if [[ ! -d "$RUNNER_DIR/.venv" ]]; then
  python3 -m venv "$RUNNER_DIR/.venv"
fi
"$RUNNER_DIR/.venv/bin/pip" install -q -r "$RUNNER_DIR/requirements.txt"

if [[ "$NO_BUILD" -eq 0 ]]; then
  (cd "$ROOT" && zig build -Doptimize=ReleaseSafe cli)
  (cd "$ROOT" && docker build --platform "$DOCKER_PLATFORM" -f interop/Dockerfile -t "$IMAGE_TAG" .)
fi

LOCAL_IMPL_JSON="$RUNNER_DIR/implementations.local.json"
jq -s '.[0] * .[1]' "$RUNNER_DIR/implementations.json" "$ROOT/interop/implementations.json" >"$LOCAL_IMPL_JSON"

BACKUP_IMPL_JSON="$RUNNER_DIR/implementations.json.bak"
cp "$RUNNER_DIR/implementations.json" "$BACKUP_IMPL_JSON"
restore_impl_json() {
  if [[ -f "$BACKUP_IMPL_JSON" ]]; then
    mv "$BACKUP_IMPL_JSON" "$RUNNER_DIR/implementations.json"
  fi
}
trap restore_impl_json EXIT
cp "$LOCAL_IMPL_JSON" "$RUNNER_DIR/implementations.json"

build_runner_cmd() {
  local log_dir="$1"
  local client="$2"
  local server="$3"

  local -a cmd=(
    "$RUNNER_DIR/.venv/bin/python" run.py
    --test "$TESTS"
    --replace "zig=${IMAGE_TAG}"
    --log-dir "$log_dir"
  )

  if [[ -n "$client" ]]; then
    cmd+=( --client "$client" )
  elif [[ -n "$CLIENTS" ]]; then
    cmd+=( --client "$CLIENTS" )
  fi

  if [[ -n "$server" ]]; then
    cmd+=( --server "$server" )
  elif [[ -n "$SERVERS" ]]; then
    cmd+=( --server "$SERVERS" )
  fi

  if [[ -n "$MUST_INCLUDE" ]]; then
    cmd+=( --must-include "$MUST_INCLUDE" )
  fi
  printf '%s\0' "${cmd[@]}"
}

run_runner_cmd() {
  local log_dir="$1"
  local client="$2"
  local server="$3"
  local label="$4"
  local -a cmd=()
  while IFS= read -r -d '' token; do
    cmd+=("$token")
  done < <(build_runner_cmd "$log_dir" "$client" "$server")

  echo "${label}Command:       ${cmd[*]}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  (cd "$RUNNER_DIR" && "${cmd[@]}")
}

echo "=== Interop Replay Configuration ==="
echo "Run URL:       ${RUN_URL}"
echo "Run result:    ${RUN_RESULT_URL}"
echo "Run ID:        ${RUN_ID}"
echo "Runner dir:    ${RUNNER_DIR}"
echo "Runner ref:    $(git -C "$RUNNER_DIR" rev-parse --short HEAD)"
echo "Image tag:     ${IMAGE_TAG}"
echo "Tests:         ${TESTS}"
echo "Clients:       ${CLIENTS:-<all>}"
echo "Servers:       ${SERVERS:-<all>}"
echo "Must include:  ${MUST_INCLUDE:-<none>}"
echo "Log dir:       ${LOG_DIR}"

PAIRWISE=0
if [[ -n "$MUST_INCLUDE" && -n "$CLIENTS" && -n "$SERVERS" ]]; then
  if [[ "$CLIENTS" == *,* || "$SERVERS" == *,* ]]; then
    PAIRWISE=1
  fi
fi

if [[ "$PAIRWISE" -eq 0 ]]; then
  run_runner_cmd "$LOG_DIR" "" "" ""
  echo "Interop replay finished. Logs written to: ${LOG_DIR}"
  exit 0
fi

IFS=',' read -r -a client_list <<<"$CLIENTS"
IFS=',' read -r -a server_list <<<"$SERVERS"

pair_count=0
for server in "${server_list[@]}"; do
  server="${server//[[:space:]]/}"
  [[ -n "$server" ]] || continue
  for client in "${client_list[@]}"; do
    client="${client//[[:space:]]/}"
    [[ -n "$client" ]] || continue
    if [[ "$client" != "$MUST_INCLUDE" && "$server" != "$MUST_INCLUDE" ]]; then
      continue
    fi
    pair_count=$((pair_count + 1))
    pair_log_dir="${LOG_DIR}-server_${server}-client_${client}"
    if [[ -e "$pair_log_dir" ]]; then
      pair_log_dir="${pair_log_dir}-$(date -u +%Y%m%dT%H%M%SZ)-${pair_count}"
    fi
    run_runner_cmd "$pair_log_dir" "$client" "$server" "[pair ${pair_count}] "
  done
done

if [[ "$pair_count" -eq 0 ]]; then
  echo "No client/server pairs matched must-include constraint." >&2
  exit 1
fi

echo "Interop replay finished. Logs written under prefix: ${LOG_DIR}-server_*"
