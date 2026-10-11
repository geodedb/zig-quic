#!/usr/bin/env bash
# SONNY-4780: measure both revisions on this runner; never compare architectures.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() { echo "ci-perf-gate: $*" >&2; exit 2; }

head=$(git rev-parse --verify 'HEAD^{commit}')
if [[ $(git rev-parse --is-shallow-repository) == true ]]; then
    git fetch --no-tags --unshallow origin
fi

if [[ ${CI_PIPELINE_SOURCE:-} == merge_request_event ]]; then
    baseline=${CI_MERGE_REQUEST_DIFF_BASE_SHA:-}
    [[ -n $baseline ]] || fail "MR diff base is required"
elif [[ -n ${CI_COMMIT_BEFORE_SHA:-} && ! ${CI_COMMIT_BEFORE_SHA} =~ ^0+$ ]]; then
    baseline=$CI_COMMIT_BEFORE_SHA
else
    # Tag and new-branch pipelines have no before SHA. Compare the previous
    # commit, and fail on a root commit rather than comparing HEAD to itself.
    baseline=$(git rev-parse --verify 'HEAD^1^{commit}') || fail "previous commit is required"
fi

[[ $baseline =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ && ! $baseline =~ ^0+$ ]] \
    || fail "baseline must be a nonzero full commit SHA"
[[ $baseline != "$head" ]] || fail "baseline must differ from HEAD"
if ! git cat-file -e "$baseline^{commit}" 2>/dev/null; then
    git fetch --no-tags --depth=1 origin "$baseline"
fi
git merge-base --is-ancestor "$baseline" "$head" \
    || fail "baseline must be an ancestor of HEAD"

mkdir -p benchmarks/results/paired
printf 'baseline=%s\ncandidate=%s\n' "$baseline" "$head" \
    > benchmarks/results/paired/ci-revisions.txt
# Benchmark fixes change measurement semantics. Measure the parent production
# code with the same committed harness as HEAD; record the overlay provenance.
# Otherwise legacy rounded samples and precise batch samples are incomparable.
exec bash scripts/perf-gate.sh "--baseline-commit=$baseline" "--harness-commit=$head" --suite=micro
