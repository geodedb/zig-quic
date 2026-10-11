#!/usr/bin/env python3
"""Copy one committed benchmark implementation onto a clean baseline worktree.

Only regular tracked benchmarks/**/*.zig files may change. Production sources,
build configuration, and result documents are never rewritten by this helper.
The current comparator remains responsible for its existing thresholds.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo)


def sources(repo, revision):
    result = {}
    for entry in git(repo, "ls-tree", "-rz", revision, "--", "benchmarks").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if not path.endswith(".zig") or not path.startswith("benchmarks/"):
            continue
        mode, kind, blob = metadata.decode().split()
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"benchmark source must be a regular file: {path}")
        if any(part in (".", "..") for part in Path(path).parts):
            raise ValueError(f"unsafe benchmark path: {path}")
        result[path] = (blob, git(repo, "cat-file", "blob", blob))
    if not result:
        raise ValueError("no committed benchmark sources")
    return result


def prepare(root, baseline, revision, output):
    root, baseline = root.resolve(), baseline.resolve()
    if root == baseline:
        raise ValueError("baseline must be a separate worktree")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("harness revision must be a full commit SHA")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    if revision != head:
        raise ValueError("harness revision must equal the candidate HEAD")
    if git(baseline, "status", "--porcelain"):
        raise ValueError("baseline worktree must be clean")
    baseline_head = git(baseline, "rev-parse", "HEAD").decode().strip()
    current = sources(root, revision)
    previous = sources(baseline, baseline_head)
    paths = sorted(current.keys() | previous.keys())
    # Validate all paths before the first write. Reject symlinks at any level,
    # including directories introduced by an older baseline revision.
    for relative in paths:
        for directory in (root, baseline):
            target = directory / relative
            for ancestor in [target, *target.parents]:
                if ancestor == directory:
                    break
                if ancestor.is_symlink():
                    raise ValueError(f"symlink in benchmark path: {relative}")
            if target.exists() and (
                not target.is_file() or target.stat().st_nlink != 1
            ):
                raise ValueError(
                    f"benchmark source must be a regular file without hard links: {relative}"
                )
        if (
            relative in current
            and (root / relative).read_bytes() != current[relative][1]
        ):
            raise ValueError(
                f"candidate benchmark differs from committed harness: {relative}"
            )
    extras = git(root, "ls-files", "--others", "-z", "--", "benchmarks")
    if any(path.endswith(b".zig") for path in extras.split(b"\0")):
        raise ValueError("candidate has untracked benchmark source")
    if git(root, "status", "--porcelain"):
        raise ValueError("candidate worktree must be clean for runtime provenance")
    if output.exists():
        raise ValueError("refusing to overwrite an existing provenance document")
    for relative in paths:
        destination = baseline / relative
        if relative not in current:
            destination.unlink()
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(current[relative][1])
    changed = set(git(baseline, "diff", "--name-only", "HEAD").decode().splitlines())
    extra = set(
        git(baseline, "ls-files", "--others", "--exclude-standard")
        .decode()
        .splitlines()
    )
    if not (changed | extra) <= set(paths):
        raise ValueError("baseline changes escaped the benchmark source allowlist")
    for relative, (_, content) in current.items():
        if (baseline / relative).read_bytes() != content:
            raise ValueError(f"baseline harness copy mismatch: {relative}")
    manifest = {
        "baseline_runtime_commit": baseline_head,
        "candidate_runtime_commit": head,
        "benchmark_commit": revision,
        "scope": "Tracked regular benchmarks/**/*.zig files only; baseline runtime and build files unchanged.",
        "files": [
            {
                "path": relative,
                "blob": blob,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for relative, (blob, content) in sorted(current.items())
        ],
        "removed_baseline_sources": sorted(previous.keys() - current.keys()),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-worktree", type=Path, required=True)
    parser.add_argument("--harness-commit", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(ROOT, args.baseline_worktree, args.harness_commit, args.manifest)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"prepare-perf-harness: {error}\n")


if __name__ == "__main__":
    main()
