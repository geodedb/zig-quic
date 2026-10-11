#!/usr/bin/env python3
"""Exercise paired capture provenance and source boundaries with real Git trees."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "prepare_perf_harness", SCRIPTS / "prepare_perf_harness.py"
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="quic-harness-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repo = self.directory / "candidate"
        self.baseline = self.directory / "baseline"
        self.repo.mkdir()
        self.env = dict(
            os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"
        )
        for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"]:
            self.env.pop(name, None)
        self.git("init", "-q", "--initial-branch=main")
        for name, content in {
            "benchmarks/common.zig": "legacy measurement\n",
            "benchmarks/obsolete.zig": "removed measurement\n",
            "benchmarks/results/baseline.json": '{"reference":"preserve"}\n',
            "src/runtime": "100\n",
            "build.zig": "parent build configuration\n",
            ".gitignore": "benchmarks/results/paired/\n",
        }.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (self.repo / "scripts").mkdir()
        for name in ["perf-gate.sh", "prepare_perf_harness.py"]:
            shutil.copy2(SCRIPTS / name, self.repo / "scripts" / name)
        self.parent = self.commit("parent")
        (self.repo / "benchmarks/common.zig").write_text("precise measurement\n")
        (self.repo / "benchmarks/obsolete.zig").unlink()
        (self.repo / "benchmarks/new.zig").write_text("new measurement\n")
        (self.repo / "src/runtime").write_text("125\n")
        (self.repo / "build.zig").write_text("candidate build configuration\n")
        self.head = self.commit("candidate")
        self.git("worktree", "add", "--detach", str(self.baseline), self.parent)
        self.manifest = self.directory / "provenance.json"

    def git(self, *args, cwd=None):
        return subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=Harness Test",
                "-c",
                "user.email=test@example.invalid",
                *args,
            ],
            cwd=cwd or self.repo,
            env=self.env,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def commit(self, message, cwd=None):
        self.git("add", ".", cwd=cwd)
        self.git("commit", "-qm", message, cwd=cwd)
        return self.git("rev-parse", "HEAD", cwd=cwd)

    def prepare(self, revision=None):
        return HELPER.prepare(
            self.repo, self.baseline, revision or self.head, self.manifest
        )

    def test_same_harness_preserves_distinct_runtime_build_and_recorded_baseline(self):
        result = self.prepare()
        self.assertEqual((self.baseline / "src/runtime").read_text(), "100\n")
        self.assertEqual((self.repo / "src/runtime").read_text(), "125\n")
        self.assertEqual(
            (self.baseline / "build.zig").read_text(), "parent build configuration\n"
        )
        self.assertEqual(
            (self.baseline / "benchmarks/results/baseline.json").read_text(),
            '{"reference":"preserve"}\n',
        )
        self.assertEqual(
            (self.baseline / "benchmarks/common.zig").read_bytes(),
            (self.repo / "benchmarks/common.zig").read_bytes(),
        )
        self.assertTrue((self.baseline / "benchmarks/new.zig").is_file())
        self.assertFalse((self.baseline / "benchmarks/obsolete.zig").exists())
        self.assertEqual(result["baseline_runtime_commit"], self.parent)
        self.assertEqual(result["candidate_runtime_commit"], self.head)
        self.assertEqual(result["benchmark_commit"], self.head)
        self.assertEqual(
            result["removed_baseline_sources"], ["benchmarks/obsolete.zig"]
        )
        self.assertEqual(json.loads(self.manifest.read_text()), result)
        for entry in result["files"]:
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256((self.repo / entry["path"]).read_bytes()).hexdigest(),
            )
        self.assertFalse(
            self.git(
                "diff",
                "HEAD",
                "--",
                "src",
                "build.zig",
                "benchmarks/results",
                cwd=self.baseline,
            )
        )

    def test_dirty_candidate_measurement_is_rejected_before_baseline_mutation(self):
        (self.repo / "benchmarks/common.zig").write_text("uncommitted measurement\n")
        with self.assertRaisesRegex(ValueError, "differs from committed"):
            self.prepare()
        self.assertFalse(self.git("status", "--porcelain", cwd=self.baseline))
        self.assertFalse(self.manifest.exists())

    def test_untracked_even_ignored_measurement_is_rejected(self):
        (self.repo / ".gitignore").write_text("benchmarks/hidden.zig\n")
        (self.repo / "benchmarks/hidden.zig").write_text("untracked measurement\n")
        with self.assertRaisesRegex(ValueError, "untracked"):
            self.prepare()
        self.assertFalse(self.git("status", "--porcelain", cwd=self.baseline))

    def test_dirty_baseline_and_wrong_harness_identity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "candidate HEAD"):
            self.prepare(self.parent)
        (self.baseline / "src/runtime").write_text("unexpected runtime\n")
        with self.assertRaisesRegex(ValueError, "must be clean"):
            self.prepare()
        self.assertEqual(
            (self.baseline / "benchmarks/common.zig").read_text(),
            "legacy measurement\n",
        )

    def test_dirty_candidate_runtime_cannot_be_attributed_to_committed_revision(self):
        (self.repo / "src/runtime").write_text("uncommitted runtime\n")
        with self.assertRaisesRegex(ValueError, "candidate worktree must be clean"):
            self.prepare()
        self.assertFalse(self.git("status", "--porcelain", cwd=self.baseline))
        self.assertFalse(self.manifest.exists())

    def test_committed_symlink_cannot_redirect_writes_into_runtime(self):
        path = self.baseline / "benchmarks/common.zig"
        path.unlink()
        path.symlink_to("../src/runtime")
        self.commit("symlink baseline", cwd=self.baseline)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.prepare()
        self.assertEqual((self.baseline / "src/runtime").read_text(), "100\n")

    def test_clean_hardlink_cannot_redirect_writes_into_runtime(self):
        path = self.baseline / "benchmarks/common.zig"
        path.write_text("100\n")
        self.commit("matching bytes", cwd=self.baseline)
        path.unlink()
        os.link(self.baseline / "src/runtime", path)
        self.assertFalse(self.git("status", "--porcelain", cwd=self.baseline))
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.prepare()
        self.assertEqual((self.baseline / "src/runtime").read_text(), "100\n")

    def test_existing_provenance_is_not_overwritten(self):
        self.manifest.write_text("earlier evidence\n")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.prepare()
        self.assertEqual(self.manifest.read_text(), "earlier evidence\n")
        self.assertFalse(self.git("status", "--porcelain", cwd=self.baseline))

    def test_paired_driver_preserves_runtime_difference_and_propagates_failure(self):
        # The fake compiler captures real fixture files from each Git worktree;
        # this tests orchestration, not benchmark correctness or performance.
        fake = self.directory / "fake-zig"
        fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args[:2] == ["build", "bench"]:
    output = next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
    pathlib.Path(output).write_text(json.dumps({"runtime": pathlib.Path("src/runtime").read_text(), "harness": pathlib.Path("benchmarks/common.zig").read_text(), "rows": []}))
elif args[:2] == ["build", "bench-compare"]:
    left = json.loads(pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("--baseline="))).read_text())
    right = json.loads(pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("--current="))).read_text())
    assert left["harness"] == right["harness"] == "precise measurement\\n"
    assert left["runtime"] == "100\\n" and right["runtime"] == "125\\n"
    sys.exit(17)
else:
    sys.exit(99)
""")
        fake.chmod(0o755)
        result = subprocess.run(
            [
                "bash",
                "scripts/perf-gate.sh",
                f"--baseline-commit={self.parent}",
                f"--harness-commit={self.head}",
                "--suite=micro",
            ],
            cwd=self.repo,
            env=dict(self.env, ZIG=str(fake)),
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        paired = self.repo / "benchmarks/results/paired"
        provenance = json.loads(
            (paired / f"{self.parent[:8]}-harness.json").read_text()
        )
        self.assertEqual(provenance["benchmark_commit"], self.head)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.head)
        self.assertFalse(self.git("status", "--porcelain"))


if __name__ == "__main__":
    unittest.main()
