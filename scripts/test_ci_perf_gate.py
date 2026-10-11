#!/usr/bin/env python3
"""Exercise CI baseline selection with real full and shallow Git histories."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("ci-perf-gate.sh")


class BaselineSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="quic-ci-perf-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.env = {
            "PATH": os.defpath,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        self.git("init", "-q", "--initial-branch=main")
        scripts = self.repo / "scripts"
        scripts.mkdir()
        shutil.copyfile(SCRIPT, scripts / SCRIPT.name)
        (scripts / "perf-gate.sh").write_text(
            '#!/bin/bash\nset -eu\nprintf "%s\\n" "$@" > gate.args\n'
            'exit "${TEST_GATE_EXIT:-0}"\n'
        )
        self.first = self.commit("first")
        self.second = self.commit("second")
        self.head = self.commit("candidate")

    def git(self, *args, cwd=None):
        return subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=CI Gate Test",
                "-c",
                "user.email=ci@example.invalid",
                *args,
            ],
            cwd=cwd or self.repo,
            env=self.env,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def commit(self, value):
        (self.repo / "source").write_text(value)
        self.git("add", ".")
        self.git("commit", "-qm", value)
        return self.git("rev-parse", "HEAD")

    def run_gate(self, variables, repo=None):
        return subprocess.run(
            ["bash", "scripts/ci-perf-gate.sh"],
            cwd=repo or self.repo,
            env=dict(self.env, **variables),
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_selected(self, result, baseline, repo=None):
        repo = repo or self.repo
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (repo / "gate.args").read_text().splitlines(),
            [f"--baseline-commit={baseline}", "--suite=micro"],
        )
        self.assertEqual(
            (repo / "benchmarks/results/paired/ci-revisions.txt").read_text(),
            f"baseline={baseline}\ncandidate={self.head}\n",
        )
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=repo), self.head)

    def test_mr_uses_diff_base_across_multiple_commits(self):
        self.assert_selected(
            self.run_gate(
                {
                    "CI_PIPELINE_SOURCE": "merge_request_event",
                    "CI_MERGE_REQUEST_DIFF_BASE_SHA": self.first,
                    "CI_COMMIT_BEFORE_SHA": self.second,
                }
            ),
            self.first,
        )

    def test_branch_uses_previous_push_sha(self):
        self.assert_selected(
            self.run_gate(
                {
                    "CI_PIPELINE_SOURCE": "push",
                    "CI_COMMIT_BEFORE_SHA": self.first,
                }
            ),
            self.first,
        )

    def test_tag_and_new_branch_use_actual_parent(self):
        for variables in [
            {"CI_COMMIT_TAG": "v1.0.1", "CI_COMMIT_BEFORE_SHA": "0" * 40},
            {},
        ]:
            with self.subTest(variables=variables):
                self.assert_selected(self.run_gate(variables), self.second)

    def test_missing_zero_malformed_or_self_mr_base_fails_before_gate(self):
        for baseline in ["", "0" * 40, "HEAD~1", self.head]:
            with self.subTest(baseline=baseline):
                result = self.run_gate(
                    {
                        "CI_PIPELINE_SOURCE": "merge_request_event",
                        "CI_MERGE_REQUEST_DIFF_BASE_SHA": baseline,
                    }
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.repo / "gate.args").exists())

    def test_unavailable_commit_fails_before_gate(self):
        result = self.run_gate({"CI_COMMIT_BEFORE_SHA": "f" * 40})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.repo / "gate.args").exists())

    def test_unrelated_commit_is_rejected(self):
        self.git("checkout", "-qb", "other", self.first)
        unrelated = self.commit("other branch")
        self.git("checkout", "-q", "main")
        result = self.run_gate({"CI_COMMIT_BEFORE_SHA": unrelated})
        self.assertEqual(result.returncode, 2)
        self.assertIn("ancestor", result.stderr)
        self.assertFalse((self.repo / "gate.args").exists())

    def test_shallow_clone_fetches_history_without_changing_head(self):
        shallow = self.root / "shallow clone"
        self.git("clone", "-q", "--depth=1", self.repo.as_uri(), str(shallow))
        self.assertEqual(
            self.git("rev-parse", "--is-shallow-repository", cwd=shallow), "true"
        )
        result = self.run_gate(
            {
                "CI_PIPELINE_SOURCE": "merge_request_event",
                "CI_MERGE_REQUEST_DIFF_BASE_SHA": self.first,
            },
            repo=shallow,
        )
        self.assert_selected(result, self.first, repo=shallow)

    def test_root_commit_cannot_compare_itself(self):
        self.git("checkout", "-q", "--detach", self.first)
        result = self.run_gate({})
        self.assertEqual(result.returncode, 2)
        self.assertIn("previous commit is required", result.stderr)
        self.assertFalse((self.repo / "gate.args").exists())

    def test_performance_failure_is_propagated(self):
        result = self.run_gate(
            {"CI_COMMIT_BEFORE_SHA": self.first, "TEST_GATE_EXIT": "17"}
        )
        self.assertEqual(result.returncode, 17)
        self.assertTrue((self.repo / "gate.args").exists())


if __name__ == "__main__":
    unittest.main()
