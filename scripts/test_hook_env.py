#!/usr/bin/env python3
"""SONNY-4778: hook tool caches must not change the enclosing Git worktree."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts/hook-env.sh"


class HookEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="quic-hook-env-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clean_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.clean_env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.parent = self.make_repo("enclosing")
        self.linked = self.root / "protected worktree"
        self.git(self.parent, "worktree", "add", "--detach", str(self.linked), "HEAD")
        self.foreign = self.make_repo("tool cache")
        gitdir = Path(self.git(self.linked, "rev-parse", "--absolute-git-dir"))
        self.gitdir = gitdir
        self.poisoned_env = dict(self.clean_env)
        self.poisoned_env.update(
            GIT_DIR=str(gitdir),
            GIT_WORK_TREE=str(self.linked),
            GIT_COMMON_DIR=str(self.parent / ".git"),
            GIT_INDEX_FILE=str(gitdir / "index"),
            GIT_OBJECT_DIRECTORY=str(self.parent / ".git/objects"),
            GIT_PREFIX="nested/",
        )

    def git(self, cwd, *args):
        return subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=Hook Test",
                "-c",
                "user.email=hook@example.invalid",
                *args,
            ],
            cwd=cwd,
            env=self.clean_env,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def make_repo(self, name):
        repo = self.root / name
        repo.mkdir()
        self.git(repo, "init", "-q", "--initial-branch=main")
        (repo / "source").write_text(name + " base\n")
        self.git(repo, "add", "source")
        self.git(repo, "commit", "-qm", "base")
        self.git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        (repo / "source").write_text(name + " candidate\n")
        self.git(repo, "commit", "-qam", "candidate")
        return repo

    def snapshot(self):
        files = [
            self.gitdir / "index",
            self.parent / ".git/config",
            self.linked / "source",
        ]
        return self.git(self.linked, "rev-parse", "HEAD"), {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files
        }

    def run_wrapped(self, command):
        # The raw mode is used only to demonstrate RED in disposable fixtures.
        prefix = (
            []
            if os.environ.get("QUIC_HOOK_ENV_RED_CONTROL") == "1"
            else ["bash", str(WRAPPER)]
        )
        return subprocess.run(
            [*prefix, *command],
            cwd=self.linked,
            env=self.poisoned_env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_foreign_reset_preserves_enclosing_head_index_config_and_source(self):
        before = self.snapshot()
        result = self.run_wrapped(
            [
                "git",
                "-C",
                str(self.foreign),
                "reset",
                "--mixed",
                "refs/remotes/origin/main",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(
            self.git(self.foreign, "rev-parse", "HEAD"),
            self.git(self.foreign, "rev-parse", "refs/remotes/origin/main"),
        )

    def test_foreign_bare_init_preserves_enclosing_config_and_worktree(self):
        before = self.snapshot()
        cache = self.root / "new tool cache"
        result = self.run_wrapped(["git", "init", "--bare", str(cache)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue((cache / "HEAD").is_file())
        self.assertEqual(
            self.git(self.linked, "rev-parse", "--is-bare-repository"), "false"
        )

    def test_arguments_exit_status_and_nonrepository_environment_are_preserved(self):
        self.poisoned_env["GIT_SSH_COMMAND"] = "preserved-auth-command"
        self.poisoned_env["HOOK_ENV_SENTINEL"] = "preserved-value"
        result = self.run_wrapped(
            [
                sys.executable,
                "-c",
                "import json,os,sys; print(json.dumps([sys.argv[1:], os.getenv('GIT_SSH_COMMAND'), os.getenv('HOOK_ENV_SENTINEL')])); sys.exit(23)",
                "with spaces",
                "literal$()",
            ]
        )
        self.assertEqual(result.returncode, 23)
        self.assertEqual(
            json.loads(result.stdout),
            [
                ["with spaces", "literal$()"],
                "preserved-auth-command",
                "preserved-value",
            ],
        )

    def test_every_local_hook_uses_the_environment_boundary(self):
        local = False
        entries = []
        for line in (ROOT / ".pre-commit-config.yaml").read_text().splitlines():
            if line.startswith("- repo:"):
                local = line.strip() == "- repo: local"
            if local and line.strip().startswith("entry:"):
                entries.append(line.strip())
                self.assertTrue(
                    line.strip().startswith("entry: bash scripts/hook-env.sh "), line
                )
        self.assertGreaterEqual(len(entries), 6)


if __name__ == "__main__":
    unittest.main()
