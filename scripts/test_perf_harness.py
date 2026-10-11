#!/usr/bin/env python3
"""Exercise paired capture provenance and source boundaries with real Git trees."""

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
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
            ".gitignore": (SCRIPTS.parent / ".gitignore").read_text(),
        }.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (self.repo / "scripts").mkdir()
        for name in ["ci-perf-gate.sh", "perf-gate.sh", "prepare_perf_harness.py"]:
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

    def install_ci_toolchain(self, tampered=False):
        """Exercise the actual CI anchor with a local, checksum-verified archive."""
        fake_bin = self.directory / "download-fixture-bin"
        fake_bin.mkdir()
        temporary = self.directory / "temporary"
        temporary.mkdir()
        archive = self.directory / "zig-fixture.tar.xz"
        executable = b'#!/bin/sh\nprintf "0.16.0\\n"\ntouch "$TEST_ZIG_EXECUTED"\n'
        with tarfile.open(archive, "w:xz") as output:
            entry = tarfile.TarInfo("zig-x86_64-linux-0.16.0/zig")
            entry.size = len(executable)
            entry.mode = 0o755
            output.addfile(entry, io.BytesIO(executable))
        index = self.directory / "download-index.json"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        index.write_text(
            json.dumps(
                {
                    "0.16.0": {
                        "x86_64-linux": {
                            "shasum": "0" * 64 if tampered else digest,
                        }
                    }
                }
            )
        )
        for name, content in {
            "apt-get": "#!/bin/sh\nexit 0\n",
            "uname": "#!/bin/sh\nprintf 'x86_64\\n'\n",
            "curl": (
                "#!/usr/bin/python3\nimport os, shutil, sys\n"
                "url = next(x for x in sys.argv if x.startswith('https://'))\n"
                "target = sys.argv[sys.argv.index('-o') + 1]\n"
                "if url == 'https://ziglang.org/download/index.json':\n"
                "    source = os.environ['TEST_ZIG_INDEX']\n"
                "elif url == 'https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz':\n"
                "    source = os.environ['TEST_ZIG_ARCHIVE']\n"
                "else:\n    sys.exit('Unexpected download URL: ' + url)\n"
                "shutil.copyfile(source, target)\n"
            ),
        }.items():
            path = fake_bin / name
            path.write_text(content)
            path.chmod(0o755)
        # This anchor deliberately uses only shell scalars and literal blocks.
        # Run every command, including its PATH export and `zig version`, so
        # installer side effects cannot be omitted from the clean-source test.
        yaml = (SCRIPTS.parent / ".gitlab-ci.yml").read_text()
        anchor = yaml.split(".install-zig: &install-zig\n", 1)[1].split(
            "\n# zig-format component", 1
        )[0]
        commands = []
        in_block = False
        for line in anchor.splitlines():
            if line.startswith("  - |"):
                self.assertEqual(line, "  - |")
                in_block = True
            elif line.startswith("  - "):
                in_block = False
                commands.append(line[4:])
            elif line.startswith("    ") and in_block:
                commands.append(line[4:])
            elif not line.strip() or line.lstrip().startswith("#"):
                continue
            else:
                self.fail("Unsupported installer anchor syntax: " + line)
        executed = self.directory / "zig-executed"
        env = dict(
            self.env,
            PATH=str(fake_bin) + os.pathsep + os.defpath,
            TMPDIR=str(temporary),
            ZIG_VERSION="0.16.0",
            TEST_ZIG_INDEX=str(index),
            TEST_ZIG_ARCHIVE=str(archive),
            TEST_ZIG_EXECUTED=str(executed),
        )
        result = subprocess.run(
            ["sh", "-eu", "-c", "\n".join(commands)],
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
        )
        return result, executed

    def test_verified_ci_installer_preserves_clean_candidate_for_harness(self):
        result, executed = self.install_ci_toolchain()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(executed.exists(), "CI PATH must select the verified toolchain")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.prepare()

    def test_ci_installer_rejects_bad_checksum_before_running_toolchain(self):
        result, executed = self.install_ci_toolchain(tampered=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout + result.stderr)
        self.assertFalse(executed.exists())

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
            ["bash", "scripts/ci-perf-gate.sh"],
            cwd=self.repo,
            env=dict(
                self.env,
                ZIG=str(fake),
                CI_PIPELINE_SOURCE="merge_request_event",
                CI_MERGE_REQUEST_DIFF_BASE_SHA=self.parent,
            ),
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
