#!/usr/bin/env python3
"""Exercise simulator acceptance and failure cleanup without network privileges."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ci_qns import Runner, execute


class FakeDocker:
    def __init__(self, assets, failure=None):
        self.assets = assets
        self.failure = failure
        self.down = False
        self.attempts = 0
        self.removals = 0
        self.simulator_fresh = False

    def __call__(self, command, *, env, timeout=30, log=None):
        if log:
            log.write_text("container diagnostics\n")
        if command[1] == "inspect":
            client = command[-1] == "a" * 64
            state = {
                "Status": "exited",
                "ExitCode": 0 if client else 143,
                "OOMKilled": False,
                "Error": "",
            }
            if self.failure == "client-exit" and client:
                state["ExitCode"] = 17
            if self.failure == "server-exit" and not client:
                state["ExitCode"] = 23
            if self.failure == "oom":
                state["OOMKilled"] = True
            return json.dumps(state)
        args = command[command.index("generic") + 1 :]
        if args[0] == "down":
            self.down = True
            if self.failure == "cleanup":
                raise RuntimeError("cleanup failed")
        elif args[0] == "rm":
            self.removals += 1
            if "sim" in args:
                self.simulator_fresh = False
        elif args[0] == "ps":
            if "--status" in args:
                return "sim\n"
            if self.failure == "missing-container":
                return ""
            return ("a" if args[-1] == "client" else "b") * 64
        elif args[0] == "up" and args[-1] == "sim":
            self.simulator_fresh = True
        elif args[0] == "up" and "server" in args:
            self.attempts += 1
            if self.failure == "stale-simulator" and not self.simulator_fresh:
                raise RuntimeError("simulator retained the previous endpoints")
            self.simulator_fresh = False
            if self.failure == "compose":
                raise RuntimeError("compose exited 2")
            if self.failure == "timeout":
                raise subprocess.TimeoutExpired(command, timeout)
            if self.failure != "missing-download":
                output = self.assets / "downloads/5000"
                if self.failure == "symlink":
                    output.symlink_to(self.assets / "www/5000")
                else:
                    payload = (self.assets / "www/5000").read_bytes()
                    if self.failure == "corrupt":
                        payload = bytes([payload[0] ^ 1]) + payload[1:]
                    elif self.failure == "truncated":
                        payload = payload[:-1]
                    elif self.failure == "oversized":
                        payload += b"extra"
                    output.write_bytes(payload)
        elif args[0] == "logs" and self.failure == "logs":
            raise RuntimeError("logs failed")
        return ""


class SimulatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="qns-result-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.assets = self.root / "examples/interop/quic-network-simulator"
        (self.assets / "www").mkdir(parents=True)
        (self.assets / "www/5000").write_bytes(bytes(range(250)) * 20)

    def run_driver(self, failure=None):
        docker = FakeDocker(self.assets, failure)
        runner = Runner(self.root, {"QUIC_GO_IMAGE": "pinned-peer"}, docker)
        code = runner.run()
        report = json.loads((runner.results / "result.json").read_text())
        self.assertTrue(docker.down)
        return code, report, docker, runner

    def test_all_four_directions_require_actual_payloads(self):
        code, report, docker, runner = self.run_driver()
        self.assertEqual(code, 0)
        self.assertEqual(docker.attempts, 4)
        self.assertEqual(len(report["cases"]), 4)
        for case in report["cases"]:
            self.assertTrue(case["passed"])
            self.assertEqual(case["bytes"], 5000)
            self.assertEqual(
                (runner.results / case["name"] / "downloads/5000").read_bytes(),
                (self.assets / "www/5000").read_bytes(),
            )

    def test_each_process_or_payload_failure_rejects_the_job(self):
        for failure in (
            "compose",
            "timeout",
            "client-exit",
            "server-exit",
            "oom",
            "missing-container",
            "missing-download",
            "corrupt",
            "truncated",
            "oversized",
            "symlink",
        ):
            with self.subTest(failure=failure):
                code, report, docker, _ = self.run_driver(failure)
                self.assertEqual(code, 1)
                self.assertFalse(report["passed"])
                self.assertEqual(docker.attempts, 4)
                self.assertTrue(all(not case["passed"] for case in report["cases"]))

    def test_replacing_endpoints_does_not_reuse_simulator_state(self):
        code, report, docker, _ = self.run_driver("stale-simulator")
        self.assertEqual(code, 0)
        self.assertEqual(docker.attempts, 4)
        self.assertTrue(all(case["passed"] for case in report["cases"]))

    def test_stale_matching_file_cannot_satisfy_a_new_case(self):
        downloads = self.assets / "downloads"
        downloads.mkdir()
        (downloads / "5000").write_bytes((self.assets / "www/5000").read_bytes())
        code, report, _, runner = self.run_driver("missing-download")
        self.assertEqual(code, 1)
        first = report["cases"][0]
        self.assertTrue(
            (
                runner.results / first["name"] / "previous-output/downloads/5000"
            ).is_file()
        )
        self.assertFalse(first["passed"])

    def test_failure_to_collect_logs_still_removes_endpoints(self):
        code, report, docker, _ = self.run_driver("logs")
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(docker.removals, 8)

    def test_final_cleanup_failure_is_not_success(self):
        code, report, _, _ = self.run_driver("cleanup")
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])

    def test_empty_source_is_not_a_transfer(self):
        (self.assets / "www/5000").write_bytes(b"")
        code, report, docker, _ = self.run_driver()
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(docker.attempts, 0)


class CommandTests(unittest.TestCase):
    def test_real_nonzero_process_propagates(self):
        with self.assertRaisesRegex(RuntimeError, "exited 19"):
            execute([sys.executable, "-c", "raise SystemExit(19)"], env=os.environ)

    def test_real_process_timeout_is_bounded_and_propagates(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            execute(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                env=os.environ,
                timeout=0.05,
            )
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
