#!/usr/bin/env python3
"""Exercise interop orchestration with real child processes, including failures."""

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("ci_interop.py")


class InteropProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="quic-interop-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copyfile(SCRIPT, self.root / SCRIPT.name)
        self.server = self.root / "server.py"
        self.server.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, time\n"
            "pathlib.Path('server.pid').write_text(str(os.getpid()))\n"
            "mode = os.environ.get('SERVER_MODE', 'ready')\n"
            "if mode == 'early':\n"
            " print('startup diagnostic', flush=True)\n"
            " raise SystemExit(7)\n"
            "if mode != 'silent': print('listening on 127.0.0.1:4433', flush=True)\n"
            "if mode == 'crash':\n"
            " while not pathlib.Path('client.pid').exists(): time.sleep(0.01)\n"
            " print('runtime diagnostic', flush=True)\n"
            " raise SystemExit(9)\n"
            "time.sleep(60)\n"
        )
        self.server.chmod(0o700)
        self.client = self.root / "client.py"
        self.client.write_text(
            "import os, pathlib, sys, time\n"
            "pathlib.Path('client.pid').write_text(str(os.getpid()))\n"
            "mode = os.environ.get('CLIENT_MODE', 'success')\n"
            "if mode == 'wait': time.sleep(60)\n"
            "if mode == 'failure':\n"
            " print('client diagnostic', flush=True)\n"
            " raise SystemExit(11)\n"
            "if mode != 'no-marker': print('Test completed successfully', flush=True)\n"
            "if len(sys.argv) > 1: print(sys.argv[1], flush=True)\n"
        )
        self.command = [
            sys.executable,
            str(self.root / SCRIPT.name),
            "--name",
            "fixture",
            "--server",
            str(self.server),
            "--timeout",
            "2",
            "--startup-timeout",
            "2",
            "--",
            sys.executable,
            str(self.client),
            "literal spaces; $dollars",
        ]

    def assert_clean(self):
        for name in ("server", "client"):
            pidfile = self.root / f"{name}.pid"
            if pidfile.exists():
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)

    def run_case(self, **variables):
        result = subprocess.run(
            self.command,
            cwd=self.root,
            env=dict(os.environ, **variables),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assert_clean()
        return result

    def test_success_and_literal_arguments_keep_project_logs(self):
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("literal spaces; $dollars", result.stdout)
        self.assertTrue(
            (self.root / "test-results/interop/fixture/server.log").is_file()
        )
        self.assertTrue(
            (self.root / "test-results/interop/fixture/client.log").is_file()
        )

    def test_early_server_failure_does_not_start_client(self):
        result = self.run_case(SERVER_MODE="early")
        self.assertEqual(result.returncode, 1)
        self.assertIn("startup diagnostic", result.stdout)
        self.assertIn("before readiness with status 7", result.stderr)
        self.assertFalse((self.root / "client.pid").exists())

    def test_server_crash_stops_client_and_retains_diagnostic(self):
        result = self.run_case(SERVER_MODE="crash", CLIENT_MODE="wait")
        self.assertEqual(result.returncode, 1)
        self.assertIn("runtime diagnostic", result.stdout)
        self.assertIn("during interop with status 9", result.stderr)

    def test_client_failure_is_not_hidden(self):
        result = self.run_case(CLIENT_MODE="failure")
        self.assertEqual(result.returncode, 1)
        self.assertIn("client diagnostic", result.stdout)
        self.assertIn("client exited with status 11", result.stderr)

    def test_zero_exit_without_success_marker_fails(self):
        result = self.run_case(CLIENT_MODE="no-marker")
        self.assertEqual(result.returncode, 1)
        self.assertIn("without the required success marker", result.stderr)

    def test_client_timeout_cleans_both_processes(self):
        result = self.run_case(CLIENT_MODE="wait")
        self.assertEqual(result.returncode, 1)
        self.assertIn("client timed out", result.stderr)

    def test_readiness_timeout_does_not_start_client(self):
        result = self.run_case(SERVER_MODE="silent")
        self.assertEqual(result.returncode, 1)
        self.assertIn("server readiness timed out", result.stderr)
        self.assertFalse((self.root / "client.pid").exists())

    def test_interrupted_run_cleans_both_processes(self):
        process = subprocess.Popen(
            self.command,
            cwd=self.root,
            env=dict(os.environ, CLIENT_MODE="wait"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "client.pid").exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("client did not start")
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 1)
            self.assertIn("interrupted by signal", stderr)
            self.assert_clean()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == "__main__":
    unittest.main()
