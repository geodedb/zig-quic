#!/usr/bin/env python3
"""Exercise the security scan driver with failing scanner/build subprocesses."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


DRIVER = Path(__file__).with_name("check-client-security.sh")
RUST_CLIENTS = [
    "clients/rust",
    "test-clients/legacy-clients/rust",
    "test-clients/quinn-client",
]
GO_CLIENTS = [
    "examples/interop",
    "test-clients/quic-test-legacy/xnet-quic",
    "test-clients/quic-go-client",
    "test-clients/legacy-clients/go",
]
PROGRAMS = ["client.go", "server.go", "test_client.go", "test_client_comprehensive.go"]


class SecurityDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="quic-security-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(DRIVER, self.root / "scripts/check-client-security.sh")
        for name in RUST_CLIENTS + GO_CLIENTS:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.events = self.root / "events.jsonl"
        fake = """#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
event = {'tool': pathlib.Path(sys.argv[0]).name,
         'cwd': str(pathlib.Path.cwd().relative_to(root)), 'args': sys.argv[1:]}
with open(root / 'events.jsonl', 'a') as output:
    output.write(json.dumps(event) + '\\n')
needle = os.environ.get('FAIL_MATCH', '')
failed_cwd = os.environ.get('FAIL_CWD', '')
if (failed_cwd and failed_cwd == event['cwd']) or (needle and needle in ' '.join(event['args'])):
    sys.exit(17)
if sys.argv[1] == 'build':
    pathlib.Path(sys.argv[3]).write_text('fixture binary')
if '-mode=binary' in sys.argv:
    assert pathlib.Path(sys.argv[-1]).read_text() == 'fixture binary'
"""
        for name in ["go", "cargo"]:
            path = self.bin / name
            path.write_text(fake)
            path.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + ":/usr/bin:/bin",
            FIXTURE_ROOT=str(self.root),
        )
        self.env.pop("FAIL_MATCH", None)
        self.env.pop("FAIL_CWD", None)

    def run_driver(self, mode, failure="", failure_cwd=""):
        result = subprocess.run(
            ["/bin/sh", str(self.root / "scripts/check-client-security.sh"), mode],
            cwd="/",
            env=dict(self.env, FAIL_MATCH=failure, FAIL_CWD=failure_cwd),
            capture_output=True,
            text=True,
        )
        events = (
            [json.loads(line) for line in self.events.read_text().splitlines()]
            if self.events.exists()
            else []
        )
        return result, events

    def test_rust_success_scans_all_clients_from_their_own_directory(self):
        result, events = self.run_driver("rust")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["cwd"] for e in events], RUST_CLIENTS)
        self.assertTrue(
            all(e["args"] == ["audit", "--deny", "unsound"] for e in events)
        )

    def test_rust_failure_never_skips_or_redirects_remaining_clients(self):
        for failed in RUST_CLIENTS:
            with self.subTest(failed=failed):
                self.events.unlink(missing_ok=True)
                result, events = self.run_driver("rust", failure_cwd=failed)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([e["cwd"] for e in events], RUST_CLIENTS)
                self.assertIn("FAIL: " + failed, result.stderr)
                self.assertEqual(result.stderr.count("FAIL:"), 1)

    def test_missing_client_directory_fails_but_later_clients_are_scanned(self):
        (self.root / RUST_CLIENTS[0]).rmdir()
        result, events = self.run_driver("rust")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([e["cwd"] for e in events], RUST_CLIENTS[1:])

    def test_go_success_scans_all_modules_and_each_standalone_binary(self):
        result, events = self.run_driver("go")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["cwd"] for e in events[:4]], GO_CLIENTS)
        builds = [e for e in events if e["args"][0] == "build"]
        self.assertEqual([e["args"][-1] for e in builds], ["./" + p for p in PROGRAMS])
        binaries = [e for e in events if "-mode=binary" in e["args"]]
        self.assertEqual(len(binaries), 4)
        self.assertTrue(
            all(not Path(e["args"][-1]).exists() for e in binaries),
            "temporary binaries must be cleaned",
        )

    def test_go_first_scan_failure_still_scans_remaining_modules_and_binaries(self):
        result, events = self.run_driver("go", failure_cwd=GO_CLIENTS[0])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len([e for e in events if e["args"][0] == "run"]), 8)
        self.assertEqual([e["cwd"] for e in events[:4]], GO_CLIENTS)

    def test_go_failed_build_cannot_scan_a_stale_binary_or_hide_failure(self):
        result, events = self.run_driver("go", "/client.go ./client.go")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len([e for e in events if e["args"][0] == "build"]), 4)
        binaries = [e for e in events if "-mode=binary" in e["args"]]
        self.assertEqual([Path(e["args"][-1]).name for e in binaries], PROGRAMS[1:])

    def test_go_binary_scan_failure_fails_the_whole_run(self):
        result, events = self.run_driver("go", "-mode=binary")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len([e for e in events if "-mode=binary" in e["args"]]), 4)

    def test_missing_scanner_is_an_error(self):
        # Use only fixture utilities so an installed system cargo cannot mask absence.
        (self.bin / "cargo").unlink()
        (self.bin / "dirname").symlink_to(shutil.which("dirname"))
        self.env["PATH"] = str(self.bin)
        result, events = self.run_driver("rust")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])
        self.assertEqual(result.stderr.count("FAIL:"), 3)

    def test_unknown_mode_fails_without_running_a_scanner(self):
        result, events = self.run_driver("unknown")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
