#!/usr/bin/env python3
"""Test multi-round gate decisions with synthetic data, not performance measurements."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent


class PairedRoundTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="quic-rounds-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repo = self.directory / "candidate"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        template = self.directory / "empty-template"
        template.mkdir()
        self.git("init", "--template=" + str(template))
        self.git("config", "user.name", "Regression Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / "scripts").mkdir()
        shutil.copy2(SCRIPTS / "perf-gate.sh", self.repo / "scripts/perf-gate.sh")
        (self.repo / "src").mkdir()
        (self.repo / "src/runtime").write_text("100\n")
        self.git("add", ".")
        self.git("commit", "-m", "baseline fixture")
        self.parent = self.git("rev-parse", "HEAD")
        (self.repo / "src/runtime").write_text("125\n")
        self.git("add", ".")
        self.git("commit", "-m", "current fixture")

    def git(self, *args):
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.strip()

    def run_rounds(self, current_rows):
        # Deterministic compiler fixtures test the shell driver's evidence
        # handling. These values are not performance measurements.
        compiler = self.directory / "rounds-zig"
        compiler.write_text("""#!/usr/bin/env python3
import json, os, pathlib, re, sys
args = sys.argv[1:]
def argument(name):
    return next(a.split("=", 1)[1] for a in args if a.startswith(name + "="))
if args[:2] == ["build", "bench"]:
    output = pathlib.Path(argument("--output"))
    match = re.search(r"\\.r([0-9]+)\\.json$", output.name)
    round_index = int(match[1]) - 1 if match else 0
    current = pathlib.Path("src/runtime").read_text() == "125\\n"
    throughput, latency = json.loads(os.environ["ROUND_ROWS"])[round_index] if current else [100, 100]
    output.write_text(json.dumps({"round": round_index + 1, "rows": [{
        "scenario_name": "micro/fixture", "variant": "fixture",
        "throughput_ops_per_sec": throughput,
        "latency_p50_ns": latency, "latency_p95_ns": latency,
        "latency_p99_ns": latency}]}))
elif args[:2] == ["build", "bench-compare"]:
    baseline = pathlib.Path(argument("--baseline"))
    current = pathlib.Path(argument("--current"))
    left = json.loads(baseline.read_text())
    right = json.loads(current.read_text())
    with open(os.environ["ROUND_COMPARISONS"], "a") as log:
        log.write(json.dumps([baseline.name, current.name, right]) + "\\n")
    assert left["round"] == right["round"]
    row = right["rows"][0]
    sys.exit(0 if row["throughput_ops_per_sec"] >= 80 and row["latency_p99_ns"] <= 120 else 1)
else:
    sys.exit(99)
""")
        compiler.chmod(0o755)
        comparisons = self.directory / "comparisons.jsonl"
        result = subprocess.run(
            [
                "bash",
                "scripts/perf-gate.sh",
                f"--baseline-commit={self.parent}",
                "--suite=micro",
            ],
            cwd=self.repo,
            env=dict(
                self.env,
                ZIG=str(compiler),
                PERF_GATE_ROUNDS=str(len(current_rows)),
                ROUND_ROWS=json.dumps(current_rows),
                ROUND_COMPARISONS=str(comparisons),
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        receipts = [json.loads(line) for line in comparisons.read_text().splitlines()]
        return result, receipts

    def test_multiround_gate_keeps_a_failing_pair_after_a_passing_pair(self):
        result, comparisons = self.run_rounds([[100, 100], [10, 100]])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 2)
        self.assertEqual([row[2]["round"] for row in comparisons], [1, 2])

    def test_multiround_gate_cannot_synthesize_a_row_from_incompatible_rounds(self):
        result, comparisons = self.run_rounds([[100, 400], [50, 100]])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 2)
        self.assertEqual(
            [
                (
                    row[2]["rows"][0]["throughput_ops_per_sec"],
                    row[2]["rows"][0]["latency_p99_ns"],
                )
                for row in comparisons
            ],
            [(100, 400), (50, 100)],
        )

    def test_multiround_gate_compares_every_pair_when_all_pass(self):
        result, comparisons = self.run_rounds([[100, 100], [90, 110]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 2)
        for index, (baseline, current, _) in enumerate(comparisons, 1):
            self.assertTrue(baseline.endswith(f"-baseline.r{index}.json"))
            self.assertEqual(current, f"HEAD-current.r{index}.json")


if __name__ == "__main__":
    unittest.main()
