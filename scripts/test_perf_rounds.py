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
    # build.zig contents per fixture commit; None means no build.zig.
    baseline_build_zig = None
    current_build_zig = None

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
        self.write_build_zig(self.baseline_build_zig)
        self.git("add", "-A")
        self.git("commit", "-m", "baseline fixture")
        self.parent = self.git("rev-parse", "HEAD")
        (self.repo / "src/runtime").write_text("125\n")
        self.write_build_zig(self.current_build_zig)
        self.git("add", "-A")
        self.git("commit", "-m", "current fixture")

    def write_build_zig(self, contents):
        path = self.repo / "build.zig"
        if contents is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(contents)

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
if args[:1] == ["build"] and args[1:2] in (["bench"], ["bench-isolated"]):
    output = pathlib.Path(argument("--output"))
    with open(os.environ["ROUND_STEPS"], "a") as log:
        log.write(args[1] + "\\n")
    match = re.search(r"\\.r([0-9]+)\\.json$", output.name)
    round_index = int(match[1]) - 1 if match else 0
    current = pathlib.Path("src/runtime").read_text() == "125\\n"
    with open(os.environ["ROUND_CAPTURES"], "a") as log:
        log.write(output.name + "\\n")
    throughput, latency = json.loads(os.environ["ROUND_ROWS"])[round_index] if current else [100, 100]
    output.write_text(json.dumps({"round": round_index + 1, "rows": [{
        "scenario_name": "micro/fixture", "variant": "fixture",
        "throughput_ops_per_sec": throughput,
        "latency_p50_ns": latency, "latency_p95_ns": latency,
        "latency_p99_ns": latency}]}))
elif args[:2] == ["build", "bench-compare"]:
    # Simplified compare.zig multi-round contract: one call with every pair
    # in round order; a row fails only when it fails in every pair.
    # compare.zig's real rule (every HEAD round worse than every baseline
    # round, plus a median effect beyond threshold and floor) is unit-tested
    # against recorded CI noise in tests/test_bench_compare.zig.
    baselines = [pathlib.Path(a.split("=", 1)[1]) for a in args if a.startswith("--baseline=")]
    currents = [pathlib.Path(a.split("=", 1)[1]) for a in args if a.startswith("--current=")]
    assert len(baselines) == len(currents) and baselines
    failed = 0
    for baseline, current in zip(baselines, currents):
        left = json.loads(baseline.read_text())
        right = json.loads(current.read_text())
        with open(os.environ["ROUND_COMPARISONS"], "a") as log:
            log.write(json.dumps([baseline.name, current.name, right]) + "\\n")
        assert left["round"] == right["round"]
        row = right["rows"][0]
        failed += not (row["throughput_ops_per_sec"] >= 80 and row["latency_p99_ns"] <= 120)
    sys.exit(1 if failed == len(baselines) else 0)
else:
    sys.exit(99)
""")
        compiler.chmod(0o755)
        comparisons = self.directory / "comparisons.jsonl"
        captures = self.directory / "captures.txt"
        steps = self.directory / "steps.txt"
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
                ROUND_CAPTURES=str(captures),
                ROUND_STEPS=str(steps),
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        receipts = [json.loads(line) for line in comparisons.read_text().splitlines()]
        self.captures = captures.read_text().splitlines()
        self.steps = steps.read_text().splitlines()
        return result, receipts

    def test_multiround_gate_ignores_a_regression_that_does_not_reproduce(self):
        # Shared CI runners flag random rows in single rounds; a pair that
        # fails while others pass is noise, not a regression.
        result, comparisons = self.run_rounds([[100, 100], [10, 100], [10, 100]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 3)
        self.assertEqual([row[2]["round"] for row in comparisons], [1, 2, 3])

    def test_multiround_gate_fails_a_regression_that_reproduces(self):
        result, comparisons = self.run_rounds([[10, 100], [50, 100], [10, 100]])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 3)

    def test_multiround_gate_alternates_capture_order(self):
        self.run_rounds([[100, 100], [100, 100], [100, 100]])
        self.assertEqual(len(self.captures), 6)
        order = [
            ("current" if name.startswith("HEAD-") else "baseline")
            for name in self.captures
        ]
        self.assertEqual(
            order,
            ["baseline", "current", "current", "baseline", "baseline", "current"],
        )

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

    def test_paired_gate_uses_the_monolithic_bench_without_isolated_step(self):
        result, _ = self.run_rounds([[100, 100], [100, 100]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.steps, ["bench"] * 4)

    def test_multiround_gate_compares_every_pair_when_all_pass(self):
        result, comparisons = self.run_rounds([[100, 100], [90, 110]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(comparisons), 2)
        for index, (baseline, current, _) in enumerate(comparisons, 1):
            self.assertTrue(baseline.endswith(f"-baseline.r{index}.json"))
            self.assertEqual(current, f"HEAD-current.r{index}.json")


ISOLATED_BUILD_ZIG = 'const step = b.step("bench-isolated", "...");\n'


class IsolatedStepTests(PairedRoundTests):
    """Micro captures use bench-isolated only when both commits define it."""

    baseline_build_zig = ISOLATED_BUILD_ZIG
    current_build_zig = ISOLATED_BUILD_ZIG

    def test_paired_gate_uses_the_monolithic_bench_without_isolated_step(self):
        pass

    def test_paired_gate_uses_isolated_step_on_both_sides(self):
        result, _ = self.run_rounds([[100, 100], [100, 100]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.steps, ["bench-isolated"] * 4)


class IsolatedStepOnlyAtHeadTests(PairedRoundTests):
    """A baseline without bench-isolated keeps both sides on bench."""

    baseline_build_zig = None
    current_build_zig = ISOLATED_BUILD_ZIG


if __name__ == "__main__":
    unittest.main()
