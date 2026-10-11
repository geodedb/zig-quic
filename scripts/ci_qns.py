#!/usr/bin/env python3
"""Verify each simulator case using process results and fresh downloaded bytes."""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ci_interop import stop


def execute(command, *, env, timeout=30, log=None):
    with log.open("w") if log else open(os.devnull, "w") as output:
        process = subprocess.Popen(
            command,
            env=env,
            stdout=output if log else subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, _ = process.communicate(timeout=timeout)
            if process.returncode:
                raise RuntimeError(
                    f"{command[0]} exited {process.returncode}: {stdout or log}"
                )
            return stdout or ""
        finally:
            stop(process)


class Runner:
    def __init__(self, root, env, command=execute):
        self.root = root
        self.env = dict(env)
        self.command = command
        self.assets = root / "examples/interop/quic-network-simulator"
        self.logs = self.assets / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.results = Path(tempfile.mkdtemp(prefix="ci-cases-", dir=self.logs))
        self.compose = [
            "docker",
            "compose",
            "-f",
            str(root / "examples/interop/docker-compose.full.yml"),
            "--profile",
            "generic",
        ]

    def call(self, *args, **kwargs):
        return self.command(self.compose + list(args), env=self.env, **kwargs)

    def archive_outputs(self, destination):
        for name, path in (
            ("sim", self.logs / "sim"),
            ("server", self.logs / "server"),
            ("client", self.logs / "client"),
            ("downloads", self.assets / "downloads"),
        ):
            if path.is_symlink():
                raise RuntimeError(f"Output directory is a symlink: {path}")
            if path.exists():
                path.rename(destination / name)
            path.mkdir(mode=0o2770)
            path.chmod(0o2770)

    def state(self, service):
        identifier = self.call("ps", "-aq", service).strip()
        if not re.fullmatch(r"[a-f0-9]{12,64}", identifier):
            raise RuntimeError(f"Missing or ambiguous {service} container")
        state = json.loads(
            self.command(
                ["docker", "inspect", "--format", "{{json .State}}", identifier],
                env=self.env,
            )
        )
        if (
            state.get("Status") != "exited"
            or state.get("OOMKilled") is not False
            or state.get("Error") != ""
        ):
            raise RuntimeError(f"Invalid {service} termination: {state}")
        return state

    def run_case(self, name, server, client, testcase):
        result = {"name": name, "testcase": testcase, "passed": False}
        case = self.results / name
        case.mkdir()
        self.env.update(
            SERVER_IMAGE=server,
            CLIENT_IMAGE=client,
            TESTCASE=testcase,
            REQUESTS="https://server4/5000",
            QNS_H3_ALLOW_EMPTY="0",
        )
        try:
            # Endpoint recreation changes link-layer identities. Give each
            # case a fresh simulator instead of retaining its previous peers.
            self.call("rm", "-fsv", "server", "client", "sim")
            before = case / "previous-output"
            before.mkdir()
            self.archive_outputs(before)
            source = self.assets / "www/5000"
            expected = source.read_bytes()
            if not expected:
                raise RuntimeError("Requested source payload is empty")
            self.call("up", "-d", "sim")
            for _ in range(30):
                if (
                    "sim"
                    in self.call(
                        "ps", "--status", "running", "--services", "sim"
                    ).splitlines()
                ):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Simulator did not become ready within 30 seconds")
            self.call(
                "up",
                "--no-deps",
                "--abort-on-container-exit",
                "--exit-code-from",
                "client",
                "--timeout",
                "30",
                "server",
                "client",
                timeout=120,
                log=case / "compose.log",
            )
            result["client"] = self.state("client")
            result["server"] = self.state("server")
            if result["client"]["ExitCode"] != 0:
                raise RuntimeError("Client did not exit successfully")
            # Compose terminates the long-running server when the client exits.
            if result["server"]["ExitCode"] not in (0, 137, 143):
                raise RuntimeError("Server failed instead of completing the case")
            download = self.assets / "downloads/5000"
            if download.is_symlink() or not download.is_file():
                raise RuntimeError("Client did not produce a fresh regular download")
            if download.stat().st_size != len(expected):
                raise RuntimeError("Downloaded payload has the wrong size")
            if download.read_bytes() != expected:
                raise RuntimeError("Downloaded payload differs from the requested file")
            result.update(passed=True, bytes=len(expected))
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
        finally:
            for action in ("logs", "remove", "archive"):
                try:
                    if action == "logs":
                        self.call(
                            "logs",
                            "--no-color",
                            "server",
                            "client",
                            "sim",
                            log=case / "endpoints.log",
                        )
                    elif action == "remove":
                        self.call("rm", "-fsv", "server", "client", "sim")
                    else:
                        self.archive_outputs(case)
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    subprocess.TimeoutExpired,
                ) as error:
                    result["passed"] = False
                    result.setdefault("cleanup_errors", []).append(f"{action}: {error}")
            (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        return result

    def run(self):
        results = []
        report = {"passed": False, "cases": results}
        try:
            peer = self.env["QUIC_GO_IMAGE"]
            for testcase in ("handshake", "transfer"):
                for role, server, client in (
                    ("zig-server", "zig-qns:local", peer),
                    ("zig-client", peer, "zig-qns:local"),
                ):
                    results.append(
                        self.run_case(f"{testcase}-{role}", server, client, testcase)
                    )
            report["passed"] = len(results) == 4 and all(r["passed"] for r in results)
        except (
            KeyError,
            OSError,
            RuntimeError,
            ValueError,
            subprocess.TimeoutExpired,
        ) as error:
            report["error"] = str(error)
        except KeyboardInterrupt:
            report["error"] = "Interrupted"
        finally:
            try:
                self.call("down", "-v", "--timeout", "10")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                report.update(passed=False, cleanup_error=str(error))
            (self.results / "result.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )
        return 0 if report["passed"] else 1


def main():
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    return Runner(Path(__file__).resolve().parents[1], os.environ).run()


if __name__ == "__main__":
    sys.exit(main())
