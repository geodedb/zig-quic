#!/usr/bin/env python3
"""Run one real QUIC interop client, retaining diagnostics and owned-process cleanup."""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def stop(process):
    if process is None:
        return
    # Each subprocess owns its own session. Never signal unrelated servers.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # Also terminate descendants if their parent has already exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run(args):
    root = Path.cwd().resolve()
    if not args.name or any(
        c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in args.name
    ):
        raise ValueError(
            "name must contain only lowercase letters, digits, hyphens or underscores"
        )
    if args.timeout <= 0 or args.startup_timeout <= 0:
        raise ValueError("timeouts must be positive")
    command = args.client[1:] if args.client[:1] == ["--"] else args.client
    if not command:
        raise ValueError("a client command is required")
    logs = root / "test-results" / "interop" / args.name
    logs.mkdir(parents=True, exist_ok=True)
    server_log = logs / "server.log"
    client_log = logs / "client.log"
    server = client = None
    error = None
    try:
        with server_log.open("w") as output:
            server = subprocess.Popen(
                [
                    args.server,
                    "--bind",
                    args.bind,
                    "--cert",
                    "server-cert.pem",
                    "--key",
                    "server-key.pem",
                    "--insecure",
                ],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        deadline = time.monotonic() + args.startup_timeout
        while True:
            if server.poll() is not None:
                raise RuntimeError(
                    f"server exited before readiness with status {server.returncode}"
                )
            if f"listening on {args.bind}" in server_log.read_text(errors="replace"):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("server readiness timed out")
            time.sleep(0.05)
        with client_log.open("w") as output:
            client = subprocess.Popen(
                command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True
            )
        deadline = time.monotonic() + args.timeout
        while True:
            if server.poll() is not None:
                raise RuntimeError(
                    f"server exited during interop with status {server.returncode}"
                )
            code = client.poll()
            if code is not None:
                if code:
                    raise RuntimeError(f"client exited with status {code}")
                if args.success_marker not in client_log.read_text(errors="replace"):
                    raise RuntimeError(
                        "client exited without the required success marker"
                    )
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("client timed out")
            time.sleep(0.05)
    except (OSError, RuntimeError, KeyboardInterrupt) as exc:
        error = str(exc)
    finally:
        stop(client)
        stop(server)
    for path in (server_log, client_log):
        if path.exists():
            print(f"--- {path.relative_to(root)} ---")
            print("\n".join(path.read_text(errors="replace").splitlines()[-40:]))
    if error:
        print(f"Interop failed: {error}", file=sys.stderr)
        return 1
    print(f"Interop passed: {args.name}")
    return 0


def main():
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--server", default="./zig-out/bin/quic-server")
    parser.add_argument("--bind", default="127.0.0.1:4433")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--startup-timeout", type=float, default=10)
    parser.add_argument("--success-marker", default="Test completed successfully")
    parser.add_argument("client", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return run(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
