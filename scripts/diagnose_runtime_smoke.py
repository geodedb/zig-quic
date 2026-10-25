#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 CodePros
"""Run the existing native smoke steps with bounded process diagnostics."""

import json
import os
from pathlib import Path
import signal
import subprocess
import time

out = Path("runtime-diagnostics")
out.mkdir(exist_ok=True)
records = []


def snapshot(root_pid):
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,etime=,time=,pcpu=,rss=,comm="],
        check=True, capture_output=True, text=True,
    )
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 6)
        if len(fields) == 7:
            rows.append(dict(zip(
                ["pid", "ppid", "elapsed", "cpu_time", "cpu_percent", "rss_kib", "command"], fields
            )))
    selected = {str(root_pid)}
    while True:
        children = {r["pid"] for r in rows if r["ppid"] in selected}
        if children <= selected:
            break
        selected |= children
    return [r for r in rows if r["pid"] in selected]


def stop(process):
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


steps = [
    ("portable", ["test-portable-runtime"]),
    ("udp", ["test", "-Dtest-filter=udp_batch_runtime_smoke"]),
    ("transport", ["test", "-Dtest-filter=transport_geode_compat"]),
]
for name, args in steps:
    command = ["zig", "build", *args, "-j2", "--summary", "all", "--verbose"]
    print(json.dumps({"phase": name, "event": "start", "command": command}), flush=True)
    started = time.monotonic()
    record = {"phase": name, "command": command, "snapshots": []}
    sampled = False
    with (out / f"{name}.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                elapsed = round(time.monotonic() - started, 1)
                rows = snapshot(process.pid)
                observation = {"elapsed_seconds": elapsed, "processes": rows}
                record["snapshots"].append(observation)
                print(json.dumps({"phase": name, **observation}), flush=True)
                (out / "progress.json").write_text(json.dumps([*records, record], indent=2))
                if elapsed >= 180 and not sampled and rows:
                    candidates = [r for r in rows if Path(r["command"]).name == "test"] or rows[-1:]
                    for row in candidates:
                        sample_path = out / f"{name}-{row['pid']}.sample.txt"
                        with (out / f"{name}-sample.log").open("a") as sample_log:
                            subprocess.run(
                                ["sample", row["pid"], "1", "10", "-file", str(sample_path)],
                                stdout=sample_log, stderr=subprocess.STDOUT, timeout=20, check=False,
                            )
                    sampled = True
                if elapsed >= 600:
                    record["timed_out"] = True
                    stop(process)
                    break
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            stop(process)
    record["exit_code"] = process.returncode
    record["seconds"] = round(time.monotonic() - started, 1)
    records.append(record)
    (out / "progress.json").write_text(json.dumps(records, indent=2))
    print(json.dumps({"phase": name, "event": "finished", "exit_code": process.returncode,
                      "seconds": record["seconds"]}), flush=True)
    if process.returncode or record.get("timed_out"):
        raise SystemExit(1)
