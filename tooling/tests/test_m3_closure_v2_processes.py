from __future__ import annotations

import hashlib
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

from m3_closure_v2.processes import (
    ProcessState,
    inspect_record,
    load_process_record,
    start_owned_process,
    stop_owned_process,
)


def test_owned_process_record_detects_running_and_stopped(tmp_path: Path) -> None:
    process, record = start_owned_process(
        name="test-sleeper",
        command=[
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_path=tmp_path / "process.log",
        record_path=tmp_path / "process.json",
    )
    try:
        assert process.poll() is None
        assert record.schema == "weall.m3.process-record.v2"
        assert inspect_record(record) is ProcessState.RUNNING_OWNED
        loaded = load_process_record(tmp_path / "process.json")
        assert loaded == record
        assert (
            stop_owned_process(record, grace_s=2.0)
            is ProcessState.STOPPED_STALE_RECORD
        )
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_exec_transition_preserves_owned_identity(tmp_path: Path) -> None:
    marker = tmp_path / "exec-now"
    helper = tmp_path / "exec_helper.py"
    helper.write_text(
        "\n".join(
            [
                "import os",
                "import pathlib",
                "import sys",
                "import time",
                "marker = pathlib.Path(sys.argv[1])",
                "while not marker.exists():",
                "    time.sleep(0.01)",
                "os.execlp('sleep', 'sleep', '30')",
                "",
            ]
        ),
        encoding="utf-8",
    )

    process, record = start_owned_process(
        name="exec-transition",
        command=[sys.executable, str(helper), str(marker)],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_path=tmp_path / "exec.log",
        record_path=tmp_path / "exec-process.json",
    )
    try:
        initial_hash = record.initial_command_sha256
        marker.touch()

        changed = False
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                raw = Path(f"/proc/{record.pid}/cmdline").read_bytes()
            except OSError:
                break
            if raw and hashlib.sha256(raw).hexdigest() != initial_hash:
                changed = True
                break
            time.sleep(0.02)

        assert changed, "helper did not complete the expected exec transition"
        assert inspect_record(record) is ProcessState.RUNNING_OWNED
        assert (
            stop_owned_process(record, grace_s=2.0)
            is ProcessState.STOPPED_STALE_RECORD
        )
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_start_time_mismatch_is_treated_as_unowned(tmp_path: Path) -> None:
    process, record = start_owned_process(
        name="identity-mismatch",
        command=[
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_path=tmp_path / "mismatch.log",
        record_path=tmp_path / "mismatch-process.json",
    )
    try:
        forged = replace(
            record,
            start_time_ticks=record.start_time_ticks + 1,
        )
        assert (
            inspect_record(forged)
            is ProcessState.PID_REUSED_OR_MISMATCHED
        )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
