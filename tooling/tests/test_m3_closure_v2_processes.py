from __future__ import annotations

import os
import sys
from pathlib import Path

from m3_closure_v2.processes import (
    ProcessState,
    inspect_record,
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
        assert inspect_record(record) is ProcessState.RUNNING_OWNED
        assert stop_owned_process(record, grace_s=2.0) is ProcessState.STOPPED_STALE_RECORD
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
