from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Sequence

from .errors import ProcessOwnershipError
from .util import atomic_write_json


class ProcessState(str, Enum):
    RUNNING_OWNED = "running_owned"
    STOPPED_STALE_RECORD = "stopped_stale_record"
    PID_REUSED_OR_MISMATCHED = "pid_reused_or_mismatched"


def _cmdline_bytes(pid: int) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None


def _cmdline_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ProcessRecord:
    schema: str
    name: str
    pid: int
    process_group_id: int
    command: tuple[str, ...]
    command_sha256: str
    created_at_unix_ms: int

    def to_json(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "pid": self.pid,
            "process_group_id": self.process_group_id,
            "command": list(self.command),
            "command_sha256": self.command_sha256,
            "created_at_unix_ms": self.created_at_unix_ms,
        }


def inspect_record(record: ProcessRecord) -> ProcessState:
    raw = _cmdline_bytes(record.pid)
    if raw is None:
        return ProcessState.STOPPED_STALE_RECORD
    if _cmdline_sha256(raw) != record.command_sha256:
        return ProcessState.PID_REUSED_OR_MISMATCHED
    return ProcessState.RUNNING_OWNED


def start_owned_process(
    *,
    name: str,
    command: Sequence[str],
    cwd: str | Path,
    env: dict[str, str] | None,
    stdout_path: str | Path,
    record_path: str | Path,
) -> tuple[subprocess.Popen[bytes], ProcessRecord]:
    resolved_command = tuple(str(item) for item in command)
    if not resolved_command:
        raise ProcessOwnershipError("process_command_empty")

    output = Path(stdout_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    stream = output.open("ab", buffering=0)
    try:
        process = subprocess.Popen(
            resolved_command,
            cwd=str(Path(cwd).resolve()),
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        stream.close()

    raw = None
    for _ in range(100):
        raw = _cmdline_bytes(process.pid)
        if raw:
            break
        if process.poll() is not None:
            raise ProcessOwnershipError(
                f"process_exited_before_record:{name}:{process.returncode}"
            )
        time.sleep(0.01)
    if not raw:
        process.terminate()
        raise ProcessOwnershipError(f"process_cmdline_unavailable:{name}")

    record = ProcessRecord(
        schema="weall.m3.process-record.v1",
        name=name,
        pid=process.pid,
        process_group_id=os.getpgid(process.pid),
        command=resolved_command,
        command_sha256=_cmdline_sha256(raw),
        created_at_unix_ms=int(time.time() * 1000),
    )
    atomic_write_json(record_path, record.to_json())
    return process, record


def stop_owned_process(
    record: ProcessRecord,
    *,
    grace_s: float = 10.0,
) -> ProcessState:
    state = inspect_record(record)
    if state is ProcessState.STOPPED_STALE_RECORD:
        return state
    if state is ProcessState.PID_REUSED_OR_MISMATCHED:
        raise ProcessOwnershipError(
            f"refusing_to_signal_unowned_pid:{record.pid}"
        )

    os.killpg(record.process_group_id, signal.SIGTERM)
    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline:
        if inspect_record(record) is ProcessState.STOPPED_STALE_RECORD:
            return ProcessState.STOPPED_STALE_RECORD
        time.sleep(0.05)

    if inspect_record(record) is ProcessState.RUNNING_OWNED:
        os.killpg(record.process_group_id, signal.SIGKILL)
    return ProcessState.STOPPED_STALE_RECORD


def load_process_record(path: str | Path) -> ProcessRecord:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProcessOwnershipError(f"process_record_unreadable:{source}") from exc
    try:
        return ProcessRecord(
            schema=str(raw["schema"]),
            name=str(raw["name"]),
            pid=int(raw["pid"]),
            process_group_id=int(raw["process_group_id"]),
            command=tuple(str(item) for item in raw["command"]),
            command_sha256=str(raw["command_sha256"]),
            created_at_unix_ms=int(raw["created_at_unix_ms"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessOwnershipError(
            f"process_record_shape_invalid:{source}"
        ) from exc
