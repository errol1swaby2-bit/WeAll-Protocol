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


@dataclass(frozen=True)
class KernelProcessIdentity:
    boot_id: str
    pid: int
    kernel_state: str
    start_time_ticks: int
    process_group_id: int
    session_id: int
    uid: int


def _read_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8"
        ).strip()
    except OSError as exc:
        raise ProcessOwnershipError("kernel_boot_id_unavailable") from exc
    if not value:
        raise ProcessOwnershipError("kernel_boot_id_empty")
    return value


def _parse_proc_stat(pid: int) -> tuple[str, int, int, int]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise ProcessLookupError(pid) from exc

    close = raw.rfind(")")
    if close < 0:
        raise ProcessOwnershipError(f"proc_stat_shape_invalid:{pid}")
    fields = raw[close + 2 :].split()

    # fields[0] is kernel stat field 3 (state). Therefore:
    # process group = field 5 -> index 2
    # session       = field 6 -> index 3
    # start time    = field 22 -> index 19
    if len(fields) <= 19:
        raise ProcessOwnershipError(f"proc_stat_fields_short:{pid}")
    state = str(fields[0])
    try:
        process_group_id = int(fields[2])
        session_id = int(fields[3])
        start_time_ticks = int(fields[19])
    except ValueError as exc:
        raise ProcessOwnershipError(f"proc_stat_integer_invalid:{pid}") from exc
    return state, start_time_ticks, process_group_id, session_id


def _read_uid(pid: int) -> int:
    try:
        lines = Path(f"/proc/{pid}/status").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError as exc:
        raise ProcessLookupError(pid) from exc
    for line in lines:
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) < 2:
                break
            try:
                return int(parts[1])
            except ValueError as exc:
                raise ProcessOwnershipError(
                    f"proc_uid_invalid:{pid}"
                ) from exc
    raise ProcessOwnershipError(f"proc_uid_missing:{pid}")


def read_process_identity(pid: int) -> KernelProcessIdentity | None:
    try:
        state, start_time_ticks, process_group_id, session_id = (
            _parse_proc_stat(pid)
        )
        uid = _read_uid(pid)
    except ProcessLookupError:
        return None
    return KernelProcessIdentity(
        boot_id=_read_boot_id(),
        pid=int(pid),
        kernel_state=state,
        start_time_ticks=start_time_ticks,
        process_group_id=process_group_id,
        session_id=session_id,
        uid=uid,
    )


def _cmdline_bytes(pid: int) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None


def _cmdline_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _readlink_or_empty(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


@dataclass(frozen=True)
class ProcessRecord:
    schema: str
    name: str
    pid: int
    process_group_id: int
    session_id: int
    start_time_ticks: int
    boot_id: str
    uid: int
    command: tuple[str, ...]
    initial_command_sha256: str
    initial_executable: str
    initial_working_directory: str
    created_at_unix_ms: int

    def to_json(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "pid": self.pid,
            "process_group_id": self.process_group_id,
            "session_id": self.session_id,
            "start_time_ticks": self.start_time_ticks,
            "boot_id": self.boot_id,
            "uid": self.uid,
            "command": list(self.command),
            "initial_command_sha256": self.initial_command_sha256,
            "initial_executable": self.initial_executable,
            "initial_working_directory": self.initial_working_directory,
            "created_at_unix_ms": self.created_at_unix_ms,
        }


def inspect_record(record: ProcessRecord) -> ProcessState:
    observed = read_process_identity(record.pid)
    if observed is None or observed.kernel_state == "Z":
        return ProcessState.STOPPED_STALE_RECORD

    expected = (
        record.boot_id,
        record.pid,
        record.start_time_ticks,
        record.process_group_id,
        record.session_id,
        record.uid,
    )
    actual = (
        observed.boot_id,
        observed.pid,
        observed.start_time_ticks,
        observed.process_group_id,
        observed.session_id,
        observed.uid,
    )
    if actual != expected:
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

    resolved_cwd = Path(cwd).resolve()
    if not resolved_cwd.is_dir():
        raise ProcessOwnershipError(f"process_cwd_invalid:{resolved_cwd}")

    output = Path(stdout_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    stream = output.open("ab", buffering=0)
    try:
        process = subprocess.Popen(
            resolved_command,
            cwd=str(resolved_cwd),
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        stream.close()

    identity = None
    raw_command = None
    for _ in range(200):
        identity = read_process_identity(process.pid)
        raw_command = _cmdline_bytes(process.pid)
        if (
            identity is not None
            and identity.kernel_state != "Z"
            and raw_command
        ):
            break
        if process.poll() is not None:
            raise ProcessOwnershipError(
                f"process_exited_before_record:{name}:{process.returncode}"
            )
        time.sleep(0.01)

    if identity is None or identity.kernel_state == "Z" or not raw_command:
        process.terminate()
        raise ProcessOwnershipError(f"process_identity_unavailable:{name}")

    if identity.process_group_id != process.pid:
        process.terminate()
        raise ProcessOwnershipError(
            f"process_not_session_group_leader:"
            f"pid={process.pid}:pgid={identity.process_group_id}"
        )

    record = ProcessRecord(
        schema="weall.m3.process-record.v2",
        name=name,
        pid=process.pid,
        process_group_id=identity.process_group_id,
        session_id=identity.session_id,
        start_time_ticks=identity.start_time_ticks,
        boot_id=identity.boot_id,
        uid=identity.uid,
        command=resolved_command,
        initial_command_sha256=_cmdline_sha256(raw_command),
        initial_executable=_readlink_or_empty(
            Path(f"/proc/{process.pid}/exe")
        ),
        initial_working_directory=_readlink_or_empty(
            Path(f"/proc/{process.pid}/cwd")
        ),
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

    state = inspect_record(record)
    if state is ProcessState.PID_REUSED_OR_MISMATCHED:
        raise ProcessOwnershipError(
            f"ownership_changed_during_shutdown:{record.pid}"
        )
    if state is ProcessState.RUNNING_OWNED:
        os.killpg(record.process_group_id, signal.SIGKILL)

    deadline = time.monotonic() + max(1.0, grace_s)
    while time.monotonic() < deadline:
        if inspect_record(record) is ProcessState.STOPPED_STALE_RECORD:
            return ProcessState.STOPPED_STALE_RECORD
        time.sleep(0.05)
    raise ProcessOwnershipError(
        f"owned_process_group_did_not_stop:{record.process_group_id}"
    )


def load_process_record(path: str | Path) -> ProcessRecord:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProcessOwnershipError(f"process_record_unreadable:{source}") from exc
    try:
        record = ProcessRecord(
            schema=str(raw["schema"]),
            name=str(raw["name"]),
            pid=int(raw["pid"]),
            process_group_id=int(raw["process_group_id"]),
            session_id=int(raw["session_id"]),
            start_time_ticks=int(raw["start_time_ticks"]),
            boot_id=str(raw["boot_id"]),
            uid=int(raw["uid"]),
            command=tuple(str(item) for item in raw["command"]),
            initial_command_sha256=str(raw["initial_command_sha256"]),
            initial_executable=str(raw["initial_executable"]),
            initial_working_directory=str(raw["initial_working_directory"]),
            created_at_unix_ms=int(raw["created_at_unix_ms"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessOwnershipError(
            f"process_record_shape_invalid:{source}"
        ) from exc
    if record.schema != "weall.m3.process-record.v2":
        raise ProcessOwnershipError(
            f"process_record_schema_invalid:{record.schema}"
        )
    return record
