from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import ContractError, ProcessOwnershipError
from .http_client import RateLimitedJsonClient, RetryPolicy
from .models import parse_transcript
from .processes import (
    ProcessRecord,
    ProcessState,
    inspect_record,
    start_owned_process,
    stop_owned_process,
)
from .receipts import ReceiptStore
from .util import (
    atomic_write_json,
    canonical_json_sha256,
    sha256_file,
)
from .verification import verify_transcript_statuses


@dataclass(frozen=True)
class ReplayStatusConfig:
    source_repo: Path
    source_branch: str
    implementation_freeze_commit: str
    implementation_tree: str
    historical_freeze_commit: str
    evidence_commit: str
    evidence_transcript_path: str
    preserved_database: Path
    output_root: Path
    backend_host: str = "127.0.0.1"
    backend_port: int = 18411
    ballot_profile_id: str = "controlled-testnet-aggregate-v1"
    minimum_request_interval_s: float = 0.35
    max_request_attempts: int = 10
    retry_base_delay_s: float = 0.5
    retry_max_delay_s: float = 30.0
    request_timeout_s: float = 15.0

    @property
    def backend_url(self) -> str:
        return f"http://{self.backend_host}:{self.backend_port}"

    @property
    def backend_dir(self) -> Path:
        return self.source_repo / "Weall-Protocol"

    @property
    def python_executable(self) -> Path:
        return self.source_repo / ".venv-m3" / "bin" / "python"

    @property
    def fingerprint(self) -> str:
        return canonical_json_sha256(
            {
                "source_repo": str(self.source_repo),
                "source_branch": self.source_branch,
                "implementation_freeze_commit": self.implementation_freeze_commit,
                "implementation_tree": self.implementation_tree,
                "historical_freeze_commit": self.historical_freeze_commit,
                "evidence_commit": self.evidence_commit,
                "evidence_transcript_path": self.evidence_transcript_path,
                "preserved_database": str(self.preserved_database),
                "preserved_database_sha256": sha256_file(
                    self.preserved_database
                ),
                "backend_url": self.backend_url,
                "ballot_profile_id": self.ballot_profile_id,
                "minimum_request_interval_s": self.minimum_request_interval_s,
                "max_request_attempts": self.max_request_attempts,
                "retry_base_delay_s": self.retry_base_delay_s,
                "retry_max_delay_s": self.retry_max_delay_s,
                "request_timeout_s": self.request_timeout_s,
            }
        )

    def validate(self) -> None:
        if not self.source_repo.is_absolute():
            raise ContractError("source_repo_not_absolute")
        if not self.source_repo.is_dir() or self.source_repo.is_symlink():
            raise ContractError("source_repo_invalid")
        if not self.backend_dir.is_dir():
            raise ContractError("backend_dir_missing")
        if not self.python_executable.is_file():
            raise ContractError("python_executable_missing")
        if (
            not self.preserved_database.is_file()
            or self.preserved_database.is_symlink()
        ):
            raise ContractError("preserved_database_invalid")
        if not self.output_root.is_absolute():
            raise ContractError("output_root_not_absolute")
        if len(self.implementation_freeze_commit) != 40:
            raise ContractError("implementation_freeze_invalid")
        if len(self.implementation_tree) != 40:
            raise ContractError("implementation_tree_invalid")
        if len(self.historical_freeze_commit) != 40:
            raise ContractError("historical_freeze_invalid")
        if len(self.evidence_commit) != 40:
            raise ContractError("evidence_commit_invalid")
        if not self.evidence_transcript_path or self.evidence_transcript_path.startswith("/"):
            raise ContractError("evidence_transcript_path_invalid")
        if not (1 <= self.backend_port <= 65535):
            raise ContractError("backend_port_invalid")
        if self.minimum_request_interval_s < 0:
            raise ContractError("minimum_request_interval_invalid")
        if self.max_request_attempts < 1:
            raise ContractError("max_request_attempts_invalid")


def _git(
    config: ReplayStatusConfig,
    *args: str,
    capture: bool = True,
) -> str:
    completed = subprocess.run(
        ["git", "-C", str(config.source_repo), *args],
        check=True,
        text=True,
        capture_output=capture,
    )
    return completed.stdout.strip() if capture else ""


def verify_source_freeze(config: ReplayStatusConfig) -> dict[str, Any]:
    branch = _git(config, "branch", "--show-current")
    head = _git(config, "rev-parse", "HEAD")
    tree = _git(config, "rev-parse", "HEAD^{tree}")
    status = _git(config, "status", "--porcelain", "--untracked-files=all")
    evidence_parent = _git(config, "rev-parse", f"{config.evidence_commit}^")

    if branch != config.source_branch:
        raise ContractError(
            f"source_branch_mismatch:expected={config.source_branch}:actual={branch}"
        )
    if head != config.implementation_freeze_commit:
        raise ContractError(
            f"source_head_mismatch:"
            f"expected={config.implementation_freeze_commit}:actual={head}"
        )
    if tree != config.implementation_tree:
        raise ContractError(
            f"source_tree_mismatch:"
            f"expected={config.implementation_tree}:actual={tree}"
        )
    if status:
        raise ContractError("source_repository_dirty")
    if evidence_parent != config.historical_freeze_commit:
        raise ContractError(
            f"evidence_parent_mismatch:"
            f"expected={config.historical_freeze_commit}:actual={evidence_parent}"
        )

    _git(
        config,
        "cat-file",
        "-e",
        f"{config.evidence_commit}:{config.evidence_transcript_path}",
    )

    return {
        "branch": branch,
        "head": head,
        "tree": tree,
        "clean": True,
        "historical_evidence_parent": evidence_parent,
    }


def port_is_free(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def extract_evidence_transcript(
    config: ReplayStatusConfig,
    destination: Path,
) -> None:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(config.source_repo),
            "show",
            f"{config.evidence_commit}:{config.evidence_transcript_path}",
        ],
        check=True,
        stdout=subprocess.PIPE,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(completed.stdout)
    os.chmod(destination, 0o600)


def sqlite_backup(
    source: Path,
    destination: Path,
) -> dict[str, Any]:
    if destination.exists():
        raise ContractError(f"snapshot_target_exists:{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(destination)
    try:
        src.backup(dst)
        integrity = dst.execute("PRAGMA integrity_check;").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise ContractError(f"snapshot_integrity_failed:{integrity}")
        tables = {
            str(row[0])
            for row in dst.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        if "tx_index" not in tables or "blocks" not in tables:
            raise ContractError("snapshot_required_tables_missing")
        tx_index_count = int(
            dst.execute("SELECT COUNT(*) FROM tx_index;").fetchone()[0]
        )
        height_row = dst.execute("SELECT MAX(height) FROM blocks;").fetchone()
        height = int(height_row[0] or 0)
    finally:
        dst.close()
        src.close()

    os.chmod(destination, 0o600)
    return {
        "source": str(source),
        "source_sha256": sha256_file(source),
        "destination": str(destination),
        "destination_sha256": sha256_file(destination),
        "integrity_check": "ok",
        "tx_index_row_count": tx_index_count,
        "height": height,
    }


def wait_for_json(
    url: str,
    *,
    process_record: ProcessRecord,
    timeout_s: float = 90.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_error = ""
    while time.monotonic() < deadline:
        state = inspect_record(process_record)
        if state is not ProcessState.RUNNING_OWNED:
            raise ProcessOwnershipError(
                f"backend_exited_before_readiness:{state.value}"
            )
        try:
            request = urllib.request.Request(
                url,
                method="GET",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=2.0) as response:
                raw = response.read(1024 * 1024)
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            last_error = "response_not_object"
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            urllib.error.URLError,
        ) as exc:
            last_error = f"{type(exc).__name__}:{exc}"
        time.sleep(0.25)
    raise ContractError(f"backend_readiness_timeout:{last_error}")


def _backend_environment(
    config: ReplayStatusConfig,
    runtime_dir: Path,
    database: Path,
) -> dict[str, str]:
    environment = dict(os.environ)
    venv_bin = str(config.python_executable.parent)
    environment.update(
        {
            "VIRTUAL_ENV": str(config.python_executable.parents[1]),
            "PATH": f"{venv_bin}:{environment.get('PATH', '')}",
            "PYTHONPATH": str(config.backend_dir / "src"),
            "WEALL_DEVNET_DIR": str(runtime_dir),
            "WEALL_DB_PATH": str(database),
            "WEALL_DEVNET_AUTO_VENV": "0",
            "WEALL_NET_ENABLED": "0",
            "WEALL_NET_LOOP_AUTOSTART": "0",
            "WEALL_BLOCK_LOOP_AUTOSTART": "0",
            "WEALL_PRODUCE_EMPTY_BLOCKS": "0",
            "WEALL_M3_CIVIC_GOVERNANCE_STRICT": "1",
            "WEALL_BALLOT_PROFILE_ID": config.ballot_profile_id,
            "WEALL_BALLOT_PROFILE_ACTIVE": "1",
            "GUNICORN_BIND": f"{config.backend_host}:{config.backend_port}",
        }
    )
    return environment


def run_replay_status(config: ReplayStatusConfig) -> dict[str, Any]:
    config.validate()
    if config.output_root.exists():
        raise ContractError(f"output_root_exists:{config.output_root}")
    if not port_is_free(config.backend_host, config.backend_port):
        raise ContractError(
            f"backend_port_not_free:{config.backend_host}:{config.backend_port}"
        )

    config.output_root.mkdir(parents=True, mode=0o700)
    os.chmod(config.output_root, 0o700)

    transcript_path = config.output_root / "canonical-transcript.json"
    runtime_dir = config.output_root / "runtime"
    database = runtime_dir / "node1" / "weall.db"
    snapshot_report_path = config.output_root / "snapshot-report.json"
    source_report_path = config.output_root / "source-freeze-report.json"
    ballot_report_path = config.output_root / "ballot-profile.json"
    status_report_path = config.output_root / "status-verification.json"
    process_record_path = config.output_root / "backend-process.json"
    backend_log = config.output_root / "backend.log"
    final_report_path = config.output_root / "replay-status-report.json"
    receipt_root = config.output_root / "receipts"

    source_report = verify_source_freeze(config)
    atomic_write_json(source_report_path, source_report)

    extract_evidence_transcript(config, transcript_path)
    transcript = parse_transcript(transcript_path)
    if transcript.implementation_freeze_commit != config.historical_freeze_commit:
        raise ContractError(
            "canonical_transcript_historical_freeze_mismatch"
        )

    snapshot_report = sqlite_backup(config.preserved_database, database)
    atomic_write_json(snapshot_report_path, snapshot_report)

    process = None
    process_record = None
    backend_state_after = ""
    started_at = int(time.time() * 1000)

    try:
        process, process_record = start_owned_process(
            name="m3-closure-v2-replay-backend",
            command=[
                "bash",
                str(config.backend_dir / "scripts" / "devnet_boot_genesis_node.sh"),
            ],
            cwd=config.backend_dir,
            env=_backend_environment(config, runtime_dir, database),
            stdout_path=backend_log,
            record_path=process_record_path,
        )

        wait_for_json(
            f"{config.backend_url}/v1/status",
            process_record=process_record,
        )

        subprocess.run(
            [
                str(config.python_executable),
                str(config.source_repo / "scripts" / "check_m3_live_ballot_profile.py"),
                "--api-base",
                config.backend_url,
                "--out",
                str(ballot_report_path),
                "--implementation-freeze",
                config.implementation_freeze_commit,
                "--implementation-tree",
                config.implementation_tree,
            ],
            cwd=config.source_repo,
            check=True,
        )
        os.chmod(ballot_report_path, 0o600)

        client = RateLimitedJsonClient(
            config.backend_url,
            policy=RetryPolicy(
                max_attempts=config.max_request_attempts,
                base_delay_s=config.retry_base_delay_s,
                max_delay_s=config.retry_max_delay_s,
                minimum_interval_s=config.minimum_request_interval_s,
                timeout_s=config.request_timeout_s,
            ),
        )
        summary = verify_transcript_statuses(transcript, client)
        status_payload = summary.to_json()
        status_payload.update(
            {
                "api_base": config.backend_url,
                "transcript_fingerprint": transcript.fingerprint,
                "implementation_freeze_commit": config.implementation_freeze_commit,
                "implementation_tree": config.implementation_tree,
                "historical_evidence_commit": config.evidence_commit,
            }
        )
        atomic_write_json(status_report_path, status_payload)

    finally:
        if process_record is not None:
            backend_state_after = stop_owned_process(
                process_record,
                grace_s=10.0,
            ).value
        if process is not None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    final_source_report = verify_source_freeze(config)
    final_report = {
        "schema": "weall.m3.replay-status-run.v2",
        "status": "passed",
        "started_at_unix_ms": started_at,
        "completed_at_unix_ms": int(time.time() * 1000),
        "config_fingerprint": config.fingerprint,
        "source_freeze": final_source_report,
        "transcript": str(transcript_path),
        "transcript_sha256": sha256_file(transcript_path),
        "transcript_fingerprint": transcript.fingerprint,
        "database_snapshot": snapshot_report,
        "backend_url": config.backend_url,
        "backend_process_record": str(process_record_path),
        "backend_log": str(backend_log),
        "backend_state_after": backend_state_after,
        "ballot_profile_report": str(ballot_report_path),
        "status_verification_report": str(status_report_path),
        "repository_modified": False,
        "preserved_database_modified": False,
        "ok": True,
    }
    atomic_write_json(final_report_path, final_report)

    store = ReceiptStore(receipt_root)
    receipt = store.create_passed(
        stage="replay-status",
        input_fingerprint=config.fingerprint,
        started_at_unix_ms=started_at,
        output_paths=[
            source_report_path,
            transcript_path,
            snapshot_report_path,
            ballot_report_path,
            status_report_path,
            final_report_path,
        ],
        metadata={
            "backend_state_after": backend_state_after,
            "action_count": len(transcript.actions),
            "negative_attempt_count": len(transcript.negative_attempts),
        },
    )

    return {
        "schema": "weall.m3.replay-status-command.v2",
        "status": "passed",
        "output_root": str(config.output_root),
        "backend_state_after": backend_state_after,
        "status_verification_report": str(status_report_path),
        "final_report": str(final_report_path),
        "receipt": receipt.to_json(),
        "ok": True,
    }


def config_from_mapping(raw: Mapping[str, Any]) -> ReplayStatusConfig:
    required = (
        "source_repo",
        "source_branch",
        "implementation_freeze_commit",
        "implementation_tree",
        "historical_freeze_commit",
        "evidence_commit",
        "evidence_transcript_path",
        "preserved_database",
        "output_root",
    )
    missing = [key for key in required if key not in raw]
    if missing:
        raise ContractError(f"replay_config_missing:{missing}")

    return ReplayStatusConfig(
        source_repo=Path(str(raw["source_repo"])).expanduser().resolve(),
        source_branch=str(raw["source_branch"]),
        implementation_freeze_commit=str(raw["implementation_freeze_commit"]),
        implementation_tree=str(raw["implementation_tree"]),
        historical_freeze_commit=str(raw["historical_freeze_commit"]),
        evidence_commit=str(raw["evidence_commit"]),
        evidence_transcript_path=str(raw["evidence_transcript_path"]),
        preserved_database=Path(
            str(raw["preserved_database"])
        ).expanduser().resolve(),
        output_root=Path(str(raw["output_root"])).expanduser().resolve(),
        backend_host=str(raw.get("backend_host") or "127.0.0.1"),
        backend_port=int(raw.get("backend_port") or 18411),
        ballot_profile_id=str(
            raw.get("ballot_profile_id")
            or "controlled-testnet-aggregate-v1"
        ),
        minimum_request_interval_s=float(
            raw.get("minimum_request_interval_s", 0.35)
        ),
        max_request_attempts=int(raw.get("max_request_attempts", 10)),
        retry_base_delay_s=float(raw.get("retry_base_delay_s", 0.5)),
        retry_max_delay_s=float(raw.get("retry_max_delay_s", 30.0)),
        request_timeout_s=float(raw.get("request_timeout_s", 15.0)),
    )


def load_replay_status_config(path: str | Path) -> ReplayStatusConfig:
    source = Path(path).resolve()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"replay_config_unreadable:{source}") from exc
    if not isinstance(raw, Mapping):
        raise ContractError("replay_config_not_object")
    return config_from_mapping(raw)
