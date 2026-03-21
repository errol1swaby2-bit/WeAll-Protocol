from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.replay_consistency import build_sample_chain


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_replay_consistency_audit_direct_runner_is_green_batch93(tmp_path: Path) -> None:
    summary = build_sample_chain(
        work_dir=str(tmp_path / "direct"),
        chain_id_prefix="batch93-direct",
    )
    assert summary["ok"] is True
    assert summary["issues"] == []
    assert summary["source_manifest"] == summary["replay_manifest"]
    assert summary["source_manifest"]["height"] == 3


def test_replay_consistency_audit_cli_is_green_batch93(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "replay_consistency_audit.py"),
            "--work-dir",
            str(tmp_path / "cli"),
            "--chain-id-prefix",
            "batch93-cli",
            "--json",
        ],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["issues"] == []
    assert payload["source_manifest"] == payload["replay_manifest"]
