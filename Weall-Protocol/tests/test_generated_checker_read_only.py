from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tx_index_check_mode_is_read_only_for_current_artifact(tmp_path: Path) -> None:
    source = ROOT / "generated" / "tx_index.json"
    target = tmp_path / "tx_index.json"
    target.write_bytes(source.read_bytes())
    before = target.read_bytes()

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/gen_tx_index.py",
            "--check",
            "--out",
            str(target),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert target.read_bytes() == before


def test_tx_index_check_mode_reports_stale_without_rewriting_target(tmp_path: Path) -> None:
    target = tmp_path / "tx_index.json"
    target.write_text('{"stale":true}\n', encoding="utf-8")
    before = target.read_bytes()

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/gen_tx_index.py",
            "--check",
            "--out",
            str(target),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    assert target.read_bytes() == before
