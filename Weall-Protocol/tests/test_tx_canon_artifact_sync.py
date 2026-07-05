from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_generated_tx_canon_artifacts_are_synchronized() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/check_tx_canon_artifacts.py"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "236 tx types" in result.stdout
