from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "devnet_tx.py"


def test_devnet_tx_ensure_keyfile_creates_reusable_key_material(tmp_path: Path) -> None:
    keyfile = tmp_path / "devnet-account.json"

    first = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "ensure-keyfile",
            "--account",
            "@devnet-smoke",
            "--keyfile",
            str(keyfile),
        ],
        cwd=str(ROOT),
        check=True,
        text=True,
        capture_output=True,
    )
    first_payload = json.loads(first.stdout)
    assert first_payload["ok"] is True
    assert first_payload["account"] == "@devnet-smoke"
    assert first_payload["keyfile"] == str(keyfile)
    assert "private_key_hex" not in first_payload
    assert len(first_payload["public_key_hex"]) == 3904

    stored = json.loads(keyfile.read_text(encoding="utf-8"))
    assert stored["account"] == "@devnet-smoke"
    assert len(stored["private_key_hex"]) == 64
    assert stored["public_key_hex"] == first_payload["public_key_hex"]

    second = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "ensure-keyfile",
            "--account",
            "@devnet-smoke",
            "--keyfile",
            str(keyfile),
        ],
        cwd=str(ROOT),
        check=True,
        text=True,
        capture_output=True,
    )
    second_payload = json.loads(second.stdout)
    assert second_payload["public_key_hex"] == first_payload["public_key_hex"]
