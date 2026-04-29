# tests/test_smoke.py
from __future__ import annotations

from pathlib import Path

from weall.tx.canon import load_tx_index_json


def test_imports_smoke() -> None:
    # If this test runs, basic imports and pythonpath are working.
    assert True


def test_canon_index_loads() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    assert canon_path.exists(), f"Missing canon artifact at {canon_path}"

    idx = load_tx_index_json(canon_path)
    assert idx.tx_types, "Canon index should contain tx types"
    assert idx.by_name, "Canon index should have by_name mapping"
    assert idx.by_id, "Canon index should have by_id mapping"
