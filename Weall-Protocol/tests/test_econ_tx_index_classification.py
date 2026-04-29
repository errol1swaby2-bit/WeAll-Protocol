from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.econ_phase import is_economic_system_tx, is_economic_user_tx


def _repo_root() -> Path:
    # tests/ -> repo_root
    return Path(__file__).resolve().parents[1]


def _load_tx_types() -> list[dict]:
    path = _repo_root() / "generated" / "tx_index.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    tx_types = raw.get("tx_types")
    assert isinstance(tx_types, list)
    return tx_types


_ECON_DOMAINS = {"Economics", "Treasury", "Rewards"}


@pytest.mark.parametrize("entry", _load_tx_types())
def test_econ_classification_matches_tx_index(entry: dict) -> None:
    name = str(entry.get("name") or "").strip().upper()
    domain = str(entry.get("domain") or "").strip()
    ctx = str(entry.get("context") or "").strip().lower()
    receipt_only = bool(entry.get("receipt_only", False))

    if not name:
        return

    in_econ = domain in _ECON_DOMAINS

    if not in_econ:
        assert is_economic_user_tx(name) is False
        assert is_economic_system_tx(name) is False
        return

    if ctx == "user":
        assert is_economic_user_tx(name) is True
        # user-context txs should not be classified as system economic
        assert is_economic_system_tx(name) is False
        return

    # Non-user contexts in economic domains should classify as system econ.
    assert is_economic_user_tx(name) is False
    assert is_economic_system_tx(name) is True

    # If canon marks it receipt-only, it must also be system econ.
    if receipt_only:
        assert is_economic_system_tx(name) is True
