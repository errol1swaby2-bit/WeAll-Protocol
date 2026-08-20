from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.tx.canon import CanonError, TxIndex, load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_current_tx_index_numeric_lookup_honors_generated_by_id_map() -> None:
    raw = json.loads(TX_INDEX.read_text(encoding="utf-8"))
    idx = load_tx_index_json(TX_INDEX)

    assert len(idx.by_id) == len(raw["by_id"]) == len(raw["tx_types"])
    for raw_id, pos in raw["by_id"].items():
        expected = raw["tx_types"][pos]
        actual = idx.by_id[int(raw_id)]
        assert actual["name"] == expected["name"]
        assert actual["id"] == expected["id"]

    # Regression sentinel: this ID is intentionally not the 100th list entry.
    assert idx.by_id[100]["name"] == "POH_APPLICATION_SUBMIT"


def test_current_tx_index_rejects_mismatched_lookup_maps() -> None:
    raw = {
        "tx_types": [{"name": "ACCOUNT_REGISTER", "id": "stable"}],
        "by_name": {"ACCOUNT_REGISTER": 1},
        "by_id": {"1": 0},
    }

    with pytest.raises(CanonError, match="by_name.*out of range|by_name.*mismatch"):
        TxIndex.from_raw(raw)


def test_empty_current_tx_index_fixture_remains_supported() -> None:
    idx = TxIndex.from_raw({"tx_types": [], "by_name": {}, "by_id": {}})
    assert idx.tx_types == []
    assert idx.by_name == {}
    assert idx.by_id == {}
