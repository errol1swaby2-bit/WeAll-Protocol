from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
SCRIPT = BACKEND / "scripts" / "generate_tx_coverage_report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_tx_coverage_report", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_tx_index_shape_produces_nonempty_canonical_report(tmp_path):
    module = _load_module()
    out = tmp_path / "tx_coverage_report.md"

    assert module.main(["--out", str(out)]) == 0

    text = out.read_text(encoding="utf-8")
    tx_index = json.loads((BACKEND / "generated" / "tx_index.json").read_text(encoding="utf-8"))
    expected = len(tx_index["tx_types"])
    assert expected > 0
    assert f"- total tx types: **{expected}**" in text
    assert "- total tx types: **0**" not in text
    assert sum(1 for line in text.splitlines() if line.startswith("| `")) == expected


def test_current_tx_index_shape_rejects_mismatched_lookup_maps():
    module = _load_module()
    idx = {
        "tx_types": [{"name": "ACCOUNT_REGISTER"}],
        "by_name": {"ACCOUNT_REGISTER": 1},
        "by_id": {"1": 0},
    }

    with pytest.raises(SystemExit, match="by_name mismatch"):
        module._tx_records(idx)
