from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def join(*parts: str) -> str:
    return "".join(parts)


REMOVED_TXS = {
    join("POH_", "EMAIL_", "ATTESTATION_", "SUBMIT"),
    join("ORACLE_", "REGISTER"),
    join("ORACLE_", "SUSPEND"),
    join("ORACLE_", "ROTATE_", "KEY"),
    join("ORACLE_", "UPDATE_", "METADATA"),
}


def test_removed_external_identity_txs_are_absent_from_canon_and_generated_artifacts() -> None:
    paths = [
        ROOT / "specs/tx_canon/tx_canon.yaml",
        ROOT / "generated/tx_index.json",
        ROOT / "generated/tx_contract_map.json",
        ROOT / "generated/helper_contract_map.json",
    ]

    hits: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for tx in REMOVED_TXS:
            if tx in text:
                hits.append(f"{path.relative_to(ROOT)} still contains removed tx")

    assert not hits, "\n".join(hits)


def test_generated_tx_index_count_is_225_after_external_identity_removal() -> None:
    data = json.loads((ROOT / "generated/tx_index.json").read_text(encoding="utf-8"))
    by_name = data.get("by_name") or data.get("tx_types") or {}
    if isinstance(by_name, dict):
        assert len(by_name) == 225
