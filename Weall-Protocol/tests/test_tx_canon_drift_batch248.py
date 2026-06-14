from __future__ import annotations

import hashlib
import json
from pathlib import Path

from weall.runtime.tx_conflicts import BarrierClass, TxFamily, build_conflict_descriptor
from weall.runtime.tx_contracts import (
    handler_name_for_tx_type,
    load_default_tx_index,
    noncanon_registry_tx_types,
    tx_contract_summary,
)
from weall.runtime.tx_schema import model_for_tx_type


TX_TYPE = "POH_LIVE_JUROR_REPLACE"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_batch248_live_juror_replace_is_canonical_and_claimed() -> None:
    idx = load_default_tx_index()
    row = idx.get(TX_TYPE)

    assert len(idx.list_types()) == 236
    assert isinstance(row, dict)
    assert row["domain"] == "PoH"
    assert row["origin"] == "SYSTEM"
    assert row["context"] == "block"
    assert row["receipt_only"] is True
    assert row["subject_gate"] == "Juror"

    assert handler_name_for_tx_type(TX_TYPE) == "poh"
    assert TX_TYPE not in noncanon_registry_tx_types(idx)
    assert model_for_tx_type(TX_TYPE) is not None

    summary = tx_contract_summary(idx)
    assert summary["tx_count"] == 236
    assert summary["unclaimed_count"] == 0
    assert summary["single_claim_count"] == 236


def test_batch248_generated_index_matches_canon_source_hash() -> None:
    root = _repo_root()
    spec_path = root / "specs" / "tx_canon" / "tx_canon.yaml"
    index_path = root / "generated" / "tx_index.json"

    raw = json.loads(index_path.read_text(encoding="utf-8"))
    expected_hash = hashlib.sha256(spec_path.read_bytes()).hexdigest()

    assert raw["source_sha256"] == expected_hash
    assert raw["meta"]["version"] == "1.25.0"
    assert raw["by_id"]["129"] == raw["by_name"][TX_TYPE]
    assert raw["tx_types"][raw["by_name"][TX_TYPE]]["name"] == TX_TYPE


def test_batch248_live_juror_replace_conflict_rule_is_poh_authority() -> None:
    desc = build_conflict_descriptor(
        {
            "tx_type": TX_TYPE,
            "signer": "SYSTEM",
            "payload": {
                "case_id": "live-case-1",
                "old_juror_id": "@old",
                "new_juror_id": "@new",
            },
        }
    )

    assert desc.family == TxFamily.POH
    assert desc.barrier_class == BarrierClass.AUTHORITY_BARRIER
    assert "authority:poh" in desc.authority_keys
    assert "poh:application:live-case-1" in desc.write_keys
