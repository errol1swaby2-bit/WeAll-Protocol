from __future__ import annotations

import json
from pathlib import Path

import yaml

from weall.runtime.system_tx_engine import (
    build_system_queue_lookup,
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.tx.canon import TxIndex

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "DISPUTE_JUROR_ASSIGN": ["DISPUTE_OPEN", "CONTENT_ESCALATE_TO_DISPUTE"],
    "ACCOUNT_RECOVERY_RECEIPT": [
        "ACCOUNT_RECOVERY_FINALIZE",
        "ACCOUNT_RECOVERY_REQUEST",
    ],
}


def _read_json(relative: str) -> dict:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_canon_and_generated_index_expose_multi_causal_parent_types() -> None:
    canon_rows = yaml.safe_load(
        (ROOT / "specs/tx_canon/tx_canon.yaml").read_text(encoding="utf-8")
    )["txs"]
    by_name = {str(row["name"]): row for row in canon_rows}
    index = TxIndex.load_from_file(ROOT / "generated/tx_index.json")

    for tx_type, parents in EXPECTED.items():
        row = by_name[tx_type]
        assert row["parent"] == parents[0]
        assert row["parent_any_of"] == parents
        got = index.get(tx_type) or {}
        assert got["parent_tx_type"] == parents[0]
        assert got["parent_tx_types"] == parents


def test_v2_multi_causal_receipts_do_not_claim_single_parent_replay() -> None:
    matrix = _read_json("generated/v2/tx_contract_matrix.json")
    receipt_index = _read_json("generated/v2/receipt_contract_index.json")
    tx_rows = {row["tx_type"]: row for row in matrix["rows"]}
    receipt_rows = {row["tx_type"]: row for row in receipt_index["rows"]}

    for tx_type, parents in EXPECTED.items():
        tx = tx_rows[tx_type]
        receipt = tx["receipt_contract"]
        assert tx["authority"] == "canonical_scheduler_system_authority"
        assert tx["replay_behavior"] == (
            "block_only_system_queue_bound_multi_causal_deterministic_replay"
        )
        assert receipt["kind"] == "receipt_only_multi_causal_scheduler_bound"
        assert receipt["parent"] == parents[0]
        assert receipt["parents"] == parents
        assert receipt["binding"] == "deterministic_system_queue_multi_causal_context"

        indexed = receipt_rows[tx_type]
        assert indexed["parent"] == parents[0]
        assert indexed["parents"] == parents
        assert indexed["binding"] == "deterministic_system_queue_multi_causal_context"
        assert indexed["replay_binding"] == (
            "block_only_system_queue_bound_multi_causal_deterministic_replay"
        )


def test_runtime_queue_binding_accepts_declared_alternate_causal_contexts() -> None:
    index = TxIndex.load_from_file(ROOT / "generated/tx_index.json")
    cases = (
        (
            "DISPUTE_JUROR_ASSIGN",
            "CONTENT_ESCALATE_TO_DISPUTE",
            "post",
            {"dispute_id": "d1", "juror": "juror1"},
        ),
        (
            "ACCOUNT_RECOVERY_RECEIPT",
            "ACCOUNT_RECOVERY_REQUEST",
            "pre",
            {"request_id": "r1", "status": "expired"},
        ),
    )
    for tx_type, alternate_parent, phase, payload in cases:
        canon = index.get(tx_type) or {}
        assert canon["parent_tx_type"] != alternate_parent
        assert alternate_parent in canon["parent_tx_types"]

        state = {
            "height": 0,
            "params": {"system_signer": "SYSTEM"},
            "system_queue": [],
        }
        enqueue_system_tx(
            state,
            tx_type=tx_type,
            payload=payload,
            due_height=1,
            signer="SYSTEM",
            once=True,
            parent=alternate_parent,
            phase=phase,
        )
        emitted = system_tx_emitter(state, index, next_height=1, phase=phase)
        assert len(emitted) == 1
        assert emitted[0].parent == alternate_parent
        ok, reason = validate_system_tx_queue_binding(
            state,
            index,
            emitted[0],
            next_height=1,
            phase=phase,
            queue_objects_by_id=build_system_queue_lookup(state),
        )
        assert (ok, reason) == (True, "")
