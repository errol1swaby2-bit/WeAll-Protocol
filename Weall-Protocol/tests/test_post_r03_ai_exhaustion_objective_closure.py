from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from weall.runtime.domain_dispatch import _enforce_apply_time_canon, apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.lineage_witness import make_single_tx_witness
from weall.runtime.system_tx_engine import (
    build_system_queue_lookup,
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_schema import validate_tx_envelope
from weall.tx.canon import TxIndex

ROOT = Path(__file__).resolve().parents[1]


def _index() -> TxIndex:
    return TxIndex.load_from_file(ROOT / "generated" / "tx_index.json")


def _state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "SYSTEM": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "params": {"system_signer": "SYSTEM"},
    }


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> dict:
    env = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "system": system,
        "sig": "deadbeef",
    }
    if parent is not None:
        env["parent"] = parent
    validate_tx_envelope(env)
    return env


def test_generated_tx_index_preserves_parent_type_without_activating_stale_reputation() -> None:
    canon = yaml.safe_load((ROOT / "specs" / "tx_canon" / "tx_canon.yaml").read_text())["txs"]
    index = _index()

    for row in canon:
        got = index.get(row["name"]) or {}
        assert got["domain"] == row["domain"]
        assert got["origin"] == row["origin"]
        assert got["context"] == row["context"]
        assert bool(got.get("receipt_only", False)) is bool(row.get("receipt_only", False))
        assert str(got.get("subject_gate") or "") == str(row.get("gate") or "")
        assert str(got.get("parent_tx_type") or "") == str(row.get("parent") or "")
        assert "parent" not in got
        assert bool(got.get("system_only", False)) is bool(row.get("system_only", False))
        assert bool(got.get("via_gov_execute", False)) is bool(row.get("via_gov_execute", False))

    for name in (
        "CONTENT_POST_CREATE",
        "CONTENT_POST_EDIT",
        "CONTENT_POST_DELETE",
        "CONTENT_COMMENT_CREATE",
    ):
        assert "min_reputation" not in (index.get(name) or {})


def test_parent_tx_type_metadata_does_not_become_direct_apply_parent_reference() -> None:
    state = {"params": {"system_signer": "SYSTEM"}}
    env = {
        "tx_type": "VALIDATOR_REGISTER",
        "signer": "SYSTEM",
        "nonce": 0,
        "payload": {},
        "sig": "",
        "system": True,
    }
    _enforce_apply_time_canon(state, env)


def test_system_emitter_does_not_synthesize_parent_ref_from_parent_tx_type() -> None:
    state = {"height": 0, "params": {"system_signer": "SYSTEM"}, "system_queue": []}
    canon = _index()
    assert (canon.get("EPOCH_OPEN") or {}).get("parent_tx_type") == "BLOCK_FINALIZE"
    enqueue_system_tx(
        state, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=1, phase="post", parent=None
    )
    emitted = system_tx_emitter(state, canon, next_height=1, phase="post")
    assert len(emitted) == 1
    assert emitted[0].parent is None
    assert "_parent_ref" not in emitted[0].payload


def test_system_queue_binding_validates_explicit_concrete_parent_reference() -> None:
    state = {"height": 0, "params": {"system_signer": "SYSTEM"}, "system_queue": []}
    canon = _index()
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={
            "epoch": 1,
            "_lineage_witness": make_single_tx_witness(
                parent_tx_type="BLOCK_FINALIZE",
                parent_tx_id="tx:" + "a" * 64,
                same_block_position=0,
            ).to_json(),
        },
        due_height=1,
        phase="post",
        parent="block:finalize:0001",
    )
    emitted = system_tx_emitter(state, canon, next_height=1, phase="post")
    assert len(emitted) == 1
    assert emitted[0].parent == "block:finalize:0001"
    ok, why = validate_system_tx_queue_binding(
        state,
        canon,
        emitted[0],
        next_height=1,
        phase="post",
        queue_objects_by_id=build_system_queue_lookup(state),
    )
    assert (ok, why) == (True, "")
    tampered = emitted[0].model_copy(update={"parent": None})
    ok, why = validate_system_tx_queue_binding(
        state,
        canon,
        tampered,
        next_height=1,
        phase="post",
        queue_objects_by_id=build_system_queue_lookup(state),
    )
    assert ok is False
    assert why == "system_queue_parent_mismatch"


def test_tier2_receipt_fails_closed_for_missing_or_nonfinalized_case() -> None:
    state = _state()
    with pytest.raises(ApplyError) as missing:
        apply_tx(
            state,
            _env(
                "POH_TIER2_RECEIPT",
                "SYSTEM",
                0,
                {"case_id": "missing", "receipt_id": "r1"},
                system=True,
                parent="POH_TIER2_FINALIZE",
            ),
        )
    assert missing.value.reason == "tier2_case_not_found"

    state = _state()
    state["poh"] = {"tier2_cases": {"c1": {"status": "under_review"}}}
    with pytest.raises(ApplyError) as unfinished:
        apply_tx(
            state,
            _env(
                "POH_TIER2_RECEIPT",
                "SYSTEM",
                0,
                {"case_id": "c1", "receipt_id": "r1"},
                system=True,
                parent="POH_TIER2_FINALIZE",
            ),
        )
    assert unfinished.value.reason == "tier2_case_not_finalized"

    state["poh"]["tier2_cases"]["c1"]["status"] = "awarded"
    out = apply_tx(
        state,
        _env(
            "POH_TIER2_RECEIPT",
            "SYSTEM",
            0,
            {"case_id": "c1", "receipt_id": "r1"},
            system=True,
            parent="POH_TIER2_FINALIZE",
        ),
    )
    assert out["applied"] == "POH_TIER2_RECEIPT"
    assert state["poh"]["tier2_cases"]["c1"]["tier2_receipt_emitted"] is True


def test_live_receipt_fails_closed_for_missing_or_nonfinalized_case() -> None:
    state = _state()
    with pytest.raises(ApplyError) as missing:
        apply_tx(
            state,
            _env(
                "POH_LIVE_RECEIPT",
                "SYSTEM",
                0,
                {"case_id": "missing", "receipt_id": "r1"},
                system=True,
                parent="POH_LIVE_FINALIZE",
            ),
        )
    assert missing.value.reason == "live_case_not_found"

    state = _state()
    state["poh"] = {"live_cases": {"c1": {"status": "under_review"}}}
    with pytest.raises(ApplyError) as unfinished:
        apply_tx(
            state,
            _env(
                "POH_LIVE_RECEIPT",
                "SYSTEM",
                0,
                {"case_id": "c1", "receipt_id": "r1"},
                system=True,
                parent="POH_LIVE_FINALIZE",
            ),
        )
    assert unfinished.value.reason == "live_case_not_finalized"

    state["poh"]["live_cases"]["c1"]["status"] = "rejected"
    out = apply_tx(
        state,
        _env(
            "POH_LIVE_RECEIPT",
            "SYSTEM",
            0,
            {"case_id": "c1", "receipt_id": "r1"},
            system=True,
            parent="POH_LIVE_FINALIZE",
        ),
    )
    assert out["applied"] == "POH_LIVE_RECEIPT"
    assert state["poh"]["live_cases"]["c1"]["live_receipt_emitted"] is True


def test_generic_poh_evidence_bind_requires_declared_evidence() -> None:
    state = _state()
    with pytest.raises(ApplyError) as missing:
        apply_tx(
            state,
            _env(
                "POH_EVIDENCE_BIND",
                "@bob",
                1,
                {"evidence_id": "missing-e", "target_id": "target-1"},
            ),
        )
    assert missing.value.reason == "evidence_not_declared"

    state = _state()
    state["poh"] = {"evidence": {"e1": {"evidence_id": "e1", "payload": {}}}}
    out = apply_tx(
        state,
        _env(
            "POH_EVIDENCE_BIND",
            "@bob",
            1,
            {"evidence_id": "e1", "target_id": "target-1"},
        ),
    )
    rec = state["poh"]["evidence_binds"][out["bind_id"]]
    assert rec["evidence_id"] == "e1"
    assert rec["target_id"] == "target-1"
    assert rec["bound_by"] == "@bob"
