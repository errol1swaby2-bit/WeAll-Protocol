"""CASE canonical admission/atomicity diagnostics — NO consensus semantic approval.

The direct-handler reproductions are separate: this module checks the actual
canonical admission, bounded journal and deepcopy oracle. Successful duplicate
binding is deliberately classified as a known receipt/state HOLD, not success.
No trusted identity or queue origin is inferred from synthetic SYSTEM markers.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.block_admission import admit_block_txs
from weall.runtime.domain_apply import (
    ApplyError,
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json

INDEX = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"


def _canon():
    return load_tx_index_json(INDEX)


def _state() -> dict:
    return {
        "height": 0,
        "chain_id": "case-audit-testnet",
        "params": {"system_signer": "SYSTEM"},
        "accounts": {},
    }


def _env(
    tx_type: str,
    payload: dict,
    *,
    nonce: int = 0,
    signer: str = "SYSTEM",
    system: bool = True,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        system=system,
        parent=parent,
        chain_id="case-audit-testnet",
        payload=copy.deepcopy(payload),
    )


@pytest.mark.parametrize(
    "tx_type,payload",
    [
        ("CASE_TYPE_REGISTER", {"case_type": "audit"}),
        ("CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "dispute-a"}),
    ],
)
def test_public_ingress_refuses_unqueued_system_case(tx_type: str, payload: dict) -> None:
    state = _state()
    original = copy.deepcopy(state)
    forged = _env(tx_type, payload)
    for context in ("http", "mempool", "gossip", "operator"):
        verdict = admit_tx(forged, state, canon=_canon(), context=context)
        assert verdict.ok is False
        assert verdict.code == "system_tx_forbidden"
        assert verdict.reason == "system_only_tx_not_allowed_in_public_ingress"
        assert state == original


@pytest.mark.parametrize(
    "tx_type,payload",
    [
        ("CASE_TYPE_REGISTER", {}),
        ("CASE_BIND_TO_DISPUTE", {}),
    ],
)
def test_canonical_block_admission_rejects_missing_case_required_fields(
    tx_type: str, payload: dict
) -> None:
    state = _state()
    original = copy.deepcopy(state)
    env = _env(tx_type, payload)
    verdict = admit_tx(env, state, canon=_canon(), context="block")
    assert verdict.ok is False
    assert verdict.code == "invalid_payload"
    assert state == original

    _, _, rejects = admit_block_txs(
        [env], LedgerView.from_ledger(state), _canon(), verify_signatures=True
    )
    assert len(rejects) == 1
    assert rejects[0] is not None
    assert rejects[0].code == "invalid_payload"
    assert state == original


@pytest.mark.parametrize(
    "tx_type,reason",
    [
        ("CASE_TYPE_REGISTER", "missing_case_type"),
        ("CASE_BIND_TO_DISPUTE", "missing_dispute_id"),
    ],
)
def test_case_reject_is_atomic_in_bounded_journal_and_deepcopy_oracle(
    tx_type: str, reason: str
) -> None:
    env = _env(tx_type, {})
    baseline = _state()
    for apply_fn in (
        apply_tx_atomic_meta_bounded_rollback,
        apply_tx_atomic_meta_deepcopy,
    ):
        state = copy.deepcopy(baseline)
        before_root = compute_state_root(state)
        with pytest.raises(ApplyError) as failure:
            apply_fn(state, env, consume_nonce_on_fail=False)
        assert (failure.value.code, failure.value.reason) == ("invalid_payload", reason)
        assert state == baseline
        assert compute_state_root(state) == before_root


def test_conflicting_duplicate_case_binding_same_outcome_in_both_atomic_executors() -> None:
    """Known HOLD: success receipt does not reflect the first-write-wins state."""
    first = _env("CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "dispute-1"})
    conflict = _env(
        "CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "dispute-2"}
    )
    observations = []
    for apply_fn in (
        apply_tx_atomic_meta_bounded_rollback,
        apply_tx_atomic_meta_deepcopy,
    ):
        state = _state()
        receipt1 = apply_fn(state, first)
        receipt2 = apply_fn(state, conflict)
        bound = state["cases"]["bindings"]["case-a"]["dispute_id"]
        assert receipt1["dispute_id"] == bound == "dispute-1"
        assert receipt2["receipt"] is True
        assert receipt2["dispute_id"] == "dispute-2"
        assert receipt2["dispute_id"] != bound
        observations.append((copy.deepcopy(state), receipt1, receipt2, compute_state_root(state)))
    assert observations[0] == observations[1]


def test_forged_case_system_queue_parent_and_payload_are_rejected() -> None:
    state = _state()
    state["system_queue"] = []
    enqueue_system_tx(
        state,
        tx_type="CASE_BIND_TO_DISPUTE",
        payload={"case_id": "case-a", "dispute_id": "dispute-1"},
        due_height=1,
        signer="SYSTEM",
        parent="case-authorized-parent",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon=_canon(), next_height=1, phase="post")
    items = [e for e in emitted if e.tx_type == "CASE_BIND_TO_DISPUTE"]
    assert len(items) == 1
    genuine = items[0]
    assert genuine.system and genuine.nonce == 0

    ok, reason = validate_system_tx_queue_binding(
        state, _canon(), genuine, next_height=1, phase="post"
    )
    assert ok, reason

    for parent, payload, expected in (
        ("case-forged-parent", dict(genuine.payload), "system_queue_parent_mismatch"),
        (
            genuine.parent,
            {**genuine.payload, "dispute_id": "dispute-forged"},
            "system_queue_payload_mismatch",
        ),
    ):
        forged = _env(
            genuine.tx_type,
            payload,
            parent=parent,
        )
        ok, reason = validate_system_tx_queue_binding(
            state, _canon(), forged, next_height=1, phase="post"
        )
        assert not ok and reason == expected
