"""PR73 canonical ACCOUNT_BAN duplicate comparison with bounded rollback.

Synthetic domain/canonical-application tests, not authenticated SYSTEM receipts,
real-chain replay, BFT convergence, migration approval, or V2 semantic acceptance.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_apply import (
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.errors import ApplyError
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


def _state() -> dict:
    return {
        "params": {},
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": "0",
                "reputation_milli": 0,
                "balance": 0,
                "keys": [],
            }
        },
    }


def _tx(payload: dict, *, nonce: int = 7) -> TxEnvelope:
    return TxEnvelope(
        tx_type="ACCOUNT_BAN",
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        system=True,
        parent="stage10:synthetic-parent",
        sig="synthetic-not-authenticated",
    )


def _payload() -> dict:
    return {
        "account_id": "@alice",
        "reason": "original",
        "source": {"dispute": "fixture", "evidence": [{"key": "nested", "value": 1}]},
    }


def _banned_state(payload: dict | None = None) -> dict:
    state = _state()
    created = apply_tx_atomic_meta(state, _tx(payload or _payload()))
    assert created == {"applied": "ACCOUNT_BAN", "account_id": "@alice", "deduped": False}
    assert state["accounts"]["@alice"]["banned"] is True
    return state


def test_duplicate_account_ban_is_canonical_noop_with_nested_payload() -> None:
    payload = _payload()
    state = _banned_state(payload)
    before = copy.deepcopy(state)
    prior_root = compute_state_root(state)

    repeated = apply_tx_atomic_meta(state, _tx(copy.deepcopy(payload)))

    assert repeated == {"applied": "ACCOUNT_BAN", "account_id": "@alice", "deduped": True}
    assert state == before
    assert compute_state_root(state) == prior_root


def test_bounded_journal_and_deepcopy_oracle_agree_for_identical_duplicate() -> None:
    state = _banned_state()
    bounded_state = copy.deepcopy(state)
    deepcopy_state = copy.deepcopy(state)

    bounded = apply_tx_atomic_meta(bounded_state, _tx(_payload()))
    oracle = apply_tx_atomic_meta_deepcopy(deepcopy_state, _tx(_payload()))

    assert bounded == oracle
    assert bounded_state == deepcopy_state == state
    assert compute_state_root(bounded_state) == compute_state_root(deepcopy_state)


@pytest.mark.parametrize("apply", [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy])
def test_conflicting_duplicate_rejected_atomically(apply) -> None:
    state = _banned_state()
    before = copy.deepcopy(state)
    old_root = compute_state_root(state)
    changed = _payload()
    changed["reason"] = "rewritten"

    with pytest.raises(ApplyError) as error:
        apply(state, _tx(changed))

    assert error.value.code == "conflicting_receipt"
    assert error.value.reason == "duplicate_ban_receipt_conflict"
    assert state == before
    assert compute_state_root(state) == old_root


@pytest.mark.parametrize("apply", [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy])
def test_conflicting_nested_payload_rejected_atomically(apply) -> None:
    state = _banned_state()
    before = copy.deepcopy(state)
    old_root = compute_state_root(state)
    changed = _payload()
    changed["source"]["evidence"][0]["value"] = 2

    with pytest.raises(ApplyError) as error:
        apply(state, _tx(changed))

    assert error.value.reason == "duplicate_ban_receipt_conflict"
    assert state == before
    assert compute_state_root(state) == old_root


def test_missing_account_id_rejects_without_mutating_canonical_state() -> None:
    state = _state()
    before = copy.deepcopy(state)
    old_root = compute_state_root(state)

    with pytest.raises(ApplyError) as error:
        apply_tx_atomic_meta(state, _tx({"reason": "missing-target"}))

    assert error.value.reason == "missing_account_id"
    assert state == before
    assert compute_state_root(state) == old_root
