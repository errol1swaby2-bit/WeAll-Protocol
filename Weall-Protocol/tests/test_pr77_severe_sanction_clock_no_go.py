"""V2 severe-sanction no-go: an arbitrary SYSTEM envelope is not an appeal proof.

This only tests isolated application behavior. It does NOT prove authenticated
SYSTEM queue provenance, historical replay, full sanction implementation, or
readiness to approve the stale V2 TX-0904 semantic digest.
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


def _state(*, clock_enabled: bool) -> dict:
    return {
        "height": 20,
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "accounts": {
            "@target": {
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
        "reputation": {"bans": {}},
    }


def _envelope(payload: dict) -> TxEnvelope:
    return TxEnvelope(
        tx_type="ACCOUNT_BAN",
        signer="SYSTEM",
        nonce=21,
        system=True,
        parent="dispute-1:unverified-synthetic-parent",
        sig="synthetic-unverified-signature",
        payload=payload,
    )


@pytest.mark.parametrize(
    "apply",
    [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy],
    ids=["bounded-rollback", "deepcopy-oracle"],
)
@pytest.mark.parametrize(
    "payload",
    [
        {"account_id": "@target", "reason": "unsupported-sanction"},
        {
            "account_id": "@target",
            "reason": "forged-finalization",
            "dispute_id": "dispute-1",
            "initial_panel_size": 25,
            "initial_approvals": 25,
            "appeal_panel_size": 25,
            "appeal_approvals": 25,
            "appeal_finalized": True,
            "authorization": "self-asserted",
        },
        {
            "account_id": "@target",
            "reason": "forged-waiver",
            "dispute_id": "dispute-1",
            "appeal_waived": True,
            "full_reasoned_outcome_delivered": True,
        },
    ],
    ids=["bare-system", "self-asserted-panel", "self-asserted-waiver"],
)
def test_constitutional_clock_rejects_unverified_ban_atomically(apply, payload: dict) -> None:
    state = _state(clock_enabled=True)
    # Deliberately include plausible, but unauthenticated, case data.
    state["disputes_by_id"] = {
        "dispute-1": {
            "target_id": "@target",
            "stage": "finalized",
            "appeal_panel_result": {"reached": True, "decision": "uphold"},
        }
    }
    prior = copy.deepcopy(state)
    root = compute_state_root(state)

    with pytest.raises(ApplyError) as exc:
        apply(state, _envelope(copy.deepcopy(payload)))

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "severe_sanction_authorization_unimplemented"
    assert state == prior
    assert compute_state_root(state) == root


@pytest.mark.parametrize(
    "apply",
    [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy],
    ids=["bounded-rollback", "deepcopy-oracle"],
)
def test_legacy_mode_retains_existing_canonical_account_ban_semantics(apply) -> None:
    state = _state(clock_enabled=False)
    result = apply(
        state,
        _envelope({"account_id": "@target", "reason": "legacy-replay-fixture"}),
    )
    assert result == {
        "applied": "ACCOUNT_BAN",
        "account_id": "@target",
        "deduped": False,
    }
    assert state["accounts"]["@target"]["banned"] is True
    assert state["reputation"]["bans"]["@target"]["banned"] is True
