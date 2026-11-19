"""PR77 characterization of inline account reinstatement's ban-index divergence.

Synthetic full-transaction execution is NOT a provenance, appeal-authority,
historical replay, or network exploitability proof.  These tests document the
current behavior without changing or approving consensus semantics.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.reputation import apply_reputation
from weall.runtime.domain_apply import apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy
from weall.runtime.errors import ApplyError
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_contracts import handler_claims_for_tx_type, handler_name_for_tx_type


def _state(*, clock_enabled: bool) -> dict:
    return {
        "height": 20,
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "accounts": {
            "@target": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": True,
                "locked": True,
                "restricted": True,
                "latest_restriction": "synthetic",
                "reputation_milli": -100000,
                "reputation": "-100",
                "balance": 0,
                "keys": [],
            }
        },
        "reputation": {
            "bans": {
                "@target": {
                    "account_id": "@target",
                    "banned": True,
                    "set_at_nonce": 12,
                    "reason": "synthetic_reputation_floor",
                    "payload": {"delta_milli": -100000},
                    "auto": True,
                }
            },
        },
        "disputes_by_id": {
            "d-remedy": {
                "id": "d-remedy",
                "target_type": "account",
                "target_id": "@target",
                "stage": "appealed",
                "appeals": [{"by": "@target"}],
                "assigned_jurors": [],
                "votes": {},
                "resolution": {
                    "summary": "original synthetic restriction",
                    "actions": [
                        {
                            "tx_type": "ACCOUNT_RESTRICTION_SET",
                            "payload": {"account_id": "@target", "restriction": "synthetic"},
                        }
                    ],
                },
            }
        },
    }


def _final_receipt() -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        nonce=21,
        system=True,
        parent="synthetic:dispute-resolve-parent",
        sig="synthetic-not-authenticated",
        payload={
            "dispute_id": "d-remedy",
            "receipt_id": "pr77:reinstatement-consistency",
            "appeal_resolution": {
                "decision": "modify",
                "actions": [
                    {
                        "tx_type": "ACCOUNT_REINSTATE",
                        "payload": {"account_id": "@target", "reason": "synthetic_appeal_remedy"},
                    }
                ],
            },
        },
    )


def test_legacy_final_receipt_inline_reinstate_leaves_active_ban_index() -> None:
    """Historical legacy full-TX path leaves ban-index divergence for review."""
    original = _state(clock_enabled=False)
    bounded = copy.deepcopy(original)
    reference = copy.deepcopy(original)

    bounded_result = apply_tx_atomic_meta(bounded, _final_receipt())
    reference_result = apply_tx_atomic_meta_deepcopy(reference, _final_receipt())

    assert bounded_result == reference_result
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)
    assert bounded_result["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert any(
        action.get("tx_type") == "ACCOUNT_REINSTATE"
        for action in bounded_result["enforcement_applied"]
    )
    assert bounded["accounts"]["@target"]["banned"] is False
    assert bounded["accounts"]["@target"]["locked"] is False
    assert bounded["accounts"]["@target"]["restricted"] is False
    assert bounded["reputation"]["bans"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["auto"] is True


@pytest.mark.parametrize(
    "applier",
    [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy],
    ids=["bounded-atomic", "reference-deepcopy"],
)
def test_constitutional_unverified_appeal_receipt_rejected_atomically(applier) -> None:
    """An unresolved synthetic appeal cannot supply its own final decision."""
    state = _state(clock_enabled=True)
    before = copy.deepcopy(state)
    with pytest.raises(ApplyError) as exc:
        applier(state, _final_receipt())
    assert exc.value.reason == "appeal_panel_decision_not_finalized"
    assert state == before
    assert state["reputation"]["bans"]["@target"]["banned"] is True
    assert state["accounts"]["@target"]["banned"] is True


def test_canonical_reputation_reinstate_also_updates_ban_index() -> None:
    """Distinct direct applier path updates both state surfaces."""
    state = _state(clock_enabled=False)
    result = apply_reputation(
        state,
        TxEnvelope(
            tx_type="ACCOUNT_REINSTATE",
            signer="SYSTEM",
            nonce=21,
            system=True,
            parent="synthetic:dispute-resolve-parent",
            sig="synthetic-not-authenticated",
            payload={"account_id": "@target", "reason": "synthetic_appeal_remedy"},
        ),
    )
    assert result["applied"] == "ACCOUNT_REINSTATE"
    assert state["accounts"]["@target"]["banned"] is False
    assert state["reputation"]["bans"]["@target"]["banned"] is False


def test_account_ban_canonical_handler_is_reputation_not_legacy_identity() -> None:
    """The identity module contains an old function but is not its canon route."""
    assert handler_claims_for_tx_type("ACCOUNT_BAN") == ["reputation"]
    assert handler_name_for_tx_type("ACCOUNT_BAN") == "reputation"


def test_legacy_synthetic_reputation_delta_can_reban_after_inline_reinstatement() -> None:
    """A zero delta at the -100 floor revives exclusion after a remedy.

    This is an executor-only synthetic chain, NOT proof of an authenticated
    reputation-delta SYSTEM producer, constitutional ban, or live exploit.
    """
    seed = _state(clock_enabled=False)
    bounded = copy.deepcopy(seed)
    reference = copy.deepcopy(seed)
    apply_tx_atomic_meta(bounded, _final_receipt())
    apply_tx_atomic_meta_deepcopy(reference, _final_receipt())

    assert bounded["accounts"]["@target"]["banned"] is False
    assert bounded["reputation"]["bans"]["@target"]["banned"] is True

    delta = TxEnvelope(
        tx_type="REPUTATION_DELTA_APPLY",
        signer="SYSTEM",
        nonce=22,
        system=True,
        parent="synthetic:unverified-delta-parent",
        sig="synthetic-not-authenticated",
        payload={
            "account_id": "@target",
            "delta_milli": 0,
            "delta_id": "pr77:synthetic-reban-after-reinstatement",
            "reason": "synthetic_zero_delta",
        },
    )
    bounded_result = apply_tx_atomic_meta(bounded, delta)
    reference_result = apply_tx_atomic_meta_deepcopy(reference, delta)

    assert bounded_result == reference_result
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)
    assert bounded_result["newly_banned"] is True
    assert bounded["accounts"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["set_at_nonce"] == 22
