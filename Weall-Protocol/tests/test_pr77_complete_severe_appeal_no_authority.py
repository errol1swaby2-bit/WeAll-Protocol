"""PR77: even a plausibly completed 25/20 + fresh 25/20 appeal is not ACCOUNT_BAN authority.

This is synthetic domain-execution evidence. It contains no independently
authenticated severe classification, juror identities, BFT block finality,
historical role ledger or reviewed semantic digest. It never enables bans.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.domain_apply import apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy
from weall.runtime.errors import ApplyError
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


def _state() -> dict:
    jurors = [f"@juror-{number:03d}" for number in range(90)]
    initial = jurors[:25]
    voters = initial[:20]
    nullifiers = {
        dispute._dispute_ballot_nullifier(
            dispute_id="severe-case", panel_round=1, juror=juror, appeal=False
        ): {"final": True, "panel_round": 1}
        for juror in voters
    }
    role = {
        "active": True,
        "responsibilities": {"reviewer": {"dispute_review": {"active": True, "opted_in": True}}},
    }
    return {
        "height": 11,
        "chain_id": "pr77-synthetic-complete-appeal",
        "meta": {"constitutional_clock": {"enabled": True}},
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
            "experimental_severe_auto_appeal_v0": True,
        },
        "accounts": {
            **{j: {"poh_tier": 2, "banned": False, "locked": False} for j in jurors},
            "@target": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "jurors": {
                "active_set": jurors,
                "by_id": {j: copy.deepcopy(role) for j in jurors},
            }
        },
        "reputation": {"bans": {}},
        "system_queue": [],
        "disputes_by_id": {
            "severe-case": {
                "id": "severe-case",
                "target_type": "account",
                "target_id": "@target",
                "sanction_class": "S4",
                "severity": "severe",
                "stage": "juror_review",
                "panel_status": "assigned",
                "panel_round": 1,
                "panel_commitment": "synthetic-unverified-initial",
                "assigned_jurors": initial,
                "substitute_juror_ids": jurors[25:30],
                "eligible_juror_ids": initial,
                "vote_counts": {"yes": 20, "no": 0},
                "voted_juror_ids": voters,
                "ballot_nullifiers": nullifiers,
                "votes": {},
                "resolved": False,
            }
        },
    }


def _env(tx_type: str, *, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    system = signer == "SYSTEM"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        system=system,
        parent="synthetic-not-authorized-parent" if system else None,
        sig="synthetic-unverified",
    )


def _complete_experimental_appeal(state: dict) -> None:
    resolve = dispute.apply_dispute(
        state,
        _env(
            "DISPUTE_RESOLVE",
            signer="SYSTEM",
            nonce=12,
            payload={
                "dispute_id": "severe-case",
                "resolution": {"outcome": "report_upheld", "summary": "synthetic decision"},
                "_system_queue_id": "synthetic-unverified-parent",
            },
        ),
    )
    assert resolve["applied"] == "DISPUTE_RESOLVE"
    case = state["disputes_by_id"]["severe-case"]
    assert case["stage"] == "appeal_review"
    assert case["automatic_appeal_record"]["source"] == "experimental_system_resolution_v0"
    fresh = case["appeal_panel_juror_ids"]
    subs = case["appeal_substitute_juror_ids"]
    assert len(fresh) == 25
    assert len(subs) == 5
    assert set(fresh + subs).isdisjoint(set(case["original_panel_juror_ids"]))
    assert set(fresh + subs).isdisjoint(set(case["original_substitute_juror_ids"]))

    for number, juror in enumerate(fresh[:20], 1):
        result = dispute.apply_dispute(
            state,
            _env(
                "DISPUTE_JUROR_ACCEPT",
                signer=juror,
                nonce=100 + number,
                payload={"dispute_id": "severe-case"},
            ),
        )
        assert result["applied"] == "DISPUTE_JUROR_ACCEPT"

    for number, juror in enumerate(fresh[:20], 1):
        result = dispute.apply_dispute(
            state,
            _env(
                "DISPUTE_VOTE_SUBMIT",
                signer=juror,
                nonce=200 + number,
                payload={"dispute_id": "severe-case", "appeal_decision": "uphold"},
            ),
        )
        assert result["applied"] == "DISPUTE_VOTE_SUBMIT"
    case = state["disputes_by_id"]["severe-case"]
    assert case["appeal_vote_counts"] == {"uphold": 20}
    assert case["stage"] == "appeal_resolved"
    assert case["appeal_panel_result"]["reached"] is True


@pytest.mark.parametrize(
    "claimed_waiver", [None, True, {"signed": True, "received_reasoned_outcome": True}]
)
def test_complete_synthetic_appeal_never_unlocks_severe_finalization(
    claimed_waiver: object,
) -> None:
    state = _state()
    _complete_experimental_appeal(state)
    case = state["disputes_by_id"]["severe-case"]
    if claimed_waiver is not None:
        case["appeal_waiver"] = copy.deepcopy(claimed_waiver)
    before_tick = copy.deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=12) == 0
    assert state == before_tick
    assert not any(
        item.get("tx_type") in {"ACCOUNT_BAN", "DISPUTE_FINAL_RECEIPT"}
        for item in state["system_queue"]
    )
    receipt = _env(
        "DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        nonce=13,
        payload={
            "dispute_id": "severe-case",
            "receipt_id": "synthetic-not-authorized-final",
            "appeal_resolution": {
                "decision": "uphold",
                "actions": [{"tx_type": "ACCOUNT_BAN", "payload": {"account_id": "@target"}}],
            },
        },
    )
    before_receipt = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        dispute.apply_dispute(state, receipt)
    assert (exc.value.code, exc.value.reason) == (
        "forbidden",
        "severe_sanction_automatic_appeal_unimplemented",
    )
    assert state == before_receipt
    assert not state["accounts"]["@target"]["banned"]
    assert not state["reputation"]["bans"]


@pytest.mark.parametrize(
    "applier", [apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy], ids=["journal", "deepcopy"]
)
def test_complete_synthetic_appeal_never_authorizes_direct_system_ban(applier) -> None:
    state = _state()
    _complete_experimental_appeal(state)
    case = state["disputes_by_id"]["severe-case"]
    ban = _env(
        "ACCOUNT_BAN",
        signer="SYSTEM",
        nonce=14,
        payload={
            "account_id": "@target",
            "dispute_id": "severe-case",
            "reason": "synthetic",
            "initial_approvals": 20,
            "fresh_appeal_approvals": 20,
            "appeal_panel_commitment": case["appeal_panel_commitment"],
            "appeal_waiver": {"authenticated": True, "after_full_outcome": True},
            "_system_queue_id": "synthetic-unverified-parent",
        },
    )
    snapshot = copy.deepcopy(state)
    original = copy.deepcopy(snapshot)
    root = compute_state_root(snapshot)
    with pytest.raises(ApplyError) as error:
        applier(snapshot, ban)
    assert (error.value.code, error.value.reason) == (
        "forbidden",
        "severe_sanction_authorization_unimplemented",
    )
    assert snapshot == original
    assert compute_state_root(snapshot) == root
