from __future__ import annotations

from weall.runtime.apply.poh import (
    apply_poh_async_evidence_declare,
    apply_poh_async_finalize,
    apply_poh_async_juror_accept,
    apply_poh_async_juror_assign,
    apply_poh_async_request_open,
    apply_poh_async_review_submit,
)
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> dict:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "system": system,
    }


def _solo_bootstrap_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 1,
        "tip": "genesis",
        "params": {
            "poh_bootstrap_mode": "allowlist",
            "bootstrap_expires_height": 1008,
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_min_rep_milli": 0,
            },
        },
        "accounts": {
            "@founder": {"poh_tier": 2, "nonce": 0, "banned": False, "locked": False, "reputation_milli": 0},
            "@alice": {"poh_tier": 0, "nonce": 0, "banned": False, "locked": False, "reputation_milli": 0},
            "@bob": {"poh_tier": 0, "nonce": 0, "banned": False, "locked": False, "reputation_milli": 0},
        },
        "roles": {"validators": {"active_set": ["@founder"]}},
        "poh": {"async_cases": {}},
    }


def _async_case_to_tier1(state: dict, account: str, *, case_id: str, nonce_base: int) -> None:
    apply_poh_async_request_open(
        state,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            account,
            nonce_base,
            {"account_id": account, "case_id": case_id, "response_commitment": f"resp:{case_id}"},
        ),
    )
    apply_poh_async_evidence_declare(
        state,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            account,
            nonce_base + 1,
            {"case_id": case_id, "evidence_commitment": f"evidence:{case_id}"},
        ),
    )
    before = len(state.get("system_queue") or [])
    assert schedule_poh_async_system_txs(state, next_height=state["height"] + 1) >= 1
    new_items = list(state.get("system_queue") or [])[before:]
    queued = [item for item in new_items if item.get("tx_type") == "POH_ASYNC_JUROR_ASSIGN"][-1]
    assert queued["tx_type"] == "POH_ASYNC_JUROR_ASSIGN"
    assert queued["payload"]["jurors"] == ["@founder"]
    apply_poh_async_juror_assign(
        state,
        _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", nonce_base + 2, queued["payload"], system=True),
    )
    apply_poh_async_juror_accept(
        state,
        _env("POH_ASYNC_JUROR_ACCEPT", "@founder", nonce_base + 3, {"case_id": case_id}),
    )
    apply_poh_async_review_submit(
        state,
        _env("POH_ASYNC_REVIEW_SUBMIT", "@founder", nonce_base + 4, {"case_id": case_id, "verdict": "approve"}),
    )
    out = apply_poh_async_finalize(
        state,
        _env("POH_ASYNC_FINALIZE", "SYSTEM", nonce_base + 5, {"case_id": case_id}, system=True),
    )
    assert out["outcome"] == "approved"
    assert state["accounts"][account]["poh_tier"] == 1


def test_solo_genesis_human_can_bootstrap_multiple_async_tier1_users() -> None:
    state = _solo_bootstrap_state()

    _async_case_to_tier1(state, "@alice", case_id="async-alice", nonce_base=1)
    _async_case_to_tier1(state, "@bob", case_id="async-bob", nonce_base=10)

    alice_case = state["poh"]["async_cases"]["async-alice"]
    assert alice_case["assigned_juror_count"] == 1
    assert alice_case["minimum_reviews"] == 1
    assert alice_case["approval_threshold"] == 1
    assert alice_case["bootstrap_adaptive_quorum"]["active_validators"] == 1


def test_async_quorum_expands_with_active_validator_count() -> None:
    state = _solo_bootstrap_state()
    state["accounts"]["@v2"] = {
        "poh_tier": 2,
        "nonce": 0,
        "banned": False,
        "locked": False,
        "reputation_milli": 0,
    }
    state["roles"]["validators"]["active_set"] = ["@founder", "@v2"]

    apply_poh_async_request_open(
        state,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            "@alice",
            1,
            {"account_id": "@alice", "case_id": "async-alice", "response_commitment": "resp"},
        ),
    )
    apply_poh_async_evidence_declare(
        state,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            "@alice",
            2,
            {"case_id": "async-alice", "evidence_commitment": "evidence"},
        ),
    )

    assert schedule_poh_async_system_txs(state, next_height=2) == 1
    queued = state["system_queue"][-1]
    assert len(queued["payload"]["jurors"]) == 2
    assert set(queued["payload"]["jurors"]) == {"@founder", "@v2"}
