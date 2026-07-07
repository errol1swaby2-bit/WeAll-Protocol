from __future__ import annotations

from weall.runtime.domain_apply import apply_tx
from weall.runtime.poh.eligibility import require_poh_tier
from weall.runtime.poh.state import effective_poh_tier, set_account_poh_status
from weall.runtime.reviewer_responsibilities import reviewer_lane_active
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def _reviewer_record(*, live: bool = False, tier2: bool = False) -> dict:
    reviewer: dict = {}
    if live:
        reviewer["poh_live_review"] = {"opted_in": True, "active": True}
    if tier2:
        reviewer["poh_async_review"] = {"opted_in": True, "active": True}
    return {
        "enrolled": True,
        "active": True,
        "status": "active",
        "responsibilities": {"reviewer": reviewer},
    }


def _state_with_tier1_subject(*, live_reviewers: bool = False, tier2_reviewers: bool = False) -> dict:
    state = {
        "chain_id": "test",
        "height": 11,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0},
            "j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 1},
            "j2": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 1},
            "j3": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 1},
        },
        "roles": {
            "jurors": {
                "active_set": ["j1", "j2", "j3"],
                "by_id": {
                    "j1": _reviewer_record(live=live_reviewers, tier2=tier2_reviewers),
                    "j2": _reviewer_record(live=live_reviewers, tier2=tier2_reviewers),
                    "j3": _reviewer_record(live=live_reviewers, tier2=tier2_reviewers),
                },
            }
        },
    }
    set_account_poh_status(
        state,
        account_id="alice",
        poh_tier=1,
        verified_at_height=5,
        proof_commitment="async:previous",
        issuer_authority_id="poh_async_finalize",
        last_updated_height=5,
    )
    return state


def test_live_finalize_upgrades_canonical_status_so_tier2_protocol_actions_unlock() -> None:
    state = _state_with_tier1_subject(live_reviewers=True)
    assert effective_poh_tier(state, "alice") == 1

    opened = apply_tx(
        state,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            {
                "account_id": "alice",
                "session_commitment": "session:cmt:alice",
                "room_commitment": "room:cmt:alice",
                "prompt_commitment": "prompt:cmt:alice",
            },
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(opened["case_id"])
    apply_tx(
        state,
        _env(
            "POH_LIVE_SESSION_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "session:cmt:alice"},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_LIVE_REQUEST_OPEN",
        ),
    )
    apply_tx(
        state,
        _env(
            "POH_LIVE_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_LIVE_SESSION_INIT",
        ),
    )

    for i, juror in enumerate(["j1", "j2", "j3"], start=4):
        apply_tx(state, _env("POH_LIVE_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": i}, signer=juror, nonce=i))
        apply_tx(
            state,
            _env(
                "POH_LIVE_ATTENDANCE_MARK",
                {"case_id": case_id, "juror_id": juror, "attended": True, "session_commitment": "session:cmt:alice", "ts_ms": i + 10},
                signer=juror,
                nonce=i + 10,
            ),
        )
        apply_tx(
            state,
            _env(
                "POH_LIVE_VERDICT_SUBMIT",
                {"case_id": case_id, "verdict": "pass", "session_commitment": "session:cmt:alice", "ts_ms": i + 20},
                signer=juror,
                nonce=i + 20,
            ),
        )

    finalized = apply_tx(
        state,
        _env(
            "POH_LIVE_FINALIZE",
            {"case_id": case_id, "ts_ms": 99},
            signer="SYSTEM",
            nonce=40,
            system=True,
            parent="POH_LIVE_VERDICT_SUBMIT",
        ),
    )

    assert finalized["outcome"] == "pass"
    assert finalized["tier_awarded"] == 2
    assert state["accounts"]["alice"]["poh_tier"] == 2
    assert effective_poh_tier(state, "alice") == 2
    assert state["poh"]["account_status"]["alice"]["poh_tier"] == 2
    assert state["poh"]["account_status"]["alice"]["issuer_authority_id"] == "poh_live_finalize"

    # Tier-2 human status unlocks full Tier-2 protocol eligibility, but does not
    # silently opt the user into optional reviewer responsibility lanes.
    require_poh_tier(state, "alice", "CONTENT_POST_CREATE")
    require_poh_tier(state, "alice", "GOV_VOTE_CAST")
    require_poh_tier(state, "alice", "GROUP_CREATE")
    assert reviewer_lane_active(state, "alice", "poh_live_review") is False


def test_legacy_tier2_finalize_upgrades_existing_canonical_tier1_status() -> None:
    state = _state_with_tier1_subject(tier2_reviewers=True)
    assert effective_poh_tier(state, "alice") == 1

    opened = apply_tx(
        state,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:tier2:alice"},
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(opened["case_id"])
    apply_tx(
        state,
        _env(
            "POH_TIER2_JUROR_ASSIGN",
            {
                "case_id": case_id,
                "jurors": ["j1", "j2", "j3"],
                "n_jurors": 3,
                "min_total_reviews": 3,
                "pass_threshold": 2,
                "fail_max": 1,
            },
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )
    apply_tx(state, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "pass"}, signer="j1", nonce=3))
    apply_tx(state, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "pass"}, signer="j2", nonce=4))
    apply_tx(state, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "fail"}, signer="j3", nonce=5))

    finalized = apply_tx(
        state,
        _env(
            "POH_TIER2_FINALIZE",
            {"case_id": case_id, "ts_ms": 77},
            signer="SYSTEM",
            nonce=6,
            system=True,
            parent="POH_TIER2_REVIEW_SUBMIT",
        ),
    )

    assert finalized["outcome"] == "pass"
    assert state["accounts"]["alice"]["poh_tier"] == 2
    assert effective_poh_tier(state, "alice") == 2
    assert state["poh"]["account_status"]["alice"]["poh_tier"] == 2
    assert state["poh"]["account_status"]["alice"]["issuer_authority_id"] == "poh_tier2_finalize"
    require_poh_tier(state, "alice", "ROLE_JUROR_ENROLL")


def test_bootstrap_tier2_grant_also_updates_canonical_status_for_protocol_access() -> None:
    state = {
        "chain_id": "test",
        "height": 3,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "pubkey": "alice-pk", "pubkeys": ["alice-pk"], "banned": False, "locked": False},
        },
        "params": {
            "system_signer": "SYSTEM",
            "poh_bootstrap_open": True,
            "poh_bootstrap_max_height": 10,
        },
        "poh": {},
        "roles": {"jurors": {"active_set": [], "by_id": {}}},
    }
    set_account_poh_status(
        state,
        account_id="alice",
        poh_tier=1,
        verified_at_height=1,
        proof_commitment="async:previous",
        issuer_authority_id="poh_async_finalize",
        last_updated_height=1,
    )

    apply_tx(
        state,
        _env(
            "POH_BOOTSTRAP_TIER2_GRANT",
            {"account_id": "alice", "pubkey": "alice-pk"},
            signer="alice",
            nonce=1,
        ),
    )

    assert state["accounts"]["alice"]["poh_tier"] == 2
    assert effective_poh_tier(state, "alice") == 2
    assert state["poh"]["account_status"]["alice"]["poh_tier"] == 2
    assert state["poh"]["account_status"]["alice"]["issuer_authority_id"] == "poh_bootstrap_open"
    require_poh_tier(state, "alice", "GROUP_CREATE")
    assert reviewer_lane_active(state, "alice", "poh_live_review") is False
