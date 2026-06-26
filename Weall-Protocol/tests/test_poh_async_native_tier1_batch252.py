from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str,
    nonce: int,
    *,
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


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
            "j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j2": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j3": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "outside": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "poh": {},
        "params": {
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_expiry_window_blocks": 100,
            }
        },
    }


def _open_assign_accept(st: dict) -> str:
    opened = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": "alice",
                "challenge_id": "prompt:1",
                "challenge_commitment": "commit:challenge:1",
            },
            signer="alice",
            nonce=1,
        ),
    )
    assert opened and opened["applied"] == "POH_ASYNC_REQUEST_OPEN"
    case_id = str(opened["case_id"])

    declared = apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            {
                "case_id": case_id,
                "evidence_id": "evi:1",
                "evidence_commitment": "commit:evidence:1",
                "response_commitment": "commit:response:1",
                "public_evidence_id": "public:prompt-answer:1",
            },
            signer="alice",
            nonce=2,
        ),
    )
    assert declared and declared["applied"] == "POH_ASYNC_EVIDENCE_DECLARE"

    bound = apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_BIND",
            {"case_id": case_id, "evidence_id": "evi:1", "target_id": case_id},
            signer="alice",
            nonce=3,
        ),
    )
    assert bound and bound["applied"] == "POH_ASYNC_EVIDENCE_BIND"

    assigned = apply_tx(
        st,
        _env(
            "POH_ASYNC_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
            signer="SYSTEM",
            nonce=4,
            system=True,
            parent="POH_ASYNC_REQUEST_OPEN",
        ),
    )
    assert assigned and assigned["applied"] == "POH_ASYNC_JUROR_ASSIGN"

    for nonce, jid in enumerate(("j1", "j2", "j3"), start=5):
        accepted = apply_tx(
            st,
            _env("POH_ASYNC_JUROR_ACCEPT", {"case_id": case_id}, signer=jid, nonce=nonce),
        )
        assert accepted and accepted["applied"] == "POH_ASYNC_JUROR_ACCEPT"

    return case_id


def test_native_async_poh_approval_grants_tier1_without_email() -> None:
    st = _state()
    case_id = _open_assign_accept(st)

    for nonce, jid, verdict in (
        (8, "j1", "approve"),
        (9, "j2", "approve"),
        (10, "j3", "reject"),
    ):
        reviewed = apply_tx(
            st,
            _env(
                "POH_ASYNC_REVIEW_SUBMIT",
                {
                    "case_id": case_id,
                    "verdict": verdict,
                    "reason_code": "human_reviewed",
                    "review_commitment": f"commit:review:{jid}",
                },
                signer=jid,
                nonce=nonce,
            ),
        )
        assert reviewed and reviewed["applied"] == "POH_ASYNC_REVIEW_SUBMIT"

    finalized = apply_tx(
        st,
        _env(
            "POH_ASYNC_FINALIZE",
            {"case_id": case_id},
            signer="SYSTEM",
            nonce=11,
            system=True,
            parent="POH_ASYNC_REVIEW_SUBMIT",
        ),
    )

    assert finalized and finalized["outcome"] == "approved"
    assert finalized["tier_awarded"] == 1
    assert effective_poh_tier(st, "alice") == 1
    case = st["poh"]["async_cases"][case_id]
    assert case["protocol_native"] is True
    assert case["external_identity_authority"] == "forbidden"
    assert "email" not in case
    assert "email_hash" not in case
    assert case["response_commitment"] == "commit:response:1"

    receipt = apply_tx(
        st,
        _env(
            "POH_ASYNC_RECEIPT",
            {"case_id": case_id},
            signer="SYSTEM",
            nonce=12,
            system=True,
            parent="POH_ASYNC_FINALIZE",
        ),
    )
    assert receipt and receipt["applied"] == "POH_ASYNC_RECEIPT"
    assert st["poh"]["async_cases"][case_id]["receipt"]["verification_type"] == "async"


def test_native_async_rejection_does_not_grant_tier1() -> None:
    st = _state()
    case_id = _open_assign_accept(st)
    for nonce, jid, verdict in (
        (8, "j1", "reject"),
        (9, "j2", "invalid_evidence"),
        (10, "j3", "approve"),
    ):
        apply_tx(
            st,
            _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": verdict}, signer=jid, nonce=nonce),
        )

    finalized = apply_tx(
        st,
        _env("POH_ASYNC_FINALIZE", {"case_id": case_id}, signer="SYSTEM", nonce=11, system=True, parent="POH_ASYNC_REVIEW_SUBMIT"),
    )

    assert finalized and finalized["outcome"] == "rejected"
    assert finalized["tier_awarded"] == 0
    assert effective_poh_tier(st, "alice") == 0


def test_native_async_rejects_non_assigned_and_duplicate_reviews() -> None:
    st = _state()
    case_id = _open_assign_accept(st)

    with pytest.raises(ApplyError) as non_assigned:
        apply_tx(
            st,
            _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "approve"}, signer="outside", nonce=8),
        )
    assert non_assigned.value.reason == "juror_not_assigned"

    apply_tx(
        st,
        _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "approve"}, signer="j1", nonce=9),
    )
    with pytest.raises(ApplyError) as duplicate:
        apply_tx(
            st,
            _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "reject"}, signer="j1", nonce=10),
        )
    assert duplicate.value.reason == "duplicate_async_review"


def test_native_async_public_state_rejects_private_external_identity_fields() -> None:
    st = _state()
    with pytest.raises(ApplyError) as exc:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_REQUEST_OPEN",
                {
                    "account_id": "alice",
                    "challenge_commitment": "commit:challenge",
                    "email": "alice@example.invalid",
                },
                signer="alice",
                nonce=1,
            ),
        )
    assert exc.value.reason == "native_async_sensitive_identity_field_forbidden"
    assert "email" in exc.value.details["fields"]
