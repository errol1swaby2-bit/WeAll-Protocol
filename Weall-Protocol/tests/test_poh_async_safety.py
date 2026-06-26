from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
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
        "tip": "tip:10",
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
            "j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j2": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j3": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j4": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "poh": {},
        "roles": {
            "jurors": {
                "active_set": ["j1", "j2", "j3", "j4"],
            }
        },
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


def _open_with_evidence(st: dict) -> str:
    opened = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": "alice",
                "case_id": "case:async:1",
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
    return case_id


def _assign_accept(st: dict, case_id: str) -> None:
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
    for nonce, juror in enumerate(("j1", "j2", "j3"), start=5):
        accepted = apply_tx(st, _env("POH_ASYNC_JUROR_ACCEPT", {"case_id": case_id}, signer=juror, nonce=nonce))
        assert accepted and accepted["applied"] == "POH_ASYNC_JUROR_ACCEPT"


def _approve_finalize(st: dict, case_id: str) -> None:
    for nonce, juror, verdict in (
        (8, "j1", "approve"),
        (9, "j2", "approve"),
        (10, "j3", "reject"),
    ):
        reviewed = apply_tx(st, _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": verdict}, signer=juror, nonce=nonce))
        assert reviewed and reviewed["applied"] == "POH_ASYNC_REVIEW_SUBMIT"
    finalized = apply_tx(
        st,
        _env("POH_ASYNC_FINALIZE", {"case_id": case_id}, signer="SYSTEM", nonce=11, system=True, parent="POH_ASYNC_REVIEW_SUBMIT"),
    )
    assert finalized and finalized["outcome"] == "approved"


def test_async_evidence_locks_after_assignment_batch286() -> None:
    st = _state()
    case_id = _open_with_evidence(st)
    apply_tx(
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

    with pytest.raises(ApplyError) as changed:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_EVIDENCE_DECLARE",
                {"case_id": case_id, "evidence_id": "evi:swap", "response_commitment": "commit:swap"},
                signer="alice",
                nonce=5,
            ),
        )
    assert changed.value.reason == "async_evidence_locked"
    assert st["poh"]["async_cases"][case_id]["response_commitment"] == "commit:response:1"


def test_async_needs_followup_blocks_finalization_batch286() -> None:
    st = _state()
    case_id = _open_with_evidence(st)
    _assign_accept(st, case_id)
    for nonce, juror, verdict in (
        (8, "j1", "approve"),
        (9, "j2", "approve"),
        (10, "j3", "needs_followup"),
    ):
        apply_tx(st, _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": verdict}, signer=juror, nonce=nonce))

    with pytest.raises(ApplyError) as premature:
        apply_tx(
            st,
            _env("POH_ASYNC_FINALIZE", {"case_id": case_id}, signer="SYSTEM", nonce=11, system=True, parent="POH_ASYNC_REVIEW_SUBMIT"),
        )
    assert premature.value.reason == "async_case_needs_followup"
    assert effective_poh_tier(st, "alice") == 0
    assert st["poh"]["async_cases"][case_id]["status"] == "needs_followup"


def test_async_receipt_must_match_finalized_case_state_batch286() -> None:
    st = _state()
    case_id = _open_with_evidence(st)
    _assign_accept(st, case_id)
    _approve_finalize(st, case_id)

    with pytest.raises(ApplyError) as outcome_mismatch:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_RECEIPT",
                {"case_id": case_id, "outcome": "rejected"},
                signer="SYSTEM",
                nonce=12,
                system=True,
                parent="POH_ASYNC_FINALIZE",
            ),
        )
    assert outcome_mismatch.value.reason == "async_receipt_outcome_mismatch"

    with pytest.raises(ApplyError) as tier_mismatch:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_RECEIPT",
                {"case_id": case_id, "tier_awarded": 0},
                signer="SYSTEM",
                nonce=13,
                system=True,
                parent="POH_ASYNC_FINALIZE",
            ),
        )
    assert tier_mismatch.value.reason == "async_receipt_tier_mismatch"

    receipt = apply_tx(
        st,
        _env("POH_ASYNC_RECEIPT", {"case_id": case_id}, signer="SYSTEM", nonce=14, system=True, parent="POH_ASYNC_FINALIZE"),
    )
    assert receipt and receipt["applied"] == "POH_ASYNC_RECEIPT"
    stored = st["poh"]["async_cases"][case_id]["receipt"]
    assert stored["outcome"] == "approved"
    assert stored["tier_awarded"] == 1


def test_async_scheduler_queues_assign_finalize_and_receipt_batch286() -> None:
    st = _state()
    case_id = _open_with_evidence(st)
    enqueued = schedule_poh_async_system_txs(st, next_height=11)
    assert enqueued == 1
    queue = st.get("system_queue")
    assert isinstance(queue, list)
    assert any(item.get("tx_type") == "POH_ASYNC_JUROR_ASSIGN" and item.get("payload", {}).get("case_id") == case_id for item in queue)

    # Apply the deterministic assignment selected by the scheduler, then review.
    assign_payload = next(item["payload"] for item in queue if item.get("tx_type") == "POH_ASYNC_JUROR_ASSIGN")
    assigned = apply_tx(st, _env("POH_ASYNC_JUROR_ASSIGN", dict(assign_payload), signer="SYSTEM", nonce=4, system=True, parent="POH_ASYNC_REQUEST_OPEN"))
    assert assigned and assigned["applied"] == "POH_ASYNC_JUROR_ASSIGN"
    jurors = [str(j) for j in assigned["jurors"]]
    for nonce, juror in enumerate(jurors, start=5):
        apply_tx(st, _env("POH_ASYNC_JUROR_ACCEPT", {"case_id": case_id}, signer=juror, nonce=nonce))
    for nonce, juror, verdict in (
        (8, jurors[0], "approve"),
        (9, jurors[1], "approve"),
        (10, jurors[2], "reject"),
    ):
        apply_tx(st, _env("POH_ASYNC_REVIEW_SUBMIT", {"case_id": case_id, "verdict": verdict}, signer=juror, nonce=nonce))

    enqueued_after_reviews = schedule_poh_async_system_txs(st, next_height=12)
    assert enqueued_after_reviews >= 2
    queued_types = [item.get("tx_type") for item in st.get("system_queue", [])]
    assert "POH_ASYNC_FINALIZE" in queued_types
    assert "POH_ASYNC_RECEIPT" in queued_types


def test_async_assignment_requires_declared_evidence_batch286() -> None:
    st = _state()
    opened = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": "alice",
                "case_id": "case:async:no-evidence",
                "challenge_id": "prompt:1",
                "challenge_commitment": "commit:challenge:1",
                "response_commitment": "commit:response:request-only",
            },
            signer="alice",
            nonce=1,
        ),
    )
    assert opened and opened["applied"] == "POH_ASYNC_REQUEST_OPEN"
    case_id = str(opened["case_id"])

    assert schedule_poh_async_system_txs(st, next_height=11) == 0
    assert not st.get("system_queue")

    with pytest.raises(ApplyError) as premature_assign:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_JUROR_ASSIGN",
                {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
                signer="SYSTEM",
                nonce=2,
                system=True,
                parent="POH_ASYNC_REQUEST_OPEN",
            ),
        )
    assert premature_assign.value.reason == "async_evidence_required_before_assignment"
