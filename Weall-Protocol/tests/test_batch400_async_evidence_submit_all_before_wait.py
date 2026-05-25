from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def _page() -> str:
    return (WEB / "src" / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")


def _submit_async_body(src: str) -> str:
    return src.split("async function submitAsyncEvidence()", 1)[1].split("async function submitLiveRequest()", 1)[0]


def test_batch400_async_evidence_submits_full_sequence_and_waits_for_reviewable_truth() -> None:
    body = _submit_async_body(_page())

    assert "Batch 408: node admission is still sequential-nonce based" in body
    assert "POH_ASYNC_REQUEST_OPEN" in body
    assert "POH_ASYNC_EVIDENCE_DECLARE" in body
    assert "POH_ASYNC_EVIDENCE_BIND" in body
    assert body.index("POH_ASYNC_REQUEST_OPEN") < body.index("POH_ASYNC_EVIDENCE_DECLARE") < body.index("POH_ASYNC_EVIDENCE_BIND")

    # The frontend may not claim that verification evidence is submitted just
    # because request-open committed.  It must wait for each nonce-dependent tx
    # to reconcile before submitting the next tx, then require reviewable case
    # state after evidence-bind.
    assert "waitForAccountNonceAtLeast(acct, Number(open?.env?.nonce || 0)" in body
    assert "waitForAccountNonceAtLeast(acct, Number(declare?.env?.nonce || 0)" in body
    assert "waitForAsyncCaseReviewable" in body
    assert "reviewability.reviewable" in body
    assert "Async verification txs were submitted, but the case is not reviewable yet" in body
    assert "acceptAccepted: true" in body
