from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def _page() -> str:
    return (WEB / "src" / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")


def _submit_async_body(src: str) -> str:
    return src.split("async function submitAsyncEvidence()", 1)[1].split("async function submitLiveRequest()", 1)[0]


def test_async_evidence_submits_full_sequence_and_waits_for_reviewable_truth() -> None:
    body = _submit_async_body(_page())

    assert "beginNonceSequence(acct, base)" in body
    assert "Submit the remaining same-signer verification txs immediately with" in body
    assert "POH_ASYNC_REQUEST_OPEN" in body
    assert "POH_ASYNC_EVIDENCE_DECLARE" in body
    assert "POH_ASYNC_EVIDENCE_BIND" in body
    assert body.index("POH_ASYNC_REQUEST_OPEN") < body.index("POH_ASYNC_EVIDENCE_DECLARE") < body.index("POH_ASYNC_EVIDENCE_BIND")

    # The frontend may not claim that verification evidence is submitted just
    # because request-open committed.  It now submits the contiguous same-signer
    # tx sequence before waiting, then requires reviewable case state after
    # evidence-bind.
    assert "submitSignedTxInSequence" in body
    assert "parent: open?.result?.tx_id || null" in body
    assert "parent: declare?.result?.tx_id || null" in body
    assert "waitForAsyncCaseReviewable" in body
    assert "reviewability.reviewable" in body
    assert "Async verification txs were submitted, but the case is not reviewable yet" in body
    assert "acceptAccepted: true" in body
