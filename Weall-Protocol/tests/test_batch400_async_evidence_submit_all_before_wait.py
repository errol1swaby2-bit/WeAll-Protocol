from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def _page() -> str:
    return (WEB / "src" / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")


def _submit_async_body(src: str) -> str:
    return src.split("async function submitAsyncEvidence()", 1)[1].split("async function submitLiveRequest()", 1)[0]


def test_batch400_async_evidence_submits_full_sequence_before_waiting_for_case_visibility() -> None:
    body = _submit_async_body(_page())

    assert "Batch 400: keep the native async evidence sequence contiguous" in body
    assert "POH_ASYNC_REQUEST_OPEN" in body
    assert "POH_ASYNC_EVIDENCE_DECLARE" in body
    assert "POH_ASYNC_EVIDENCE_BIND" in body
    assert body.index("POH_ASYNC_REQUEST_OPEN") < body.index("POH_ASYNC_EVIDENCE_DECLARE") < body.index("POH_ASYNC_EVIDENCE_BIND")

    # The old flow waited after request-open and evidence-declare.  That could
    # stall forever when observer-local status was stricter than genesis case
    # visibility, leaving no complete reviewable case for the genesis reviewer.
    assert "Async verification request was not confirmed on the observer yet" not in body
    assert "Async verification evidence declaration was not confirmed on the observer yet" not in body

    # The only post-sequence wait should be for the complete async case to be
    # visible, with a fallback diagnostic that does not require local sync truth.
    assert "maxWaitMs: 120000" in body
    assert "Async verification evidence was submitted, but the reviewable case is not visible yet" in body
    assert "acceptAccepted: true" in body
