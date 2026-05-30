from pathlib import Path


def test_batch498_frontend_bad_nonce_parser_reads_nested_expected_got() -> None:
    session = Path("../web/src/auth/session.ts").read_text(encoding="utf-8")
    assert "payload?.error?.details?.details?.details" in session
    assert "candidate?.expected ?? nestedDetails?.expected" in session
    assert "candidate?.got ?? nestedDetails?.got" in session
    assert "setReservedNonce(signer, hint.expected - 1);" in session


def test_batch498_frontend_nonce_failures_are_not_recorded() -> None:
    tx_action = Path("../web/src/lib/txAction.ts").read_text(encoding="utf-8")
    start = tx_action.index('["bad_nonce"')
    end = tx_action.index('if (code === "signer_submission_busy"')
    block = tx_action[start:end]
    assert '"backend_failure"' in block
    assert '"recorded_not_yet_visible"' not in block

    tx_feedback = Path("../web/src/lib/txFeedback.ts").read_text(encoding="utf-8")
    start = tx_feedback.index('code.includes("nonce")')
    end = tx_feedback.index('if (\n    code.includes("duplicate_submission_blocked")')
    block = tx_feedback[start:end]
    assert '"backend_failure"' in block
    assert '"recorded_not_yet_visible"' not in block


def test_batch498_session_repair_does_not_swallow_bad_nonce_403() -> None:
    tx_queue = Path("../web/src/components/TxQueueProvider.tsx").read_text(encoding="utf-8")
    start = tx_queue.index("function shouldAttemptSessionRepair")
    end = tx_queue.index("function isTransientToastStatus")
    block = tx_queue[start:end]
    assert 'code.includes("nonce")' in block
    assert "return false;" in block
