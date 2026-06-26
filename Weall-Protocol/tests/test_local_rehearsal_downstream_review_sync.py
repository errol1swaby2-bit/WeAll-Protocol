from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web" / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_devnet_sync_from_peer_sends_operator_token_when_configured_batch386() -> None:
    src = _read(NESTED / "scripts" / "devnet_sync_from_peer.sh")

    assert "local headers=(-H 'content-type: application/json')" in src
    assert "x-weall-state-sync-operator-token: ${WEALL_STATE_SYNC_OPERATOR_TOKEN}" in src
    assert "x-weall-observer-operator-token: ${WEALL_OBSERVER_EDGE_OPERATOR_TOKEN}" in src
    assert "x-weall-operator-token: ${WEALL_OPERATOR_TOKEN}" in src
    assert 'curl -sS "${headers[@]}" --data-binary' in src


def test_local_two_frontend_rehearsal_starts_downstream_sync_worker_batch386() -> None:
    src = _read(NESTED / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert 'DOWNSTREAM_SYNC_PID=""' in src
    assert "Starting genesis-to-observer downstream sync worker" in src
    assert 'DOWNSTREAM_SYNC_LOG="${LOG_DIR}/local-genesis-to-observer-sync.log"' in src
    assert 'bash scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}" || true' in src
    assert 'export WEALL_STATE_SYNC_OPERATOR_TOKEN="${SYNC_TOKEN}"' in src
    assert "downstream_sync_log=${DOWNSTREAM_SYNC_LOG}" in src


def test_async_evidence_waits_for_local_sync_before_dependent_txs_batch386() -> None:
    page = _read(WEB / "pages" / "AccountVerificationPage.tsx")

    assert "requireLocalStateSynced?: boolean" in page
    assert "const localSynced = st?.local_state_synced === true" in page
    assert "return false" in re.search(r"async function waitForSubmittedTxVisible\(.*?\n\}", page, re.S).group(0)
    assert "Batch 400: keep the native async evidence sequence contiguous" in page
    assert "Submit request-open, evidence-declare, and evidence-bind first; then" in page
    assert "const boundCaseVisible = await waitForAsyncCaseVisible" in page
    assert "if (!boundCaseVisible)" in page
    assert "bindStatusVisible = await waitForSubmittedTxVisible" in page
    assert "requireLocalStateSynced: false" in page
    assert "acceptAccepted: true" in page


def test_content_escalation_uses_explicit_content_review_lane_opt_in_batch386() -> None:
    src = _read(NESTED / "src" / "weall" / "runtime" / "apply" / "content.py")

    assert "explicit_active_juror_opt_in_required" in src
    assert "_filter_target_owner_from_jurors" in src
    assert "CONTENT_REVIEW_LANE" in src
    assignment_block = src.split("reviewer_responsibility_policy", 1)[0].rsplit("assigned_jurors =", 1)[-1]
    assert "eligible_reviewer_ids(state, CONTENT_REVIEW_LANE)" in assignment_block
    assert "_active_juror_accounts(state)" not in assignment_block
    assert "_active_validator_accounts(state)" not in assignment_block
    assert "_bootstrap_reviewer_accounts(state)" not in assignment_block
    assert "fallback_signer" not in assignment_block
