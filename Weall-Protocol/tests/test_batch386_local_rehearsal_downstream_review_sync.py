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
    assert "const openVisible = await waitForSubmittedTxVisible" in page
    assert "requireLocalStateSynced: true" in page
    assert "if (!openVisible) throw new Error" in page
    assert "if (!declareVisible) throw new Error" in page
    assert "if (!bindVisible) throw new Error" in page
    assert "if (!openCaseVisible) throw new Error" in page
    assert "if (!boundCaseVisible) throw new Error" in page


def test_content_escalation_has_bootstrap_reviewer_fallback_batch386() -> None:
    src = _read(NESTED / "src" / "weall" / "runtime" / "apply" / "content.py")

    assert "def _bootstrap_reviewer_accounts" in src
    assert 'params.get("bootstrap_founder_account")' in src
    assert 'params.get("bootstrap_operator")' in src
    assert "or _bootstrap_reviewer_accounts(state)" in src
    assert 'fallback_signer = "" if _as_str(env.signer).strip().upper() == "SYSTEM" else env.signer' in src
