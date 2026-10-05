from __future__ import annotations

import copy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str, *, chain_id: str = "p0-a06-closure") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, *, signer: str = "@alice") -> dict:
    submitted = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert submitted["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    block = ex.get_block_by_height(1)
    assert isinstance(block, dict)
    assert isinstance(block.get("receipts"), list) and block["receipts"]
    return block


def _snapshot_response(ex: WeAllExecutor) -> tuple[StateSyncResponseMsg, dict]:
    anchor = build_snapshot_anchor(ex.state)
    request = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id=ex.chain_id,
            schema_version="1",
            tx_index_hash=ex._tx_index_hash,
            sent_ts_ms=0,
            corr_id="p0-a06-receipt-closure",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )
    response = ex._state_sync_service().handle_request(request)
    assert response.ok is True
    assert response.snapshot is not None
    assert len(response.blocks or ()) == 1
    return response, anchor


def _replace_checkpoint(response: StateSyncResponseMsg, checkpoint: dict) -> StateSyncResponseMsg:
    return StateSyncResponseMsg(
        header=response.header,
        ok=True,
        reason=response.reason,
        height=response.height,
        snapshot=response.snapshot,
        snapshot_hash=response.snapshot_hash,
        snapshot_anchor=response.snapshot_anchor,
        blocks=(checkpoint,),
    )


def test_a06_follower_rejects_receipt_tamper_then_accepts_canonical_and_restart_preserves_it(
    tmp_path: Path,
) -> None:
    """A06-F001/A16-F002: receipt commitments survive follower apply and restart."""

    leader = _executor(tmp_path, "leader")
    canonical = _produce_register_block(leader)
    response, anchor = _snapshot_response(leader)

    forged = copy.deepcopy(response.blocks[0])
    forged["receipts"][0]["signer"] = "@forged"
    tampered_response = _replace_checkpoint(response, forged)

    follower = _executor(tmp_path, "follower")
    with pytest.raises(
        ExecutorError,
        match="state_sync_verify_failed:snapshot_checkpoint_commitment_invalid:receipts_root_mismatch",
    ):
        follower.apply_state_sync_response(
            tampered_response,
            trusted_anchor=anchor,
            allow_snapshot_bootstrap=True,
        )

    assert int(follower.state.get("height") or 0) == 0
    assert follower.get_block_by_height(1) is None

    metas = follower.apply_state_sync_response(
        response,
        trusted_anchor=anchor,
        allow_snapshot_bootstrap=True,
    )
    assert isinstance(metas, list)
    assert int(follower.state.get("height") or 0) == 1

    stored = follower.get_block_by_height(1)
    assert isinstance(stored, dict)
    assert stored["block_id"] == canonical["block_id"]
    assert stored["block_hash"] == canonical["block_hash"]
    assert stored["header"]["receipts_root"] == canonical["header"]["receipts_root"]
    assert stored["receipts"] == canonical["receipts"]

    restarted = _executor(tmp_path, "follower")
    restarted_block = restarted.get_block_by_height(1)
    assert isinstance(restarted_block, dict)
    assert int(restarted.state.get("height") or 0) == 1
    assert restarted_block["block_id"] == canonical["block_id"]
    assert restarted_block["block_hash"] == canonical["block_hash"]
    assert restarted_block["header"]["receipts_root"] == canonical["header"]["receipts_root"]
    assert restarted_block["receipts"] == canonical["receipts"]


class _ReadExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return copy.deepcopy(self._state)


def _session() -> dict:
    return {
        "active": True,
        "issued_at_ts": 1,
        "ttl_s": 100,
        "device_id": "browser:p0-a12",
    }


def _privacy_state() -> dict:
    return {
        "chain_id": "p0-a12-closure",
        "height": 7,
        "time": 10,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-alice": _session()},
            },
            "@j1": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-j1": _session()},
            },
            "@mallory": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-mallory": _session()},
            },
        },
        "roles": {"jurors": {"active_set": ["@j1"]}},
        "poh": {
            "async_cases": {
                "async:alice:1": {
                    "account_id": "@alice",
                    "status": "assigned",
                    "assigned_jurors": ["@j1"],
                    "jurors": {"@j1": {"accepted": True}},
                    "evidence_commitments": {},
                    "evidence_binds": {},
                    "reviewer_restricted_evidence": {},
                    "reviewable_evidence": {},
                    "public_evidence_ids": [],
                }
            },
            "tier2_cases": {
                "tier2:alice:1": {
                    "account_id": "@alice",
                    "status": "assigned",
                    "jurors": {"@j1": {"accepted": True}},
                    "evidence": {"commitment": "private-tier2-metadata"},
                }
            },
            "live_cases": {
                "live:alice:1": {
                    "account_id": "@alice",
                    "status": "init",
                    "session_commitment": "session-commitment",
                    "room_commitment": "room-commitment",
                    "prompt_commitment": "prompt-commitment",
                    "jurors": {"@j1": {"role": "interacting", "accepted": True}},
                }
            },
            "live_sessions": {},
            "live_session_participants": {},
        },
    }


def _client() -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _ReadExecutor(_privacy_state())
    return TestClient(app, raise_server_exceptions=False)


def _headers(account: str, session_key: str) -> dict[str, str]:
    return {
        "x-weall-account": account,
        "x-weall-session-key": session_key,
    }


@pytest.mark.parametrize(
    ("path", "principal", "session_key"),
    [
        ("/v1/poh/async/my-cases?account=@alice", "@alice", "sk-alice"),
        ("/v1/poh/async/juror-cases?juror=@j1", "@j1", "sk-j1"),
        ("/v1/poh/tier2/my-cases?account=@alice", "@alice", "sk-alice"),
        ("/v1/poh/tier2/juror-cases?juror=@j1", "@j1", "sk-j1"),
        ("/v1/poh/live/my-cases?account=@alice", "@alice", "sk-alice"),
        ("/v1/poh/live/assigned?juror=@j1", "@j1", "sk-j1"),
    ],
)
def test_a12_all_scoped_poh_queues_require_session_and_exact_principal(
    path: str,
    principal: str,
    session_key: str,
) -> None:
    """A12-F001/A18-F002: every sensitive queue is session-bound at the real API."""

    client = _client()

    anonymous = client.get(path)
    assert anonymous.status_code == 403, anonymous.text
    assert anonymous.json()["error"]["code"] == "poh_session_required"

    wrong_identity = client.get(path, headers=_headers("@mallory", "sk-mallory"))
    assert wrong_identity.status_code == 403, wrong_identity.text
    assert wrong_identity.json()["error"]["code"] == "poh_session_identity_mismatch"

    authorized = client.get(path, headers=_headers(principal, session_key))
    assert authorized.status_code == 200, authorized.text


@pytest.mark.parametrize(
    "path",
    [
        "/v1/poh/tier2/case/tier2:alice:1",
        "/v1/poh/live/case/live:alice:1",
    ],
)
def test_a12_full_case_views_are_participant_only_at_real_api(path: str) -> None:
    """A12-F001: full Tier-2/Live reviewer and evidence maps are participant-only."""

    client = _client()

    anonymous = client.get(path)
    assert anonymous.status_code == 403, anonymous.text
    assert anonymous.json()["error"]["code"] == "poh_session_required"

    unrelated = client.get(path, headers=_headers("@mallory", "sk-mallory"))
    assert unrelated.status_code == 403, unrelated.text
    assert unrelated.json()["error"]["code"] == "poh_case_viewer_forbidden"

    applicant = client.get(path, headers=_headers("@alice", "sk-alice"))
    assert applicant.status_code == 200, applicant.text

    juror = client.get(path, headers=_headers("@j1", "sk-j1"))
    assert juror.status_code == 200, juror.text
