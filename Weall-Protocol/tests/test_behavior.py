from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.runtime.apply.consensus import apply_consensus
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.poh import apply_poh
from weall.runtime.poh.state import POH_STATUS_ACTIVE, canonical_account_poh_status, set_account_poh_status
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: dict | None = None, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="",
        system=system,
        parent=parent,
    )


def _run_json(script: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), "--json"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(proc.stdout)


def test_public_bft_multi_process_harness_runs() -> None:
    out = _run_json("rehearse_public_bft_multi_process_v1_5.py")
    assert out["ok"] is True
    assert out["public_validator_enabled"] is False
    assert out["process_count"] == 4
    assert out["validator_count"] == 4
    assert out["quorum_threshold"] == 3
    assert len({row["validator_set_hash"] for row in out["rows"]}) == 1
    assert len({row["vote_payload_sha256"] for row in out["rows"]}) == 4


def test_fresh_node_state_sync_harness_runs() -> None:
    out = _run_json("rehearse_fresh_node_state_sync_v1_5.py")
    assert out["ok"] is True
    assert out["same_state_root"] is True
    assert out["bad_anchor_rejected"] is True
    assert out["source_state_root"] == out["fresh_node_state_root"]


def test_fresh_node_state_sync_direct_snapshot_roundtrip() -> None:
    source_state = {
        "height": 3,
        "tip_hash": "tip-3",
        "finalized": {"height": 3, "block_id": "b3"},
        "accounts": {"alice": {"nonce": 1}, "bob": {"nonce": 2}},
    }
    anchor = build_snapshot_anchor(source_state)
    svc = StateSyncService(
        chain_id="batch500",
        schema_version="1",
        tx_index_hash="hash",
        state_provider=lambda: source_state,
        require_trusted_anchor=True,
        enforce_finalized_anchor=True,
    )
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="batch500",
            schema_version="1",
            tx_index_hash="hash",
            corr_id="b500-direct",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )
    resp = svc.handle_request(req)
    assert resp.ok is True
    svc.verify_response(resp, trusted_anchor=anchor)
    assert compute_state_root(resp.snapshot or {}) == compute_state_root(source_state)


def test_slash_execute_records_accountability_and_queues_non_economic_suspend() -> None:
    state = {
        "height": 10,
        "roles": {"validators": {"active_set": ["validator-a", "validator-b"]}},
        "validators": {
            "registry": {
                "validator-a": {"account": "validator-a", "status": "active", "active": True},
                "validator-b": {"account": "validator-b", "status": "active", "active": True},
            }
        },
        "consensus": {"validator_set": {"epoch": 4, "active_set": ["validator-a", "validator-b"]}},
        "system_queue": [],
    }
    res = apply_consensus(
        state,
        _env(
            "SLASH_EXECUTE",
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent="slash-parent",
            payload={"slash_id": "slash-1", "account": "validator-a", "reason": "equivocation"},
        ),
    )
    assert res is not None
    consequence = res["consequence"]
    assert consequence["economic_penalty_applied"] is False
    assert consequence["non_economic_suspension_queued"] is True
    assert consequence["effective_epoch"] == 5

    rec = state["validators"]["registry"]["validator-a"]
    assert rec["accountability_status"] == "slashed_non_economic"
    assert rec["accountability"]["slash_count"] == 1
    assert rec["status"] == "pending_suspension"

    queued = [item for item in state["system_queue"] if item.get("tx_type") == "VALIDATOR_SUSPEND"]
    assert len(queued) == 1
    assert queued[0]["payload"]["account"] == "validator-a"
    assert queued[0]["payload"]["effective_epoch"] == 5
    assert queued[0]["payload"]["economic_penalty_applied"] is False


def test_upheld_poh_challenge_revokes_and_requires_reverification() -> None:
    state = {"height": 21, "accounts": {"alice": {"poh_tier": 2, "poh_status": "active"}}}
    set_account_poh_status(
        state,
        account_id="alice",
        poh_tier=2,
        status=POH_STATUS_ACTIVE,
        verified_at_height=1,
    )
    apply_poh(
        state,
        _env("POH_CHALLENGE_OPEN", signer="bob", nonce=1, payload={"account_id": "alice", "reason": "duplicate"}),
    )
    res = apply_poh(
        state,
        _env(
            "POH_CHALLENGE_RESOLVE",
            signer="reviewer",
            nonce=2,
            payload={"challenge_id": "pohc:alice:1", "resolution": "upheld"},
        ),
    )
    assert res is not None
    assert res["consequence"]["reverification_required"] is True
    status = canonical_account_poh_status(state, "alice")
    assert status["poh_tier"] == 0
    assert status["status"] == "revoked"
    rev = state["poh"]["reverification"]["by_account"]["alice"]
    assert rev["status"] == "required"
    assert rev["challenge_id"] == "pohc:alice:1"


def test_appealed_dispute_requires_appeal_decision_before_enforcement() -> None:
    state = {
        "height": 40,
        "content": {
            "posts": {
                "post:alice:1": {
                    "id": "post:alice:1",
                    "author": "alice",
                    "visibility": "public",
                    "deleted": False,
                    "labels": [],
                    "locked": False,
                }
            },
            "comments": {},
        },
        "disputes_by_id": {
            "d1": {
                "dispute_id": "d1",
                "id": "d1",
                "stage": "appealed",
                "appeals": [{"by": "alice", "height": 39}],
                "resolution": {
                    "summary": "remove",
                    "actions": [
                        {"tx_type": "CONTENT_LABEL_SET", "payload": {"target_id": "post:alice:1", "labels": ["policy_violation"]}},
                        {"tx_type": "CONTENT_VISIBILITY_SET", "payload": {"target_id": "post:alice:1", "visibility": "deleted"}},
                        {"tx_type": "CONTENT_THREAD_LOCK_SET", "payload": {"target_id": "post:alice:1", "locked": True}},
                    ],
                },
            }
        },
    }
    res = apply_dispute(
        state,
        _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", nonce=1, system=True, payload={"dispute_id": "d1"}),
    )
    assert res is not None
    assert state["disputes_by_id"]["d1"]["stage"] == "appeal_review"
    assert state["content"]["posts"]["post:alice:1"]["visibility"] == "public"

    res2 = apply_dispute(
        state,
        _env(
            "DISPUTE_FINAL_RECEIPT",
            signer="SYSTEM",
            nonce=2,
            system=True,
            payload={"dispute_id": "d1", "appeal_resolution": {"decision": "uphold", "summary": "appeal reviewed; removal upheld"}},
        ),
    )
    assert res2 is not None
    assert state["disputes_by_id"]["d1"]["stage"] == "finalized"
    assert state["disputes_by_id"]["d1"]["appeal_finalization"]["decision"] == "uphold"
    post = state["content"]["posts"]["post:alice:1"]
    assert post["visibility"] == "deleted"
    assert post["deleted"] is True
    assert post["locked"] is True
    assert "policy_violation" in post["labels"]


def test_appeal_reverse_suppresses_delayed_enforcement() -> None:
    state = {
        "height": 41,
        "content": {"posts": {"post:alice:2": {"id": "post:alice:2", "author": "alice", "visibility": "public", "deleted": False, "labels": [], "locked": False}}, "comments": {}},
        "disputes_by_id": {
            "d2": {
                "dispute_id": "d2",
                "id": "d2",
                "stage": "appealed",
                "appeals": [{"by": "alice", "height": 40}],
                "resolution": {
                    "summary": "remove",
                    "actions": [{"tx_type": "CONTENT_VISIBILITY_SET", "payload": {"target_id": "post:alice:2", "visibility": "deleted"}}],
                },
            }
        },
    }
    res = apply_dispute(
        state,
        _env(
            "DISPUTE_FINAL_RECEIPT",
            signer="SYSTEM",
            nonce=1,
            system=True,
            payload={"dispute_id": "d2", "appeal_resolution": {"decision": "reverse", "summary": "appeal accepted"}},
        ),
    )
    assert res is not None
    assert state["disputes_by_id"]["d2"]["stage"] == "finalized"
    assert state["disputes_by_id"]["d2"]["final_resolution"]["actions"] == []
    assert state["content"]["posts"]["post:alice:2"]["visibility"] == "public"


def test_generated_artifact_is_tracked_and_consistent() -> None:
    path = ROOT / "generated" / "b499_b503_mechanics_proof_v1_5.json"
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["ok"] is True
    assert data["truth_boundaries"]["public_validators_enabled"] is False
    assert data["truth_boundaries"]["live_economics_enabled"] is False
    assert data["batches"]["499"]["ok"] is True
    assert data["batches"]["500"]["ok"] is True
