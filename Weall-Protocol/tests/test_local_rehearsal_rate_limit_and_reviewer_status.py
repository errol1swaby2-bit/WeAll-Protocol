from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.security import RateLimitMiddleware
from weall.runtime.tx_schema import validate_tx_envelope


def test_rate_limit_buckets_can_be_raised_by_explicit_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "devnet")
    monkeypatch.setenv("WEALL_RL_WRITE_RATE_PER_SEC", "100")
    monkeypatch.setenv("WEALL_RL_WRITE_BURST", "100")

    app = FastAPI()

    @app.post("/v1/tx/submit")
    def _submit():
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware, ttl_s=60, max_keys=100, prune_every=1)

    with TestClient(app) as client:
        statuses = [client.post("/v1/tx/submit").status_code for _ in range(30)]

    assert statuses == [200] * 30


def test_reputation_delta_apply_schema_accepts_replay_provenance_fields() -> None:
    _, payload = validate_tx_envelope({
        "tx_type": "REPUTATION_DELTA_APPLY",
        "signer": "SYSTEM",
        "nonce": 0,
        "sig": "SYSTEM",
        "system": True,
        "payload": {
            "account_id": "@alice",
            "delta": 1.5,
            "delta_id": "repaccrual:public_post:post1",
            "reason": "public_content_accrual",
            "event_code": "SAFETY_ACCURATE_REPORT",
            "source_flow": "reputation_delta",
            "source_object_id": "post1",
            "target_id": "post1",
            "occurred_at_block": 58,
            "occurred_at_time": 58,
            "expires_at_optional": None,
            "reversal_of_optional": "",
        },
    })

    assert payload is not None
    assert payload.account_id == "@alice"
    assert payload.source_object_id == "post1"


def test_local_rehearsal_script_raises_rate_limit_headroom_and_honors_queue_env() -> None:
    src = open("scripts/devnet_local_two_frontend_rehearsal.sh", encoding="utf-8").read()
    assert "WEALL_RL_WRITE_RATE_PER_SEC" in src
    assert "WEALL_RL_WRITE_BURST" in src
    assert "WEALL_RL_READ_RATE_PER_SEC" in src
    assert "WEALL_RL_READ_BURST" in src
    assert 'WEALL_TX_QUEUE_DRAIN_BATCH="${WEALL_TX_QUEUE_DRAIN_BATCH:-25}"' in src
    assert 'WEALL_RECONCILE_POLL_S="${WEALL_RECONCILE_POLL_S:-1}"' in src


def test_reviewer_lane_copy_distinguishes_pending_from_paused() -> None:
    src = open("../web/src/lib/reviewLanes.ts", encoding="utf-8").read()
    assert "Opted in, activation pending" not in src
    assert "Opted in" in src
    assert "Active" in src
    assert "Opted in, paused/inactive" not in src
    assert "paused_at_nonce" in src
