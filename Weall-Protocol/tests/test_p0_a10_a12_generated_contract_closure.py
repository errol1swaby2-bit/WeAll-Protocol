from __future__ import annotations

import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.groups import apply_groups
from weall.runtime.group_treasury_scheduler import group_spend_plan_hash
from weall.runtime.tx_admission_types import TxEnvelope


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _api_vectors() -> dict[str, dict]:
    payload = json.loads(
        (_repo_root() / "generated" / "api_response_vectors_v1_5.json").read_text(encoding="utf-8")
    )
    vectors = payload.get("vectors") if isinstance(payload, dict) else None
    assert isinstance(vectors, list)
    return {
        str(vector.get("id")): vector
        for vector in vectors
        if isinstance(vector, dict) and str(vector.get("id") or "").strip()
    }


def _economic_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 20,
        "time": 100,
        "params": {
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "accounts": {
            "@recipient": {
                "balance": 0,
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            }
        },
        "treasury_wallets": {
            "TREASURY_GROUP::group-1": {
                "wallet_id": "TREASURY_GROUP::group-1",
                "balance": 25,
            }
        },
        "system_queue": [],
    }


def _approved_spend() -> tuple[dict, dict]:
    spend = {
        "spend_id": "spend-replay-1",
        "group_id": "group-1",
        "treasury_id": "TREASURY_GROUP::group-1",
        "to": "@recipient",
        "amount": 10,
        "status": "proposed",
        "signatures": {"@signer": {"at_nonce": 1}},
        "allowed_signers": ["@signer"],
        "threshold": 1,
        "created_at_height": 10,
        "earliest_execute_height": 15,
    }
    approval = {
        "proposal_id": "proposal-replay-1",
        "group_id": "group-1",
        "treasury_id": "TREASURY_GROUP::group-1",
        "to": "@recipient",
        "amount": 10,
        "spend_plan_hash": group_spend_plan_hash(spend),
    }
    spend["governance_approval"] = approval
    payload = {
        "spend_id": "spend-replay-1",
        "_governance_proposal_id": approval["proposal_id"],
        "_approved_spend_plan_hash": approval["spend_plan_hash"],
    }
    return spend, payload


def _group_execute(payload: dict, *, nonce: int) -> TxEnvelope:
    return TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_EXECUTE",
        signer="SYSTEM",
        nonce=nonce,
        payload=dict(payload),
        system=True,
        chain_id="weall-prod",
    )


def test_a10_governance_bound_value_movement_is_one_shot_after_serialized_state_replay() -> None:
    """A10-F005: a governed spend may move value once, never again on replay."""

    state = _economic_state()
    spend, payload = _approved_spend()
    state["group_treasury_spends"] = {spend["spend_id"]: spend}

    first = apply_groups(state, _group_execute(payload, nonce=1))
    assert first == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-replay-1",
        "to": "@recipient",
        "amount": 10,
    }
    assert state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert state["accounts"]["@recipient"]["balance"] == 10
    assert state["group_treasury_spends"]["spend-replay-1"]["status"] == "executed"

    persisted = json.loads(json.dumps(state, sort_keys=True))
    replay = apply_groups(persisted, _group_execute(payload, nonce=2))

    assert replay == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-replay-1",
        "deduped": True,
    }
    assert persisted["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert persisted["accounts"]["@recipient"]["balance"] == 10


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
        "device_id": "browser:p0-a12-vectors",
    }


def _privacy_state() -> dict:
    return {
        "chain_id": "p0-a12-generated-vector-closure",
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


def _vector_error_code(vector: dict) -> str:
    envelope = vector.get("expected_error_envelope")
    assert isinstance(envelope, dict)
    error = envelope.get("error")
    assert isinstance(error, dict)
    code = str(error.get("code") or "").strip()
    assert code
    return code


def test_a12_generated_scoped_queue_vectors_execute_against_runtime() -> None:
    """A12-F001/A18-F002: generated auth vectors are executable runtime truth."""

    vectors = _api_vectors()
    cases = [
        (
            "poh-async-my-cases-requires-session",
            "/v1/poh/async/my-cases?account=@alice",
            "@alice",
            "sk-alice",
        ),
        (
            "poh-async-juror-cases-session",
            "/v1/poh/async/juror-cases?juror=@j1",
            "@j1",
            "sk-j1",
        ),
        (
            "poh-tier2-my-cases-session",
            "/v1/poh/tier2/my-cases?account=@alice",
            "@alice",
            "sk-alice",
        ),
        (
            "poh-tier2-juror-cases-session",
            "/v1/poh/tier2/juror-cases?juror=@j1",
            "@j1",
            "sk-j1",
        ),
        (
            "poh-live-my-cases-session",
            "/v1/poh/live/my-cases?account=@alice",
            "@alice",
            "sk-alice",
        ),
        (
            "poh-live-assigned-session",
            "/v1/poh/live/assigned?juror=@j1",
            "@j1",
            "sk-j1",
        ),
    ]
    client = _client()

    for vector_id, path, principal, session_key in cases:
        vector = vectors[vector_id]
        assert vector["route_present"] is True
        assert "poh_session_required" in vector["error_codes"]
        assert "poh_session_identity_mismatch" in vector["error_codes"]

        anonymous = client.get(path)
        assert anonymous.status_code == 403, (vector_id, anonymous.text)
        assert anonymous.json()["error"]["code"] == _vector_error_code(vector)

        wrong = client.get(path, headers=_headers("@mallory", "sk-mallory"))
        assert wrong.status_code == 403, (vector_id, wrong.text)
        assert wrong.json()["error"]["code"] == "poh_session_identity_mismatch"

        authorized = client.get(path, headers=_headers(principal, session_key))
        assert authorized.status_code == 200, (vector_id, authorized.text)


def test_a12_generated_full_case_vectors_execute_participant_privacy_boundary() -> None:
    """A12-F001/A18-F002: generated full-case vectors enforce participant-only reads."""

    vectors = _api_vectors()
    cases = [
        (
            "poh-tier2-case-participant-session",
            "/v1/poh/tier2/case/tier2:alice:1",
        ),
        (
            "poh-live-case-participant-session",
            "/v1/poh/live/case/live:alice:1",
        ),
    ]
    client = _client()

    for vector_id, path in cases:
        vector = vectors[vector_id]
        assert vector["route_present"] is True
        assert "poh_session_required" in vector["error_codes"]
        assert "poh_case_viewer_forbidden" in vector["error_codes"]

        anonymous = client.get(path)
        assert anonymous.status_code == 403, (vector_id, anonymous.text)
        assert anonymous.json()["error"]["code"] == _vector_error_code(vector)

        unrelated = client.get(path, headers=_headers("@mallory", "sk-mallory"))
        assert unrelated.status_code == 403, (vector_id, unrelated.text)
        assert unrelated.json()["error"]["code"] == "poh_case_viewer_forbidden"

        applicant = client.get(path, headers=_headers("@alice", "sk-alice"))
        assert applicant.status_code == 200, (vector_id, applicant.text)

        juror = client.get(path, headers=_headers("@j1", "sk-j1"))
        assert juror.status_code == 200, (vector_id, juror.text)
