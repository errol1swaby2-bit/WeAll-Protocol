#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.content import apply_content
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.groups import apply_groups
from weall.runtime.apply.messaging import apply_messaging
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.apply.storage import apply_storage
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope

CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


class _Executor:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state

    def read_state(self) -> dict[str, Any]:
        return self.state

    def snapshot(self) -> dict[str, Any]:
        return self.state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _Executor(state)
    return TestClient(app, raise_server_exceptions=False)


def _base_state() -> dict[str, Any]:
    return {
        "height": 300,
        "chain_id": "weall-prod",
        "time": 2_000_000_000,
        "params": {"economic_unlock_time": 1, "economics_enabled": False, "ipfs_replication_factor": 2},
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "reputation": 30, "banned": False, "locked": False, "session_keys": {"sk:@alice": {"active": True}}, "security_policy": {"messaging_encryption_key_id": "alice-key", "messaging_encryption_public_jwk": {"kty": "EC", "crv": "P-256", "x": "alice-x", "y": "alice-y"}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "reputation": 15, "banned": False, "locked": False, "session_keys": {"sk:@bob": {"active": True}}, "security_policy": {"messaging_encryption_key_id": "bob-key", "messaging_encryption_public_jwk": {"kty": "EC", "crv": "P-256", "x": "bob-x", "y": "bob-y"}}},
            "@juror": {"nonce": 0, "poh_tier": 2, "reputation": 10, "banned": False, "locked": False},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "reputation": 8, "banned": False, "locked": False},
            "SYSTEM": {"nonce": 0, "poh_tier": 0},
        },
        "roles": {"validators": {"active_set": ["@alice", "@bob", "@juror"]}, "poh_reviewers": {"active": {"@reviewer": True}}},
        "system_queue": [],
        "poh": {"async_cases": {}, "challenges": {}},
        "economics": {
            "fee_policy": {"post_fee_int": 0, "comment_fee_int": 0, "reaction_fee_int": 0, "transfer_fee_int": 0},
            "reward_policy": {"recipient_eligibility": {"min_poh_tier": 2}},
            "wallet_policy": {"initialization": "genesis_or_first_verified_account"},
            "anti_farming_policy": {"duplicate_reward_window": 30},
            "treasury_accountability_policy": {"public_receipts_required": True},
            "transfer_receipt_policy": {"pending_and_failed_receipts_required": True},
        },
        "treasury_wallets": {"community": "treasury:community"},
        "tokenomics_simulation": {"cap_int": 21_000_000},
    }


def _run_poh_challenge_reverify(state: dict[str, Any]) -> dict[str, Any]:
    case_id = "poh-case-life"
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@alice", 1, {"case_id": case_id, "account_id": "@alice", "evidence_commitment": "sha256:" + "a" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@alice", 2, {"case_id": case_id, "evidence_id": "ev1", "evidence_commitment": "sha256:" + "a" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": case_id, "jurors": ["@reviewer", "@bob", "@juror"]}, system=True, parent="poh:case"))
    for idx, juror in enumerate(["@reviewer", "@bob", "@juror"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", juror, idx, {"case_id": case_id}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", juror, idx + 10, {"case_id": case_id, "verdict": "approve"}))
    apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 1, {"case_id": case_id}, system=True, parent="poh:case"))
    open_out = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@bob", 1, {"account_id": "@alice", "case_id": case_id, "reason": "duplicate-human-risk"}))
    cid = str(open_out["challenge_id"])
    resolved = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 2, {"challenge_id": cid, "resolution": "upheld", "case_id": case_id}, system=True, parent="poh:challenge"))
    rev_case = "poh-case-reverify"
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@alice", 3, {"case_id": rev_case, "account_id": "@alice", "evidence_commitment": "sha256:" + "b" * 64, "challenge_id": cid}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@alice", 4, {"case_id": rev_case, "evidence_id": "ev2", "evidence_commitment": "sha256:" + "b" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 2, {"case_id": rev_case, "jurors": ["@bob", "@juror", "@reviewer"]}, system=True, parent="poh:reverify"))
    for idx, juror in enumerate(["@bob", "@juror", "@reviewer"], start=20):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", juror, idx, {"case_id": rev_case}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", juror, idx + 10, {"case_id": rev_case, "verdict": "approve"}))
    finalized = apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 3, {"case_id": rev_case}, system=True, parent="poh:reverify"))
    return {"challenge_id": cid, "resolve": resolved, "reverify_finalize": finalized, "reviewer_eligible": state["accounts"]["@reviewer"].get("poh_reviewer_eligible")}


def run_harness() -> dict[str, Any]:
    state = _base_state()
    poh = _run_poh_challenge_reverify(state)
    group = apply_groups(state, _env("GROUP_CREATE", "@bob", 1, {"group_id": "g-life", "name": "Lifecycle", "visibility": "public"}))
    post = apply_content(state, _env("CONTENT_POST_CREATE", "@bob", 3, {"post_id": "post:lifecycle:api", "body": "v1.5 api lifecycle", "visibility": "public", "tags": ["v15"]}))
    apply_content(state, _env("CONTENT_REACTION_SET", "@bob", 3, {"target_id": "post:lifecycle:api", "reaction": "helpful"}))
    msg = apply_messaging(state, _env("DIRECT_MESSAGE_SEND", "@bob", 4, {
        "thread_id": "thread-life",
        "to": "@alice",
        "message_id": "msg-life",
        "encryption": "WEALL_E2EE_V1",
        "ciphertext_b64": "Y2lwaGVy",
        "iv_b64": "aXY=",
        "sender_encryption_key_id": "bob-key",
        "recipient_encryption_key_id": "alice-key",
        "sender_encryption_public_jwk": {"kty": "EC", "crv": "P-256", "x": "bob-x", "y": "bob-y"},
        "recipient_encryption_public_jwk": {"kty": "EC", "crv": "P-256", "x": "alice-x", "y": "alice-y"},
    }))
    dispute = apply_dispute(state, _env("DISPUTE_OPEN", "@bob", 4, {"dispute_id": "d-api-life", "target_type": "content", "target_id": "post:lifecycle:api", "reason": "appealable lifecycle"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 4, {"dispute_id": "d-api-life", "juror": "@juror"}, system=True, parent="dispute:open"))
    apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@juror", 5, {"dispute_id": "d-api-life"}))
    apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 6, {"dispute_id": "d-api-life", "vote": "yes", "resolution": {"summary": "temporary account posting limit", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@bob", "restriction": "posting_limited"}}]}}))
    final = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 7, {"dispute_id": "d-api-life"}, system=True, parent="dispute:resolve"))
    state.setdefault("storage", {}).setdefault("operators", {})["opA"] = {"enabled": True, "capacity_bytes": 1000}
    state["storage"]["operators"]["opB"] = {"enabled": True, "capacity_bytes": 1000}
    state["storage"].setdefault("pins", {})["pin-api"] = {"pin_id": "pin-api", "cid": CID_A, "targets": ["opA"], "size_bytes": 10, "replication_factor": 2}
    failed_pin = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 8, {"pin_id": "pin-api", "cid": CID_A, "operator_id": "opA", "ok": False}, system=True, parent="storage:pin-api"))
    confirmed_pin = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 9, {"pin_id": "pin-api", "cid": CID_A, "operator_id": "opB", "ok": True, "retrieval_ok": True}, system=True, parent="storage:pin-api"))
    econ_rejected = False
    try:
        apply_economics(state, _env("BALANCE_TRANSFER", "@bob", 10, {"to": "@bob", "amount_int": 1}))
    except EconomicsApplyError as exc:
        econ_rejected = exc.reason in {"economics_disabled", "economics_time_locked"}
    declared = apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", "SYSTEM", 11, {"upgrade_id": "u-api-life", "version": "v1.5-api", "hash": "sha256:api"}, system=True, parent="gov:upgrade"))
    activated = apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", "SYSTEM", 12, {"upgrade_id": "u-api-life"}, system=True, parent="protocol:u-api-life"))
    with _client(state) as client:
        session_me = client.get("/v1/session/me", headers={"x-weall-account": "@alice", "x-weall-session-key": "sk:@alice"})
        feed = client.get("/v1/feed?rank=production&limit=5")
    active = state.get("protocol", {}).get("active", {}) if isinstance(state.get("protocol"), dict) else {}
    return {
        "ok": bool(session_me.status_code == 200 and feed.status_code == 200 and feed.json().get("ranking", {}).get("mode") == "production" and final.get("enforcement_applied") and state.get("storage", {}).get("pins", {}).get("pin-api", {}).get("availability_status") == "available" and active.get("record_only_boundary", {}).get("artifact_apply_enabled") is False),
        "batch": "530",
        "api_routes_exercised": ["GET /v1/session/me", "GET /v1/feed"],
        "domains_exercised": ["session", "poh", "groups", "content", "feed", "messaging", "dispute", "storage", "economics_locked", "protocol_upgrade_record_only"],
        "poh": poh,
        "group_id": group.get("group_id") if isinstance(group, dict) else "",
        "post_id": post.get("post_id") if isinstance(post, dict) else "",
        "message_applied": bool(msg),
        "dispute_id": dispute.get("dispute_id") if isinstance(dispute, dict) else "",
        "final_enforcement_count": len(final.get("enforcement_applied", [])) if isinstance(final, dict) else 0,
        "storage_failed_pin_reassigned": bool(failed_pin.get("reassignment")) if isinstance(failed_pin, dict) else False,
        "storage_retrieval_confirmed": bool(state.get("storage", {}).get("pins", {}).get("pin-api", {}).get("availability_status") == "available"),
        "economics_locked_rejection": econ_rejected,
        "protocol_upgrade_record_only": bool(isinstance(active.get("record_only_boundary"), dict) and active["record_only_boundary"].get("artifact_apply_enabled") is False),
        "feed_ranking": feed.json().get("ranking", {}) if feed.status_code == 200 else {},
        "final_state_root": compute_state_root(state),
        "protocol_declare_applied": bool(declared),
        "protocol_activate_applied": bool(activated),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
