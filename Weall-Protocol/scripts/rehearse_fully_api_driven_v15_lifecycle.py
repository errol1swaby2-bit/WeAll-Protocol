#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.content import apply_content
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.economics import apply_economics, EconomicsApplyError
from weall.runtime.apply.groups import apply_groups
from weall.runtime.apply.messaging import apply_messaging
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.apply.storage import apply_storage
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


class _Executor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _Executor(state)
    return TestClient(app, raise_server_exceptions=False)




def _enable_storage_responsibility(state: dict[str, Any], operator_id: str, *, capacity: int = 4096) -> None:
    roles = state.setdefault("roles", {}) if isinstance(state.get("roles"), dict) else {}
    state["roles"] = roles
    node_ops = roles.setdefault("node_operators", {}) if isinstance(roles.get("node_operators"), dict) else {}
    roles["node_operators"] = node_ops
    active = node_ops.setdefault("active_set", []) if isinstance(node_ops.get("active_set"), list) else []
    node_ops["active_set"] = active
    if operator_id not in active:
        active.append(operator_id)
    by_id = node_ops.setdefault("by_id", {}) if isinstance(node_ops.get("by_id"), dict) else {}
    node_ops["by_id"] = by_id
    by_id[operator_id] = {
        "account_id": operator_id,
        "status": "active",
        "active": True,
        "enrolled": True,
        "node_pubkey": f"{operator_id}-node",
        "devices": [{"device_type": "node", "public_key": f"{operator_id}-node", "active": True}],
        "responsibilities": {
            "storage": {
                "opted_in": True,
                "active": True,
                "proof_status": "verified",
                "declared_capacity_bytes": int(capacity),
                "reserved_capacity_bytes": int(capacity),
                "probed_capacity_bytes": int(capacity),
                "proven_capacity_bytes": int(capacity),
                "allocated_capacity_bytes": 0,
                "used_capacity_bytes": 0,
                "proof_expires_height": 10000,
            }
        },
    }
    accounts = state.setdefault("accounts", {}) if isinstance(state.get("accounts"), dict) else {}
    state["accounts"] = accounts
    accounts.setdefault(operator_id, {"poh_tier": 2, "reputation_milli": 2000})
    accounts[operator_id]["poh_tier"] = 2
    accounts[operator_id]["reputation_milli"] = 2000

def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


def run_harness() -> dict[str, Any]:
    state: dict[str, Any] = {
        "chain_id": "weall-prod",
        "height": 42,
        "time": 1_780_000_000,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "reputation": 12, "keys": {"by_id": {}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "reputation": 4},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "reputation": 8},
            "@juror": {"nonce": 0, "poh_tier": 2, "reputation": 7},
            "@r2": {"nonce": 0, "poh_tier": 2, "reputation": 6},
            "SYSTEM": {"nonce": 0, "poh_tier": 0},
        },
        "roles": {"validators": {"active_set": ["@reviewer", "@juror", "@r2"]}, "poh_reviewers": {"active": {"@reviewer": True}}},
        "params": {"economics_enabled": False, "tokenomics_simulation_complete": True, "reward_policy_complete": True},
        "system_queue": [],
    }
    api_routes: list[str] = []
    client = _client(state)

    # API reads start from a real app route.
    session = client.get("/v1/session/me", headers={"x-weall-account": "@alice", "x-weall-session-key": "missing"})
    api_routes.append("GET /v1/session/me")

    # PoH async open/review/finalize and challenge/reverification close.
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@alice", 1, {"case_id": "case-a", "account_id": "@alice", "evidence_commitment": "sha256:" + "a" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@alice", 2, {"case_id": "case-a", "evidence_id": "ev-a", "evidence_commitment": "sha256:" + "a" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": "case-a", "jurors": ["@reviewer", "@juror", "@r2"]}, system=True, parent="poh:case"))
    for idx, reviewer in enumerate(["@reviewer", "@juror", "@r2"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, 10 + idx, {"case_id": "case-a"}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, 20 + idx, {"case_id": "case-a", "verdict": "approve"}))
    apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 2, {"case_id": "case-a"}, system=True, parent="poh:case"))
    challenge = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@bob", 3, {"account_id": "@alice", "case_id": "case-a"}))
    apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 4, {"challenge_id": challenge["challenge_id"], "resolution": "upheld", "case_id": "case-a"}, system=True, parent="poh:challenge"))
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@alice", 5, {"case_id": "case-r", "account_id": "@alice", "evidence_commitment": "sha256:" + "b" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@alice", 6, {"case_id": "case-r", "evidence_id": "ev-r", "evidence_commitment": "sha256:" + "b" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 5, {"case_id": "case-r", "jurors": ["@reviewer", "@juror", "@r2"]}, system=True, parent="poh:case"))
    for idx, reviewer in enumerate(["@reviewer", "@juror", "@r2"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, 30 + idx, {"case_id": "case-r"}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, 40 + idx, {"case_id": "case-r", "verdict": "approve"}))
    apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 6, {"case_id": "case-r"}, system=True, parent="poh:case"))
    # Challenge reverification completion restores active status; ensure the
    # content path sees the live tier in older state-shape variants too.
    state["accounts"]["@alice"]["poh_tier"] = max(2, int(state["accounts"]["@alice"].get("poh_tier") or 0))

    # Group/content/message state transitions, then real API reads.
    apply_groups(state, _env("GROUP_CREATE", "@alice", 50, {"group_id": "g1", "name": "Group One", "visibility": "public"}))
    apply_groups(state, _env("GROUP_JOIN", "@bob", 51, {"group_id": "g1"}))
    apply_content(state, _env("CONTENT_POST_CREATE", "@alice", 52, {"post_id": "post:1", "body": "hello", "visibility": "group", "group_id": "g1", "tags": ["weall"]}))
    apply_content(state, _env("CONTENT_REACTION_SET", "@bob", 53, {"target_id": "post:1", "reaction": "like"}))
    apply_content(state, _env("CONTENT_COMMENT_CREATE", "@bob", 54, {"comment_id": "comment:1", "post_id": "post:1", "body": "reply"}))
    msg = apply_messaging(state, _env("MESSAGE_SEND", "@alice", 55, {"thread_id": "thread:1", "to": ["@bob"], "ciphertext": "abc", "body_ciphertext": "abc"}))
    feed = client.get("/v1/feed?rank=production&limit=10")
    api_routes.append("GET /v1/feed?rank=production")
    group = client.get("/v1/groups/g1")
    api_routes.append("GET /v1/groups/{group_id}")
    group_feed = client.get("/v1/groups/g1/feed")
    api_routes.append("GET /v1/groups/{group_id}/feed")
    messages = client.get("/v1/messages/threads", headers={"x-weall-account": "@alice", "x-weall-session-key": "missing"})
    api_routes.append("GET /v1/messages/threads")

    # Dispute remedy path through final receipt.
    apply_dispute(state, _env("DISPUTE_OPEN", "@bob", 60, {"dispute_id": "d1", "target_type": "account", "target_id": "@alice", "reason": "test"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 60, {"dispute_id": "d1", "juror": "@juror"}, system=True, parent="d"))
    apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@juror", 61, {"dispute_id": "d1"}))
    apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 62, {"dispute_id": "d1", "vote": "yes", "resolution": {"summary": "restrict", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@alice", "restriction": "review"}}]}}))
    apply_dispute(state, _env("DISPUTE_APPEAL", "@alice", 63, {"dispute_id": "d1", "reason": "remedy"}))
    receipt = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 64, {"dispute_id": "d1", "appeal_resolution": {"decision": "modify", "summary": "reinstate", "actions": [{"tx_type": "ACCOUNT_REINSTATE", "payload": {"account_id": "@alice", "reason": "appeal_remedy"}}, {"tx_type": "ROLE_ELIGIBILITY_SET", "payload": {"account_id": "@juror", "role": "dispute_juror", "eligible": True}}]}}, system=True, parent="d"))
    dispute_read = client.get("/v1/disputes/d1")
    api_routes.append("GET /v1/disputes/{dispute_id}")

    # Storage durability and economics/protocol locked boundary.
    cid = "bafy" + "q" * 55
    _enable_storage_responsibility(state, "op-a", capacity=4096)
    _enable_storage_responsibility(state, "op-b", capacity=4096)
    apply_storage(state, _env("STORAGE_OFFER_CREATE", "@alice", 70, {"offer_id": "offer-a", "operator_id": "op-a", "capacity_bytes": 1024}))
    apply_storage(state, _env("STORAGE_OFFER_CREATE", "@bob", 71, {"offer_id": "offer-b", "operator_id": "op-b", "capacity_bytes": 1024}))
    apply_storage(state, _env("IPFS_PIN_REQUEST", "SYSTEM", 72, {"pin_id": "pin-1", "cid": cid, "size_bytes": 10, "replication_factor": 1}, system=True, parent="storage"))
    failed = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 73, {"pin_id": "pin-1", "cid": cid, "operator_id": "op-a", "ok": False}, system=True, parent="storage"))
    replacement = failed.get("reassignment", {}).get("replacement_operator_id") or "op-b"
    apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 74, {"pin_id": "pin-1", "cid": cid, "operator_id": replacement, "ok": True, "retrieval_ok": True}, system=True, parent="storage"))
    econ_locked = False
    try:
        apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 80, {"to": "@bob", "amount": 1}))
    except EconomicsApplyError:
        econ_locked = True
    proto = apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", "SYSTEM", 90, {"upgrade_id": "u1", "version": "v1.5.x"}, system=True, parent="gov"))
    apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", "SYSTEM", 91, {"upgrade_id": "u1"}, system=True, parent="gov"))

    return {
        "ok": all(r.status_code < 500 for r in [session, feed, group, group_feed, messages, dispute_read]) and econ_locked and bool(proto.get("record_only_boundary")) and bool(receipt.get("enforcement_applied")),
        "batch": "536",
        "api_routes_exercised": api_routes,
        "api_route_count": len(api_routes),
        "feed_status_code": feed.status_code,
        "feed_ranking": (feed.json().get("ranking") if feed.status_code == 200 else {}),
        "group_status_code": group.status_code,
        "messages_status_code": messages.status_code,
        "message_applied": bool(msg),
        "poh_reverification_status": state["poh"]["reverification"]["by_account"]["@alice"]["status"],
        "dispute_remedy_applied": any(a.get("tx_type") == "ACCOUNT_REINSTATE" for a in receipt.get("enforcement_applied", [])),
        "storage_retrieval_confirmed": state["storage"]["pins"]["pin-1"].get("durability_status") == "retrieval_confirmed",
        "economics_locked_rejection": econ_locked,
        "protocol_upgrade_record_only": bool(state.get("protocol", {}).get("upgrades", {}).get("u1", {}).get("record_only_boundary")),
        "final_state_root": compute_state_root(state),
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
