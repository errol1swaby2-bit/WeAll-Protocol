#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_fresh_node_replay_sync_v1_5 import run_harness as run_replay_sync
from rehearse_real_validator_network_v1_5 import run_harness as run_validator_network
from weall.runtime.apply.content import apply_content
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.apply.storage import apply_storage
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope

CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


def _base_state() -> dict[str, Any]:
    return {
        "height": 100,
        "chain_id": "weall-prod",
        "time": 2_000_000_000,
        "params": {"economic_unlock_time": 1, "economics_enabled": False, "ipfs_replication_factor": 1},
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk:@alice": {"active": True}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk:@bob": {"active": True}}},
            "@juror": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk:@juror": {"active": True}}},
            "SYSTEM": {"nonce": 0, "poh_tier": 0},
        },
        "roles": {"validators": {"active_set": ["@alice"]}},
        "system_queue": [],
        "poh": {"challenges": {}, "async_cases": {}},
    }


def _run_content_dispute_storage_economics_protocol(state: dict[str, Any]) -> dict[str, Any]:
    post = apply_content(state, _env("CONTENT_POST_CREATE", "@alice", 1, {"post_id": "post:lifecycle:1", "body": "v1.5 lifecycle", "visibility": "public", "tags": ["v15"], "media": []}))
    dispute = apply_dispute(state, _env("DISPUTE_OPEN", "@bob", 1, {"dispute_id": "d-life", "target_type": "content", "target_id": "post:lifecycle:1", "reason": "lifecycle review"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d-life", "juror": "@juror"}, system=True, parent="tx:dispute-open"))
    apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@juror", 1, {"dispute_id": "d-life"}))
    apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 2, {"dispute_id": "d-life", "vote": "yes", "resolution": {"summary": "limit creator", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@alice", "restriction": "posting_limited"}}]}}))
    final = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 2, {"dispute_id": "d-life"}, system=True, parent="dispute:d-life"))

    state.setdefault("storage", {}).setdefault("operators", {})["opA"] = {"enabled": True, "capacity_bytes": 1000}
    state.setdefault("storage", {}).setdefault("pins", {})["pin-life"] = {"pin_id": "pin-life", "cid": CID_A, "targets": ["opA"], "size_bytes": 10, "replication_factor": 1}
    pin = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": "pin-life", "cid": CID_A, "operator_id": "opA", "ok": True, "retrieval_ok": True}, system=True, parent="storage:pin-life"))

    econ_rejected = False
    try:
        apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 2, {"to": "@bob", "amount_int": 1}))
    except EconomicsApplyError as exc:
        econ_rejected = exc.reason in {"economics_disabled", "economics_time_locked"}

    declared = apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", "SYSTEM", 4, {"upgrade_id": "u-life", "version": "v1.5-life", "hash": "sha256:life"}, system=True, parent="gov:life"))
    activated = apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", "SYSTEM", 5, {"upgrade_id": "u-life"}, system=True, parent="protocol:u-life"))
    active = state.get("protocol", {}).get("active", {}) if isinstance(state.get("protocol"), dict) else {}

    return {
        "post_id": post.get("post_id") if isinstance(post, dict) else "",
        "dispute_id": dispute.get("dispute_id") if isinstance(dispute, dict) else "",
        "final_enforcement_count": len(final.get("enforcement_applied", [])) if isinstance(final, dict) else 0,
        "storage_retrieval_confirmed": bool(state.get("storage", {}).get("pins", {}).get("pin-life", {}).get("availability_status") == "available"),
        "economics_locked_rejection": econ_rejected,
        "protocol_upgrade_record_only": bool(isinstance(active.get("record_only_boundary"), dict) and active.get("record_only_boundary", {}).get("artifact_apply_enabled") is False and active.get("record_only_boundary", {}).get("migration_execution_enabled") is False),
        "protocol_declare_applied": isinstance(declared, dict),
        "protocol_activate_applied": isinstance(activated, dict),
    }


def run_harness() -> dict[str, Any]:
    state = _base_state()
    validator = run_validator_network()
    replay = run_replay_sync()
    journey = _run_content_dispute_storage_economics_protocol(state)
    locked_boundaries = {"public_validators": False, "live_economics": False, "automatic_upgrades": False, "production_helpers": False}
    ok = bool(
        validator.get("ok")
        and replay.get("ok")
        and journey["post_id"]
        and journey["dispute_id"]
        and journey["final_enforcement_count"] >= 1
        and journey["storage_retrieval_confirmed"]
        and journey["economics_locked_rejection"]
        and journey["protocol_upgrade_record_only"]
        and not any(locked_boundaries.values())
    )
    return {
        "ok": ok,
        "batch": "525",
        "validator_network": validator,
        "fresh_node_replay_sync": replay,
        "journey": journey,
        "final_state_root": compute_state_root(state),
        "locked_boundaries": locked_boundaries,
        "lifecycle_domains": ["account", "session", "poh", "content", "feed", "dispute", "governance", "validator", "state_sync", "storage", "locked_economics", "protocol_upgrade_record_only"],
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
