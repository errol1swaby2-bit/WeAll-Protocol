#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for p in (SRC, SCRIPTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from rehearse_fresh_node_sync_completion_v1_5 import run_harness as run_fresh_sync
from rehearse_controlled_validator_network_completion_v1_5 import run_harness as run_validator_network
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.storage import apply_storage
from weall.runtime.poh.state import POH_STATUS_ACTIVE, canonical_account_poh_status, set_account_poh_status
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]
CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: Json | None = None, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="", system=system, parent=parent)


def run_storage_reassignment() -> Json:
    state: Json = {
        "height": 5,
        "params": {"ipfs_replication_factor": 2},
        "storage": {
            "operators": {
                "op-a": {"enabled": True, "capacity_bytes": 10_000, "used_bytes": 0},
                "op-b": {"enabled": True, "capacity_bytes": 10_000, "used_bytes": 0},
                "op-c": {"enabled": True, "capacity_bytes": 10_000, "used_bytes": 0},
            }
        },
    }
    pin = apply_storage(state, _env("IPFS_PIN_REQUEST", signer="alice", nonce=1, payload={"pin_id": "pin-complete", "cid": CID_A, "size_bytes": 0}))
    targets = list(pin["targets"])
    failed = targets[0]
    confirm = apply_storage(state, _env("IPFS_PIN_CONFIRM", signer="SYSTEM", system=True, parent="pin-complete", nonce=2, payload={"pin_id": "pin-complete", "cid": CID_A, "operator_id": failed, "ok": False}))
    rec = state["storage"]["pins"]["pin-complete"]
    return {
        "ok": bool(confirm.get("reassignment", {}).get("reassigned") is True and failed not in rec.get("targets", []) and len(rec.get("targets", [])) == 2),
        "initial_targets": targets,
        "failed_operator_id": failed,
        "reassignment": confirm.get("reassignment"),
        "final_targets": list(rec.get("targets", [])),
        "durability_status": rec.get("durability_status"),
    }


def run_dispute_account_enforcement() -> Json:
    state: Json = {
        "height": 8,
        "accounts": {"mallory": {}},
        "disputes_by_id": {
            "d-account": {
                "dispute_id": "d-account",
                "id": "d-account",
                "stage": "appeal_review",
                "appeals": [{"by": "mallory", "height": 7}],
                "resolution": {
                    "summary": "account abuse upheld",
                    "actions": [
                        {"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "mallory", "restriction": "posting_limited", "reason": "abuse_upheld"}}
                    ],
                },
                "appeal_panel_result": {"reached": True, "decision": "uphold", "resolution": {"decision": "uphold"}},
            }
        },
    }
    out = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", system=True, parent="d-account", nonce=9, payload={"dispute_id": "d-account"}))
    rec = state["accounts"]["mallory"]
    return {
        "ok": bool(rec.get("restricted") is True and rec.get("latest_restriction") == "posting_limited" and out.get("appeal_finalization", {}).get("decision") == "uphold"),
        "account": rec,
        "enforcement_applied": out.get("enforcement_applied"),
    }


def run_poh_challenge_completion() -> Json:
    state: Json = {"height": 10, "accounts": {"alice": {"poh_tier": 2}, "juror-a": {}, "juror-b": {}, "juror-c": {}}, "roles": {"validators": {"active_set": ["juror-a", "juror-b", "juror-c"]}}}
    for acct in ("alice", "juror-a", "juror-b", "juror-c"):
        set_account_poh_status(state, account_id=acct, poh_tier=2, status=POH_STATUS_ACTIVE, verified_at_height=1)
    apply_poh(state, _env("POH_CHALLENGE_OPEN", signer="bob", nonce=1, payload={"account_id": "alice", "reason": "duplicate"}))
    apply_poh(state, _env("POH_CHALLENGE_RESOLVE", signer="reviewer", nonce=2, payload={"challenge_id": "pohc:alice:1", "resolution": "upheld"}))
    case_id = "pohasync:alice:3"
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", signer="alice", nonce=3, payload={"tier": 1}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", signer="alice", nonce=4, payload={"case_id": case_id, "evidence_commitment": "a" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", signer="SYSTEM", system=True, parent="assign", nonce=5, payload={"case_id": case_id, "jurors": ["juror-a", "juror-b", "juror-c"]}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=6):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", signer=juror, nonce=i, payload={"case_id": case_id}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=9):
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", signer=juror, nonce=i, payload={"case_id": case_id, "verdict": "approve"}))
    state["height"] = 11
    final = apply_poh(state, _env("POH_ASYNC_FINALIZE", signer="SYSTEM", system=True, parent="final", nonce=12, payload={"case_id": case_id}))
    ch = state["poh"]["challenges"]["pohc:alice:1"]
    status = canonical_account_poh_status(state, "alice")
    return {
        "ok": bool(final.get("outcome") == "approved" and ch.get("status") == "resolved_reverified" and status.get("status") == "active"),
        "challenge_status": ch.get("status"),
        "post_challenge_reverification": ch.get("post_challenge_reverification"),
        "canonical_status": status,
    }


def run_governance_execution_audit() -> Json:
    state: Json = {
        "height": 20,
        "gov_proposals_by_id": {
            "gp-audit": {
                "proposal_id": "gp-audit",
                "stage": "tallied",
                "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_percent": 67}}],
                "tallies": [{"height": 19, "payload": {"passed": True}}],
            }
        },
    }
    out = apply_governance(state, _env("GOV_EXECUTE", signer="SYSTEM", system=True, parent="gp-audit", nonce=21, payload={"proposal_id": "gp-audit"}))
    audit = state.get("governance_execution_audit", [])
    execution = state.get("gov_proposals_by_id", {}).get("gp-audit", {}).get("executions", [])
    latest_audit = audit[-1] if audit else {}
    latest_execution = execution[-1] if execution else {}
    execution_hash = latest_audit.get("execution_hash")
    return {
        "ok": bool(
            out == {"applied": True, "proposal_id": "gp-audit"}
            and execution_hash
            and latest_execution.get("execution_hash") == execution_hash
        ),
        "execution_hash": execution_hash,
        "emitted_actions": latest_audit.get("emitted_actions"),
        "audit": latest_audit,
    }


def build_report() -> Json:
    validator = run_validator_network()
    fresh_sync = run_fresh_sync()
    storage = run_storage_reassignment()
    dispute = run_dispute_account_enforcement()
    poh = run_poh_challenge_completion()
    governance = run_governance_execution_audit()
    batches = {
        "510": validator,
        "511": {"poh": poh, "dispute": dispute, "ok": bool(poh.get("ok") and dispute.get("ok"))},
        "512": governance,
        "513": storage,
        "514": fresh_sync,
    }
    ok = all(bool(v.get("ok")) for v in batches.values())
    return {
        "artifact": "b510_b515_completion_proof_v1_5",
        "ok": bool(ok),
        "batches": batches,
        "truth_boundaries": {
            "public_validators_enabled": False,
            "live_economics_enabled": False,
            "automatic_protocol_upgrades_enabled": False,
            "production_helper_execution_enabled": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    report = build_report()
    if args.write:
        out = ROOT / "generated" / "b510_b515_completion_proof_v1_5.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(out)
    else:
        print(json.dumps(report, sort_keys=True, indent=None if args.json else 2))
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
