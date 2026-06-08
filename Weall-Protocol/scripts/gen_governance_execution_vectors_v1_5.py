#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json

Json = dict[str, Any]


def _env(tx_type: str, signer: str, nonce: int, payload: Json, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def run_vector() -> Json:
    canon = load_tx_index_json(ROOT / "generated" / "tx_index.json")
    state: Json = {
        "height": 10,
        "accounts": {"@alice": {"nonce": 0, "poh_tier": 2, "reputation_milli": 6000}},
        "roles": {"validators": {"active_set": ["@alice"], "by_id": {"@alice": {"active": True}}}},
        "system_queue": [],
        "params": {"gov_action_allowlist": ["VALIDATOR_SUSPEND"]},
        "gov_config": {},
        "validators": {"registry": {"validator-b": {"account": "validator-b", "status": "active", "active": True}}},
    }
    proposal_payload = {
        "proposal_id": "b509-vector-quorum",
        "title": "Suspend validator vector",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "VALIDATOR_SUSPEND", "payload": {"account": "validator-b", "reason": "governance-vector", "effective_epoch": 2}}],
    }
    applied: list[Json] = []
    applied.append({"tx_type": "GOV_PROPOSAL_CREATE", "result": apply_tx(state, _env("GOV_PROPOSAL_CREATE", "@alice", 1, proposal_payload))})
    applied.append({"tx_type": "GOV_VOTE_CAST", "result": apply_tx(state, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "b509-vector-quorum", "vote": "yes"}))})
    emitted_h11 = system_tx_emitter(state, canon=canon, next_height=11, phase="post")
    emitted_types_h11 = [env.tx_type for env in emitted_h11]
    state["height"] = 11
    for env in emitted_h11:
        applied.append({"tx_type": env.tx_type, "result": apply_tx(state, env)})
    emitted_h12 = system_tx_emitter(state, canon=canon, next_height=12, phase="post")
    emitted_types_h12 = [env.tx_type for env in emitted_h12]
    state["height"] = 12
    for env in emitted_h12:
        applied.append({"tx_type": env.tx_type, "result": apply_tx(state, env)})
    proposal = state["gov_proposals_by_id"]["b509-vector-quorum"]
    ok = (
        proposal.get("stage") == "finalized"
        and "GOV_EXECUTE" in emitted_types_h11
        and "VALIDATOR_SUSPEND" in emitted_types_h12
        and state.get("validators", {}).get("registry", {}).get("validator-b", {}).get("status") in {"pending_suspension", "suspended"}
        and bool(state.get("gov_execution_receipts"))
        and bool(state.get("gov_proposal_receipts"))
    )
    return {
        "artifact": "b509_governance_execution_vectors_v1_5",
        "ok": bool(ok),
        "proposal_id": "b509-vector-quorum",
        "emitted_h11": emitted_types_h11,
        "emitted_h12": emitted_types_h12,
        "final_stage": proposal.get("stage"),
        "validator_b_status": state.get("validators", {}).get("registry", {}).get("validator-b", {}).get("status", ""),
        "execution_receipt_count": len(state.get("gov_execution_receipts") or []),
        "proposal_receipt_count": len(state.get("gov_proposal_receipts") or []),
        "applied": applied,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_vector()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
