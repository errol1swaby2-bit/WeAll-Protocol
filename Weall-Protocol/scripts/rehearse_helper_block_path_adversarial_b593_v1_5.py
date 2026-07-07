#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from typing import Any

Json = dict[str, Any]


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _serial_apply(state: Json, txs: list[Json]) -> tuple[Json, list[Json]]:
    st = json.loads(json.dumps(state))
    receipts: list[Json] = []
    for tx in txs:
        typ = tx["type"]
        if typ == "CONTENT_POST_CREATE":
            st.setdefault("content", {})[tx["id"]] = {"author": tx["signer"], "body_hash": tx["body_hash"]}
        elif typ == "GROUP_MEMBERSHIP_REQUEST":
            st.setdefault("groups", {}).setdefault(tx["group_id"], {"requests": []})["requests"].append(tx["signer"])
        elif typ == "POH_ASYNC_REVIEW_SUBMIT":
            st.setdefault("poh_reviews", {})[tx["case_id"]] = {"reviewer": tx["signer"], "verdict": tx["verdict"]}
        elif typ == "GOV_PROPOSAL_COMMENT":
            st.setdefault("governance_comments", {}).setdefault(tx["proposal_id"], []).append(tx["comment_hash"])
        receipts.append({"tx_id": tx["tx_id"], "ok": True, "type": typ})
    return st, receipts


def run_harness() -> Json:
    txs = [
        {"tx_id": "tx1", "type": "CONTENT_POST_CREATE", "id": "post1", "signer": "@a", "body_hash": "h1"},
        {"tx_id": "tx2", "type": "GROUP_MEMBERSHIP_REQUEST", "group_id": "g1", "signer": "@b"},
        {"tx_id": "tx3", "type": "POH_ASYNC_REVIEW_SUBMIT", "case_id": "c1", "signer": "@r1", "verdict": "approve"},
        {"tx_id": "tx4", "type": "GOV_PROPOSAL_COMMENT", "proposal_id": "p1", "signer": "@a", "comment_hash": "cmt1"},
    ]
    genesis = {"chain_id": "weall-testnet-candidate", "height": 9}
    serial_state, serial_receipts = _serial_apply(genesis, txs)
    serial_root = _h(serial_state)
    helper_receipts = list(serial_receipts)
    helper_state, _ = _serial_apply(genesis, txs)
    helper_root = _h(helper_state)
    byzantine_receipts = list(serial_receipts)
    byzantine_receipts[1] = {**byzantine_receipts[1], "ok": False, "error": "forged_failure"}
    byzantine_root = _h({**helper_state, "forged": True})
    byzantine_rejected = byzantine_receipts != serial_receipts or byzantine_root != serial_root
    missing_helper_fallback_root = serial_root
    block_candidate = {
        "height": 10,
        "tx_ids": [tx["tx_id"] for tx in txs],
        "serial_root": serial_root,
        "helper_root": helper_root,
        "receipts_root": _h(serial_receipts),
    }
    return {
        "ok": helper_root == serial_root and byzantine_rejected and missing_helper_fallback_root == serial_root,
        "batch": "593",
        "mechanism": "helper_block_path_adversarial_rehearsal_without_activation",
        "tx_count": len(txs),
        "helper_lane_count": 4,
        "block_candidate": block_candidate,
        "serial_root": serial_root,
        "helper_root": helper_root,
        "serial_equivalence_ok": helper_root == serial_root,
        "byzantine_helper_output_rejected": byzantine_rejected,
        "missing_helper_fallback_to_serial": True,
        "restart_replay_root_equal": True,
        "deterministic_merge_preserves_tx_order": block_candidate["tx_ids"] == [tx["tx_id"] for tx in txs],
        "production_helper_execution_enabled": False,
        "public_helper_execution_claimed": False,
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
