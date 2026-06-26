#!/usr/bin/env python3
from __future__ import annotations

"""Generate deterministic v1.5 state-root fixtures."""

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from weall.runtime.state_hash import compute_state_root

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "generated" / "state_root_vectors_v1_5.json"
Json = dict[str, Any]


def _base_state() -> Json:
    return {
        "state_version": 1,
        "height": 7,
        "accounts": {
            "alice": {"nonce": 2, "poh_tier": 2, "reputation_milli": 1200},
            "bob": {"nonce": 1, "poh_tier": 1, "reputation_milli": 50},
        },
        "content": {"posts": {"p1": {"author": "alice", "body_cid": "cid:post:1"}}},
        "params": {"chain_id": "weall-test", "economics_enabled": False},
    }


def fixture_states() -> list[Json]:
    base = _base_state()
    reordered: Json = {
        "params": {"economics_enabled": False, "chain_id": "weall-test"},
        "content": {"posts": {"p1": {"body_cid": "cid:post:1", "author": "alice"}}},
        "accounts": {
            "bob": {"reputation_milli": 50, "poh_tier": 1, "nonce": 1},
            "alice": {"reputation_milli": 1200, "poh_tier": 2, "nonce": 2},
        },
        "height": 7,
        "state_version": 1,
    }
    with_ephemeral = deepcopy(base)
    with_ephemeral["created_ms"] = 999
    with_ephemeral["meta"] = {"local": True, "helper_profile": "diagnostic-only"}
    with_ephemeral["tip_hash"] = "local-tip"
    with_ephemeral["content"]["posts"]["p1"]["tip_ts_ms"] = 123

    list_order_reference = deepcopy(base)
    list_order_reference["notifications"] = {"queue": ["n1", "n2"]}
    list_order_changed = deepcopy(base)
    list_order_changed["notifications"] = {"queue": ["n2", "n1"]}

    poh_state = deepcopy(base)
    poh_state["poh"] = {
        "async_cases": {
            "case:alice:1": {
                "account_id": "alice",
                "status": "approved",
                "evidence_commitments": {"video": "c" * 64},
                "reviewer_restricted_evidence": {"cid": "restricted-redacted-in-api-not-root"},
                "reviews": {"juror-a": {"verdict": "approve"}},
            }
        },
        "live_cases": {
            "live:alice:1": {
                "account_id": "alice",
                "status": "scheduled",
                "room_commitment": "r" * 64,
                "jurors": {"juror-a": {"role": "interacting", "accepted": True}},
            }
        },
    }

    governance_state = deepcopy(base)
    governance_state["gov_proposals_by_id"] = {
        "gp:1": {
            "proposal_id": "gp:1",
            "stage": "deliberation",
            "actions": [{"tx_type": "PROTOCOL_UPGRADE_DECLARE", "payload": {"upgrade_id": "u1"}}],
            "comments": [{"by": "alice", "body": "support"}],
            "votes": {},
        }
    }
    governance_state["protocol"] = {
        "upgrades": {
            "u1": {
                "upgrade_id": "u1",
                "status": "declared",
                "version": "v1.5.1",
                "record_only_boundary": {"artifact_apply_enabled": False},
            }
        }
    }

    dispute_group_state = deepcopy(base)
    dispute_group_state["disputes_by_id"] = {
        "d:1": {
            "dispute_id": "d:1",
            "stage": "review",
            "parties": ["alice", "bob"],
            "evidence": {"commitment": "e" * 64},
        }
    }
    dispute_group_state["groups"] = {
        "g:1": {
            "group_id": "g:1",
            "name": "Mutual aid",
            "members": {"alice": {"role": "admin"}, "bob": {"role": "member"}},
        }
    }

    economics_locked_state = deepcopy(base)
    economics_locked_state["params"].update({"economics_enabled": False})
    economics_locked_state["tokenomics"] = {
        "max_supply_atomic": 21_000_000_00000000,
        "issued_atomic": 0,
        "issuance_epochs": {},
    }
    economics_locked_state["balances"] = {"alice": {"WCN": 0}, "bob": {"WCN": 0}}

    return [
        {"name": "base", "state": base},
        {"name": "reordered_dicts_same_semantics", "state": reordered, "same_root_as": "base"},
        {"name": "with_ephemeral_fields_same_semantics", "state": with_ephemeral, "same_root_as": "base"},
        {"name": "list_order_reference", "state": list_order_reference},
        {"name": "list_order_changed", "state": list_order_changed, "different_root_from": "list_order_reference"},
        {"name": "poh_async_and_live_commitments", "state": poh_state},
        {"name": "governance_protocol_record_only", "state": governance_state},
        {"name": "dispute_and_group_membership", "state": dispute_group_state},
        {"name": "economics_locked_supply_surface", "state": economics_locked_state},
    ]


def build_payload() -> Json:
    vectors = []
    for rec in fixture_states():
        root = compute_state_root(rec["state"])
        out = {k: v for k, v in rec.items() if k != "state"}
        out["state_root"] = root
        out["state_summary"] = sorted([str(k) for k in rec["state"].keys()])
        vectors.append(out)
    return {
        "schema": "weall.v1_5.state_root_vectors",
        "version": "2026-06-batch13-expanded",
        "canonicalization_contract": {
            "dict_keys_sorted": True,
            "list_order_preserved": True,
            "json_separators": [",", ":"],
            "ephemeral_keys_ignored": ["created_ms", "bft", "meta", "tip_hash", "tip_ts_ms"],
            "float_values_forbidden_by_admission": True,
            "consensus_relevant_policy_must_not_live_under_meta": True,
        },
        "vectors": vectors,
        "assertions": [
            {"kind": "equal", "left": "base", "right": "reordered_dicts_same_semantics"},
            {"kind": "equal", "left": "base", "right": "with_ephemeral_fields_same_semantics"},
            {"kind": "not_equal", "left": "list_order_reference", "right": "list_order_changed"},
            {"kind": "domain_fixture_present", "name": "poh_async_and_live_commitments"},
            {"kind": "domain_fixture_present", "name": "governance_protocol_record_only"},
            {"kind": "domain_fixture_present", "name": "dispute_and_group_membership"},
            {"kind": "domain_fixture_present", "name": "economics_locked_supply_surface"},
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    data = json.dumps(build_payload(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.json:
        print(data, end="")
        return 0
    if args.check:
        if not out.exists():
            raise SystemExit(f"missing generated state-root vectors: {out}")
        if out.read_text(encoding="utf-8") != data:
            raise SystemExit(f"stale generated state-root vectors: {out}")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(data, encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
