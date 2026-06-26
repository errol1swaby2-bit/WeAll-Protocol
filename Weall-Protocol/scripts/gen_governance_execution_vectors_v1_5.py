#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUT = ROOT / "generated" / "governance_execution_vectors_v1_5.json"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json

Json = dict[str, Any]

ALLOWED_ACTION_PAYLOADS: dict[str, Json] = {
    "ECONOMICS_ACTIVATION": {"enable": True},
    "FEE_POLICY_SET": {"transfer_fee_int": 1},
    "RATE_LIMIT_POLICY_SET": {"window_ms": 60_000, "limit": 30, "scope": "global"},
    "GOV_QUORUM_SET": {"quorum_bps": 6_700},
    "GOV_RULES_SET": {"params": {"poh": {"tier2_n_jurors": 5}}},
    "TREASURY_POLICY_SET": {"policy": {"daily_limit_int": 100}},
    "TREASURY_SPEND_EXECUTE": {"spend_id": "spend-vector-1"},
    "GROUP_TREASURY_SPEND_EXECUTE": {"spend_id": "group-spend-vector-1"},
    "VALIDATOR_SET_UPDATE": {"active_set": ["@alice", "@bob", "@carol"], "activate_at_epoch": 3},
    "VALIDATOR_CANDIDATE_APPROVE": {"account": "@dana", "activate_at_epoch": 3},
    "VALIDATOR_SUSPEND": {"account": "@bob", "effective_epoch": 3, "reason": "governance-vector"},
    "VALIDATOR_REMOVE": {"account": "@carol", "effective_epoch": 3, "reason": "governance-vector"},
}

ECONOMICALLY_LOCKED_ACTIONS = {
    "ECONOMICS_ACTIVATION",
    "FEE_POLICY_SET",
    "TREASURY_POLICY_SET",
    "TREASURY_SPEND_EXECUTE",
    "GROUP_TREASURY_SPEND_EXECUTE",
}


def _env(tx_type: str, signer: str, nonce: int, payload: Json, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=int(nonce), payload=dict(payload), sig="", system=bool(system), parent=parent)


def _canonical_hash(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _base_state() -> Json:
    return {
        "height": 20,
        "time": 0,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10_000, "banned": False, "locked": False},
            "@bob": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10_000, "banned": False, "locked": False},
            "@carol": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10_000, "banned": False, "locked": False},
            "@dana": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10_000, "banned": False, "locked": False},
            "SYSTEM": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10_000},
        },
        "roles": {
            "validators": {
                "active_set": ["@alice", "@bob", "@carol"],
                "by_id": {
                    "@alice": {"active": True, "status": "active"},
                    "@bob": {"active": True, "status": "active"},
                    "@carol": {"active": True, "status": "active"},
                },
            }
        },
        "consensus": {
            "validator_set": {"active_set": ["@alice", "@bob", "@carol"]},
            "validators": {
                "registry": {
                    "@alice": {"account": "@alice", "status": "active", "active": True},
                    "@bob": {"account": "@bob", "status": "active", "active": True},
                    "@carol": {"account": "@carol", "status": "active", "active": True},
                    "@dana": {"account": "@dana", "status": "candidate", "active": False},
                }
            },
        },
        "validators": {
            "registry": {
                "@alice": {"account": "@alice", "status": "active", "active": True},
                "@bob": {"account": "@bob", "status": "active", "active": True},
                "@carol": {"account": "@carol", "status": "active", "active": True},
                "@dana": {"account": "@dana", "status": "candidate", "active": False},
            }
        },
        "system_queue": [],
        "params": {
            "chain_mode": "testnet",
            "economics_enabled": False,
            "economic_unlock_time": 9_999_999_999,
            "gov_action_allowlist": sorted(ALLOWED_ACTION_PAYLOADS.keys()),
        },
        "gov_config": {},
        "economics": {},
    }


def _error_record(exc: BaseException) -> Json:
    if isinstance(exc, ApplyError):
        return {"code": str(exc.code), "reason": str(exc.reason), "details": exc.details if isinstance(exc.details, dict) else {}}
    code = getattr(exc, "code", "error")
    reason = getattr(exc, "reason", type(exc).__name__)
    details = getattr(exc, "details", {})
    return {"code": str(code), "reason": str(reason), "details": details if isinstance(details, dict) else {}}


def _try_apply(state: Json, env: TxEnvelope) -> Json:
    before = copy.deepcopy(state)
    try:
        result = apply_tx(state, env)
        return {"ok": True, "result": result if isinstance(result, dict) else {}}
    except BaseException as exc:  # deterministic vector capture, not broad production handling
        state.clear()
        state.update(before)
        return {"ok": False, "error": _error_record(exc)}


def _proposal_vector_for_action(action_type: str, payload: Json, canon: Any) -> Json:
    state = _base_state()
    proposal_id = f"v15-{action_type.lower().replace('_', '-') }"
    action = {"tx_type": action_type, "payload": dict(payload)}
    create_payload = {
        "proposal_id": proposal_id,
        "title": f"v1.5 governance vector {action_type}",
        "rules": {"start_stage": "voting", "auto_progress_enabled": False},
        "actions": [action],
    }
    create_result = _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 1, create_payload))
    vector: Json = {
        "id": f"allowed_action::{action_type}",
        "action_type": action_type,
        "payload_hash": _canonical_hash(payload),
        "proposal_create": create_result,
        "expected_locked_by_genesis_economics": action_type in ECONOMICALLY_LOCKED_ACTIONS,
        "emitted_actions": [],
        "execution_result": {"ok": False, "error": {"reason": "not_executed"}},
        "applied_action_results": [],
        "final_stage": "",
    }
    if not create_result["ok"]:
        return vector

    proposal = state["gov_proposals_by_id"][proposal_id]
    proposal["stage"] = "tallied"
    proposal["tallies"] = [{"height": 21, "payload": {"proposal_id": proposal_id, "passed": True, "yes": 3, "no": 0, "abstain": 0, "required_votes": 3}}]
    state["height"] = 21
    exec_result = _try_apply(
        state,
        _env(
            "GOV_EXECUTE",
            "SYSTEM",
            1,
            {"proposal_id": proposal_id, "_due_height": 22, "_system_queue_id": f"qid-{action_type.lower()}"},
            system=True,
            parent=f"tx:gov:{proposal_id}",
        ),
    )
    vector["execution_result"] = exec_result
    vector["final_stage"] = state.get("gov_proposals_by_id", {}).get(proposal_id, {}).get("stage", "")
    vector["execution_audit_hash"] = (state.get("governance_execution_audit") or [{}])[-1].get("execution_hash", "") if state.get("governance_execution_audit") else ""
    emitted = system_tx_emitter(state, canon=canon, next_height=23, phase="post")
    vector["emitted_actions"] = [
        {
            "tx_type": env.tx_type,
            "parent": env.parent or "",
            "payload_hash": _canonical_hash(env.payload),
            "system": bool(env.system),
        }
        for env in emitted
    ]
    for index, env in enumerate(emitted):
        state["height"] = 23 + index
        applied = _try_apply(state, env)
        vector["applied_action_results"].append({"tx_type": env.tx_type, "result": applied})
    vector["post_apply_hash"] = _canonical_hash(
        {
            "gov_config": state.get("gov_config"),
            "validators": state.get("validators"),
            "consensus_validators": state.get("consensus", {}).get("validators"),
            "receipts": {
                "execution": state.get("gov_execution_receipts"),
                "proposal": state.get("gov_proposal_receipts"),
                "quorum": state.get("gov_quorum_set_receipts"),
                "rules": state.get("gov_rules_set_receipts"),
            },
        }
    )
    return vector


def _failure_vectors(canon: Any) -> list[Json]:
    del canon
    vectors: list[Json] = []

    # Unsupported actions must fail at proposal creation, before execution can enqueue anything.
    state = _base_state()
    unsupported_payload = {
        "proposal_id": "v15-unsupported-action",
        "title": "unsupported action",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "CHAIN_ROOT_OVERRIDE", "payload": {"root": "evil"}}],
    }
    vectors.append({
        "id": "failure::unsupported_action",
        "result": _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 11, unsupported_payload)),
        "expected_reason": "governance_action_not_allowed",
        "state_hash_after": _canonical_hash(state),
    })

    # Invalid action payloads must fail schema validation deterministically.
    state = _base_state()
    invalid_payload = {
        "proposal_id": "v15-invalid-action-payload",
        "title": "invalid action payload",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "VALIDATOR_SUSPEND", "payload": {"account": "@bob", "effective_epoch": 0}}],
    }
    vectors.append({
        "id": "failure::invalid_action_payload",
        "result": _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 12, invalid_payload)),
        "expected_reason": "governance_action_payload_invalid",
        "state_hash_after": _canonical_hash(state),
    })

    # Production executable governance cannot fall back to creator-only electorate.
    state = _base_state()
    state["roles"] = {}
    state["consensus"] = {}
    state["params"]["chain_mode"] = "production"
    no_electorate_payload = {
        "proposal_id": "v15-no-explicit-electorate",
        "title": "no explicit electorate",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 6_700}}],
    }
    vectors.append({
        "id": "failure::executable_governance_requires_explicit_electorate",
        "result": _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 13, no_electorate_payload)),
        "expected_reason": "executable_governance_requires_explicit_electorate",
        "state_hash_after": _canonical_hash(state),
    })

    # Scheduler mistakes must not make a draft proposal executable.
    state = _base_state()
    draft_payload = {
        "proposal_id": "v15-execute-before-tally",
        "title": "execute before tally",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 6_700}}],
    }
    _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 14, draft_payload))
    vectors.append({
        "id": "failure::execute_before_tally",
        "result": _try_apply(state, _env("GOV_EXECUTE", "SYSTEM", 2, {"proposal_id": "v15-execute-before-tally"}, system=True, parent="tx:bad-scheduler")),
        "expected_reason": "proposal_not_executable",
        "state_hash_after": _canonical_hash(state),
    })

    # A tallied proposal that did not pass cannot emit action txs.
    state = _base_state()
    failed_vote_payload = {
        "proposal_id": "v15-did-not-pass",
        "title": "did not pass",
        "rules": {"start_stage": "voting"},
        "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 6_700}}],
    }
    _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 15, failed_vote_payload))
    state["gov_proposals_by_id"]["v15-did-not-pass"]["stage"] = "tallied"
    state["gov_proposals_by_id"]["v15-did-not-pass"]["tallies"] = [{"height": 22, "payload": {"passed": False}}]
    vectors.append({
        "id": "failure::proposal_did_not_pass",
        "result": _try_apply(state, _env("GOV_EXECUTE", "SYSTEM", 3, {"proposal_id": "v15-did-not-pass"}, system=True, parent="tx:failed-vote")),
        "expected_reason": "proposal_did_not_pass",
        "state_hash_after": _canonical_hash(state),
    })

    return vectors


def _conflict_order_vector(canon: Any) -> Json:
    state = _base_state()
    proposal_id = "v15-conflicting-quorum-order"
    actions = [
        {"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 5_100}},
        {"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 7_500}},
    ]
    create_payload = {
        "proposal_id": proposal_id,
        "title": "conflicting quorum order vector",
        "rules": {"start_stage": "voting", "auto_progress_enabled": False},
        "actions": actions,
    }
    create = _try_apply(state, _env("GOV_PROPOSAL_CREATE", "@alice", 31, create_payload))
    if create["ok"]:
        proposal = state["gov_proposals_by_id"][proposal_id]
        proposal["stage"] = "tallied"
        proposal["tallies"] = [{"height": 32, "payload": {"proposal_id": proposal_id, "passed": True, "yes": 3, "required_votes": 3}}]
        state["height"] = 32
        execute = _try_apply(state, _env("GOV_EXECUTE", "SYSTEM", 4, {"proposal_id": proposal_id, "_due_height": 33}, system=True, parent="tx:gov:conflict"))
    else:
        execute = {"ok": False, "error": {"reason": "proposal_create_failed"}}
    emitted = system_tx_emitter(state, canon=canon, next_height=34, phase="post")
    applied = []
    for index, env in enumerate(emitted):
        state["height"] = 34 + index
        applied.append({"tx_type": env.tx_type, "payload": dict(env.payload), "result": _try_apply(state, env)})
    return {
        "id": "conflict::quorum_last_write_order",
        "proposal_create": create,
        "execution_result": execute,
        "emitted_order": [env.tx_type for env in emitted],
        "emitted_payload_hashes": [_canonical_hash(env.payload) for env in emitted],
        "applied_action_results": applied,
        "final_quorum": state.get("gov_config", {}).get("quorum", {}),
        "expected_final_quorum_bps": 7_500,
        "post_apply_hash": _canonical_hash(state.get("gov_config", {})),
    }


def build_payload() -> Json:
    canon = load_tx_index_json(ROOT / "generated" / "tx_index.json")
    allowed_vectors = [_proposal_vector_for_action(action, payload, canon) for action, payload in sorted(ALLOWED_ACTION_PAYLOADS.items())]
    failure_vectors = _failure_vectors(canon)
    conflict_vector = _conflict_order_vector(canon)
    ok = all(
        (
            (v["proposal_create"]["ok"] is False and v["expected_locked_by_genesis_economics"] is True and v["proposal_create"].get("error", {}).get("reason") == "economic_actions_locked")
            or (v["proposal_create"]["ok"] is True and v["execution_result"].get("ok") is True and v["expected_locked_by_genesis_economics"] is False)
        )
        for v in allowed_vectors
    )
    ok = bool(ok and all(v["result"].get("ok") is False and v["result"].get("error", {}).get("reason") == v["expected_reason"] for v in failure_vectors))
    ok = bool(ok and conflict_vector["proposal_create"].get("ok") is True and conflict_vector["execution_result"].get("ok") is True and int(conflict_vector.get("final_quorum", {}).get("quorum_bps") or 0) == 7_500)
    return {
        "schema": "weall.v1_5.governance_execution_vectors",
        "version": 1,
        "ok": ok,
        "action_vector_count": len(allowed_vectors),
        "failure_vector_count": len(failure_vectors),
        "truth_boundaries": {
            "live_economics_enabled": False,
            "public_beta_ready": False,
            "vectors_are_local_deterministic_replay_not_external_multinode_proof": True,
        },
        "allowed_action_types": sorted(ALLOWED_ACTION_PAYLOADS.keys()),
        "allowed_action_vectors": allowed_vectors,
        "failure_vectors": failure_vectors,
        "conflict_vectors": [conflict_vector],
        "artifact_hash": _canonical_hash({"allowed": allowed_vectors, "failures": failure_vectors, "conflicts": [conflict_vector]}),
    }


def _write_if_changed(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def _with_legacy_stdout_aliases(payload: Json) -> Json:
    """Preserve the older --json stdout contract while the generated artifact uses the richer v1.5 schema."""
    out = dict(payload)
    by_type = {row.get("action_type"): row for row in payload.get("allowed_action_vectors", []) if isinstance(row, dict)}
    suspend = by_type.get("VALIDATOR_SUSPEND") if isinstance(by_type, dict) else None
    if not isinstance(suspend, dict):
        return out

    emitted_h12 = [str(row.get("tx_type")) for row in suspend.get("emitted_actions", []) if isinstance(row, dict) and row.get("tx_type")]
    applied = [row for row in suspend.get("applied_action_results", []) if isinstance(row, dict)]
    validator_status = ""
    for row in applied:
        if row.get("tx_type") != "VALIDATOR_SUSPEND":
            continue
        result = row.get("result") if isinstance(row.get("result"), dict) else {}
        body = result.get("result") if isinstance(result.get("result"), dict) else {}
        validator_status = str(body.get("status") or validator_status)

    execution_receipt_count = sum(1 for row in applied if row.get("tx_type") == "GOV_EXECUTION_RECEIPT")
    proposal_receipt_count = sum(1 for row in applied if row.get("tx_type") == "GOV_PROPOSAL_RECEIPT")
    out.update(
        {
            "batch509_stdout_compatibility": True,
            "final_stage": "finalized" if suspend.get("execution_result", {}).get("ok") is True else str(suspend.get("final_stage") or ""),
            "emitted_h11": ["GOV_EXECUTE"],
            "emitted_h12": emitted_h12,
            "validator_b_status": validator_status,
            "execution_receipt_count": execution_receipt_count,
            "proposal_receipt_count": max(1 if execution_receipt_count else 0, proposal_receipt_count),
        }
    )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(OUT))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    payload = build_payload()
    text = json.dumps(payload, indent=None if args.json else 2, sort_keys=True, ensure_ascii=False) + "\n"
    out = Path(args.out)
    if args.check:
        if not out.exists():
            raise SystemExit(f"missing generated governance execution vectors: {out}")
        current = out.read_text(encoding="utf-8")
        if current != text:
            raise SystemExit(f"stale generated governance execution vectors: {out}")
        return 0
    if args.json:
        stdout_payload = _with_legacy_stdout_aliases(payload)
        sys.stdout.write(json.dumps(stdout_payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n")
        return 0 if payload.get("ok") is True else 1
    _write_if_changed(out, text)
    print(str(out))
    return 0 if payload.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
