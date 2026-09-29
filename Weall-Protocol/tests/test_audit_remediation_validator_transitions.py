from __future__ import annotations

import copy
import json
from pathlib import Path

from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs
from weall.runtime.scheduler_pipeline import run_leader_post_schedulers, run_replay_post_schedulers
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt
from weall.tx.canon import load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]


def _state() -> dict:
    return {
        "height": 5,
        "accounts": {
            "@op": {
                "poh_tier": 2,
                "reputation_milli": 6000,
                "devices": {
                    "by_id": {
                        "node:1": {
                            "device_type": "node",
                            "pubkey": "node-pub",
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "active_set": ["@op"],
                "by_id": {
                    "@op": {
                        "account_id": "@op",
                        "active": True,
                        "enrolled": True,
                    }
                },
            },
            "validators": {"active_set": [], "by_id": {}},
        },
        "system_queue": [],
    }


def _receipt() -> dict:
    return build_validator_readiness_receipt(
        account_id="@op",
        node_pubkey="node-pub",
        bft_pubkey="bft-pub",
        chain_id="weall-prod",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="sha256:manifest",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:runtime-profile",
        readiness_expires_height=50,
    )


def _opt_in_payload() -> dict:
    receipt = _receipt()
    return {
        "account_id": "@op",
        "node_pubkey": receipt["node_pubkey"],
        "bft_pubkey": receipt["bft_pubkey"],
        "chain_id": receipt["chain_id"],
        "schema_version": receipt["schema_version"],
        "protocol_version": receipt["protocol_version"],
        "manifest_hash": receipt["manifest_hash"],
        "tx_index_hash": receipt["tx_index_hash"],
        "runtime_profile_hash": receipt["runtime_profile_hash"],
        "readiness_expires_height": receipt["readiness_expires_height"],
        "readiness_checks": receipt["readiness_checks"],
        "validator_readiness_receipt_hash": receipt["readiness_receipt_hash"],
    }


def _user_env(payload: dict) -> dict:
    return {
        "tx_type": "NODE_OPERATOR_VALIDATOR_OPT_IN",
        "signer": "@op",
        "nonce": 1,
        "payload": payload,
        "system": False,
        "sig": "",
    }


def test_full_readiness_receipt_survives_opt_in_and_drives_system_lifecycle() -> None:
    state = _state()
    apply_tx(state, _user_env(_opt_in_payload()))
    validator = state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["validator"]
    assert validator["readiness_status"] == "pending"
    assert validator["bft_pubkey"] == "bft-pub"
    assert validator["readiness_receipt_hash"].startswith("sha256:")
    assert validator["readiness_checks"]["restart_safe"] is True

    assert schedule_node_operator_system_txs(state, next_height=6) == 1
    idx = load_tx_index_json(ROOT / "generated" / "tx_index.json")
    emitted = system_tx_emitter(state, idx, next_height=6, phase="post")
    readiness = next(env for env in emitted if env.tx_type == "VALIDATOR_READINESS_VERIFY")
    apply_tx(state, readiness.to_json())

    assert schedule_node_operator_system_txs(state, next_height=7) == 1
    emitted2 = system_tx_emitter(state, idx, next_height=7, phase="post")
    activation = next(env for env in emitted2 if env.tx_type == "ROLE_VALIDATOR_ACTIVATE")
    apply_tx(state, activation.to_json())
    assert "@op" in state["roles"]["validators"]["active_set"]


def test_invalid_readiness_receipt_never_schedules_verification() -> None:
    state = _state()
    payload = _opt_in_payload()
    payload["validator_readiness_receipt_hash"] = "sha256:tampered"
    apply_tx(state, _user_env(payload))
    assert schedule_node_operator_system_txs(state, next_height=6) == 0
    assert not state["system_queue"]


def test_leader_and_replay_derive_identical_validator_transition_queue() -> None:
    base = _state()
    apply_tx(base, _user_env(_opt_in_payload()))
    leader = copy.deepcopy(base)
    replay = copy.deepcopy(base)
    run_leader_post_schedulers(leader, next_height=6)
    run_replay_post_schedulers(replay, next_height=6)
    assert leader["system_queue"] == replay["system_queue"]


def test_scheduler_system_transitions_are_not_gov_receipts() -> None:
    payload = json.loads((ROOT / "generated" / "tx_index.json").read_text(encoding="utf-8"))
    rows = payload.get("tx_types") or []
    by_name = {str(row.get("name")): row for row in rows if isinstance(row, dict)}
    for name in (
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "VALIDATOR_READINESS_VERIFY",
        "ROLE_VALIDATOR_ACTIVATE",
    ):
        row = by_name[name]
        assert row["origin"] == "SYSTEM"
        assert row["receipt_only"] is False
        assert row.get("parent_tx_type") in (None, "")
        assert row.get("subject_gate") == "Validator"
