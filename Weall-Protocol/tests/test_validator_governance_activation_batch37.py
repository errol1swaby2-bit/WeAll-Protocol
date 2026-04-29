from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    return load_tx_index_json(canon_path)


def _mk_state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {"validators": {"active_set": ["alice"]}},
        "system_queue": [],
        "params": {
            "gov_action_allowlist": [
                "VALIDATOR_SET_UPDATE",
                "VALIDATOR_CANDIDATE_APPROVE",
                "VALIDATOR_SUSPEND",
                "VALIDATOR_REMOVE",
            ]
        },
    }


def test_governance_execute_can_schedule_suspend_receipt() -> None:
    idx = _load_index()
    st = _mk_state()

    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="alice",
            nonce=1,
            payload={
                "proposal_id": "p-suspend",
                "actions": [
                    {
                        "tx_type": "VALIDATOR_SUSPEND",
                        "payload": {"account": "alice", "effective_epoch": 3, "reason": "maintenance"},
                    }
                ],
            },
            sig="",
            system=False,
        ),
    )

    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_EXECUTE",
            signer="SYSTEM",
            nonce=1,
            payload={"proposal_id": "p-suspend", "_due_height": 1, "_system_queue_id": "qid-suspend"},
            sig="",
            system=True,
        ),
    )

    q = st["system_queue"]
    queued = [item for item in q if item.get("tx_type") == "VALIDATOR_SUSPEND"]
    assert len(queued) == 1
    assert int(queued[0]["due_height"]) == 2

    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    assert "VALIDATOR_SUSPEND" in [env.tx_type for env in post_h2]


def test_governance_execute_can_schedule_remove_receipt() -> None:
    idx = _load_index()
    st = _mk_state()

    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="alice",
            nonce=1,
            payload={
                "proposal_id": "p-remove",
                "actions": [
                    {
                        "tx_type": "VALIDATOR_REMOVE",
                        "payload": {"account": "alice", "effective_epoch": 4, "reason": "governance_remove"},
                    }
                ],
            },
            sig="",
            system=False,
        ),
    )

    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_EXECUTE",
            signer="SYSTEM",
            nonce=1,
            payload={"proposal_id": "p-remove", "_due_height": 1, "_system_queue_id": "qid-remove"},
            sig="",
            system=True,
        ),
    )

    q = st["system_queue"]
    queued = [item for item in q if item.get("tx_type") == "VALIDATOR_REMOVE"]
    assert len(queued) == 1
    assert int(queued[0]["due_height"]) == 2

    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    assert "VALIDATOR_REMOVE" in [env.tx_type for env in post_h2]
