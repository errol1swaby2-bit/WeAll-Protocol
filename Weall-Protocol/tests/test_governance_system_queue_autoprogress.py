from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter, validate_system_tx_queue_binding
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"))


def _state() -> dict:
    return {
        "height": 10,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000},
        },
        "roles": {"validators": {"active_set": ["@alice"], "by_id": {"@alice": {"active": True}}}},
        "system_queue": [],
        "params": {
            "gov_action_allowlist": [
                "ECONOMICS_ACTIVATION",
                "FEE_POLICY_SET",
                "GOV_QUORUM_SET",
                "GOV_RULES_SET",
                "VALIDATOR_CANDIDATE_APPROVE",
            ]
        },
    }


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def test_governance_autoprogress_enqueues_bound_system_txs_instead_of_direct_apply_batch313() -> None:
    st = _state()
    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-auto",
                "title": "approve",
                "rules": {"start_stage": "voting"},
                "actions": [
                    {
                        "tx_type": "GOV_QUORUM_SET",
                        "payload": {"quorum_bps": 5000},
                    }
                ],
            },
        ),
    )

    apply_tx(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-auto", "vote": "yes"}))

    proposal = st["gov_proposals_by_id"]["p-auto"]
    assert proposal["stage"] == "voting"
    assert proposal.get("closed_at_height", 0) == 0
    assert proposal.get("tallied_at_height", 0) == 0
    assert proposal.get("executed_at_height", 0) == 0
    assert proposal.get("finalized_at_height", 0) == 0

    queued_types = [item.get("tx_type") for item in st.get("system_queue", [])]
    assert queued_types == [
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    ]
    assert all(int(item.get("due_height")) == 11 for item in st["system_queue"])
    assert all(str(item.get("phase")) == "post" for item in st["system_queue"])


def test_governance_autoprogress_emitted_system_txs_are_queue_bound_batch313() -> None:
    st = _state()
    canon = _tx_index()
    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "@alice", 1, {"proposal_id": "p-auto", "title": "approve", "rules": {"start_stage": "voting"}}))
    apply_tx(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-auto", "vote": "yes"}))

    emitted = system_tx_emitter(st, canon, next_height=11, phase="post")
    assert [env.tx_type for env in emitted] == [
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    ]

    for env in emitted:
        ok, why = validate_system_tx_queue_binding(st, canon, env, next_height=11, phase="post")
        assert ok is True, why
        apply_tx(st, env)

    proposal = st["gov_proposals_by_id"]["p-auto"]
    assert proposal["stage"] == "finalized"
    assert proposal["closed_at_height"] == 11
    assert proposal["tallied_at_height"] == 11
    assert proposal["executed_at_height"] == 11
    assert proposal["finalized_at_height"] == 11
