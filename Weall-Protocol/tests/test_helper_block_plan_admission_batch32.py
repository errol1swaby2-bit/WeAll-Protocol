from __future__ import annotations

from weall.runtime.block_admission import admit_bft_block
from weall.runtime.parallel_execution import canonical_helper_execution_plan_fingerprint


def _state() -> dict:
    return {
        "chain_id": "c1",
        "roles": {"validators": {"active_set": ["v1", "v2", "v3", "v4"]}},
        "consensus": {
            "validator_set": {"epoch": 5, "active_set": ["v1", "v2", "v3", "v4"], "hash": "vh"},
        },
        "bft": {},
        "blocks": {"p1": {"prev_block_id": ""}},
    }


def _block(helper_execution: dict) -> dict:
    return {
        "block_id": "b1",
        "prev_block_id": "p1",
        "proposer": "v1",
        "validator_epoch": 5,
        "validator_set_hash": "vh",
        "justify_qc": {
            "chain_id": "c1",
            "view": 0,
            "block_id": "p1",
            "signatures": [{"signer": "v1", "signature": "x"}, {"signer": "v2", "signature": "x"}, {"signer": "v3", "signature": "x"}],
            "validator_epoch": 5,
            "validator_set_hash": "vh",
        },
        "header": {"chain_id": "c1", "height": 1, "view": 0},
        "txs": [],
        "helper_execution": helper_execution,
    }


def test_admit_bft_block_rejects_helper_execution_plan_id_mismatch_batch32(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setattr("weall.runtime.block_admission._validate_bft_proposal_leader_view", lambda block, state: (True, None))
    monkeypatch.setattr("weall.runtime.bft_hotstuff.qc_from_json", lambda qc: type("QC", (), {"chain_id": "c1", "block_id": "p1", "view": 0})())
    monkeypatch.setattr("weall.runtime.bft_hotstuff.verify_qc", lambda qc, validators, validator_pubkeys: True)

    lanes = [{"lane_id": "L1", "helper_id": "h1", "tx_ids": ["t1"], "descriptor_hash": "d1", "plan_id": "wrong"}]
    helper_execution = {"enabled": True, "plan_id": canonical_helper_execution_plan_fingerprint(lanes), "lanes": lanes}
    ok, rej = admit_bft_block(block=_block(helper_execution), state=_state())
    assert ok is False
    assert rej is not None
    assert rej.reason == "helper_execution_lane_plan_id_mismatch"
