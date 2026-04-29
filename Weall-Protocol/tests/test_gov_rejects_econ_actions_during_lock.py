# tests/test_gov_rejects_econ_actions_during_lock.py
from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _mk_state_locked() -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + (90 * 24 * 60 * 60)
    return {
        "chain_id": "weall-test",
        "height": 0,
        "tip": "",
        "time": genesis_time + 60,  # still locked
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": False,
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION", "FEE_POLICY_SET"],
        },
        "economics": {"fee_policy": {"transfer_fee_int": 0}},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
        },
    }


def test_gov_proposal_create_rejects_economic_actions_before_unlock() -> None:
    st = _mk_state_locked()
    env = TxEnvelope.from_json(
        {
            "tx_type": "GOV_PROPOSAL_CREATE",
            "signer": "alice",
            "nonce": 1,
            "payload": {
                "proposal_id": "p:econ:locked",
                "rules": {"auto_lifecycle": False},
                "actions": [
                    {"tx_type": "FEE_POLICY_SET", "payload": {"transfer_fee_int": 1}},
                ],
            },
            "sig": "",
            "parent": None,
            "system": False,
        }
    )

    with pytest.raises(ApplyError):
        apply_tx(st, env)

    props = st.get("gov_proposals_by_id")
    assert not props, "proposal should not be created during lock when it contains economic actions"
