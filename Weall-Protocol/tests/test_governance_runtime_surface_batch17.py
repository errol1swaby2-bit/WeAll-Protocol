from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _mk_state() -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + (90 * 24 * 60 * 60)
    return {
        "chain_id": "weall-test",
        "height": 0,
        "tip": "",
        "time": unlock_time + 100,
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": True,
            "gov_action_allowlist": [
                "ECONOMICS_ACTIVATION",
                "FEE_POLICY_SET",
                "GOV_QUORUM_SET",
                "GOV_RULES_SET",
                "TREASURY_PARAMS_SET",
                "VALIDATOR_SET_UPDATE",
            ],
        },
        "economics": {"fee_policy": {"transfer_fee_int": 0}},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
        },
    }


def _env_proposal(actions: list[dict]) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "tx_type": "GOV_PROPOSAL_CREATE",
            "signer": "alice",
            "nonce": 1,
            "payload": {
                "proposal_id": "p:surface",
                "rules": {"auto_lifecycle": False},
                "actions": actions,
            },
            "sig": "",
            "parent": None,
            "system": False,
        }
    )


def test_gov_proposal_rejects_disallowed_runtime_action() -> None:
    st = _mk_state()
    env = _env_proposal([{"tx_type": "ACCOUNT_REGISTER", "payload": {"account_id": "@x"}}])

    with pytest.raises(ApplyError) as ei:
        apply_tx(st, env)

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "governance_action_not_allowed"


def test_gov_rules_set_rejects_non_whitelisted_param_roots() -> None:
    st = _mk_state()
    env = _env_proposal([{"tx_type": "GOV_RULES_SET", "payload": {"accounts": {"danger": 1}}}])

    with pytest.raises(ApplyError) as ei:
        apply_tx(st, env)

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "governance_rules_root_not_allowed"


def test_gov_rules_set_accepts_whitelisted_param_paths() -> None:
    st = _mk_state()
    env = _env_proposal(
        [
            {
                "tx_type": "GOV_RULES_SET",
                "payload": {"params": {"poh": {"tier2_n_jurors": 7}}},
            }
        ]
    )

    meta = apply_tx(st, env)
    assert meta and meta["applied"] is True
    assert "p:surface" in st["gov_proposals_by_id"]
