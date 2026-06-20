from __future__ import annotations

import pytest

from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, *, signer: str = "@attacker", system: bool = False, payload: dict | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=1, payload=payload or {"account_id": "@target"}, system=system, chain_id="weall-testnet-v1")


@pytest.mark.parametrize(
    "tx_type",
    [
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_VALIDATOR_SUSPEND",
        "VALIDATOR_READINESS_VERIFY",
        "ROLE_EMISSARY_SEAT",
        "ROLE_EMISSARY_REMOVE",
    ],
)
def test_system_only_role_appliers_fail_closed_when_called_directly_without_system_env(tx_type):
    with pytest.raises(RolesApplyError) as exc:
        apply_roles({"accounts": {}, "roles": {}}, _env(tx_type))
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "system_tx_required"


def test_self_bound_validator_opt_in_still_works_for_tier2_node_operator():
    ledger = {
        "accounts": {
            "@alice": {
                "poh_tier": 2,
                "reputation_milli": 6000,
                "devices": {"by_id": {"node1": {"device_type": "node", "pubkey": "node-key-1"}}},
            }
        },
        "roles": {"node_operators": {"active_set": ["@alice"], "by_id": {"@alice": {"active": True}}}},
    }
    out = apply_roles(
        ledger,
        _env(
            "NODE_OPERATOR_VALIDATOR_OPT_IN",
            signer="@alice",
            payload={"account_id": "@alice", "node_pubkey": "node-key-1", "reputation_required_milli": 5000},
        ),
    )
    assert out["applied"] == "NODE_OPERATOR_VALIDATOR_OPT_IN"
    validator = ledger["roles"]["node_operators"]["by_id"]["@alice"]["responsibilities"]["validator"]
    assert validator["opted_in"] is True
    assert validator["readiness_status"] == "pending"
