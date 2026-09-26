from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import (
    GroupEmissaryElectionFinalizePayload,
    GroupTreasurySpendCancelPayload,
    GroupTreasurySpendSignPayload,
)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (GroupTreasurySpendSignPayload, {"spend_id": "s1"}),
        (GroupTreasurySpendCancelPayload, {"spend_id": "s1"}),
        (GroupEmissaryElectionFinalizePayload, {"election_id": "e1"}),
    ],
)
def test_reference_only_group_actions_require_explicit_scope(model, payload) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize("tx_type", ["GROUP_TREASURY_SPEND_SIGN", "GROUP_TREASURY_SPEND_CANCEL"])
def test_group_spend_reference_cannot_cross_scope(tx_type: str) -> None:
    state = {
        "group_treasury_spends": {
            "s1": {
                "spend_id": "s1",
                "group_id": "group-a",
                "status": "proposed",
                "allowed_signers": ["alice"],
                "signatures": {},
            }
        }
    }
    env = TxEnvelope(
        tx_type=tx_type,
        signer="alice",
        nonce=1,
        payload={"group_id": "group-b", "spend_id": "s1"},
    )
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(state, env)
    assert exc.value.reason == "group_scope_mismatch"


def test_group_election_finalize_reference_cannot_cross_scope() -> None:
    state = {
        "group_emissary_elections": {
            "e1": {"election_id": "e1", "group_id": "group-a", "status": "open"}
        }
    }
    env = TxEnvelope(
        tx_type="GROUP_EMISSARY_ELECTION_FINALIZE",
        signer="alice",
        nonce=1,
        payload={"group_id": "group-b", "election_id": "e1"},
    )
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(state, env)
    assert exc.value.reason == "group_scope_mismatch"
