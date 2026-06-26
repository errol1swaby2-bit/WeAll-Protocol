from __future__ import annotations

import pytest

from weall.runtime.apply.economics import apply_economics
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="FEE_POLICY_SET", signer="SYSTEM", nonce=1, payload=payload, sig="", system=True)


def _state() -> dict:
    return {
        "time": 1_000,
        "params": {"genesis_time": 0, "economic_unlock_time": 1, "economics_enabled": True},
        "economics": {"fee_policy": {"transfer_fee_int": 0, "post_fee_int": 0, "comment_fee_int": 0}},
        "accounts": {},
    }


@pytest.mark.parametrize(
    "field",
    [
        "post_fee_int",
        "comment_fee_int",
        "like_fee_int",
        "governance_fee_int",
        "vote_fee_int",
        "poh_fee_int",
        "dispute_fee_int",
        "onboarding_fee_int",
    ],
)
def test_civic_social_governance_fee_fields_reject_positive_values(field: str) -> None:
    st = _state()

    with pytest.raises(ApplyError) as ei:
        apply_economics(st, _env({field: 1}))

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "civic_social_governance_actions_must_remain_fee_free"


def test_transfer_fee_remains_governance_controlled_after_activation() -> None:
    st = _state()

    result = apply_economics(st, _env({"transfer_fee_int": 7}))

    assert result["applied"] == "FEE_POLICY_SET"
    assert st["economics"]["fee_policy"]["transfer_fee_int"] == 7


def test_zero_legacy_social_fee_keys_remain_allowed_for_state_compatibility() -> None:
    st = _state()

    result = apply_economics(st, _env({"post_fee_int": 0, "comment_fee_int": 0}))

    assert result["applied"] == "FEE_POLICY_SET"
    assert st["economics"]["fee_policy"]["post_fee_int"] == 0
