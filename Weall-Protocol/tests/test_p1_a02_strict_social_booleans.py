from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from weall.runtime.apply.social import SocialApplyError, apply_social
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import model_for_tx_type

EDGE_TYPES = ("FOLLOW_SET", "BLOCK_SET", "MUTE_SET")
INVALID_BOOLEAN_VALUES = ("false", "true", "0", "1", 0, 1)


def _state() -> dict:
    return {
        "accounts": {
            "@alice": {
                "poh_tier": 1,
                "nonce": 0,
                "banned": False,
                "locked": False,
            },
            "@bob": {
                "poh_tier": 1,
                "nonce": 0,
                "banned": False,
                "locked": False,
            },
        }
    }


def _env(tx_type: str, active: object) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="@alice",
        nonce=1,
        system=False,
        payload={"target": "@bob", "active": active},
    )


@pytest.mark.parametrize("tx_type", EDGE_TYPES)
@pytest.mark.parametrize("value", INVALID_BOOLEAN_VALUES)
def test_a02_f002_schema_rejects_coercible_non_boolean_values(tx_type: str, value: object) -> None:
    model = model_for_tx_type(tx_type)
    assert model is not None
    with pytest.raises(ValidationError):
        model.model_validate({"target": "@bob", "active": value})


@pytest.mark.parametrize("tx_type", EDGE_TYPES)
@pytest.mark.parametrize("value", [False, True])
def test_a02_f002_schema_preserves_real_json_booleans(tx_type: str, value: bool) -> None:
    model = model_for_tx_type(tx_type)
    assert model is not None
    parsed = model.model_validate({"target": "@bob", "active": value})
    assert parsed.active is value


@pytest.mark.parametrize("tx_type", EDGE_TYPES)
@pytest.mark.parametrize("value", INVALID_BOOLEAN_VALUES)
def test_a02_f002_apply_fails_closed_on_non_boolean_values(tx_type: str, value: object) -> None:
    state = _state()
    before = copy.deepcopy(state)

    with pytest.raises(SocialApplyError, match="boolean_required") as caught:
        apply_social(state, _env(tx_type, value))

    assert caught.value.code == "invalid_payload"
    assert caught.value.reason == "boolean_required"
    assert state == before


@pytest.mark.parametrize(
    ("tx_type", "state_key"),
    [
        ("FOLLOW_SET", "follows_by_edge"),
        ("BLOCK_SET", "blocks_by_edge"),
        ("MUTE_SET", "mutes_by_edge"),
    ],
)
@pytest.mark.parametrize("value", [False, True])
def test_a02_f002_apply_preserves_boolean_meaning(
    tx_type: str, state_key: str, value: bool
) -> None:
    state = _state()

    receipt = apply_social(state, _env(tx_type, value))

    assert receipt is not None
    assert receipt["active"] is value
    edge = state["social"][state_key]["@alice:@bob"]
    assert edge["active"] is value
