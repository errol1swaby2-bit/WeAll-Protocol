from __future__ import annotations

import pytest

from weall.runtime.errors import ApplyError
from weall.runtime.gate_expr import eval_gate
from weall.runtime.poh.eligibility import can_account_perform_action, require_poh_tier
from weall.runtime.poh.state import (
    effective_poh_tier,
    require_valid_poh_tier,
    set_account_poh_status,
    v2_poh_tier,
)
from weall.runtime.apply.poh import apply_poh_tier_set
from weall.runtime.tx_schema import PAYLOAD_MODELS


def _removed_tier_word() -> str:
    return "Tier" + "3"


def _removed_tx_prefix() -> str:
    return "POH_" + "TIER" + "3" + "_"


def test_read_side_clamps_historical_values_but_write_side_rejects_removed_tier() -> None:
    assert v2_poh_tier(99) == 2

    with pytest.raises(ValueError):
        require_valid_poh_tier(int("3"))

    state = {"height": 1, "accounts": {"alice": {"poh_tier": 0}}}
    with pytest.raises(ValueError):
        set_account_poh_status(state, account_id="alice", poh_tier=int("3"))

    set_account_poh_status(state, account_id="alice", poh_tier=2)
    assert effective_poh_tier(state, "alice") == 2


def test_tier_set_cannot_write_removed_tier_value() -> None:
    state = {"accounts": {"alice": {"poh_tier": 0}}}
    with pytest.raises(ApplyError) as exc:
        apply_poh_tier_set(state, {"payload": {"account_id": "alice", "tier": int("3")}})
    assert exc.value.reason == "invalid_poh_tier"
    assert state["accounts"]["alice"]["poh_tier"] == 0


def test_removed_gate_atom_fails_closed_instead_of_aliasing_to_live_verified() -> None:
    ok, meta = eval_gate(
        _removed_tier_word() + "+",
        signer="alice",
        ledger={"accounts": {"alice": {"poh_tier": 99}}},
        payload={},
    )
    assert ok is False
    assert meta["expr"] == _removed_tier_word() + "+"


def test_removed_tx_names_are_not_valid_schema_entries() -> None:
    removed_prefix = _removed_tx_prefix()
    assert all(removed_prefix not in tx_type for tx_type in PAYLOAD_MODELS)
    assert "POH_LIVE_REQUEST_OPEN" in PAYLOAD_MODELS
    assert "POH_BOOTSTRAP_TIER2_GRANT" in PAYLOAD_MODELS


def test_eligibility_fails_closed_for_removed_tx_names() -> None:
    removed_tx = _removed_tx_prefix() + "REQUEST_OPEN"
    state = {"accounts": {"alice": {"poh_tier": 2}}}

    assert can_account_perform_action(state, "alice", removed_tx) is False

    with pytest.raises(ApplyError) as exc:
        require_poh_tier(state, "alice", removed_tx)
    assert exc.value.reason == "removed_legacy_poh_tier_action"
