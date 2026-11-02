"""PR77 read-only characterization of the alternate reputation-floor ban path.

This suite documents existing behavior; passing it is NOT evidence that the
behavior satisfies V2 sanction authorization, due process, or appeal rules.
It intentionally does not change protocol execution or V2 semantic reviews.
Synthetic SYSTEM envelopes are not proof of real producer reachability.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.reputation import REP_MIN_UNITS, apply_reputation_delta_system
from weall.runtime.domain_apply import (
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


def _state(*, clock_enabled: bool) -> dict:
    return {
        "height": 20,
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "accounts": {
            "@target": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": "0",
                "reputation_milli": 0,
                "balance": 0,
                "keys": [],
            }
        },
        "reputation": {"bans": {}},
    }


def _delta_env() -> TxEnvelope:
    return TxEnvelope(
        tx_type="REPUTATION_DELTA_APPLY",
        signer="SYSTEM",
        nonce=21,
        system=True,
        parent="dispute:test-synthetic-parent",
        sig="synthetic-not-authenticated",
        payload={
            "account_id": "@target",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:reputation-floor-characterization",
            "reason": "synthetic_floor_probe",
        },
    )


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_canonical_reputation_delta_floor_ban_occurs_in_both_modes(clock_enabled: bool) -> None:
    """Known behavior, NOT an authorization assertion or a desired future contract."""
    baseline = _state(clock_enabled=clock_enabled)
    bounded = copy.deepcopy(baseline)
    reference = copy.deepcopy(baseline)

    bounded_result = apply_tx_atomic_meta(bounded, _delta_env())
    reference_result = apply_tx_atomic_meta_deepcopy(reference, _delta_env())

    assert bounded_result == reference_result
    assert bounded_result["newly_banned"] is True
    assert bounded["accounts"]["@target"]["reputation_milli"] == int(REP_MIN_UNITS)
    assert bounded["accounts"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["auto"] is True
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_exported_system_delta_helper_has_same_independent_ban_path(clock_enabled: bool) -> None:
    """The in-process SYSTEM helper also sets banned without ACCOUNT_BAN."""
    state = _state(clock_enabled=clock_enabled)
    result = apply_reputation_delta_system(
        state,
        account_id="@target",
        delta=-100.0,
        reason="synthetic_floor_probe",
        evidence={"delta_id": "pr77:helper-floor-probe", "source": "synthetic"},
        at_nonce=21,
    )

    assert result["newly_banned"] is True
    assert state["accounts"]["@target"]["reputation_milli"] == int(REP_MIN_UNITS)
    assert state["accounts"]["@target"]["banned"] is True
    assert state["reputation"]["bans"]["@target"]["auto"] is True
