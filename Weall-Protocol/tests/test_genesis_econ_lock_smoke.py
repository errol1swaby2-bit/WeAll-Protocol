# tests/test_genesis_econ_lock_smoke.py
from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _mk_base_state(*, chain_id: str = "weall-test") -> dict:
    """
    Minimal state shape required for econ phase gating via apply_tx().
    We keep it intentionally small so this test stays stable over refactors.
    """
    genesis_time = 1_700_000_000  # fixed unix seconds (deterministic)
    unlock_time = genesis_time + (90 * 24 * 60 * 60)

    return {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "time": genesis_time,
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": False,
            # Keep allowlist present (some governance codepaths reference it),
            # but the econ gate is enforced by the economic domain apply.
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION", "FEE_POLICY_SET"],
        },
        "economics": {
            "fee_policy": {
                "transfer_fee_int": 0,
                "post_fee_int": 0,
                "comment_fee_int": 0,
                "like_fee_int": 0,
            }
        },
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "balance": 0},
        },
    }


def _env_system(tx_type: str, payload: dict, *, parent: str | None = None) -> TxEnvelope:
    # ECONOMICS_ACTIVATION is receipt-only in canon (block-context), so apply-time enforcement
    # requires a parent pointer. When these unit tests call apply_tx() directly, we supply a
    # stable synthetic parent if none is provided.
    if parent is None and str(tx_type).strip().upper() == "ECONOMICS_ACTIVATION":
        parent = "p:direct-activation"
    return TxEnvelope.from_json(
        {
            "tx_type": tx_type,
            "signer": "SYSTEM",
            "nonce": 0,
            "payload": payload,
            "sig": "",
            "parent": parent,
            "system": True,
        }
    )


def test_genesis_econ_lock_blocks_activation_before_unlock() -> None:
    """
    Genesis rule:
      - Before economic_unlock_time, ECONOMICS_ACTIVATION must be rejected.
    """
    st = _mk_base_state()
    genesis_time = int(st["params"]["genesis_time"])
    unlock_time = int(st["params"]["economic_unlock_time"])

    # Move time forward but still before unlock.
    st["time"] = genesis_time + 10 * 24 * 60 * 60
    assert st["time"] < unlock_time
    assert st["params"]["economics_enabled"] is False

    env = _env_system("ECONOMICS_ACTIVATION", {"enable": True})

    with pytest.raises(ApplyError):
        apply_tx(st, env)

    # Ensure it didn't flip economics on accidentally.
    assert st["params"]["economics_enabled"] is False


def test_genesis_unlock_allows_activation_after_unlock() -> None:
    """
    Genesis rule:
      - After unlock, ECONOMICS_ACTIVATION is allowed (and should enable economics).
    """
    st = _mk_base_state()
    unlock_time = int(st["params"]["economic_unlock_time"])

    st["time"] = unlock_time + 1
    assert st["time"] > unlock_time
    assert st["params"]["economics_enabled"] is False

    env = _env_system("ECONOMICS_ACTIVATION", {"enable": True})

    # Should not raise.
    apply_tx(st, env)

    assert st["params"]["economics_enabled"] is True


def test_fee_policy_set_requires_activation() -> None:
    """
    Genesis rule:
      - Even after unlock, economic txs (like FEE_POLICY_SET) should be rejected
        until ECONOMICS_ACTIVATION has been applied.
    """
    st = _mk_base_state()
    unlock_time = int(st["params"]["economic_unlock_time"])

    # After unlock but still not activated.
    st["time"] = unlock_time + 1
    assert st["params"]["economics_enabled"] is False

    env_fee = _env_system("FEE_POLICY_SET", {"transfer_fee_int": 7}, parent="p:test")
    with pytest.raises(ApplyError):
        apply_tx(st, env_fee)

    # Now activate economics.
    env_act = _env_system("ECONOMICS_ACTIVATION", {"enable": True})
    apply_tx(st, env_act)
    assert st["params"]["economics_enabled"] is True

    # Now FEE_POLICY_SET should succeed.
    apply_tx(st, env_fee)
    assert int(st["economics"]["fee_policy"]["transfer_fee_int"]) == 7


def test_fee_policy_set_is_deterministic_over_replay() -> None:
    """
    Quick determinism check: applying the same post-activation policy set to the same
    starting state should yield identical resulting state.
    """
    base = _mk_base_state()
    unlock_time = int(base["params"]["economic_unlock_time"])
    base["time"] = unlock_time + 1

    # Two independent runs from identical pre-state.
    st1 = deepcopy(base)
    st2 = deepcopy(base)

    act = _env_system("ECONOMICS_ACTIVATION", {"enable": True})
    fee = _env_system("FEE_POLICY_SET", {"transfer_fee_int": 3, "post_fee_int": 0}, parent="p:det")

    apply_tx(st1, act)
    apply_tx(st1, fee)

    apply_tx(st2, act)
    apply_tx(st2, fee)

    assert st1["params"]["economics_enabled"] is True
    assert st2["params"]["economics_enabled"] is True
    assert st1["economics"]["fee_policy"] == st2["economics"]["fee_policy"]
