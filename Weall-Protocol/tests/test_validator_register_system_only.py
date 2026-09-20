from __future__ import annotations

from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus
from weall.runtime.tx_admission_types import TxEnvelope


def _tx_copy(env: TxEnvelope, **update):
    copier = getattr(env, "model_copy", None)
    if callable(copier):
        return copier(update=update)
    copier = getattr(env, "copy", None)
    if callable(copier):
        return copier(update=update)
    data = dict(env)
    data.update(update)
    return TxEnvelope(**data)


def test_validator_register_does_not_activate_on_register_and_requires_system() -> None:
    state = {"validators": {"registry": {}}, "roles": {"validators": {"active_set": []}}}
    env = TxEnvelope(
        tx_type="VALIDATOR_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"account": "@alice", "pubkey": "pub1"},
        system=False,
    )
    try:
        apply_consensus(state, env)
        raise AssertionError("expected system_only rejection")
    except ConsensusApplyError as e:
        assert e.code == "forbidden"
        assert e.reason == "system_only"

    sys_env = _tx_copy(env, system=True)
    out = apply_consensus(state, sys_env)
    assert out is not None
    assert out.get("active") is False
    assert state["roles"]["validators"]["active_set"] == []
    assert state["validators"]["registry"]["@alice"]["active"] is False


def test_active_validator_key_rotation_requires_validator_set_transition() -> None:
    state = {
        "validators": {
            "registry": {
                "@alice": {
                    "account": "@alice",
                    "pubkey": "old-key",
                    "active": True,
                    "status": "active",
                }
            }
        },
        "roles": {"validators": {"active_set": ["@alice"]}},
        "consensus": {
            "validator_set": {"epoch": 7, "active_set": ["@alice"], "set_hash": "set-7"},
            "validators": {"registry": {"@alice": {"pubkey": "old-key"}}},
        },
    }
    env = TxEnvelope(
        tx_type="VALIDATOR_REGISTER",
        signer="@system",
        nonce=1,
        payload={"account": "@alice", "pubkey": "new-key"},
        system=True,
    )
    try:
        apply_consensus(state, env)
        raise AssertionError("expected active validator key rotation rejection")
    except ConsensusApplyError as exc:
        assert exc.code == "forbidden"
        assert exc.reason == "active_validator_key_rotation_requires_set_transition"
    assert state["validators"]["registry"]["@alice"]["pubkey"] == "old-key"
    assert state["consensus"]["validators"]["registry"]["@alice"]["pubkey"] == "old-key"


def test_inactive_validator_key_may_change_before_explicit_reactivation() -> None:
    state = {
        "validators": {
            "registry": {
                "@alice": {
                    "account": "@alice",
                    "pubkey": "old-key",
                    "active": False,
                    "status": "observer",
                }
            }
        },
        "roles": {"validators": {"active_set": []}},
        "consensus": {
            "validator_set": {"epoch": 8, "active_set": [], "set_hash": "set-8"},
            "validators": {"registry": {"@alice": {"pubkey": "old-key"}}},
        },
    }
    env = TxEnvelope(
        tx_type="VALIDATOR_REGISTER",
        signer="@system",
        nonce=1,
        payload={"account": "@alice", "pubkey": "new-key"},
        system=True,
    )
    out = apply_consensus(state, env)
    assert out is not None
    assert state["validators"]["registry"]["@alice"]["pubkey"] == "new-key"
    assert state["consensus"]["validators"]["registry"]["@alice"]["pubkey"] == "new-key"
    assert state["validators"]["registry"]["@alice"]["active"] is False
