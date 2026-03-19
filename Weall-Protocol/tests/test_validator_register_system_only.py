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
        assert False, "expected system_only rejection"
    except ConsensusApplyError as e:
        assert e.code == "forbidden"
        assert e.reason == "system_only"

    sys_env = _tx_copy(env, system=True)
    out = apply_consensus(state, sys_env)
    assert out is not None
    assert out.get("active") is False
    assert state["roles"]["validators"]["active_set"] == []
    assert state["validators"]["registry"]["@alice"]["active"] is False
