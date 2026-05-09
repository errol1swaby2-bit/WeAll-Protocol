from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import system_tx_emitter, validate_system_tx_queue_binding
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex
from pathlib import Path


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"))


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _state(*, explicit_electorate: bool) -> dict:
    st = {
        "chain_id": "weall-prod",
        "height": 10,
        "time": 9_999,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
        },
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 1,
            "economics_enabled": False,
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION"],
        },
        "system_queue": [],
    }
    if explicit_electorate:
        st["roles"] = {
            "validators": {
                "active_set": ["@alice"],
                "by_id": {"@alice": {"status": "active", "active": True}},
            }
        }
    return st


def test_economics_activation_cannot_be_created_without_hardened_electorate_batch322() -> None:
    st = _state(explicit_electorate=False)

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@alice",
                1,
                {
                    "proposal_id": "p-econ",
                    "title": "activate economics",
                    "rules": {"start_stage": "voting"},
                    "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
                },
            ),
        )

    assert ei.value.reason == "executable_governance_requires_explicit_electorate"
    assert st["params"]["economics_enabled"] is False


def test_economics_activation_can_execute_only_with_explicit_electorate_batch322() -> None:
    st = _state(explicit_electorate=True)
    canon = _tx_index()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-econ",
                "title": "activate economics",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
            },
        ),
    )
    apply_tx(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-econ", "vote": "yes"}))

    emitted = system_tx_emitter(st, canon, next_height=11, phase="post")
    for env in emitted:
        ok, why = validate_system_tx_queue_binding(st, canon, env, next_height=11, phase="post")
        assert ok, why
        apply_tx(st, env)

    emitted = system_tx_emitter(st, canon, next_height=12, phase="post")
    assert [env.tx_type for env in emitted] == ["ECONOMICS_ACTIVATION", "GOV_EXECUTION_RECEIPT", "GOV_PROPOSAL_RECEIPT"]
    for env in emitted:
        ok, why = validate_system_tx_queue_binding(st, canon, env, next_height=12, phase="post")
        assert ok, why
        apply_tx(st, env)

    assert st["params"]["economics_enabled"] is True
