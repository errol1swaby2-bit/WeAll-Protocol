"""Batch C adversarial role-authorization and fail-atomicity regressions.

These are executable checks of existing boundaries, not semantic sign-off.
"""
from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.domain_apply import apply_tx
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_canon_index


def _env(tx_type: str, account: str, *, system: bool = True, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM" if system else account,
        nonce=1,
        payload={"account_id": account},
        system=system,
        parent=parent,
        chain_id="weall-testnet-v1",
    )


@pytest.mark.parametrize(
    "tx_type",
    [
        "ROLE_EMISSARY_SEAT",
        "ROLE_GOV_EXECUTOR_SET",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_VALIDATOR_ACTIVATE",
    ],
)
def test_privileged_role_handlers_reject_non_system_direct_calls(tx_type: str) -> None:
    state = {"accounts": {}, "roles": {}}
    with pytest.raises(RolesApplyError) as error:
        apply_roles(state, _env(tx_type, "@target", system=False))
    assert error.value.code == "forbidden"
    assert error.value.reason == "system_tx_required"


@pytest.mark.parametrize(
    "tx_type",
    [
        "ROLE_EMISSARY_SEAT",
        "ROLE_GOV_EXECUTOR_SET",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_VALIDATOR_ACTIVATE",
    ],
)
def test_rejected_system_role_activation_is_fail_atomic(tx_type: str) -> None:
    # A SYSTEM marker does not make a nonexistent account eligible.
    state = {"accounts": {}, "roles": {}}
    before = copy.deepcopy(state)
    with pytest.raises(Exception):
        apply_tx(state, _env(tx_type, "@missing"))
    assert state == before


def test_role_queue_binding_rejects_parent_substitution() -> None:
    canon = load_canon_index()
    state = {"system_queue": []}
    enqueue_system_tx(
        state,
        tx_type="ROLE_EMISSARY_SEAT",
        payload={"account_id": "@target"},
        due_height=7,
        signer="SYSTEM",
        parent="proposal:approved",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon=canon, next_height=7, phase="post")
    assert len(emitted) == 1
    genuine = emitted[0]
    ok, reason = validate_system_tx_queue_binding(
        state, canon, genuine, next_height=7, phase="post"
    )
    assert ok, reason

    forged = TxEnvelope(
        tx_type=genuine.tx_type,
        signer=genuine.signer,
        nonce=genuine.nonce,
        payload=dict(genuine.payload),
        system=True,
        parent="proposal:forged",
        chain_id="weall-testnet-v1",
    )
    ok, reason = validate_system_tx_queue_binding(
        state, canon, forged, next_height=7, phase="post"
    )
    assert not ok
    assert reason == "system_queue_parent_mismatch"


def test_role_queue_binding_rejects_target_substitution() -> None:
    canon = load_canon_index()
    state = {"system_queue": []}
    enqueue_system_tx(
        state,
        tx_type="ROLE_GOV_EXECUTOR_SET",
        payload={"account_id": "@target"},
        due_height=7,
        signer="SYSTEM",
        parent="proposal:approved",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon=canon, next_height=7, phase="post")
    assert len(emitted) == 1
    genuine = emitted[0]
    forged = TxEnvelope(
        tx_type=genuine.tx_type,
        signer=genuine.signer,
        nonce=genuine.nonce,
        payload={**genuine.payload, "account_id": "@attacker"},
        system=True,
        parent=genuine.parent,
        chain_id="weall-testnet-v1",
    )
    ok, reason = validate_system_tx_queue_binding(
        state, canon, forged, next_height=7, phase="post"
    )
    assert not ok
    assert reason == "system_queue_payload_mismatch"
