from __future__ import annotations

from copy import deepcopy
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_envelope import TxEnvelope


Json = dict[str, Any]


def _clone(x: Json) -> Json:
    return deepcopy(x)


def _state() -> Json:
    return {
        "time": 1,
        "height": 0,
        "accounts": {
            "alice": {"balance": 1000, "nonce": 0, "poh_tier": 3},
            "bob": {"balance": 1000, "nonce": 0, "poh_tier": 3},
            "carol": {"balance": 1000, "nonce": 0, "poh_tier": 3},
        },
        "params": {
            "economic_unlock_time": 0,
            "economics_enabled": True,
            "system_signer": "SYSTEM",
        },
    }


def _env(
    tx_type: str,
    payload: dict[str, Any],
    *,
    signer: str,
    nonce: int,
    system: bool = False,
    parent: str = "",
) -> dict[str, Any]:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="",
        parent=parent,
        system=system,
    ).to_json()


def _apply(st: Json, tx_type: str, payload: dict[str, Any], *, signer: str, nonce: int, system: bool = False, parent: str = "") -> None:
    apply_tx(st, _env(tx_type, payload, signer=signer, nonce=nonce, system=system, parent=parent))


def _active_set(st: Json) -> list[str]:
    return list((((st.get("roles") or {}).get("validators") or {}).get("active_set") or []))


def _set_hash(st: Json) -> str:
    return str((((st.get("consensus") or {}).get("validator_set") or {}).get("set_hash") or ""))


def _epoch(st: Json) -> int:
    return int((((st.get("consensus") or {}).get("validator_set") or {}).get("epoch") or 0))


def _quorum(st: Json) -> int:
    return quorum_threshold(len(_active_set(st)))


def test_validator_epoch_transition_preserves_set_hash_equivalence_after_activation() -> None:
    a = _state()
    b = _clone(a)

    for st in (a, b):
        _apply(st, "VALIDATOR_SET_UPDATE", {"active_set": ["alice"], "activate_at_epoch": 1}, signer="SYSTEM", nonce=1, system=True, parent="gov:set:1")
        _apply(st, "EPOCH_OPEN", {"epoch": 1}, signer="SYSTEM", nonce=2, system=True)
        _apply(st, "VALIDATOR_CANDIDATE_REGISTER", {"node_id": "node-bob", "pubkey": "ed25519:bob", "endpoints": ["https://bob.example"]}, signer="bob", nonce=3)
        _apply(st, "VALIDATOR_CANDIDATE_APPROVE", {"account": "bob", "activate_at_epoch": 2}, signer="SYSTEM", nonce=4, system=True, parent="gov:approve:bob:2")
        _apply(st, "EPOCH_CLOSE", {"epoch": 1}, signer="SYSTEM", nonce=5, system=True)

    assert _active_set(a) == _active_set(b) == ["alice"]
    assert _set_hash(a) == _set_hash(b)
    assert _quorum(a) == _quorum(b) == 1

    for st in (a, b):
        _apply(st, "EPOCH_OPEN", {"epoch": 2}, signer="SYSTEM", nonce=6, system=True)

    assert _active_set(a) == _active_set(b) == ["alice", "bob"]
    assert _set_hash(a) == _set_hash(b)
    assert _epoch(a) == _epoch(b) == 2
    assert _quorum(a) == _quorum(b) == 2


def test_validator_epoch_transition_preserves_set_hash_equivalence_after_suspension_then_removal() -> None:
    a = _state()
    b = _clone(a)

    for st in (a, b):
        _apply(st, "VALIDATOR_SET_UPDATE", {"active_set": ["alice", "bob", "carol"], "activate_at_epoch": 1}, signer="SYSTEM", nonce=1, system=True, parent="gov:set:1")
        _apply(st, "EPOCH_OPEN", {"epoch": 1}, signer="SYSTEM", nonce=2, system=True)

    assert _active_set(a) == _active_set(b) == ["alice", "bob", "carol"]
    assert _set_hash(a) == _set_hash(b)

    for st in (a, b):
        _apply(st, "VALIDATOR_SUSPEND", {"account": "bob", "effective_epoch": 2, "reason": "liveness_failure"}, signer="SYSTEM", nonce=3, system=True, parent="gov:suspend:bob:2")
        _apply(st, "EPOCH_CLOSE", {"epoch": 1}, signer="SYSTEM", nonce=4, system=True)
        _apply(st, "EPOCH_OPEN", {"epoch": 2}, signer="SYSTEM", nonce=5, system=True)

    assert _active_set(a) == _active_set(b) == ["alice", "carol"]
    assert _set_hash(a) == _set_hash(b)
    assert _epoch(a) == _epoch(b) == 2
    assert _quorum(a) == _quorum(b) == 2

    for st in (a, b):
        _apply(st, "VALIDATOR_REMOVE", {"account": "carol", "effective_epoch": 3, "reason": "withdrawn"}, signer="SYSTEM", nonce=6, system=True, parent="gov:remove:carol:3")
        _apply(st, "EPOCH_CLOSE", {"epoch": 2}, signer="SYSTEM", nonce=7, system=True)
        _apply(st, "EPOCH_OPEN", {"epoch": 3}, signer="SYSTEM", nonce=8, system=True)

    assert _active_set(a) == _active_set(b) == ["alice"]
    assert _set_hash(a) == _set_hash(b)
    assert _epoch(a) == _epoch(b) == 3
    assert _quorum(a) == _quorum(b) == 1
