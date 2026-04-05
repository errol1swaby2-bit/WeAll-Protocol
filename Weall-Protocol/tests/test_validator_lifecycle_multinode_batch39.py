from __future__ import annotations

from copy import deepcopy
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_envelope import TxEnvelope


Json = dict[str, Any]


def _clone(x: Json) -> Json:
    return deepcopy(x)


def _base_state() -> Json:
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


def _activate_set(st: Json, active_set: list[str], *, activate_at_epoch: int, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": active_set, "activate_at_epoch": activate_at_epoch},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent=f"gov:set:{activate_at_epoch}:{nonce}",
        ),
    )


def _epoch_open(st: Json, epoch: int, *, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "EPOCH_OPEN",
            {"epoch": epoch},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
        ),
    )


def _epoch_close(st: Json, epoch: int, *, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "EPOCH_CLOSE",
            {"epoch": epoch},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
        ),
    )


def _register_candidate(st: Json, account: str, *, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "VALIDATOR_CANDIDATE_REGISTER",
            {
                "node_id": f"node-{account}",
                "pubkey": f"ed25519:{account}",
                "endpoints": [f"https://{account}.example"],
            },
            signer=account,
            nonce=nonce,
        ),
    )


def _approve_candidate(st: Json, account: str, *, activate_at_epoch: int, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "VALIDATOR_CANDIDATE_APPROVE",
            {"account": account, "activate_at_epoch": activate_at_epoch},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent=f"gov:approve:{account}:{activate_at_epoch}",
        ),
    )


def _suspend_validator(st: Json, account: str, *, effective_epoch: int, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "VALIDATOR_SUSPEND",
            {"account": account, "effective_epoch": effective_epoch, "reason": "liveness_failure"},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent=f"gov:suspend:{account}:{effective_epoch}",
        ),
    )


def _remove_validator(st: Json, account: str, *, effective_epoch: int, nonce: int) -> None:
    apply_tx(
        st,
        _env(
            "VALIDATOR_REMOVE",
            {"account": account, "effective_epoch": effective_epoch, "reason": "withdrawn"},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent=f"gov:remove:{account}:{effective_epoch}",
        ),
    )


def _active_set(st: Json) -> list[str]:
    return list((((st.get("roles") or {}).get("validators") or {}).get("active_set") or []))


def _set_hash(st: Json) -> str:
    return str((((st.get("consensus") or {}).get("validator_set") or {}).get("set_hash") or ""))


def _validator_epoch(st: Json) -> int:
    return int((((st.get("consensus") or {}).get("validator_set") or {}).get("epoch") or 0))


def _quorum(st: Json) -> int:
    return quorum_threshold(len(_active_set(st)))


def _assert_converged(nodes: list[Json]) -> None:
    active = [_active_set(n) for n in nodes]
    set_hashes = [_set_hash(n) for n in nodes]
    epochs = [_validator_epoch(n) for n in nodes]
    quorums = [_quorum(n) for n in nodes]
    assert all(x == active[0] for x in active)
    assert all(x == set_hashes[0] for x in set_hashes)
    assert all(x == epochs[0] for x in epochs)
    assert all(x == quorums[0] for x in quorums)


def test_multinode_candidate_approval_converges_at_epoch_boundary() -> None:
    base = _base_state()
    nodes = [_clone(base) for _ in range(3)]

    for st in nodes:
        _activate_set(st, ["alice"], activate_at_epoch=1, nonce=1)
        _epoch_open(st, 1, nonce=2)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice"]
    assert _quorum(nodes[0]) == 1

    for st in nodes:
        _register_candidate(st, "bob", nonce=3)
        _approve_candidate(st, "bob", activate_at_epoch=2, nonce=4)
        _epoch_close(st, 1, nonce=5)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice"]

    for st in nodes:
        _epoch_open(st, 2, nonce=6)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob"]
    assert _validator_epoch(nodes[0]) == 2
    assert _quorum(nodes[0]) == 2


def test_multinode_suspension_converges_at_epoch_boundary() -> None:
    base = _base_state()
    nodes = [_clone(base) for _ in range(3)]

    for st in nodes:
        _activate_set(st, ["alice", "bob", "carol"], activate_at_epoch=1, nonce=1)
        _epoch_open(st, 1, nonce=2)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob", "carol"]
    assert _quorum(nodes[0]) == 2

    for st in nodes:
        _suspend_validator(st, "bob", effective_epoch=2, nonce=3)
        _epoch_close(st, 1, nonce=4)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob", "carol"]

    for st in nodes:
        _epoch_open(st, 2, nonce=5)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "carol"]
    assert _validator_epoch(nodes[0]) == 2
    assert _quorum(nodes[0]) == 2


def test_multinode_removal_converges_at_epoch_boundary() -> None:
    base = _base_state()
    nodes = [_clone(base) for _ in range(3)]

    for st in nodes:
        _activate_set(st, ["alice", "bob", "carol"], activate_at_epoch=1, nonce=1)
        _epoch_open(st, 1, nonce=2)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob", "carol"]

    for st in nodes:
        _remove_validator(st, "carol", effective_epoch=2, nonce=3)
        _epoch_close(st, 1, nonce=4)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob", "carol"]

    for st in nodes:
        _epoch_open(st, 2, nonce=5)

    _assert_converged(nodes)
    assert _active_set(nodes[0]) == ["alice", "bob"]
    assert _validator_epoch(nodes[0]) == 2
    assert _quorum(nodes[0]) == 2
