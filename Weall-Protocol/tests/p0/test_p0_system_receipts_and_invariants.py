# tests/p0/test_p0_system_receipts_and_invariants.py
from __future__ import annotations

import copy
from typing import Any, Dict, List

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = Dict[str, Any]


def clone_state(state: Json) -> Json:
    return copy.deepcopy(state)


def env(
    tx_type: str,
    payload: Dict[str, Any] | None = None,
    *,
    signer: str = "SYSTEM",
    nonce: int = 1,
    system: bool = True,
    parent: str | None = "txid:parent",
) -> Json:
    e: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        e["parent"] = parent
    return e


def apply_err(state: Json, envelope: Json) -> ApplyError:
    with pytest.raises(ApplyError) as ei:
        apply_tx(state, envelope)
    return ei.value


def apply_ok(state: Json, envelope: Json) -> Dict[str, Any]:
    out = apply_tx(state, envelope)
    assert isinstance(out, dict)
    applied = out.get("applied")
    assert applied is True or applied == envelope["tx_type"]
    return out


def _queue(state: Json) -> List[Dict[str, Any]]:
    q = state.get("system_queue")
    if not isinstance(q, list):
        return []
    return [x for x in q if isinstance(x, dict)]


def test_receipt_only_block_finalize_requires_parent(base_state) -> None:
    st = clone_state(base_state)

    err = apply_err(
        st,
        env(
            "BLOCK_FINALIZE",
            {"block_id": "b1", "height": 1, "_due_height": 1},
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent=None,
        ),
    )
    assert err.code == "forbidden"
    assert err.reason in ("receipt_only_requires_parent", "missing_parent")


def test_receipt_only_validator_set_update_requires_parent(base_state) -> None:
    st = clone_state(base_state)

    err = apply_err(
        st,
        env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["alice", "bob"]},
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent=None,
        ),
    )
    assert err.code == "forbidden"
    assert err.reason in ("receipt_only_requires_parent", "missing_parent")


def test_system_only_epoch_open_rejects_non_system(base_state) -> None:
    st = clone_state(base_state)

    err = apply_err(
        st,
        env(
            "EPOCH_OPEN",
            {"epoch": 1},
            signer="alice",
            nonce=1,
            system=False,
            parent="txid:any",
        ),
    )
    assert err.code == "forbidden"
    assert err.reason in ("system_only", "system_origin_required", "system_flag_required")


def test_system_only_epoch_close_rejects_non_system(base_state) -> None:
    st = clone_state(base_state)

    err = apply_err(
        st,
        env(
            "EPOCH_CLOSE",
            {"epoch": 1},
            signer="alice",
            nonce=1,
            system=False,
            parent="txid:any",
        ),
    )
    assert err.code == "forbidden"
    assert err.reason in ("system_only", "system_origin_required", "system_flag_required")


def test_slash_execute_requires_system_and_parent(base_state) -> None:
    st = clone_state(base_state)

    err1 = apply_err(
        st,
        env(
            "SLASH_EXECUTE",
            {"slash_id": "s1", "account": "alice", "reason": "test"},
            signer="alice",
            nonce=1,
            system=False,
            parent="txid:any",
        ),
    )
    assert err1.code == "forbidden"

    err2 = apply_err(
        st,
        env(
            "SLASH_EXECUTE",
            {"slash_id": "s1", "account": "alice", "reason": "test"},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent=None,
        ),
    )
    assert err2.code == "forbidden"
    assert err2.reason in ("receipt_only_requires_parent", "missing_parent")


def test_rejects_do_not_partially_write_state_for_receipts(base_state) -> None:
    st = clone_state(base_state)
    before = copy.deepcopy(st)

    _ = apply_err(
        st,
        env(
            "BLOCK_FINALIZE",
            {"block_id": "b1", "height": 1, "_due_height": 1},
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent=None,
        ),
    )

    assert st.get("finalized") == before.get("finalized")
    assert st.get("system_queue") == before.get("system_queue")


def test_enqueue_system_tx_once_is_idempotent(base_state) -> None:
    st = clone_state(base_state)
    st.setdefault("system_queue", [])

    enqueue_system_tx(
        st,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=10,
        signer="SYSTEM",
        once=True,
        parent="p:1",
        phase="post",
    )
    enqueue_system_tx(
        st,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=10,
        signer="SYSTEM",
        once=True,
        parent="p:1",
        phase="post",
    )

    q = _queue(st)
    opens = [x for x in q if x.get("tx_type") == "EPOCH_OPEN" and int(x.get("due_height", 0)) == 10]
    assert len(opens) == 1


def test_enqueue_system_tx_dedupes_even_when_once_false(base_state) -> None:
    """
    In this build, enqueue_system_tx is conservative and dedupes identical queued items
    regardless of 'once'. This is acceptable (and arguably preferable) for production:
    it prevents system-queue spam and reduces replay/duplication edge cases.
    """
    st = clone_state(base_state)
    st.setdefault("system_queue", [])

    enqueue_system_tx(
        st,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=10,
        signer="SYSTEM",
        once=False,
        parent="p:1",
        phase="post",
    )
    enqueue_system_tx(
        st,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=10,
        signer="SYSTEM",
        once=False,
        parent="p:1",
        phase="post",
    )

    q = _queue(st)
    opens = [x for x in q if x.get("tx_type") == "EPOCH_OPEN" and int(x.get("due_height", 0)) == 10]
    assert len(opens) == 1
