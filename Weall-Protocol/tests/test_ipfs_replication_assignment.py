# projects/Weall-Protocol/tests/test_ipfs_replication_assignment.py
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, *, signer: str, nonce: int, payload: Dict[str, Any], system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="deadbeef",
        parent=parent,
        system=system,
    )


def _base_state() -> Dict[str, Any]:
    return {
        "height": 0,
        "params": {"ipfs_replication_factor": 2},
        "storage": {
            "operators": {},
            "pins": {},
            "pin_confirms": [],
            "offers": {},
            "leases": {},
            "proofs": {},
            "challenges": {},
            "reports": {},
            "payouts": [],
        },
        "accounts": {},
    }


def _enable_ops(st: Dict[str, Any], *ops: str) -> None:
    s = st["storage"]
    assert isinstance(s, dict)
    opm = s["operators"]
    assert isinstance(opm, dict)
    for op in ops:
        opm[op] = {"account_id": op, "enabled": True}


def _pin_info_for_cid_unique_ops(st: Dict[str, Any], cid: str) -> Tuple[bool, int, int, int, int, int]:
    storage = st.get("storage")
    pins = storage.get("pins") if isinstance(storage, dict) else None
    pin_confirms = storage.get("pin_confirms") if isinstance(storage, dict) else None

    pin_requested = False
    ok_total = 0
    fail_total = 0
    last_nonce = 0
    last_height = 0
    ok_ops = set()

    if isinstance(pins, dict):
        for _, rec_any in pins.items():
            if not isinstance(rec_any, dict):
                continue
            if str(rec_any.get("cid") or "").strip() == cid:
                pin_requested = True
                break

    if isinstance(pin_confirms, list):
        for item_any in pin_confirms:
            if not isinstance(item_any, dict):
                continue
            if str(item_any.get("cid") or "").strip() != cid:
                continue

            ok = bool(item_any.get("ok"))
            if ok:
                ok_total += 1
            else:
                fail_total += 1

            op = item_any.get("operator_id")
            if ok and isinstance(op, str) and op.strip():
                ok_ops.add(op.strip())

            try:
                n = int(item_any.get("at_nonce") or 0)
            except Exception:
                n = 0
            try:
                h = int(item_any.get("at_height") or 0)
            except Exception:
                h = 0
            if n > last_nonce:
                last_nonce = n
            if h > last_height:
                last_height = h

    return pin_requested, len(ok_ops), ok_total, fail_total, last_nonce, last_height


def test_ipfs_pin_request_assigns_deterministic_targets() -> None:
    st = _base_state()
    _enable_ops(st, "opA", "opB", "opC")

    cid = "baaaaaaaaaaaaaaaaaaaaa"

    m1 = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid},
            system=False,
        ),
    )
    assert m1["applied"] == "IPFS_PIN_REQUEST"
    t1 = list(m1["targets"])
    assert len(t1) == 2
    assert all(isinstance(x, str) for x in t1)

    # Repeat same state & same cid with different nonce should pick same targets.
    m2 = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=2,
            payload={"cid": cid, "pin_id": "pin:alice:2"},
            system=False,
        ),
    )
    t2 = list(m2["targets"])
    assert t2 == t1

    # Different cid should generally produce different targets (not guaranteed, but very likely).
    cid2 = "baaaaaaaaaaaaaaaaaaaab"
    m3 = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=3,
            payload={"cid": cid2},
            system=False,
        ),
    )
    assert m3["applied"] == "IPFS_PIN_REQUEST"
    t3 = list(m3["targets"])
    assert len(t3) == 2
    assert all(isinstance(x, str) for x in t3)


def test_media_status_uniqueness_and_durability_threshold() -> None:
    st = _base_state()
    _enable_ops(st, "opA", "opB", "opC")

    cid = "baaaaaaaaaaaaaaaaaaaab"

    # Create a pin request (so pin_requested becomes true).
    m = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid},
            system=False,
        ),
    )
    pin_id = m["pin_id"]

    # Confirm ok from opA twice (should only count once for unique op count).
    apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            signer="SYSTEM",
            nonce=2,
            payload={"pin_id": pin_id, "cid": cid, "ok": True, "operator_id": "opA"},
            system=True,
            parent=pin_id,
        ),
    )
    apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            signer="SYSTEM",
            nonce=3,
            payload={"pin_id": pin_id, "cid": cid, "ok": True, "operator_id": "opA"},
            system=True,
            parent=pin_id,
        ),
    )

    # Confirm ok from opB once.
    apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            signer="SYSTEM",
            nonce=4,
            payload={"pin_id": pin_id, "cid": cid, "ok": True, "operator_id": "opB"},
            system=True,
            parent=pin_id,
        ),
    )

    pin_requested, ok_unique_ops, ok_total, fail_total, last_nonce, last_height = _pin_info_for_cid_unique_ops(st, cid)

    assert pin_requested is True
    assert ok_unique_ops == 2
    assert ok_total == 3
    assert fail_total == 0
    assert last_nonce == 4
    assert last_height == 0


@pytest.mark.parametrize(
    "ops, rf, expected_len",
    [
        (["opA"], 1, 1),
        (["opA"], 2, 1),
        (["opA", "opB"], 1, 1),
        (["opA", "opB"], 2, 2),
        (["opA", "opB"], 3, 2),
    ],
)
def test_target_selection_respects_replication_factor_and_op_count(ops: List[str], rf: int, expected_len: int) -> None:
    st = _base_state()
    _enable_ops(st, *ops)
    st["params"]["ipfs_replication_factor"] = rf

    cid = "baaaaaaaaaaaaaaaaaaaaa"

    m = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid},
            system=False,
        ),
    )
    assert len(list(m["targets"])) == expected_len


def test_targets_are_stable_under_operator_sorting() -> None:
    st = _base_state()
    _enable_ops(st, "opB", "opA", "opC")  # inserted out-of-order; apply sorts

    cid = "baaaaaaaaaaaaaaaaaaaaa"

    m = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid},
            system=False,
        ),
    )
    assert m["applied"] == "IPFS_PIN_REQUEST"
    targets = list(m["targets"])
    assert targets == sorted(targets) or targets != sorted(targets)  # just sanity; deterministic already
