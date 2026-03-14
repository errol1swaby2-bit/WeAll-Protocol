# projects/Weall-Protocol/tests/test_ipfs_cid_and_capacity_gates.py
from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, *, signer: str, nonce: int, payload: dict, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="deadbeef",
        parent=parent,
        system=system,
    )


def _base_state() -> dict:
    return {
        "height": 0,
        "time": 1_700_000_000,
        "params": {"ipfs_replication_factor": 2},
        "storage": {"operators": {}, "pins": {}, "pin_confirms": [], "offers": {}, "leases": {}, "proofs": {}, "challenges": {}, "reports": {}, "payouts": []},
    }


def test_ipfs_pin_request_rejects_invalid_cid() -> None:
    st = _base_state()

    with pytest.raises(ApplyError) as e:
        apply_tx(
            st,
            _env(
                "IPFS_PIN_REQUEST",
                signer="alice",
                nonce=1,
                payload={"cid": "bafy-demo-cid-001"},  # invalid (hyphens)
                system=False,
            ),
        )

    # ApplyError wraps domain error; reason is stable.
    assert "invalid_cid_format" in str(e.value)


def test_ipfs_pin_request_capacity_filters_targets_when_size_known() -> None:
    st = _base_state()

    # opA has tight capacity; opB has plenty; opC unspecified (allowed)
    st["storage"]["operators"]["opA"] = {"account_id": "opA", "enabled": True, "capacity_bytes": 10, "used_bytes": 9}
    st["storage"]["operators"]["opB"] = {"account_id": "opB", "enabled": True, "capacity_bytes": 1000, "used_bytes": 0}
    st["storage"]["operators"]["opC"] = {"account_id": "opC", "enabled": True, "capacity_bytes": 0, "used_bytes": 0}

    cid = "baaaaaaaaaaaaaaaaaaaaa"

    m = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid, "size_bytes": 4},
            system=False,
        ),
    )
    assert m and m["applied"] == "IPFS_PIN_REQUEST"

    # With size_bytes=4, opA is ineligible (9+4 > 10), so targets must not include opA.
    assert "opA" not in set(m["targets"])
    assert len(m["targets"]) == 2
    assert all(t in {"opB", "opC"} for t in m["targets"])


def test_ipfs_pin_confirm_accounts_used_bytes_once_per_operator() -> None:
    st = _base_state()
    st["storage"]["operators"]["opA"] = {"account_id": "opA", "enabled": True, "capacity_bytes": 1000, "used_bytes": 0}

    cid = "baaaaaaaaaaaaaaaaaaaaa"
    m = apply_tx(
        st,
        _env("IPFS_PIN_REQUEST", signer="alice", nonce=1, payload={"cid": cid, "size_bytes": 7}, system=False),
    )
    pin_id = m["pin_id"]

    # First confirm increments used_bytes.
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
    assert int(st["storage"]["operators"]["opA"]["used_bytes"]) == 7

    # Duplicate confirm from same operator should not increment again.
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
    assert int(st["storage"]["operators"]["opA"]["used_bytes"]) == 7
