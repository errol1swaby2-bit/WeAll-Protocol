# projects/Weall-Protocol/tests/test_ipfs_cid_and_capacity_gates.py
from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str,
    *,
    signer: str,
    nonce: int,
    payload: dict,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
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
    }


def _enable_storage_responsibility(
    st: dict,
    account_id: str,
    *,
    declared: int,
    proven: int,
    allocated: int = 0,
    used: int = 0,
) -> None:
    roles = st.setdefault("roles", {})
    node_ops = roles.setdefault("node_operators", {})
    active_set = node_ops.setdefault("active_set", [])
    if account_id not in active_set:
        active_set.append(account_id)
    by_id = node_ops.setdefault("by_id", {})
    rec = by_id.setdefault(
        account_id,
        {
            "account_id": account_id,
            "status": "active",
            "active": True,
            "node_pubkey": f"{account_id}-node",
            "devices": [{"device_type": "node", "public_key": f"{account_id}-node", "active": True}],
        },
    )
    rec["status"] = "active"
    rec["active"] = True
    rec["enrolled"] = True
    rec["node_pubkey"] = f"{account_id}-node"
    rec["devices"] = [{"device_type": "node", "public_key": f"{account_id}-node", "active": True}]
    responsibilities = rec.setdefault("responsibilities", {})
    responsibilities["storage"] = {
        "opted_in": True,
        "active": True,
        "proof_status": "verified",
        "declared_capacity_bytes": int(declared),
        "reserved_capacity_bytes": int(declared),
        "probed_capacity_bytes": int(proven),
        "proven_capacity_bytes": int(proven),
        "allocated_capacity_bytes": int(allocated),
        "used_capacity_bytes": int(used),
        "proof_expires_height": 10_000,
    }

    accounts = st.setdefault("accounts", {})
    accounts.setdefault(account_id, {"poh_tier": 2, "tier": 2, "reputation_milli": 2000})
    accounts[account_id]["poh_tier"] = 2
    accounts[account_id]["tier"] = 2
    accounts[account_id]["reputation_milli"] = 2000
    accounts[account_id]["devices"] = {
        "by_id": {
            f"{account_id}-node": {
                "device_type": "node",
                "pubkey": f"{account_id}-node",
                "revoked": False,
            }
        }
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
    st["storage"]["operators"]["opA"] = {
        "account_id": "opA",
        "enabled": True,
        "capacity_bytes": 10,
        "used_bytes": 9,
    }
    st["storage"]["operators"]["opB"] = {
        "account_id": "opB",
        "enabled": True,
        "capacity_bytes": 1000,
        "used_bytes": 0,
    }
    st["storage"]["operators"]["opC"] = {
        "account_id": "opC",
        "enabled": True,
        "capacity_bytes": 0,
        "used_bytes": 0,
    }

    _enable_storage_responsibility(st, "opA", declared=10, proven=10, allocated=9, used=9)
    _enable_storage_responsibility(st, "opB", declared=1000, proven=1000)
    _enable_storage_responsibility(st, "opC", declared=1000, proven=1000)

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
    st["storage"]["operators"]["opA"] = {
        "account_id": "opA",
        "enabled": True,
        "capacity_bytes": 1000,
        "used_bytes": 0,
    }
    _enable_storage_responsibility(st, "opA", declared=1000, proven=1000)

    cid = "baaaaaaaaaaaaaaaaaaaaa"
    m = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            signer="alice",
            nonce=1,
            payload={"cid": cid, "size_bytes": 7},
            system=False,
        ),
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
