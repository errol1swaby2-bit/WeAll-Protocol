from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _repo_root() -> Path:
    # tests/ is at repo_root/tests
    return Path(__file__).resolve().parents[1]


def _load_canon_tx_names() -> List[str]:
    canon_path = _repo_root() / "specs" / "tx_canon" / "tx_canon.yaml"
    if not canon_path.exists():
        raise RuntimeError(f"Missing canon file: {canon_path}")

    data = yaml.safe_load(canon_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("tx_canon.yaml must parse as a dict")

    txs = data.get("txs")
    if not isinstance(txs, list):
        raise RuntimeError("tx_canon.yaml must contain top-level key 'txs' as a list")

    names: List[str] = []
    for i, item in enumerate(txs):
        if not isinstance(item, dict):
            raise RuntimeError(f"txs[{i}] must be a dict")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError(f"txs[{i}] missing/invalid 'name'")
        names.append(name.strip())

    return names


def _load_canon_receipt_only_defs() -> List[Dict[str, Any]]:
    """Return canon tx defs that are receipt_only and declare a parent.

    We only need a subset of fields for apply-time testing: name, parent, origin.
    """

    canon_path = _repo_root() / "specs" / "tx_canon" / "tx_canon.yaml"
    data = yaml.safe_load(canon_path.read_text(encoding="utf-8"))
    txs = data.get("txs")
    if not isinstance(txs, list):
        return []

    out: List[Dict[str, Any]] = []
    for item in txs:
        if not isinstance(item, dict):
            continue
        if not bool(item.get("receipt_only", False)):
            continue
        parent = item.get("parent")
        # In canon we represent single-parent receipts as a string.
        if not isinstance(parent, str) or not parent.strip():
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        origin = item.get("origin")
        out.append({"name": name.strip(), "parent": parent.strip(), "origin": str(origin or "").strip().upper()})

    return out


def _attempt_apply(tx_type: str, system_flag: bool) -> bool:
    """Return True if apply_tx() CLAIMS tx_type.

    "Claimed" means apply_tx() does *not* fail with:
      code == "tx_unimplemented" AND reason == "tx_type_not_implemented".

    Any other outcome counts as claimed (including other ApplyError values),
    because it means a handler recognized the tx but rejected payload/state.
    """

    st: Dict[str, Any] = {}

    env = TxEnvelope(
        tx_type=tx_type,
        signer="ci",
        nonce=1,
        payload={},
        sig="",
        parent=None,
        system=system_flag,
    )

    try:
        apply_tx(st, env)
        return True
    except ApplyError as e:
        code = str(getattr(e, "code", "") or "")
        reason = str(getattr(e, "reason", "") or "")
        if code == "tx_unimplemented" and reason == "tx_type_not_implemented":
            return False
        return True


@pytest.mark.parametrize("tx_type", _load_canon_tx_names())
def test_every_canon_tx_is_claimed_by_apply_tx(tx_type: str) -> None:
    """Canon enforcement check.

    We try both system=False and system=True so a tx can't "look unimplemented"
    just because it's only claimable on the system/block path.
    """

    claimed = _attempt_apply(tx_type, system_flag=False) or _attempt_apply(tx_type, system_flag=True)
    assert claimed, f"Canon tx not claimed by apply_tx(): {tx_type}"


@pytest.mark.parametrize("txdef", _load_canon_receipt_only_defs())
def test_receipt_only_canon_txs_are_claimed_when_parent_present(txdef: Dict[str, Any]) -> None:
    """Receipt-only canon coverage check that avoids the "missing parent" blind spot.

    For receipt_only txs with an explicit parent in the canon, apply-time enforcement
    requires env.parent. This test supplies env.parent so that a truly unimplemented
    tx cannot hide behind the parent-required gate.

    We keep payload empty on purpose: we only care that the tx is *claimed*
    (i.e., not tx_unimplemented/tx_type_not_implemented).
    """

    tx_type = str(txdef.get("name") or "").strip()
    parent = str(txdef.get("parent") or "").strip()
    origin = str(txdef.get("origin") or "").strip().upper()

    st: Dict[str, Any] = {}

    # Apply-time canon enforcement requires system flag + system signer when origin=SYSTEM.
    system_flag = origin == "SYSTEM"
    signer = "SYSTEM" if system_flag else "ci"

    env = TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=1,
        payload={},
        sig="",
        parent=parent,
        system=system_flag,
    )

    try:
        apply_tx(st, env)
        claimed = True
    except ApplyError as e:
        code = str(getattr(e, "code", "") or "")
        reason = str(getattr(e, "reason", "") or "")
        claimed = not (code == "tx_unimplemented" and reason == "tx_type_not_implemented")

    assert claimed, f"Receipt-only canon tx not claimed by apply_tx() when parent is present: {tx_type}"
