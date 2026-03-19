# tests/p0/test_p0_mempool_and_admission_invariants.py
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from weall.runtime.domain_apply import apply_tx_atomic
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import TxIndex

Json = dict[str, Any]


def clone_state(state: Json) -> Json:
    return copy.deepcopy(state)


def _canon_acct(a: str) -> str:
    a = str(a)
    return a if a.startswith("@") else f"@{a}"


def _ensure_canonical_accounts_for_admission(st: Json, ids: list[str]) -> None:
    """
    Admission expects canonical account IDs to exist as keys in state['accounts'].
    The base_state fixture uses non-canonical keys ("alice", "bob"), so we mirror them
    into "@alice", "@bob" for admission tests.

    We COPY the dicts (not alias) to avoid surprising coupling.
    """
    accs = st.setdefault("accounts", {})
    assert isinstance(accs, dict)

    for raw in ids:
        canon = _canon_acct(raw)
        if canon in accs:
            continue
        if raw in accs and isinstance(accs[raw], dict):
            accs[canon] = copy.deepcopy(accs[raw])
        else:
            # If missing, create a minimal account so admission can find the signer.
            accs[canon] = {"balance": 0, "nonce": 0, "poh_tier": 3}


def _load_index() -> TxIndex:
    here = Path(__file__).resolve()
    for root in [here.parent, *here.parents]:
        cand = root / "generated" / "tx_index.json"
        if cand.exists():
            return TxIndex.load_from_file(cand)
    return TxIndex.load_from_file(Path("generated/tx_index.json"))


def _acct(st: Json, a: str) -> dict[str, Any]:
    accs = st.get("accounts")
    assert isinstance(accs, dict)
    acct = accs.get(a)
    if isinstance(acct, dict):
        return acct
    acct2 = accs.get(_canon_acct(a))
    assert isinstance(acct2, dict)
    return acct2


def _env(
    tx_type: str,
    payload: Json | None = None,
    *,
    signer: str,
    nonce: int,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    e: Json = {
        "tx_type": str(tx_type),
        "signer": _canon_acct(signer) if not system else str(signer),
        "nonce": int(nonce),
        "payload": dict(payload or {}),
        "sig": "",
        "system": bool(system),
    }
    if parent is not None:
        e["parent"] = parent
    return e


def _admit_ok(st: Json, env: Json, *, context: str = "mempool") -> None:
    idx = _load_index()
    v = admit_tx(tx=env, ledger=st, canon=idx, context=context)
    assert bool(v.ok) is True, f"expected ok=True, got {v}"


def _admit_bad_nonce(st: Json, env: Json, *, context: str = "mempool") -> None:
    idx = _load_index()
    v = admit_tx(tx=env, ledger=st, canon=idx, context=context)
    assert bool(v.ok) is False, f"expected ok=False, got {v}"
    assert v.code == "bad_nonce"


def test_mempool_admission_rejects_replay_nonce_after_success(base_state) -> None:
    """
    Nonce enforcement is an admission rule.
    This test uses canonical tx fields AND ensures canonical accounts exist in ledger.
    """
    st = clone_state(base_state)
    _ensure_canonical_accounts_for_admission(st, ["alice", "bob"])

    tx1 = _env(
        "BALANCE_TRANSFER",
        {"from": "@alice", "to": "@bob", "amount": 1},
        signer="alice",
        nonce=1,
    )
    _admit_ok(st, tx1, context="mempool")
    apply_tx_atomic(st, tx1)

    # Replay nonce=1 should be rejected by admission.
    tx_replay = _env(
        "BALANCE_TRANSFER",
        {"from": "@alice", "to": "@bob", "amount": 1},
        signer="alice",
        nonce=1,
    )
    _admit_bad_nonce(st, tx_replay, context="mempool")


def test_mempool_admission_rejects_replay_nonce_after_reject_consumes_nonce(base_state) -> None:
    """
    Policy: nonce is consumed even when apply rejects.
    Assert via admission replay rejection.
    """
    st = clone_state(base_state)
    _ensure_canonical_accounts_for_admission(st, ["alice", "bob"])

    tx_fail = _env(
        "BALANCE_TRANSFER",
        {"from": "@bob", "to": "@alice", "amount": 10_000_000},
        signer="bob",
        nonce=1,
    )
    _admit_ok(st, tx_fail, context="mempool")

    with pytest.raises(ApplyError):
        apply_tx_atomic(st, tx_fail)

    tx_replay = _env(
        "BALANCE_TRANSFER",
        {"from": "@bob", "to": "@alice", "amount": 1},
        signer="bob",
        nonce=1,
    )
    _admit_bad_nonce(st, tx_replay, context="mempool")


def test_poh_tier1_view_only_gating_if_social_txs_exist(base_state) -> None:
    """
    Tier1 = view-only.
    Enforce only for social tx types that exist in canon for this build.
    """
    st = clone_state(base_state)
    st.setdefault("accounts", {})["t1"] = {"balance": 0, "nonce": 0, "poh_tier": 1}
    _ensure_canonical_accounts_for_admission(st, ["t1"])

    candidates: list[tuple[str, dict[str, Any]]] = [
        ("CONTENT_POST", {"content_id": "c1", "text": "hi"}),
        ("CONTENT_COMMENT", {"content_id": "c1", "comment_id": "m1", "text": "yo"}),
        ("CONTENT_LIKE", {"content_id": "c1"}),
    ]

    idx = _load_index()

    for tx_type, payload in candidates:
        if idx.get(tx_type) is None:
            continue

        env = _env(tx_type, payload, signer="t1", nonce=1)
        v = admit_tx(tx=env, ledger=st, canon=idx, context="mempool")

        assert bool(v.ok) is False
        assert v.code in ("gate_denied", "forbidden", "reputation_too_low")


def test_one_node_per_account_enforced_via_account_device_register(base_state) -> None:
    """
    Enforced via ACCOUNT_DEVICE_REGISTER rules.
    """
    st = clone_state(base_state)
    st.setdefault("accounts", {})["accx"] = {"balance": 0, "nonce": 0, "poh_tier": 3}
    _ensure_canonical_accounts_for_admission(st, ["accx"])

    d1 = _env(
        "ACCOUNT_DEVICE_REGISTER",
        {"device_id": "node:accx", "device_type": "node", "label": "node", "pubkey": "pkx"},
        signer="accx",
        nonce=1,
    )
    apply_tx_atomic(st, d1)

    d2 = _env(
        "ACCOUNT_DEVICE_REGISTER",
        {"device_id": "node:accx:alt", "device_type": "node", "label": "node-alt", "pubkey": "pkx"},
        signer="accx",
        nonce=2,
    )
    with pytest.raises(Exception) as ei:
        apply_tx_atomic(st, d2)

    assert "one_node_per_account" in str(ei.value)


def test_reject_has_no_side_effects_on_unrelated_state(base_state) -> None:
    st = clone_state(base_state)
    before = copy.deepcopy(st)
    _ensure_canonical_accounts_for_admission(st, ["alice"])

    bad_vote = _env(
        "GOV_VOTE_CAST",
        {"proposal_id": "does-not-exist", "vote": "yes"},
        signer="alice",
        nonce=1,
    )

    with pytest.raises(ApplyError) as ei:
        apply_tx_atomic(st, bad_vote)

    err = ei.value
    assert err.code in ("invalid_state", "forbidden", "not_found")

    for k in ("blocks", "system_queue", "ipfs_replication", "roles"):
        assert st.get(k) == before.get(k)
