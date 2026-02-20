# tests/test_apply_fail_closed.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.supported_txs import SUPPORTED_TX_TYPES
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


# This list MUST match what is actually routed/implemented in src/weall/runtime/domain_apply.py.
# The purpose of this test is to ensure apply_tx() fails closed for any canon tx_type that
# is not explicitly implemented in the deterministic apply router.
_IMPLEMENTED = set(SUPPORTED_TX_TYPES)


def test_apply_fails_closed_for_unimplemented_tx_types() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    idx = load_tx_index_json(canon_path)

    # Find a tx type that exists in canon but is NOT implemented in domain_apply.py
    unimpl = None
    for tx in idx.tx_types:
        name = tx["name"]
        if name not in _IMPLEMENTED:
            unimpl = name
            break

    # If canon currently includes only implemented txs (unlikely), skip.
    if not unimpl:
        return

    env = TxEnvelope(
        tx_type=unimpl,
        signer="alice",
        nonce=1,
        payload={},
        sig="deadbeef",
        parent=None,
    )

    with pytest.raises(ApplyError) as e:
        apply_tx({}, env)

    err = e.value
    assert err.code == "tx_unimplemented"
    assert err.reason == "tx_type_not_implemented"
