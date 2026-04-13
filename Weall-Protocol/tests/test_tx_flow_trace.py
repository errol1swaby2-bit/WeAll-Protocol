# tests/test_tx_flow_trace.py
from __future__ import annotations

from pathlib import Path

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.tx.canon import load_tx_index_json

_ALLOWED_CODES = {
    None,
    "block_only",
    "receipt_only",
    "invalid_payload",
    "payload_too_large",
    "tx_too_large",
    "bad_shape",
    "unknown_tx",
    "unknown_signer",
    "bad_nonce",
    "gate_denied",
    "reputation_too_low",
    "bad_sig",
    "forbidden",
    "receipt_only_tx_not_allowed_in_mempool",
    "tx_not_allowed_in_mempool",
    "system_tx_forbidden",
    "parent_required_by_canon",
    "non_canonical_account_id",
    "invalid_account_id",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_index():
    root = _repo_root()
    return load_tx_index_json(root / "generated" / "tx_index.json")


def _ledger() -> LedgerView:
    return LedgerView(
        accounts={
            "@alice": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10.0,
            }
        },
        roles={},
    )


def _admit(env: TxEnvelope, ledger: LedgerView, idx, context: str) -> tuple[bool, str | None]:
    ok, rej = admit_tx(env.to_json(), ledger, idx, context=context)
    if ok:
        return True, None
    assert rej is not None
    return False, rej.code


def test_tx_flow_trace_all_canon_types_do_not_crash() -> None:
    """Production-readiness smoke: all canon tx types can be admitted or rejected deterministically.

    This test is intentionally *not* asserting exact codes per TxType yet (that would
    be a spec-to-code matrix). Instead, it ensures:

      - admission never raises
      - every tx produces either OK or a canonical/expected reject code family
      - mempool vs block context paths are both exercised
    """
    idx = _load_index()
    ledger = _ledger()

    for tx in idx.tx_types:
        t = str(tx.get("name") or "").strip().upper()
        if not t:
            continue

        env = TxEnvelope(
            tx_type=t,
            signer="@alice",
            nonce=1,
            payload={},  # minimal
            sig="deadbeef",
            parent=None,
        )

        ok_m, code_m = _admit(env, ledger, idx, context="mempool")
        assert code_m in _ALLOWED_CODES, (t, ok_m, code_m)

        # For block context, try providing a parent + system flag when appropriate,
        # so we exercise more of the apply/admit logic.
        env2 = TxEnvelope(
            tx_type=t,
            signer="@alice",
            nonce=1,
            payload={},
            sig="deadbeef",
            parent="txid:parent",
            system=True,
        )
        ok_b, code_b = _admit(env2, ledger, idx, context="block")
        assert code_b in _ALLOWED_CODES, (t, ok_b, code_b)
