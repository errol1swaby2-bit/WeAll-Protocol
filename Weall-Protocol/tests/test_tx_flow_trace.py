# tests/test_tx_flow_trace.py
from __future__ import annotations

from typing import Any, Dict, Tuple

from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _load_index() -> TxIndex:
    return TxIndex.load_from_file("generated/tx_index.json")


def _ledger(poh_tier: int = 3) -> Any:
    # Mirror the lightweight LedgerView shape used throughout tests.
    # We only need accounts/params for admission.
    return {
        "accounts": {
            "alice": {
                "nonce": 0,
                "poh_tier": poh_tier,
                "banned": False,
                "locked": False,
                "reputation": 1.0,
            }
        },
        "params": {
            "chain_id": "test",
            "genesis_time": 0,
            "economic_unlock_time": 10**12,
            "system_signer": "SYSTEM",
        },
    }


_ALLOWED_CODES = {
    # success
    None,
    # common reject codes
    "unknown_tx",
    "invalid_payload",
    "payload_too_large",
    "tx_too_large",
    "bad_nonce",
    "forbidden",
    "block_only",
    "receipt_only",
    "sig_invalid",
    "unknown_signer",
}


def _admit(env: TxEnvelope, ledger: Any, idx: TxIndex, context: str) -> Tuple[bool, str | None]:
    ok, rej = admit_tx(env, ledger, idx, context=context)
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
            signer="alice",
            nonce=1,
            payload={},  # minimal
            sig="deadbeef",
            parent=None,
        )

        ok_m, code_m = _admit(env, ledger, idx, context="mempool")
        assert code_m in _ALLOWED_CODES, (t, ok_m, code_m)

        ok_b, code_b = _admit(env, ledger, idx, context="block")
        assert code_b in _ALLOWED_CODES, (t, ok_b, code_b)
