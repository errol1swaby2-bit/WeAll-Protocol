from __future__ import annotations

from weall.ledger.types import LedgerState
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def test_equivocation_results_in_slash_execute_event() -> None:
    """If a validator attests two different blocks at same (height, round), we record a SLASH_EXECUTE.

    We test this at the apply-layer (not executor block production), so we can deterministically
    apply two BLOCK_ATTEST txs in sequence.
    """

    st = LedgerState.from_dict({"state_version": 1})
    st.ensure_minimal_schema(ensure_producer="v1", strict=False)

    # Make v1 a validator for admission-gated semantics.
    st["roles"].setdefault("validators", {})["active_set"] = ["v1"]

    # Create two competing blocks at height=1.
    st["blocks"]["b1"] = {"block_id": "b1", "height": 1, "prev_block_id": "gen", "ts_ms": 0, "node_id": "v1", "tx_ids": []}
    st["blocks"]["c1"] = {"block_id": "c1", "height": 1, "prev_block_id": "gen", "ts_ms": 0, "node_id": "evil", "tx_ids": []}

    # First attestation is accepted.
    env1 = TxEnvelope(
        tx_type="BLOCK_ATTEST",
        signer="v1",
        nonce=1,
        payload={"block_id": "b1", "height": 1, "round": 0},
        sig="",
        parent=None,
        system=False,
    )
    apply_tx(st, env1)

    # Second attestation at same (height, round) to a different block should be treated as equivocation.
    env2 = TxEnvelope(
        tx_type="BLOCK_ATTEST",
        signer="v1",
        nonce=2,
        payload={"block_id": "c1", "height": 1, "round": 0},
        sig="",
        parent=None,
        system=False,
    )
    apply_tx(st, env2)

    sl = st.get("slashing")
    assert isinstance(sl, dict)
    execs = sl.get("executions")
    assert isinstance(execs, dict)

    sid = "equivocation:v1:1:0"
    assert sid in execs
