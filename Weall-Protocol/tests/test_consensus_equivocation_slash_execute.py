from __future__ import annotations

from weall.ledger.types import LedgerState
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def test_equivocation_records_evidence_without_bypassing_governance_slash_authority() -> None:
    st = LedgerState.from_dict({"state_version": 1})
    st.ensure_minimal_schema(ensure_producer="v1", strict=False)
    st["roles"].setdefault("validators", {})["active_set"] = ["v1"]
    st["blocks"]["b1"] = {"block_id": "b1", "height": 1, "prev_block_id": "gen"}
    st["blocks"]["c1"] = {"block_id": "c1", "height": 1, "prev_block_id": "gen"}

    apply_tx(
        st,
        TxEnvelope(
            tx_type="BLOCK_ATTEST",
            signer="v1",
            nonce=1,
            payload={"block_id": "b1", "height": 1, "round": 0},
        ),
    )
    apply_tx(
        st,
        TxEnvelope(
            tx_type="BLOCK_ATTEST",
            signer="v1",
            nonce=2,
            payload={"block_id": "c1", "height": 1, "round": 0},
        ),
    )

    sid = "equivocation:v1:1:0"
    slashing = st.get("slashing")
    assert isinstance(slashing, dict)
    evidence = slashing.get("equivocation_evidence")
    assert isinstance(evidence, dict) and sid in evidence
    assert evidence[sid]["status"] == "pending_governance"
    assert sid not in (slashing.get("executions") or {})
    assert not any(item.get("tx_type") == "SLASH_EXECUTE" for item in st.get("system_queue", []))
