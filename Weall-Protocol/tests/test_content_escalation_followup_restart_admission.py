"""Regress the post-escalation SYSTEM queue shape persisted at height 280.

Content escalation records its next-height followups before commit. After an
unclean power cycle, their original payloads must remain block-admissible:
re-signing, deleting or mutating queue entries would change the canonical
consensus state and would hide the actual integration defect.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from weall.ledger.state import LedgerView
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_schema import DisputeJurorAssignPayload, FlagEscalationReceiptPayload
from weall.tx.canon import TxIndex


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        (
            "DISPUTE_JUROR_ASSIGN",
            {"dispute_id": "dispute:content:1", "juror": "@reviewer"},
        ),
        (
            "FLAG_ESCALATION_RECEIPT",
            {
                "target_id": "post:sample:1",
                "dispute_id": "dispute:content:1",
                "reason": "content flag",
                "by": "SYSTEM",
            },
        ),
    ],
)
def test_persisted_content_escalation_followup_admitted_at_next_height(
    tx_type: str, payload: dict,
) -> None:
    state = {
        "chain_id": "weall-controlled-devnet",
        "height": 280,
        "tip": "prior-block",
        "params": {"system_signer": "SYSTEM"},
        "accounts": {},
        "system_queue": [],
    }
    canon = TxIndex.load_from_file(
        Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    )
    enqueue_system_tx(
        state,
        tx_type=tx_type,
        payload=payload,
        due_height=281,
        signer="SYSTEM",
        once=True,
        parent="CONTENT_ESCALATE_TO_DISPUTE",
        phase="post",
    )
    emitted = system_tx_emitter(
        state, canon, next_height=281, phase="post", proposer="@devnet-genesis"
    )
    matching = [env for env in emitted if env.tx_type == tx_type]
    assert len(matching) == 1
    env = matching[0]

    # Admitting the exact queue-derived envelope is stronger than validating
    # an isolated payload. Keep the original tx and queue commitment intact.
    verdict = admit_tx(env, LedgerView.from_ledger(state), canon=canon, context="block")
    assert verdict.ok, (verdict.code, verdict.reason)

    bound, why = validate_system_tx_queue_binding(
        state, canon, env, next_height=281, phase="post"
    )
    assert bound, why

    # This compatibility is limited to block-authorized SYSTEM transactions;
    # it must never make forged public SYSTEM submissions legal.
    external = admit_tx(env, LedgerView.from_ledger(state), canon=canon, context="http")
    assert external.ok is False
    assert external.code == "system_tx_forbidden"


def test_juror_assignment_accepts_canonical_and_persisted_aliases() -> None:
    for payload in (
        {"dispute_id": "dispute:1", "juror": "@reviewer"},
        {"dispute_id": "dispute:1", "juror_id": "@reviewer"},
        {"dispute_id": "dispute:1", "juror": "@reviewer", "juror_id": "@reviewer"},
    ):
        DisputeJurorAssignPayload.model_validate(payload)

    for payload in (
        {"dispute_id": "dispute:1"},
        {"dispute_id": "dispute:1", "juror": "@reviewer", "juror_id": "@different"},
        {"dispute_id": "dispute:1", "juror": "@reviewer", "unexpected": "extra"},
    ):
        with pytest.raises(ValidationError):
            DisputeJurorAssignPayload.model_validate(payload)


def test_flag_escalation_receipt_retains_only_canonical_provenance() -> None:
    FlagEscalationReceiptPayload.model_validate(
        {
            "target_id": "post:sample:1",
            "dispute_id": "dispute:1",
            "reason": "content flag",
            "by": "SYSTEM",
        }
    )
    with pytest.raises(ValidationError):
        FlagEscalationReceiptPayload.model_validate(
            {
                "target_id": "post:sample:1",
                "dispute_id": "dispute:1",
                "unknown_override": True,
            }
        )
