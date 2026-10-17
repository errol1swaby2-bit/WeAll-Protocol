"""The Live PoH post-scheduler must emit a strictly admissible SYSTEM payload.

Regression: a live vote at height 55 triggered a post-phase FINALIZE with
ts_ms=0; the old PohLiveFinalizePayload prohibited ts_ms, causing block
production to fail-fast before any pending reviewer votes could be included.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.tx_schema import PohLiveFinalizePayload, validate_tx_envelope


def test_live_finalize_scheduler_payload_matches_strict_block_schema() -> None:
    case_id = "poh_live:@errol:22"
    state = {
        "poh": {
            "live_cases": {
                case_id: {
                    "case_id": case_id,
                    "account_id": "@errol",
                    "status": "init",
                    "jurors": {
                        "@devnet-genesis": {
                            "role": "interacting",
                            "accepted": True,
                            "attended": True,
                            "verdict": "pass",
                        }
                    },
                }
            }
        }
    }
    scheduled = schedule_poh_live_system_txs(state, next_height=56)
    assert scheduled >= 2
    rows = state["system_queue"]
    finalize = next(row for row in rows if row["tx_type"] == "POH_LIVE_FINALIZE")
    assert finalize["phase"] == "post"
    assert finalize["due_height"] == 56
    assert finalize["payload"] == {"case_id": case_id, "ts_ms": 0}
    envelope = {
        "tx_type": finalize["tx_type"],
        "signer": "SYSTEM",
        "nonce": 0,
        "system": True,
        "payload": {
            **finalize["payload"],
            "_system_queue_id": finalize["queue_id"],
            "_due_height": finalize["due_height"],
        },
    }
    # Matches block admission's treatment of authenticated internal underscore
    # fields; receipt queue binding itself is separately checked in replay.
    schema_envelope = dict(envelope)
    schema_envelope["payload"] = {
        key: val for key, val in envelope["payload"].items() if not key.startswith("_")
    }
    _tx, payload = validate_tx_envelope(schema_envelope)
    assert isinstance(payload, PohLiveFinalizePayload)
    assert payload.ts_ms == 0
    assert payload.case_id == case_id


def test_live_finalize_schema_remains_strict_and_rejects_bad_timestamps() -> None:
    with pytest.raises(ValidationError):
        PohLiveFinalizePayload(case_id="case", ts_ms=-1)
    with pytest.raises(ValidationError):
        PohLiveFinalizePayload(case_id="case", ts_ms=0, bypass=True)
