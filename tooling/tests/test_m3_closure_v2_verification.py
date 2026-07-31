from __future__ import annotations

import json
from pathlib import Path

from m3_closure_v2.models import parse_transcript
from m3_closure_v2.verification import verify_transcript_statuses


class FakeClient:
    def __init__(self, responses: dict[str, dict]) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.traces = []

    def get_json(self, path: str) -> dict:
        self.calls.append(path)
        return self.responses[path]


def test_inline_uses_trigger_status_not_synthetic_id(tmp_path: Path) -> None:
    direct = "tx:" + "a" * 64
    trigger = "tx:" + "b" * 64
    transcript_path = tmp_path / "transcript.json"
    transcript_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "implementation_freeze_commit": "c" * 40,
                "chain_id": "weall-test",
                "actions": [
                    {
                        "label": "direct",
                        "role": "author",
                        "account": "@author",
                        "tx_type": "CONTENT_POST",
                        "tx_id": direct,
                        "subject_id": "post:1",
                        "status": "confirmed",
                    },
                    {
                        "label": "resolve",
                        "role": "system_scheduler",
                        "account": "SYSTEM",
                        "tx_type": "DISPUTE_RESOLVE",
                        "tx_id": f"inline:{trigger}:DISPUTE_RESOLVE",
                        "subject_id": "dispute:1",
                        "status": "confirmed",
                        "evidence_kind": "inline_system_transition",
                        "trigger_tx_id": trigger,
                        "trigger_included_height": 935,
                        "state_height": 934,
                    },
                ],
                "negative_attempts": [],
            }
        ),
        encoding="utf-8",
    )
    transcript = parse_transcript(transcript_path)
    fake = FakeClient(
        {
            "/v1/chain/identity": {"chain_id": "weall-test"},
            f"/v1/tx/status/{direct.replace(':', '%3A')}": {
                "status": "confirmed",
                "tx_type": "CONTENT_POST",
                "signer": "@author",
                "height": 900,
            },
            f"/v1/tx/status/{trigger.replace(':', '%3A')}": {
                "status": "confirmed",
                "tx_type": "DISPUTE_BALLOT",
                "signer": "@reviewer",
                "height": 935,
            },
        }
    )

    summary = verify_transcript_statuses(transcript, fake)  # type: ignore[arg-type]
    assert summary.inline_action_count == 1
    assert summary.direct_action_count == 1
    assert not any("inline%3A" in call for call in fake.calls)


def test_deterministic_system_receipt_uses_persisted_status_and_height(
    tmp_path: Path,
) -> None:
    receipt_tx = "tx:" + "d" * 64
    transcript_path = tmp_path / "receipt-transcript.json"
    transcript_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "implementation_freeze_commit": "c" * 40,
                "chain_id": "weall-test",
                "actions": [
                    {
                        "label": "appeal_final_receipt",
                        "role": "system_scheduler",
                        "account": "SYSTEM",
                        "tx_type": "DISPUTE_FINAL_RECEIPT",
                        "tx_id": receipt_tx,
                        "subject_id": "dispute:SYSTEM:0",
                        "status": "confirmed",
                        "evidence_kind": "deterministic_system_receipt",
                        "evidence_path": "/private/evidence/receipt.json",
                        "state_height": 952,
                    }
                ],
                "negative_attempts": [],
            }
        ),
        encoding="utf-8",
    )
    transcript = parse_transcript(transcript_path)
    fake = FakeClient(
        {
            "/v1/chain/identity": {"chain_id": "weall-test"},
            f"/v1/tx/status/{receipt_tx.replace(':', '%3A')}": {
                "status": "confirmed",
                "tx_type": "DISPUTE_FINAL_RECEIPT",
                "signer": "SYSTEM",
                "height": 952,
            },
        }
    )

    summary = verify_transcript_statuses(transcript, fake)  # type: ignore[arg-type]

    assert summary.deterministic_receipt_count == 1
    assert summary.direct_action_count == 0
    assert summary.inline_action_count == 0
    assert summary.records[0]["evidence_kind"] == "deterministic_system_receipt"
