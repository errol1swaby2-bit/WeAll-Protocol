from __future__ import annotations

import json
from pathlib import Path

import pytest

from m3_closure_v2.errors import ContractError
from m3_closure_v2.models import (
    DirectTransactionAction,
    InlineSystemTransitionAction,
    parse_transcript,
)


def _write_transcript(path: Path, actions: list[dict]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "implementation_freeze_commit": "a" * 40,
                "chain_id": "weall-test",
                "actions": actions,
                "negative_attempts": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_parse_direct_and_inline_actions(tmp_path: Path) -> None:
    trigger = "tx:" + "b" * 64
    transcript = parse_transcript(
        _write_transcript(
            tmp_path / "transcript.json",
            [
                {
                    "label": "post",
                    "role": "author",
                    "account": "@author",
                    "tx_type": "CONTENT_POST",
                    "tx_id": "tx:" + "c" * 64,
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
        )
    )

    assert isinstance(transcript.actions[0], DirectTransactionAction)
    inline = transcript.actions[1]
    assert isinstance(inline, InlineSystemTransitionAction)
    assert inline.status_query_tx_id == trigger
    assert inline.trigger_included_height == 935


def test_inline_identifier_must_bind_trigger_and_type(tmp_path: Path) -> None:
    trigger = "tx:" + "b" * 64
    with pytest.raises(ContractError, match="inline_tx_id_mismatch"):
        parse_transcript(
            _write_transcript(
                tmp_path / "bad.json",
                [
                    {
                        "label": "resolve",
                        "role": "system_scheduler",
                        "account": "SYSTEM",
                        "tx_type": "DISPUTE_RESOLVE",
                        "tx_id": "inline:wrong",
                        "subject_id": "dispute:1",
                        "status": "confirmed",
                        "evidence_kind": "inline_system_transition",
                        "trigger_tx_id": trigger,
                        "trigger_included_height": 935,
                        "state_height": 934,
                    }
                ],
            )
        )
