"""PR77 WP-01: accepted content flag is the escalation reporter authority.

The consensus behavior is explicitly height-gated; legacy heights remain unchanged.
These tests exercise the pre-mutation verifier directly and the dedup entry path.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.content import (
    ContentApplyError,
    _apply_content_escalate_to_dispute,
    _content_escalation_provenance_active,
    _verify_content_escalation_provenance,
    repair_pending_content_escalations,
)
from weall.runtime.tx_admission import TxEnvelope


def _state() -> dict:
    return {
        "height": 20,
        "params": {"content_escalation_provenance_v1_activation_height": 20},
        "content": {
            "flags": {
                "flag:alice:1": {
                    "flag_id": "flag:alice:1",
                    "target_id": "post:one",
                    "by": "alice",
                    "reason": "spam",
                    "nonce": 1,
                }
            }
        },
    }


def _env(payload: dict | None = None, *, parent: str = "CONTENT_FLAG:flag:alice:1"):
    return TxEnvelope(
        tx_type="CONTENT_ESCALATE_TO_DISPUTE",
        signer="SYSTEM",
        nonce=0,
        payload=(
            payload
            if payload is not None
            else {
                "flag_id": "flag:alice:1",
                "target_id": "post:one",
                "target_type": "content",
                "flagged_by": "alice",
            }
        ),
        system=True,
        parent=parent,
    )


def test_provenance_gate_requires_explicit_activation_height() -> None:
    state = _state()
    assert _content_escalation_provenance_active(state)
    state["height"] = 19
    assert not _content_escalation_provenance_active(state)
    state["params"] = {}
    assert not _content_escalation_provenance_active(state)


def test_accepted_flag_matches_escalation_reporter_and_parent() -> None:
    _verify_content_escalation_provenance(_state(), _env(), _env().payload, target_id="post:one")


@pytest.mark.parametrize(
    ("changes", "parent", "target"),
    [
        ({"flagged_by": "mallory"}, "CONTENT_FLAG:flag:alice:1", "post:one"),
        ({"reported_by": "mallory"}, "CONTENT_FLAG:flag:alice:1", "post:one"),
        ({"flag_id": "flag:missing"}, "CONTENT_FLAG:flag:alice:1", "post:one"),
        ({}, "CONTENT_FLAG:wrong", "post:one"),
        ({}, "CONTENT_FLAG:flag:alice:1", "post:two"),
        ({"flagged_by": ""}, "CONTENT_FLAG:flag:alice:1", "post:one"),
    ],
)
def test_forged_provenance_fails_without_mutating_state(
    changes: dict, parent: str, target: str
) -> None:
    state = _state()
    original = copy.deepcopy(state)
    payload = dict(_env().payload)
    payload.update(changes)
    env = _env(payload, parent=parent)
    with pytest.raises(ContentApplyError):
        _verify_content_escalation_provenance(state, env, payload, target_id=target)
    assert state == original


def test_dedup_does_not_bypass_provenance_check() -> None:
    state = _state()
    state["content"]["moderation"] = {"targets": {"post:one": {"dispute_id": "dispute:existing"}}}
    original = copy.deepcopy(state)
    payload = dict(_env().payload)
    payload["flagged_by"] = "mallory"
    with pytest.raises(ContentApplyError):
        _apply_content_escalate_to_dispute(state, _env(payload))
    assert state == original


def test_valid_dedup_uses_existing_dispute_after_provenance_check() -> None:
    state = _state()
    state["content"]["moderation"] = {"targets": {"post:one": {"dispute_id": "dispute:existing"}}}
    result = _apply_content_escalate_to_dispute(state, _env())
    assert result["deduped"] is True
    assert result["dispute_id"] == "dispute:existing"


def test_accepted_flag_record_itself_must_match_flag_id() -> None:
    state = _state()
    state["content"]["flags"]["flag:alice:1"]["flag_id"] = "flag:other"
    before = copy.deepcopy(state)
    with pytest.raises(ContentApplyError) as exc:
        _verify_content_escalation_provenance(state, _env(), _env().payload, target_id="post:one")
    assert exc.value.reason == "escalation_flag_provenance_mismatch"
    assert state == before


def test_legacy_height_keeps_original_dedup_path() -> None:
    state = _state()
    state["height"] = 19
    state["content"]["moderation"] = {"targets": {"post:one": {"dispute_id": "dispute:existing"}}}
    payload = dict(_env().payload)
    payload["flagged_by"] = "legacy-unverified-reporter"
    result = _apply_content_escalate_to_dispute(state, _env(payload))
    assert result["deduped"] is True


def test_repair_uses_original_flag_not_corrupted_pending_reporter(monkeypatch) -> None:
    state = _state()
    state["content"]["pending_escalations"] = {
        "flag:alice:1": {
            "status": "pending",
            "next_retry_height": 20,
            "target_id": "post:forged",
            "flagged_by": "mallory",
            "reason": "forged reason",
        }
    }
    queued: list[dict] = []

    def fake_enqueue(_state, **kwargs):
        queued.append(kwargs)
        return "queue:verified"

    monkeypatch.setattr("weall.runtime.apply.content.enqueue_system_tx", fake_enqueue)
    assert repair_pending_content_escalations(state, next_height=20) == 1
    assert len(queued) == 1
    assert queued[0]["payload"]["target_id"] == "post:one"
    assert queued[0]["payload"]["flagged_by"] == "alice"
    assert queued[0]["payload"]["reason"] == "spam"
    assert queued[0]["parent"] == "CONTENT_FLAG:flag:alice:1"


def test_repair_missing_accepted_flag_never_queues(monkeypatch) -> None:
    state = _state()
    state["content"]["flags"] = {}
    state["content"]["pending_escalations"] = {
        "flag:alice:1": {"status": "pending", "next_retry_height": 20}
    }
    queued: list[dict] = []

    def fake_enqueue(_state, **kwargs):
        queued.append(kwargs)
        return "queue:unexpected"

    monkeypatch.setattr("weall.runtime.apply.content.enqueue_system_tx", fake_enqueue)
    assert repair_pending_content_escalations(state, next_height=20) == 0
    assert queued == []


def test_legacy_repair_keeps_original_pending_fields(monkeypatch) -> None:
    state = _state()
    state["height"] = 19
    state["content"]["pending_escalations"] = {
        "flag:alice:1": {
            "status": "pending",
            "next_retry_height": 20,
            "target_id": "post:legacy",
            "flagged_by": "legacy-reporter",
            "reason": "legacy reason",
        }
    }
    queued: list[dict] = []

    def fake_enqueue(_state, **kwargs):
        queued.append(kwargs)
        return "queue:legacy"

    monkeypatch.setattr("weall.runtime.apply.content.enqueue_system_tx", fake_enqueue)
    assert repair_pending_content_escalations(state, next_height=20) == 1
    assert queued[0]["payload"]["target_id"] == "post:legacy"
    assert queued[0]["payload"]["flagged_by"] == "legacy-reporter"
