from __future__ import annotations

import pytest

from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    _validate_snapshot_validator_authority,
)
from weall.runtime.commitments import validator_set_hash


def _response() -> StateSyncResponseMsg:
    return StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id="chain",
            schema_version="1",
            tx_index_hash="tx-index",
            sent_ts_ms=None,
            corr_id="p2-sync",
        ),
        ok=True,
        reason=None,
        height=0,
        snapshot=None,
        snapshot_hash=None,
        snapshot_anchor=None,
        blocks=(),
    )


def test_p2_sync001_required_anchor_is_enforced_on_response_verification(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    svc = StateSyncService(
        chain_id="chain",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: {},
    )
    assert svc.require_trusted_anchor is True
    with pytest.raises(StateSyncVerifyError, match="trusted_anchor_required"):
        svc.verify_response(_response(), trusted_anchor=None)


def test_p2_sync002_numeric_validator_member_is_rejected_before_normalization() -> None:
    snapshot = {
        "params": {"validator_candidate_lifecycle_gate_enabled": True},
        "consensus": {"validator_set": {"epoch": 1, "active_set": [1]}},
    }
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:active_set_member_not_string",
    ):
        _validate_snapshot_validator_authority(snapshot)


def test_p2_sync002_canonical_string_validator_member_remains_valid() -> None:
    active = ["@validator"]
    snapshot = {
        "params": {"validator_candidate_lifecycle_gate_enabled": True},
        "consensus": {
            "validator_set": {
                "epoch": 1,
                "active_set": active,
                "set_hash": validator_set_hash(active),
            },
            "validators": {"registry": {"@validator": {"pubkey": "pk"}}},
        },
        "validators": {"registry": {"@validator": {"pubkey": "pk"}}},
    }
    _validate_snapshot_validator_authority(snapshot)
