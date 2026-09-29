from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    _validate_snapshot_validator_authority,
)
from weall.runtime.commitments import validator_set_hash
from weall.runtime.executor import ExecutorError, WeAllExecutor


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


def test_p2_sync001_executor_install_boundary_rejects_missing_required_anchor() -> None:
    class _RequiredAnchorService:
        require_trusted_anchor = True

        def verify_response(self, *_args, **_kwargs) -> None:
            raise AssertionError("verification must not run without the required anchor")

    executor = object.__new__(WeAllExecutor)
    executor._state_sync_service = lambda: _RequiredAnchorService()  # type: ignore[method-assign]

    with pytest.raises(ExecutorError, match="state_sync_verify_failed:trusted_anchor_required"):
        executor.apply_state_sync_response(_response(), trusted_anchor=None)


def test_p2_sync001_http_apply_rejects_missing_required_anchor_before_install(monkeypatch) -> None:
    class _Executor:
        applied = False

        @staticmethod
        def state_sync_requires_trusted_anchor() -> bool:
            return True

        def apply_state_sync_response(self, *_args, **_kwargs):
            self.applied = True
            raise AssertionError("HTTP adapter must reject before state installation")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_APPLY_REQUIRE_OPERATOR_TOKEN", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "sync-secret")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")

    executor = _Executor()
    app = create_app(boot_runtime=False)
    app.state.executor = executor
    app.state.net_node = None
    response = {
        "header": {
            "type": "STATE_SYNC_RESPONSE",
            "chain_id": "chain",
            "schema_version": "1",
            "tx_index_hash": "tx-index",
            "corr_id": "p2-sync-http",
        },
        "ok": True,
        "reason": None,
        "height": 0,
        "snapshot": None,
        "snapshot_hash": None,
        "snapshot_anchor": None,
        "blocks": [],
    }
    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.post(
            "/v1/sync/apply",
            headers={"X-WeAll-State-Sync-Operator-Token": "sync-secret"},
            json={"response": response, "allow_snapshot_bootstrap": False},
        )

    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "trusted_anchor_required"
    assert executor.applied is False
