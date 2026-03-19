from __future__ import annotations

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor


def _hdr() -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id="test", schema_version="1", tx_index_hash="deadbeef", corr_id="c1")


def test_state_sync_accepts_legacy_and_new_trusted_anchor_env_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.delenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", raising=False)
    st = {"height": 3, "tip_hash": "b3", "accounts": {"a": {"nonce": 1}}}
    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    req = StateSyncRequestMsg(header=_hdr(), mode="snapshot", selector={"trusted_anchor": build_snapshot_anchor(st)})
    resp = svc.handle_request(req)
    assert resp.ok is True


def test_state_sync_fails_closed_on_conflicting_trusted_anchor_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    with pytest.raises(StateSyncVerifyError, match="trusted_anchor_env_conflict"):
        StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: {"height": 0})
