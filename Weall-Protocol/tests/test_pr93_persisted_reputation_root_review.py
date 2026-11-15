"""PR93 read-only persisted reputation snapshot/root consistency (NO-GO).

The producer commits real canonical blocks through SQLite. An altered reader
then substitutes a changed application snapshot while returning unchanged
canonical block rows. These tests do not authenticate BFT QCs, producers,
dispute authority, juror verdicts, or constitutional authorization.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.reputation_delta_origin_review import (
    STATUS,
    review_persisted_reputation_delta_origin,
)
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
CHAIN_ID = "pr93-persisted-reputation-root-review"


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("WEALL_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in (
        ("WEALL_MODE", "testnet"),
        ("WEALL_SIGVERIFY", "1"),
        ("WEALL_UNSAFE_DEV", "0"),
        ("WEALL_BFT_ENABLED", "0"),
        ("WEALL_NET_ENABLED", "0"),
        ("WEALL_NET_LOOP_AUTOSTART", "0"),
        ("WEALL_BLOCK_LOOP_AUTOSTART", "0"),
    ):
        monkeypatch.setenv(name, value)


def _two_committed_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WeAllExecutor:
    _configure(monkeypatch)
    executor = WeAllExecutor(
        db_path=str(tmp_path / "canonical.sqlite"),
        node_id="producer",
        chain_id=CHAIN_ID,
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    for _ in range(2):
        result = executor.produce_block(max_txs=0, allow_empty=True)
        assert result.ok, result.error
    assert executor.read_state()["height"] == 2
    assert executor.get_block_by_height(1) is not None
    assert executor.get_block_by_height(2) is not None
    return executor


class _AlteredSnapshotReader:
    """Untrusted reader; historical block rows remain unchanged."""

    def __init__(self, original: WeAllExecutor):
        self._original = original
        self.chain_id = original.chain_id

    def read_state(self) -> dict[str, Any]:
        snapshot = copy.deepcopy(self._original.read_state())
        snapshot.setdefault("accounts", {})["@forged-penalty"] = {"reputation": "-1"}
        return snapshot

    def get_block_by_height(self, height: int) -> dict[str, Any] | None:
        return self._original.get_block_by_height(height)


def test_real_sqlite_canonical_blocks_match_persisted_state_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = _two_committed_blocks(tmp_path, monkeypatch)
    report = review_persisted_reputation_delta_origin(
        executor=executor,
        delta={},
        tx_index=executor.tx_index,
    )
    observed = report["persisted_history_observations"]
    assert observed["bounded_local_history_available_and_self_bound"] is True
    assert observed["adjacent_local_history_parent_links_match"] is True
    assert observed["local_state_tip_matches_last_stored_block"] is True
    assert observed["persisted_snapshot_root_matches_committed_tip_state_root"] is True
    assert report["persisted_history_errors"] == []
    assert report["status"] == STATUS
    assert report["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert report["may_enqueue_reputation_delta"] is False
    assert report["may_ban_account"] is False


def test_changed_reputation_snapshot_is_detected_even_with_valid_block_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = _two_committed_blocks(tmp_path, monkeypatch)
    report = review_persisted_reputation_delta_origin(
        executor=_AlteredSnapshotReader(executor),
        delta={},
        tx_index=executor.tx_index,
    )
    observed = report["persisted_history_observations"]
    assert observed["bounded_local_history_available_and_self_bound"] is True
    assert observed["adjacent_local_history_parent_links_match"] is True
    assert observed["local_state_tip_matches_last_stored_block"] is True
    assert observed["persisted_snapshot_root_matches_committed_tip_state_root"] is False
    assert "persisted_snapshot_state_root_mismatch" in report["persisted_history_errors"]
    assert report["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert report["may_enqueue_reputation_delta"] is False
    assert report["may_ban_account"] is False
