from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_create_post_has_immediate_submit_lock_before_async_work() -> None:
    src = (ROOT / "web" / "src" / "pages" / "CreatePostPage.tsx").read_text(encoding="utf-8")
    assert "submitInFlightRef" in src
    assert "submitInFlightRef.current = true" in src
    assert "submitInFlightRef.current = false" in src
    assert "That publish action is already being saved" in src


def test_tx_toast_error_update_and_pending_key_are_not_double_applied() -> None:
    src = (ROOT / "web" / "src" / "components" / "TxQueueProvider.tsx").read_text(encoding="utf-8")
    assert src.count('updateItem(id, "failed", args);') == 1
    assert src.count('activePendingKeysRef.current.set(pendingKey, id);') == 1
    assert "recentSame" in src


def test_rate_limited_errors_are_human_readable() -> None:
    src = (ROOT / "web" / "src" / "lib" / "errorMessages.ts").read_text(encoding="utf-8")
    assert "rate_limited" in src
    assert "The local node is receiving actions too quickly" in src
