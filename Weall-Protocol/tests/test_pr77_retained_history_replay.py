from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from scripts.pr77_retained_history_replay import (
    ReplayEvidenceError,
    file_sha256,
    inspect_offline_source,
    replay_offline_source,
)


def _fixture_db(
    tmp_path: Path, *, heights: tuple[int, ...] = (1, 2), chain_id: str = "test-chain"
) -> Path:
    db_path = tmp_path / "offline-copy.sqlite"
    with sqlite3.connect(db_path) as con:
        con.execute(
            "CREATE TABLE blocks(height INTEGER PRIMARY KEY, block_json TEXT NOT NULL)"
        )
        con.execute(
            "CREATE TABLE ledger_state(id INTEGER PRIMARY KEY, height INTEGER, state_json TEXT)"
        )
        for height in heights:
            block = {
                "height": height,
                "block_id": f"block-{height}",
                "block_hash": "a" * 64,
                "state_root": "b" * 64,
                "receipts_root": "c" * 64,
            }
            con.execute(
                "INSERT INTO blocks(height, block_json) VALUES(?, ?)",
                (height, json.dumps(block)),
            )
        state = {"chain_id": chain_id, "height": max(heights), "accounts": {}}
        con.execute(
            "INSERT INTO ledger_state(id, height, state_json) VALUES(1, ?, ?)",
            (max(heights), json.dumps(state)),
        )
    return db_path


def test_readonly_preflight_accepts_contiguous_archive_without_changing_bytes(
    tmp_path: Path,
) -> None:
    source = _fixture_db(tmp_path)
    before = source.read_bytes()
    state, blocks = inspect_offline_source(source, file_sha256(source), "test-chain")
    assert state["height"] == 2
    assert [block["height"] for block in blocks] == [1, 2]
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    ("heights", "expected"),
    (
        ((1, 3), "offline_source_height_gap:2"),
        ((2,), "offline_source_height_gap:1"),
    ),
)
def test_preflight_rejects_gapped_block_histories(
    tmp_path: Path, heights: tuple[int, ...], expected: str
) -> None:
    source = _fixture_db(tmp_path, heights=heights)
    with pytest.raises(ReplayEvidenceError, match=expected):
        inspect_offline_source(source, file_sha256(source), "test-chain")


def test_preflight_rejects_wrong_chain_and_digest(tmp_path: Path) -> None:
    source = _fixture_db(tmp_path)
    with pytest.raises(ReplayEvidenceError, match="chain_identity_mismatch"):
        inspect_offline_source(source, file_sha256(source), "other-chain")
    with pytest.raises(ReplayEvidenceError, match="source_sha256_mismatch"):
        inspect_offline_source(source, "0" * 64, "test-chain")


def test_preflight_rejects_live_wal_sidecar_and_symlink(tmp_path: Path) -> None:
    source = _fixture_db(tmp_path)
    Path(f"{source}-wal").write_bytes(b"unsafe-live-copy")
    with pytest.raises(ReplayEvidenceError, match="wal_or_shm"):
        inspect_offline_source(source, file_sha256(source), "test-chain")
    Path(f"{source}-wal").unlink()
    alias = tmp_path / "alias.sqlite"
    alias.symlink_to(source)
    with pytest.raises(ReplayEvidenceError, match="symlink"):
        inspect_offline_source(alias, file_sha256(source), "test-chain")


def test_checkout_mismatch_fails_before_opening_archive_or_creating_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _fixture_db(tmp_path)
    monkeypatch.setattr(
        "scripts.pr77_retained_history_replay.subprocess.check_output",
        lambda *args, **kwargs: "f" * 40 + "\n",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(ReplayEvidenceError, match="checkout_commit_mismatch"):
        replay_offline_source(
            source=source,
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            chain_id="test-chain",
            scratch_dir=scratch,
            tx_index=tmp_path / "index.json",
            tx_index_sha256="1" * 64,
            expected_commit="e" * 40,
        )
    assert not list(scratch.iterdir())
