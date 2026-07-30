from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from m3_closure_v2.errors import ContractError
from m3_closure_v2.replay_status import (
    ReplayStatusConfig,
    config_from_mapping,
    port_is_free,
    sqlite_backup,
)


def _create_database(path: Path) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(
            """
            CREATE TABLE tx_index (
                tx_id TEXT PRIMARY KEY,
                height INTEGER,
                block_id TEXT,
                tx_type TEXT,
                signer TEXT,
                included_ts_ms INTEGER
            );
            CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                block_id TEXT,
                block_json TEXT,
                created_ts_ms INTEGER
            );
            INSERT INTO tx_index VALUES (
                'tx:test', 7, 'block:7', 'CONTENT_POST', '@a', 1000
            );
            INSERT INTO blocks VALUES (
                7, 'block:7', '{"header":{"tx_ids":["tx:test"]}}', 1000
            );
            """
        )
        con.commit()
    finally:
        con.close()


def test_sqlite_backup_is_consistent_and_reports_height(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    target = tmp_path / "snapshot" / "weall.db"
    _create_database(source)

    report = sqlite_backup(source, target)

    assert report["integrity_check"] == "ok"
    assert report["tx_index_row_count"] == 1
    assert report["height"] == 7
    assert len(report["source_sha256"]) == 64
    assert len(report["destination_sha256"]) == 64

    source_con = sqlite3.connect(source)
    target_con = sqlite3.connect(target)
    try:
        source_rows = source_con.execute(
            "SELECT tx_id, height, block_id, tx_type, signer, included_ts_ms "
            "FROM tx_index ORDER BY tx_id;"
        ).fetchall()
        target_rows = target_con.execute(
            "SELECT tx_id, height, block_id, tx_type, signer, included_ts_ms "
            "FROM tx_index ORDER BY tx_id;"
        ).fetchall()
    finally:
        source_con.close()
        target_con.close()

    assert target_rows == source_rows


def test_config_mapping_requires_explicit_paths(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="replay_config_missing"):
        config_from_mapping({"source_repo": str(tmp_path)})


def test_port_probe_reports_free_ephemeral_port() -> None:
    assert port_is_free("127.0.0.1", 0)


def test_config_fingerprint_changes_with_request_interval(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    db = tmp_path / "source.db"
    repo.mkdir()
    _create_database(db)

    common = dict(
        source_repo=repo,
        source_branch="closure/test",
        implementation_freeze_commit="a" * 40,
        implementation_tree="b" * 40,
        historical_freeze_commit="c" * 40,
        evidence_commit="d" * 40,
        evidence_transcript_path="artifacts/transcript.json",
        preserved_database=db,
        output_root=tmp_path / "out",
    )
    first = ReplayStatusConfig(
        **common,
        minimum_request_interval_s=0.1,
    )
    second = ReplayStatusConfig(
        **common,
        minimum_request_interval_s=0.5,
    )

    assert first.fingerprint != second.fingerprint
