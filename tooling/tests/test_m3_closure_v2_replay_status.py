from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from m3_closure_v2.errors import ContractError
from m3_closure_v2.replay_status import (
    ReplayStatusConfig,
    _backend_environment,
    config_from_mapping,
    port_is_free,
    prepare_bootstrap_binding,
    sqlite_backup,
)


def _create_database(
    path: Path,
    *,
    bootstrap_profile: dict | None = None,
) -> None:
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
            CREATE TABLE ledger_state (
                id INTEGER PRIMARY KEY,
                height INTEGER,
                block_id TEXT,
                state_json TEXT,
                updated_ts_ms INTEGER
            );
            INSERT INTO tx_index VALUES (
                'tx:test', 7, 'block:7', 'CONTENT_POST', '@a', 1000
            );
            INSERT INTO blocks VALUES (
                7, 'block:7', '{"header":{"tx_ids":["tx:test"]}}', 1000
            );
            """
        )
        if bootstrap_profile is not None:
            profile_hash = __import__("hashlib").sha256(
                json.dumps(
                    bootstrap_profile,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            state = {
                "height": 7,
                "meta": {
                    "genesis_bootstrap_profile": bootstrap_profile,
                    "genesis_bootstrap_profile_hash": profile_hash,
                },
            }
            con.execute(
                "INSERT INTO ledger_state VALUES (1, 7, 'block:7', ?, 1000);",
                (json.dumps(state, sort_keys=True),),
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
    keyfile = tmp_path / "operator.json"
    repo.mkdir()
    _create_database(db)
    keyfile.write_text(
        json.dumps(
            {
                "account": "@devnet-genesis",
                "public_key_hex": "pub",
                "private_key_hex": "priv",
            }
        ),
        encoding="utf-8",
    )

    common = dict(
        source_repo=repo,
        source_branch="closure/test",
        implementation_freeze_commit="a" * 40,
        implementation_tree="b" * 40,
        historical_freeze_commit="c" * 40,
        evidence_commit="d" * 40,
        evidence_transcript_path="artifacts/transcript.json",
        preserved_database=db,
        preserved_operator_keyfile=keyfile,
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



def _bootstrap_profile(public_key: str = "pub") -> dict:
    return {
        "enabled": True,
        "mode": "explicit",
        "account": "@devnet-genesis",
        "pubkey": public_key,
        "reputation_milli": 1000,
        "storage_capacity_bytes": 0,
    }


def _write_keyfile(
    path: Path,
    *,
    public_key: str = "pub",
) -> None:
    path.write_text(
        json.dumps(
            {
                "account": "@devnet-genesis",
                "public_key_hex": public_key,
                "private_key_hex": "private-material",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_prepare_bootstrap_binding_copies_matching_key_privately(
    tmp_path: Path,
) -> None:
    database = tmp_path / "ledger.db"
    source_key = tmp_path / "historical-operator.json"
    copied_key = tmp_path / "runtime" / "genesis-operator.json"
    _create_database(
        database,
        bootstrap_profile=_bootstrap_profile(),
    )
    _write_keyfile(source_key)

    binding = prepare_bootstrap_binding(
        database=database,
        preserved_keyfile=source_key,
        copied_keyfile=copied_key,
    )

    assert binding.account == "@devnet-genesis"
    assert binding.public_key == "pub"
    assert binding.reputation_text == "1"
    assert binding.storage_capacity_bytes == 0
    assert binding.source_keyfile_sha256 == binding.copied_keyfile_sha256
    assert copied_key.read_bytes() == source_key.read_bytes()
    assert copied_key.stat().st_mode & 0o777 == 0o600

    report = binding.safe_report()
    assert report["private_material_reported"] is False
    assert "private-material" not in json.dumps(report)
    assert report["public_key_sha256"] != "pub"


def test_prepare_bootstrap_binding_rejects_key_profile_mismatch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "ledger.db"
    source_key = tmp_path / "historical-operator.json"
    _create_database(
        database,
        bootstrap_profile=_bootstrap_profile(public_key="db-pub"),
    )
    _write_keyfile(source_key, public_key="other-pub")

    with pytest.raises(
        ContractError,
        match="operator_public_key_profile_mismatch",
    ):
        prepare_bootstrap_binding(
            database=database,
            preserved_keyfile=source_key,
            copied_keyfile=tmp_path / "copy.json",
        )


def test_backend_environment_is_explicit_and_strips_inherited_protocol_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    backend = repo / "Weall-Protocol"
    python = repo / ".venv-m3" / "bin" / "python"
    database = tmp_path / "ledger.db"
    keyfile = tmp_path / "operator.json"
    copied = tmp_path / "runtime" / "genesis-operator.json"
    backend.mkdir(parents=True)
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    _create_database(
        database,
        bootstrap_profile=_bootstrap_profile(),
    )
    _write_keyfile(keyfile)
    binding = prepare_bootstrap_binding(
        database=database,
        preserved_keyfile=keyfile,
        copied_keyfile=copied,
    )
    config = ReplayStatusConfig(
        source_repo=repo,
        source_branch="closure/test",
        implementation_freeze_commit="a" * 40,
        implementation_tree="b" * 40,
        historical_freeze_commit="c" * 40,
        evidence_commit="d" * 40,
        evidence_transcript_path="artifacts/transcript.json",
        preserved_database=database,
        preserved_operator_keyfile=keyfile,
        output_root=tmp_path / "out",
    )

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@poison")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("GUNICORN_WORKERS", "99")
    monkeypatch.setenv("UNRELATED_KEEP", "yes")

    environment = _backend_environment(
        config,
        tmp_path / "runtime",
        database,
        binding,
    )

    assert environment["WEALL_GENESIS_BOOTSTRAP_ACCOUNT"] == "@devnet-genesis"
    assert environment["WEALL_GENESIS_OPERATOR_KEYFILE"] == str(copied)
    assert environment["WEALL_GENESIS_BOOTSTRAP_REPUTATION"] == "1"
    assert environment["WEALL_GENESIS_MODE"] == "0"
    assert environment["WEALL_GENESIS_BOOTSTRAP_ENABLE"] == "1"
    assert "WEALL_HELPER_MODE_ENABLED" not in environment
    assert "GUNICORN_WORKERS" not in environment
    assert environment["UNRELATED_KEEP"] == "yes"


def test_config_fingerprint_changes_with_operator_keyfile(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    db = tmp_path / "source.db"
    key_a = tmp_path / "a.json"
    key_b = tmp_path / "b.json"
    repo.mkdir()
    _create_database(db)
    _write_keyfile(key_a, public_key="a")
    _write_keyfile(key_b, public_key="b")

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
        preserved_operator_keyfile=key_a,
    )
    second = ReplayStatusConfig(
        **common,
        preserved_operator_keyfile=key_b,
    )

    assert first.fingerprint != second.fingerprint
