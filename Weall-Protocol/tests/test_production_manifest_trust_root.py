from __future__ import annotations

import hashlib
import json
from pathlib import Path

from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues
from weall.runtime.chain_manifest import chain_manifest_status, load_chain_manifest


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_tx_index(path: Path) -> str:
    obj = {"by_id": {}, "by_name": {}, "tx_types": []}
    _write_json(path, obj)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_obj(*, tx_index_hash: str, authority_key: str = "c" * 64, profile_hash: str = "e" * 64) -> dict:
    return {
        "version": 1,
        "chain_id": "weall-prod",
        "profile": "production_service",
        "mode": "prod",
        "schema_version": "1",
        "genesis_hash": "a" * 64,
        "genesis_state_root": "b" * 64,
        "tx_index_hash": tx_index_hash,
        "protocol_profile_hash": profile_hash,
        "constitution_version": "draft-2",
        "constitution_hash": "f" * 64,
        "constitution_traceability_hash": "1" * 64,
        "constitution_document_path": "docs/constitution/WEALL_GENESIS_CONSTITUTION_DRAFT_2.md",
        "genesis_time_ms": 0,
        "constitutional_clock": {
            "enabled": True,
            "target_block_interval_ms": 20000,
            "empty_blocks_enabled": True,
            "procedure_time_source": "finalized_block_height",
            "block_time_derivation": "genesis_time_plus_height_times_interval",
            "no_fast_forward": True,
            "no_height_skip": True,
            "allowed_clock_skew_ms": 2000,
            "genesis_time_ms": 0,
        },
        "authority_snapshot_version": 1,
        "trusted_authority_pubkeys": [authority_key],
    }


def test_strict_production_manifest_rejects_placeholder_authority_key(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = tmp_path / "manifest.json"
    _write_json(
        manifest_path,
        _manifest_obj(
            tx_index_hash=tx_hash,
            authority_key="REPLACE_WITH_PRODUCTION_AUTHORITY_PUBKEY_HEX",
        ),
    )

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is False
    assert "chain_manifest_trusted_authority_pubkey_unpinned" in status["issues"]


def test_strict_production_manifest_rejects_empty_profile_hash(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, _manifest_obj(tx_index_hash=tx_hash, profile_hash=""))

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is False
    assert "chain_manifest_protocol_profile_hash_unpinned" in status["issues"]


def test_strict_production_manifest_rejects_invalid_authority_key_format(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, _manifest_obj(tx_index_hash=tx_hash, authority_key="not-hex"))

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is False
    assert "chain_manifest_trusted_authority_pubkey_invalid" in status["issues"]


def test_strict_production_manifest_accepts_pinned_trust_root(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, _manifest_obj(tx_index_hash=tx_hash))

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is True
    assert status["tx_index_hash_matches"] is True


def test_production_preflight_rejects_placeholder_manifest_trust_root(tmp_path: Path, monkeypatch) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = tmp_path / "manifest.json"
    _write_json(
        manifest_path,
        _manifest_obj(
            tx_index_hash=tx_hash,
            authority_key="REPLACE_WITH_PRODUCTION_AUTHORITY_PUBKEY_HEX",
            profile_hash="",
        ),
    )
    chain_config = tmp_path / "prod.chain.json"
    _write_json(
        chain_config,
        {
            "chain_id": "weall-prod",
            "node_id": "node-a",
            "mode": "prod",
            "db_path": str(tmp_path / "weall.db"),
            "tx_index_path": str(tx_index),
            "block_interval_ms": 600000,
            "max_txs_per_block": 1000,
            "block_reward": 0,
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "allow_unsigned_txs": False,
            "log_level": "INFO",
        },
    )
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))

    cfg = load_chain_config(str(chain_config))
    issues = production_bootstrap_issues(cfg)

    assert "chain_manifest:chain_manifest_trusted_authority_pubkey_unpinned" in issues
    assert "chain_manifest:chain_manifest_protocol_profile_hash_unpinned" in issues
