from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import runtime_vrf_required


ROOT = Path(__file__).resolve().parents[1]


def _write_chain_config(path: Path, *, tx_index_path: Path, db_path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "node_id": "node-1",
                "mode": "prod",
                "db_path": str(db_path),
                "tx_index_path": str(tx_index_path),
                "block_interval_ms": 600000,
                "max_txs_per_block": 1000,
                "block_reward": 0,
                "api_host": "127.0.0.1",
                "api_port": 8000,
                "allow_unsigned_txs": False,
                "log_level": "INFO",
            }
        ),
        encoding="utf-8",
    )


def test_nonprod_runtime_vrf_default_is_off_but_can_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.delenv("WEALL_REQUIRE_VRF", raising=False)
    assert runtime_vrf_required() is False

    monkeypatch.setenv("WEALL_REQUIRE_VRF", "1")
    assert runtime_vrf_required() is True


def test_pytest_local_prod_fixture_can_build_without_vrf_when_not_networked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@fixture",
        chain_id="fixture-prod",
        tx_index_path=str(ROOT / "generated/tx_index.json"),
    )
    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:@alice"},
        }
    )["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def test_pytest_local_prod_fixture_still_fails_closed_when_networked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@fixture",
        chain_id="fixture-prod-networked",
        tx_index_path=str(ROOT / "generated/tx_index.json"),
    )
    block, _staged, _applied, _invalid, err = ex.build_block_candidate(allow_empty=True)
    assert block is None
    assert err == "vrf_missing_node_key"


def test_custom_prod_chain_config_requires_explicit_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tx_index_path = tmp_path / "tx_index.json"
    tx_index_path.write_text("{}", encoding="utf-8")
    cfg_path = tmp_path / "prod.chain.json"
    _write_chain_config(cfg_path, tx_index_path=tx_index_path, db_path=tmp_path / "weall.db")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.setenv("WEALL_CHAIN_CONFIG_PATH", str(cfg_path))
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST_PATH", raising=False)
    monkeypatch.delenv("WEALL_REQUIRE_CHAIN_MANIFEST", raising=False)

    with pytest.raises(FileNotFoundError, match="chain manifest path not configured"):
        load_chain_config()


def test_heavy_soak_cli_sets_nonproduction_vrf_fixture_defaults(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "priority1_heavy_soak.py"),
            "--work-dir",
            str(tmp_path),
            "--chain-id-prefix",
            "batch327-heavy",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_local_observer_gate_has_no_literal_removed_message_transport_marker() -> None:
    text = (ROOT / "scripts/local_observer_readiness_gate.sh").read_text(encoding="utf-8")
    removed_env_marker = "WEALL_SM" + "TP"
    removed_word_marker = "SM" + "TP"
    assert removed_env_marker not in text
    assert removed_word_marker not in text
