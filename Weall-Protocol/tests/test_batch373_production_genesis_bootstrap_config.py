from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.node_operator_responsibilities import evaluate_node_operator_responsibilities

ROOT = Path(__file__).resolve().parents[1]
FOUNDER = "@errol-genesis"
FOUNDER_PUBKEY = "c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be"


def _prod_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.setenv("WEALL_NODE_ID", FOUNDER)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", FOUNDER)
    monkeypatch.setenv("WEALL_NODE_PUBKEY", FOUNDER_PUBKEY)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "b" * 64)
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,node_operator,general_service")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    monkeypatch.setenv("WEALL_GENESIS_LEDGER_PATH", str(ROOT / "configs" / "genesis.ledger.prod.json"))
    monkeypatch.setenv("WEALL_PREVENT_REBOOTSTRAP_ON_EXISTING_DB", "1")


def test_production_genesis_file_is_complete_for_validator_preflight_batch373() -> None:
    genesis = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    founder = genesis["accounts"][FOUNDER]

    assert founder["poh_tier"] == 2
    assert int(founder["reputation_milli"]) >= 5000
    assert founder["devices"]["by_id"]["node:founding"]["pubkey"] == FOUNDER_PUBKEY

    roles = genesis["roles"]
    assert FOUNDER in roles["node_operators"]["active_set"]
    op = roles["node_operators"]["by_id"][FOUNDER]
    assert op["active"] is True
    assert op["responsibilities"]["validator"]["opted_in"] is True
    assert op["responsibilities"]["validator"]["active"] is True
    assert op["responsibilities"]["validator"]["readiness_status"] == "ready"
    assert FOUNDER in roles["validators"]["active_set"]

    evaluation = evaluate_node_operator_responsibilities(genesis, FOUNDER)
    assert evaluation["baseline"]["active"] is True, evaluation
    assert evaluation["validator"]["active"] is True, evaluation


def test_prod_first_boot_loads_pinned_genesis_and_validator_is_effective_batch373(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prod_env(monkeypatch, tmp_path)
    db_path = tmp_path / "prod-genesis.db"

    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id=FOUNDER,
        chain_id="weall-prod",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    status = ex.node_lifecycle_status()

    assert ex.state["accounts"][FOUNDER]["devices"]["by_id"]["node:founding"]["pubkey"] == FOUNDER_PUBKEY
    assert status["promotion_preflight_passed"] is True, status
    assert status["bft_enabled_effective"] is True, status
    assert status["promotion_failure_reasons"] == []


def test_prod_existing_db_without_ledger_refuses_rebootstrap_batch373(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prod_env(monkeypatch, tmp_path)
    db_path = tmp_path / "prod-genesis.db"
    db_path.write_bytes(b"")

    with pytest.raises(ExecutorError, match="production_rebootstrap_refused_existing_db_without_ledger"):
        WeAllExecutor(
            db_path=str(db_path),
            node_id=FOUNDER,
            chain_id="weall-prod",
            tx_index_path=str(ROOT / "generated" / "tx_index.json"),
        )
