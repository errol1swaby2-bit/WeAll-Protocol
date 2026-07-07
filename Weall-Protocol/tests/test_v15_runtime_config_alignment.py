from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.ledger.constants import TARGET_BLOCK_INTERVAL_SECONDS
from weall.runtime.chain_config import ChainConfig, load_chain_config, validate_chain_config

ROOT = Path(__file__).resolve().parents[1]


def _cfg(*, mode: str = "prod", block_interval_ms: int | None = None, block_reward: int = 0) -> ChainConfig:
    return ChainConfig(
        chain_id="weall-prod" if mode == "prod" else "weall-testnet-0",
        node_id="node-a",
        mode=mode,
        db_path="./data/weall.db",
        tx_index_path="./generated/tx_index.json",
        block_interval_ms=(TARGET_BLOCK_INTERVAL_SECONDS * 1000 if block_interval_ms is None else block_interval_ms),
        max_txs_per_block=1000,
        block_reward=block_reward,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def test_canonical_prod_chain_config_uses_v15_block_interval_and_no_block_reward() -> None:
    payload = json.loads((ROOT / "configs/prod.chain.json").read_text(encoding="utf-8"))

    assert payload["block_interval_ms"] == TARGET_BLOCK_INTERVAL_SECONDS * 1000 == 20_000
    assert payload["block_reward"] == 0


def test_v15_prod_and_testnet_configs_reject_legacy_block_reward() -> None:
    for mode in ("prod", "testnet", "controlled_devnet"):
        with pytest.raises(ValueError, match="block_reward must be 0 in v1.5"):
            validate_chain_config(_cfg(mode=mode, block_reward=1))


def test_v15_dev_config_default_block_interval_is_20_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.delenv("WEALL_CHAIN_CONFIG_PATH", raising=False)
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST_PATH", raising=False)
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST", raising=False)
    monkeypatch.delenv("WEALL_REQUIRE_CHAIN_MANIFEST", raising=False)

    cfg = load_chain_config()

    assert cfg.block_interval_ms == TARGET_BLOCK_INTERVAL_SECONDS * 1000 == 20_000
    assert cfg.block_reward == 0
