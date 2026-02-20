# src/weall/runtime/chain_config.py
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

Json = Dict[str, Any]


def _as_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any, default: str) -> str:
    if v is None:
        return str(default)
    s = str(v)
    return s if s.strip() else str(default)


def _as_bool(v: Any, default: bool) -> bool:
    if v is None:
        return bool(default)
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


@dataclass(frozen=True)
class ChainConfig:
    chain_id: str
    node_id: str
    mode: str  # "dev" | "testnet" | "prod"

    # Single SQLite DB file path for all node persistence.
    db_path: str
    tx_index_path: str

    block_interval_ms: int
    max_txs_per_block: int
    block_reward: int

    api_host: str
    api_port: int

    allow_unsigned_txs: bool

    log_level: str


_ALLOWED_MODES = {"dev", "testnet", "prod"}


def validate_chain_config(cfg: ChainConfig) -> None:
    """Fail-fast validation for operator config.

    Prevent silent misconfiguration that could put a node into an unsafe
    posture or an unusable state.
    """

    if not isinstance(cfg.chain_id, str) or not cfg.chain_id.strip():
        raise ValueError("chain_id must be a non-empty string")

    if not isinstance(cfg.node_id, str) or not cfg.node_id.strip():
        raise ValueError("node_id must be a non-empty string")

    mode = str(cfg.mode or "").strip().lower()
    if mode not in _ALLOWED_MODES:
        raise ValueError(f"mode must be one of {_ALLOWED_MODES}; got: {cfg.mode!r}")

    if int(cfg.api_port) <= 0 or int(cfg.api_port) > 65535:
        raise ValueError(f"api_port must be 1..65535; got: {cfg.api_port}")

    if int(cfg.block_interval_ms) < 250:
        # Too-low intervals can create tight loops and DoS a machine.
        raise ValueError(f"block_interval_ms must be >= 250; got: {cfg.block_interval_ms}")

    if int(cfg.max_txs_per_block) <= 0:
        raise ValueError(f"max_txs_per_block must be > 0; got: {cfg.max_txs_per_block}")

    # Paths must be non-empty. Some are created at runtime; tx_index must exist.
    for name, p in (("db_path", cfg.db_path), ("tx_index_path", cfg.tx_index_path)):
        if not isinstance(p, str) or not p.strip():
            raise ValueError(f"{name} must be a non-empty string")

    txi = Path(cfg.tx_index_path)
    if not txi.is_file():
        raise ValueError(
            "tx_index_path does not exist or is not a file: "
            f"{cfg.tx_index_path!r}. "
            "This build/deploy is incomplete; ensure generated/tx_index.json is present."
        )


def default_chain_config() -> ChainConfig:
    return ChainConfig(
        chain_id="weall-dev",
        node_id="local-node",
        # Production-safe defaults.
        #
        # If a user runs the node without providing an explicit config file,
        # we must NOT silently drop into a permissive development posture.
        mode="prod",
        db_path="./data/weall.db",
        tx_index_path="./generated/tx_index.json",
        block_interval_ms=20_000,
        max_txs_per_block=1_000,
        block_reward=50,
        api_host="0.0.0.0",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def read_chain_config_file(path: str) -> ChainConfig:
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("chain config must be a JSON object")

    d = default_chain_config()

    cfg = ChainConfig(
        chain_id=_as_str(raw.get("chain_id"), d.chain_id),
        node_id=_as_str(raw.get("node_id"), d.node_id),
        mode=_as_str(raw.get("mode"), d.mode),
        db_path=_as_str(raw.get("db_path"), d.db_path),
        tx_index_path=_as_str(raw.get("tx_index_path"), d.tx_index_path),
        block_interval_ms=_as_int(raw.get("block_interval_ms"), d.block_interval_ms),
        max_txs_per_block=_as_int(raw.get("max_txs_per_block"), d.max_txs_per_block),
        block_reward=_as_int(raw.get("block_reward"), d.block_reward),
        api_host=_as_str(raw.get("api_host"), d.api_host),
        api_port=_as_int(raw.get("api_port"), d.api_port),
        allow_unsigned_txs=_as_bool(raw.get("allow_unsigned_txs"), d.allow_unsigned_txs),
        log_level=_as_str(raw.get("log_level"), d.log_level),
    )

    validate_chain_config(cfg)
    return cfg


def load_chain_config(*, config_path: Optional[str] = None) -> ChainConfig:
    p = config_path or os.environ.get("WEALL_CHAIN_CONFIG_PATH")
    if p:
        return read_chain_config_file(p)

    cfg = default_chain_config()
    validate_chain_config(cfg)
    return cfg


def apply_chain_config_to_env(cfg: ChainConfig) -> None:
    validate_chain_config(cfg)
    os.environ["WEALL_CHAIN_ID"] = cfg.chain_id
    os.environ["WEALL_NODE_ID"] = cfg.node_id

    # IMPORTANT: expose mode so runtime can safely do testnet-only bootstraps.
    os.environ["WEALL_MODE"] = (cfg.mode or "prod").strip().lower()

    os.environ["WEALL_DB_PATH"] = cfg.db_path
    os.environ["WEALL_TX_INDEX_PATH"] = cfg.tx_index_path
    os.environ["WEALL_BLOCK_REWARD"] = str(int(cfg.block_reward))
    os.environ["WEALL_BLOCK_INTERVAL_MS"] = str(int(cfg.block_interval_ms))
    os.environ["WEALL_MAX_TXS_PER_BLOCK"] = str(int(cfg.max_txs_per_block))
    os.environ["WEALL_LOG_LEVEL"] = cfg.log_level

    os.environ["WEALL_ALLOW_UNSIGNED_TXS"] = "1" if cfg.allow_unsigned_txs else "0"
