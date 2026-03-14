# src/weall/runtime/executor_boot.py

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from weall.runtime.executor import WeAllExecutor


@dataclass
class ExecutorBootConfig:
    db_path: str
    node_id: str
    chain_id: str
    tx_index_path: str


# Backwards-compatible alias expected by older imports
BootConfig = ExecutorBootConfig


def boot_config_from_env() -> ExecutorBootConfig:
    db_path = os.environ.get("WEALL_DB_PATH", "./data/weall.db")
    node_id = os.environ.get("WEALL_NODE_ID", "local-node")
    chain_id = os.environ.get("WEALL_CHAIN_ID", "weall-dev")
    tx_index_path = os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json")

    return ExecutorBootConfig(
        db_path=db_path,
        node_id=node_id,
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )


def build_executor(cfg: Optional[ExecutorBootConfig] = None) -> WeAllExecutor:
    """
    Build a WeAllExecutor from an explicit boot config or, if omitted,
    from environment variables.

    This keeps the API stable for `weall.api.app`, which calls build_executor()
    with no args in production.
    """
    c = cfg or boot_config_from_env()
    return WeAllExecutor(
        db_path=c.db_path,
        node_id=c.node_id,
        chain_id=c.chain_id,
        tx_index_path=c.tx_index_path,
    )
