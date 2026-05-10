from __future__ import annotations

import os
from dataclasses import dataclass

from weall.runtime.chain_manifest import load_chain_manifest
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import validate_runtime_consensus_profile
from weall.tx.canon import ensure_tx_index_json


@dataclass
class ExecutorBootConfig:
    db_path: str
    node_id: str
    chain_id: str
    tx_index_path: str


# Backwards-compatible alias expected by older imports
BootConfig = ExecutorBootConfig


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default) or default).strip().lower() in {"1", "true", "yes", "y", "on"}


def boot_config_from_env() -> ExecutorBootConfig:
    db_path = os.environ.get("WEALL_DB_PATH", "./data/weall.db")
    node_id = os.environ.get("WEALL_NODE_ID", "local-node")
    mode = str(os.environ.get("WEALL_MODE", "") or "").strip().lower()
    env_chain_id = str(os.environ.get("WEALL_CHAIN_ID", "") or "").strip()
    explicit_manifest = bool(
        str(
            os.environ.get("WEALL_CHAIN_MANIFEST_PATH", "")
            or os.environ.get("WEALL_CHAIN_MANIFEST", "")
            or ""
        ).strip()
    )
    explicit_manifest_required = bool(os.environ.get("WEALL_REQUIRE_CHAIN_MANIFEST") is not None)

    # Preserve the historical production fail-closed error ordering: if an
    # operator gives no chain id and no explicit/required manifest to derive it
    # from, report the missing chain id before attempting default manifest load.
    if mode == "prod" and not env_chain_id and not (explicit_manifest or explicit_manifest_required):
        raise RuntimeError("Missing required env for production: WEALL_CHAIN_ID")

    manifest = load_chain_manifest(
        required=True if mode == "prod" else _truthy_env("WEALL_REQUIRE_CHAIN_MANIFEST"),
        mode=mode,
    )
    manifest_chain_id = manifest.chain_id if manifest is not None and manifest.chain_id else ""
    if mode == "prod":
        if not env_chain_id and not (manifest_chain_id and (explicit_manifest or explicit_manifest_required)):
            raise RuntimeError("Missing required env for production: WEALL_CHAIN_ID")
        chain_id = env_chain_id or manifest_chain_id
        if manifest_chain_id and manifest_chain_id != chain_id:
            raise RuntimeError("WEALL_CHAIN_ID does not match chain manifest")
    else:
        chain_id = env_chain_id or manifest_chain_id or "weall-dev"
    tx_index_path = os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json")

    return ExecutorBootConfig(
        db_path=db_path,
        node_id=node_id,
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )

def build_executor(cfg: ExecutorBootConfig | None = None) -> WeAllExecutor:
    """
    Build a WeAllExecutor from an explicit boot config or, if omitted,
    from environment variables.

    This keeps the API stable for `weall.api.app`, which calls build_executor()
    with no args in production.
    """
    c = cfg or boot_config_from_env()
    validate_runtime_consensus_profile()

    # First-boot / stale-artifact bootstrap:
    # ensure the generated tx index exists and matches the current canon spec
    # before the executor tries to load it.
    ensure_tx_index_json(out_path=c.tx_index_path)

    return WeAllExecutor(
        db_path=c.db_path,
        node_id=c.node_id,
        chain_id=c.chain_id,
        tx_index_path=c.tx_index_path,
    )
