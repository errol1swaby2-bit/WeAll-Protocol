from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from weall.runtime.chain_manifest import load_chain_manifest
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import validate_runtime_consensus_profile
from weall.tx.canon import CanonError, ensure_tx_index_json


@dataclass
class ExecutorBootConfig:
    db_path: str
    node_id: str
    chain_id: str
    tx_index_path: str


# Backwards-compatible alias expected by older imports
BootConfig = ExecutorBootConfig



def _verify_tx_index_artifact_only(tx_index_path: str) -> None:
    """Verify generated tx canon in production without regenerating artifacts."""
    path = Path(tx_index_path)
    if not path.exists():
        raise RuntimeError(f"production tx canon artifact missing: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"production tx canon artifact is not an object: {path}")
    repo_root = Path(__file__).resolve().parents[3]
    spec_path = repo_root / "specs" / "tx_canon" / "tx_canon.yaml"
    if not spec_path.exists():
        raise RuntimeError(f"production tx canon spec missing: {spec_path}")
    expected_hash = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    if str(raw.get("source_sha256") or "").strip() != expected_hash:
        raise RuntimeError("production tx canon artifact source_sha256 mismatch")
    rows = raw.get("tx_types")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("production tx canon artifact missing tx_types")
    by_name = raw.get("by_name")
    if not isinstance(by_name, dict) or len(by_name) != len(rows):
        raise RuntimeError("production tx canon artifact by_name/tx_types mismatch")


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

    # First-boot / stale-artifact bootstrap is allowed only outside production.
    # Production must be verify-only: a missing/stale generated tx canon artifact
    # is a release failure, not something a node should silently regenerate.
    mode = str(os.environ.get("WEALL_MODE", "") or "").strip().lower()
    if mode == "prod" and not _truthy_env("WEALL_ALLOW_PROD_TX_CANON_REGEN"):
        _verify_tx_index_artifact_only(c.tx_index_path)
    else:
        try:
            ensure_tx_index_json(out_path=c.tx_index_path)
        except CanonError:
            raise

    return WeAllExecutor(
        db_path=c.db_path,
        node_id=c.node_id,
        chain_id=c.chain_id,
        tx_index_path=c.tx_index_path,
    )
