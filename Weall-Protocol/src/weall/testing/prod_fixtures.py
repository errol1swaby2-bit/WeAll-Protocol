from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_BFT_ACTIVE
from weall.runtime.block_time_admission import runtime_block_clock_policy
from weall.runtime.chain_manifest import file_canonical_json_hash
from weall.runtime.constitutional_clock import expected_block_time_ms
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE
from weall.testing.sigtools import deterministic_mldsa_keypair


def write_strict_prod_chain_manifest(
    path: Path,
    *,
    chain_id: str,
    tx_index_path: str | Path,
) -> Path:
    """Write a deterministic strict production manifest for test fixtures.

    The manifest is explicit test input.  Production code must never infer these
    commitments merely because pytest is running.
    """
    tx_hash = file_canonical_json_hash(str(tx_index_path))
    payload = {
        "version": 1,
        "name": "WeAll strict production test fixture",
        "chain_id": str(chain_id),
        "mode": "prod",
        "profile": "production_service",
        "schema_version": "1",
        "genesis_hash": "11" * 32,
        "genesis_state_root": "22" * 32,
        "tx_index_hash": tx_hash,
        "protocol_profile_hash": PRODUCTION_CONSENSUS_PROFILE.profile_hash(),
        "constitution_version": "test-v1",
        "constitution_hash": "33" * 32,
        "constitution_traceability_hash": "44" * 32,
        "constitution_document_path": "tests/fixture-constitution.md",
        "genesis_time_ms": 0,
        "constitutional_clock": {
            "enabled": True,
            "target_block_interval_ms": 20_000,
            "empty_blocks_enabled": True,
            "procedure_time_source": "finalized_block_height",
            "block_time_derivation": "genesis_time_plus_height_times_interval",
            "no_fast_forward": True,
            "no_height_skip": True,
            "allowed_clock_skew_ms": 2_000,
            "genesis_time_ms": 0,
        },
        "authority_snapshot_version": 1,
        "trusted_authority_pubkeys": ["55" * 32],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def install_strict_prod_chain_manifest(
    monkeypatch: Any,
    tmp_path: Path,
    *,
    chain_id: str,
    tx_index_path: str | Path,
) -> Path:
    path = write_strict_prod_chain_manifest(
        tmp_path / "strict-prod-chain-manifest.json",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(path))
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    return path


def install_prod_node_keys(monkeypatch: Any, *, label: str = "prod-node") -> tuple[str, str]:
    pubkey, sk = deterministic_mldsa_keypair(label=label)
    privkey = sk.private_bytes_raw().hex()
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privkey)
    return pubkey, privkey


def seed_active_validator(
    executor: Any,
    *,
    account: str,
    pubkey: str,
    phase: str = CONSENSUS_PHASE_BFT_ACTIVE,
) -> None:
    state = executor.state
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = [str(account)]
    state.setdefault("validators", {}).setdefault("registry", {}).setdefault(str(account), {})[
        "pubkey"
    ] = str(pubkey)
    consensus = state.setdefault("consensus", {})
    consensus.setdefault("validators", {}).setdefault("registry", {}).setdefault(str(account), {})[
        "pubkey"
    ] = str(pubkey)
    consensus.setdefault("validator_set", {})["active_set"] = [str(account)]
    consensus.setdefault("phase", {})["current"] = str(phase)
    executor._ledger_store.write(state)
    executor.state = executor._ledger_store.read()


def next_constitutional_block_time_ms(executor: Any) -> int:
    state = executor.read_state()
    policy = runtime_block_clock_policy(state=state, mode="prod")
    height = int(state.get("height") or 0) + 1
    if not policy.enabled:
        return max(1, int(executor.chain_time_floor_ms()))
    return int(expected_block_time_ms(policy, height=height))


def seed_prod_validator_quorum(
    executor: Any,
    *,
    local_account: str = "@v1",
    local_pubkey: str = "",
) -> None:
    accounts = [str(local_account), "@v2", "@v3", "@v4"]
    state = executor.state
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(accounts)
    validators = state.setdefault("validators", {}).setdefault("registry", {})
    consensus = state.setdefault("consensus", {})
    cvalidators = consensus.setdefault("validators", {}).setdefault("registry", {})
    for idx, account in enumerate(accounts, start=1):
        pubkey = (
            str(local_pubkey)
            if account == str(local_account) and local_pubkey
            else (f"fixture-pub-{idx}")
        )
        validators.setdefault(account, {})["pubkey"] = pubkey
        cvalidators.setdefault(account, {})["pubkey"] = pubkey
    consensus.setdefault("validator_set", {})["active_set"] = list(accounts)
    consensus.setdefault("phase", {})["current"] = CONSENSUS_PHASE_BFT_ACTIVE
    executor._ledger_store.write(state)
    executor.state = executor._ledger_store.read()
