from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair
from weall.api.routes_public_parts.poh import _oracle_authority_registry


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_genesis_mode_uses_validator_identity_and_enables_operator_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    acct = "@genesis-operator"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    monkeypatch.setenv("WEALL_GENESIS_MODE", "1")
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "11" * 32)

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "genesis_mode.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id=acct, chain_id="genesis-mode", tx_index_path=tx_index_path
    )
    st = ex.read_state()

    acct_rec = st["accounts"][acct]
    assert acct_rec["poh_tier"] == 3

    node_ops = st["roles"]["node_operators"]
    assert acct in list(node_ops.get("active_set") or [])

    validators_role = st["roles"]["validators"]
    assert acct in list(validators_role.get("active_set") or [])

    consensus_registry = (((st.get("consensus") or {}).get("validators") or {}).get("registry") or {})
    assert consensus_registry[acct]["pubkey"] == pub

    params = st["params"]
    assert params["bootstrap_founder_account"] == acct
    assert params["bootstrap_allowlist"][acct]["pubkey"] == pub


def test_oracle_authority_registry_reads_genesis_bootstrap_by_id_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    acct = "@genesis-founder"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "genesis_founder.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id=acct, chain_id="genesis-founder", tx_index_path=tx_index_path
    )
    st = ex.read_state()

    registry = _oracle_authority_registry(st)
    assert acct in registry
    assert pub in list(registry[acct].get("pubkeys") or [])
