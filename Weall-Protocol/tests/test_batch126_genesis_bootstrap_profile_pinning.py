from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def test_restart_rejects_genesis_bootstrap_profile_drift_batch126(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    acct = "@bootstrap-pinned"
    pub, _sk = deterministic_ed25519_keypair(label=acct)
    db_path = str(tmp_path / "genesis_profile.db")

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "2.5")

    ex = WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-genesis", tx_index_path=_tx_index_path())
    st = ex.read_state()
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    assert meta.get("genesis_bootstrap_profile", {}).get("enabled") is True
    assert isinstance(meta.get("genesis_bootstrap_profile_hash"), str) and meta.get("genesis_bootstrap_profile_hash")

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "3.0")
    with pytest.raises(ExecutorError, match="genesis_bootstrap_profile mismatch"):
        WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-genesis", tx_index_path=_tx_index_path())


def test_restart_rejects_late_genesis_bootstrap_enablement_batch126(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    acct = "@plain-genesis"
    db_path = str(tmp_path / "plain_genesis.db")

    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", raising=False)
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", raising=False)
    monkeypatch.setenv("WEALL_NODE_ID", acct)

    ex = WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-plain", tx_index_path=_tx_index_path())
    meta = ex.read_state().get("meta") if isinstance(ex.read_state().get("meta"), dict) else {}
    assert meta.get("genesis_bootstrap_profile", {}).get("enabled") is False

    pub, _sk = deterministic_ed25519_keypair(label=acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    with pytest.raises(ExecutorError, match="genesis_bootstrap_profile mismatch"):
        WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-plain", tx_index_path=_tx_index_path())


def test_genesis_mode_profile_is_pinned_to_validator_identity_batch126(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    acct = "@genesis-mode-pinned"
    pub, _sk = deterministic_ed25519_keypair(label=acct)
    db_path = str(tmp_path / "genesis_mode_profile.db")

    monkeypatch.setenv("WEALL_GENESIS_MODE", "1")
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "11" * 32)

    ex = WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-mode", tx_index_path=_tx_index_path())
    meta = ex.read_state().get("meta") if isinstance(ex.read_state().get("meta"), dict) else {}
    assert meta.get("genesis_bootstrap_profile", {}).get("mode") == "genesis_mode"

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@other")
    with pytest.raises(ExecutorError, match="genesis_bootstrap_profile mismatch"):
        WeAllExecutor(db_path=db_path, node_id=acct, chain_id="batch126-mode", tx_index_path=_tx_index_path())
