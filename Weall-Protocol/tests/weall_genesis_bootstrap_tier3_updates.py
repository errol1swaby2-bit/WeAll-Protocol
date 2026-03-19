from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_genesis_builder_can_grant_bootstrap_tier3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Option B1: Tier-3 bootstrap is applied in genesis state builder only."""

    acct = "@bootstrap"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id=acct, chain_id="genesis-tier3", tx_index_path=tx_index_path
    )
    st = ex.read_state()

    assert st.get("height") == 0
    accounts = st.get("accounts")
    assert isinstance(accounts, dict)
    a = accounts.get(acct)
    assert isinstance(a, dict)
    assert a.get("poh_tier") == 3
    assert float(a.get("reputation") or 0.0) == pytest.approx(1.0)

    keys = a.get("keys")
    assert isinstance(keys, dict)
    by_id = keys.get("by_id")
    assert isinstance(by_id, dict)
    assert any(isinstance(v, dict) and v.get("pubkey") == pub for v in by_id.values())


def test_genesis_bootstrap_is_disabled_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    acct = "@bootstrap"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", raising=False)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall_disabled.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id=acct,
        chain_id="genesis-tier3-disabled",
        tx_index_path=tx_index_path,
    )
    st = ex.read_state()

    accounts = st.get("accounts")
    assert isinstance(accounts, dict)
    assert acct not in accounts


def test_genesis_bootstrap_requires_both_env_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-closed if only one of ACCOUNT/PUBKEY is provided."""

    acct = "@bootstrap"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    # Enable set but only account set -> error
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", raising=False)
    with pytest.raises(RuntimeError):
        WeAllExecutor(
            db_path=db_path, node_id=acct, chain_id="genesis-tier3", tx_index_path=tx_index_path
        )

    # Reset db and try only pubkey set -> error
    db_path2 = str(tmp_path / "weall2.db")
    monkeypatch.delenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", raising=False)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    with pytest.raises(RuntimeError):
        WeAllExecutor(
            db_path=db_path2, node_id=acct, chain_id="genesis-tier3", tx_index_path=tx_index_path
        )


def test_genesis_builder_bootstraps_founder_as_active_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    acct = "@bootstrap"
    pub, _sk = deterministic_ed25519_keypair(label=acct)

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "2.5")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_STORAGE_CAPACITY_BYTES", "4096")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id=acct, chain_id="genesis-tier3", tx_index_path=tx_index_path
    )
    st = ex.read_state()

    acct_rec = st["accounts"][acct]
    assert acct_rec["poh_tier"] == 3
    assert float(acct_rec["reputation"]) == pytest.approx(2.5)

    roles = st.get("roles")
    assert isinstance(roles, dict)
    node_ops = roles.get("node_operators")
    assert isinstance(node_ops, dict)
    assert acct in list(node_ops.get("active_set") or [])
    op_rec = (node_ops.get("by_id") or {}).get(acct)
    assert isinstance(op_rec, dict)
    assert op_rec.get("enrolled") is True
    assert op_rec.get("active") is True

    storage = st.get("storage")
    assert isinstance(storage, dict)
    storage_ops = storage.get("operators")
    assert isinstance(storage_ops, dict)
    storage_rec = storage_ops.get(acct)
    assert isinstance(storage_rec, dict)
    assert storage_rec.get("enabled") is True
    assert int(storage_rec.get("capacity_bytes") or 0) == 4096
