from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.chain_config import ChainConfig, production_bootstrap_issues


def _cfg(tmp_path: Path) -> ChainConfig:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    return ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "data" / "weall.db"),
        tx_index_path=str(tx_index),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def test_prod_bootstrap_requires_keys_when_network_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("public key" in x for x in issues)
    assert any("private key" in x for x in issues)


def test_prod_bootstrap_requires_validator_account_when_bft_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("validator account" in x for x in issues)


def test_prod_bootstrap_rejects_disabled_trusted_anchor_in_network_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("TRUSTED_ANCHOR" in x for x in issues)


def test_prod_bootstrap_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "1")
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example")
    monkeypatch.setenv("WEALL_PEER_ID", "validator-node-1")
    monkeypatch.delenv("WEALL_SIGVERIFY", raising=False)
    assert production_bootstrap_issues(_cfg(tmp_path)) == []


def test_prod_bootstrap_rejects_disabled_handshake_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("NET_REQUIRE_IDENTITY" in x for x in issues)


def test_prod_bootstrap_rejects_disabled_bft_identity_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "0")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "1")
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example")
    monkeypatch.setenv("WEALL_PEER_ID", "validator-node-1")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("IDENTITY_FOR_BFT" in x for x in issues)


def test_prod_bootstrap_rejects_disabled_strict_epoch_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example")
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_BFT_STRICT_EPOCH_BINDING", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("STRICT_EPOCH_BINDING" in x for x in issues)
