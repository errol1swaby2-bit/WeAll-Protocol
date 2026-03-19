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


def _set_prod_network_env(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example,https://peer-b.example")
    monkeypatch.setenv("WEALL_PEER_ID", "validator-node-1")
    monkeypatch.delenv("WEALL_SIGVERIFY", raising=False)


def test_prod_bootstrap_requires_explicit_peer_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.delenv("WEALL_PEER_ID", raising=False)
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("explicit peer id" in issue for issue in issues)


def test_prod_bootstrap_rejects_disabled_peer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("PEER_IDENTITY" in issue for issue in issues)


def test_prod_bootstrap_rejects_disabled_sync_header_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("HEADER_MATCH" in issue for issue in issues)


def test_prod_bootstrap_rejects_disabled_finalized_anchor_for_bft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("FINALIZED_ANCHOR" in issue for issue in issues)


def test_prod_bootstrap_requires_bft_fetch_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.delenv("WEALL_BFT_FETCH_BASE_URLS", raising=False)
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("fetch sources" in issue for issue in issues)


def test_prod_bootstrap_rejects_non_https_bft_fetch_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "http://peer-a.example,https://peer-b.example")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("HTTPS" in issue for issue in issues)


def test_prod_bootstrap_rejects_disabled_bft_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("BFT_FETCH_ENABLED" in issue for issue in issues)


def test_prod_bootstrap_network_happy_path_with_explicit_fetch_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    assert production_bootstrap_issues(_cfg(tmp_path)) == []


def test_prod_bootstrap_rejects_disabled_handshake_identity_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("NET_REQUIRE_IDENTITY" in issue for issue in issues)


def test_prod_bootstrap_rejects_disabled_bft_identity_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "0")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("IDENTITY_FOR_BFT" in issue for issue in issues)
