from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.chain_config import ChainConfig, production_bootstrap_report, production_bootstrap_issues
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import (
    PRODUCTION_CONSENSUS_PROFILE,
    runtime_startup_fingerprint,
    validate_runtime_consensus_profile,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _cfg(tmp_path: Path) -> ChainConfig:
    return ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "weall.db"),
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def test_prod_tolerates_legacy_startup_clock_sanity_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_STARTUP_CLOCK_SANITY_REQUIRED", "1" if not PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required else "0")
    validate_runtime_consensus_profile()


def test_production_bootstrap_report_exposes_profile_identity_and_clock_posture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_PEER_ID", "peer-1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://example.com")

    report = production_bootstrap_report(_cfg(tmp_path))

    assert report["protocol_version"] == PRODUCTION_CONSENSUS_PROFILE.protocol_version
    assert report["protocol_profile_hash"] == PRODUCTION_CONSENSUS_PROFILE.profile_hash()
    assert report["startup_clock_sanity_required"] == PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required
    assert report["startup_clock_hard_fail_ms"] == PRODUCTION_CONSENSUS_PROFILE.startup_clock_hard_fail_ms


def test_runtime_startup_fingerprint_commits_startup_clock_sanity_requirement() -> None:
    fp = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
    )
    assert fp["protocol_version"] == PRODUCTION_CONSENSUS_PROFILE.protocol_version
    assert fp["startup_clock_sanity_required"] == PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required


def test_restart_tolerates_legacy_startup_clock_sanity_meta_and_heals_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@n1",
        chain_id="startup-sanity",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex.mark_clean_shutdown()
    st = ex.read_state()
    st.setdefault("meta", {})["startup_clock_sanity_required"] = (
        not PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required
    )
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    ex2 = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@n1",
        chain_id="startup-sanity",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    healed = ex2.read_state()
    assert healed.setdefault("meta", {})["startup_clock_sanity_required"] == PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required


def test_restart_warns_and_enters_observer_mode_for_future_skewed_tip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall-clock.db"),
        node_id="@n1",
        chain_id="startup-sanity-hard-fail",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex.mark_clean_shutdown()
    st = ex.read_state()
    st["tip_ts_ms"] = 9_999_999_999_999
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    ex2 = WeAllExecutor(
        db_path=str(tmp_path / "weall-clock.db"),
        node_id="@n1",
        chain_id="startup-sanity-hard-fail",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    assert ex2.observer_mode() is True
    warning = ((ex2.read_state().get("meta") or {}) if isinstance(ex2.read_state().get("meta"), dict) else {}).get("clock_warning")
    assert isinstance(warning, dict)
    assert bool(warning.get("observer_mode_forced", False)) is True
