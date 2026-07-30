from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.ballot_policy import (
    CONTROLLED_TESTNET_BALLOT_PROFILE,
    ballot_profile_status,
)
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _tx_index_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")


def _clear_profile_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "WEALL_M3_CIVIC_GOVERNANCE_STRICT",
        "WEALL_BALLOT_PROFILE_ID",
        "WEALL_BALLOT_PROFILE_ACTIVE",
    ):
        monkeypatch.delenv(key, raising=False)


def test_m3_controlled_testnet_profile_is_canonical_genesis_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_profile_env(monkeypatch)
    monkeypatch.setenv("WEALL_M3_CIVIC_GOVERNANCE_STRICT", "1")
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ID", CONTROLLED_TESTNET_BALLOT_PROFILE)
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ACTIVE", "1")

    executor = WeAllExecutor(
        db_path=str(tmp_path / "m3-profile.db"),
        node_id="@m3-profile",
        chain_id="weall-controlled-devnet",
        tx_index_path=_tx_index_path(),
    )
    state = executor.read_state()
    params = state["params"]
    assert params["m3_civic_governance_strict"] is True
    assert params["ballot_profile_id"] == CONTROLLED_TESTNET_BALLOT_PROFILE
    assert params["ballot_profile_active"] is True
    assert params["mode"] == "controlled-testnet"
    assert ballot_profile_status(state) == {
        "profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE,
        "active": True,
        "mode": "controlled-testnet",
        "strict": True,
        "reason": "active_controlled_testnet_profile",
    }


def test_ballot_profile_remains_legacy_when_env_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_profile_env(monkeypatch)
    executor = WeAllExecutor(
        db_path=str(tmp_path / "legacy-profile.db"),
        node_id="@legacy-profile",
        chain_id="weall-controlled-devnet",
        tx_index_path=_tx_index_path(),
    )
    state = executor.read_state()
    params = state["params"]
    assert "m3_civic_governance_strict" not in params
    assert "ballot_profile_id" not in params
    assert "ballot_profile_active" not in params
    status = ballot_profile_status(state)
    assert status["strict"] is False
    assert status["active"] is True
    assert status["reason"] == "legacy_or_local_profile"


@pytest.mark.parametrize(
    ("strict", "profile", "active", "message"),
    [
        ("0", CONTROLLED_TESTNET_BALLOT_PROFILE, "1", "active ballot profile requires"),
        ("1", "other-profile", "1", "controlled-testnet ballot activation requires"),
        ("1", "", "0", "must be non-empty"),
    ],
)
def test_invalid_genesis_ballot_profile_configuration_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    strict: str,
    profile: str,
    active: str,
    message: str,
) -> None:
    _clear_profile_env(monkeypatch)
    monkeypatch.setenv("WEALL_M3_CIVIC_GOVERNANCE_STRICT", strict)
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ID", profile)
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ACTIVE", active)
    with pytest.raises(ExecutorError, match=message):
        WeAllExecutor(
            db_path=str(tmp_path / f"invalid-{strict}-{active}.db"),
            node_id="@invalid-profile",
            chain_id="weall-controlled-devnet",
            tx_index_path=_tx_index_path(),
        )
