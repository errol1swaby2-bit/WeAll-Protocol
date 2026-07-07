from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.bft_hotstuff import BFT_MIN_VALIDATORS
from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission_types import TxEnvelope


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def _mk_executor(tmp_path: Path, monkeypatch, *, observer: bool) -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding" if observer else "production_service")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1" if observer else "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0" if observer else "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0" if observer else "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", "0")
    monkeypatch.delenv("WEALL_SERVICE_ROLES", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_EXPLICIT_VALIDATOR_SIGNING_OVERRIDE", raising=False)
    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)
    return WeAllExecutor(
        db_path=str(db_path),
        node_id="node-a",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )


def test_prod_observer_mode_beats_explicit_validator_signing_override(tmp_path: Path, monkeypatch) -> None:
    ex = _mk_executor(tmp_path, monkeypatch, observer=True)
    ex.state.setdefault("roles", {})["validators"] = {"active_set": ["alice"]}
    ex.state.setdefault("consensus", {})["validators"] = {
        "registry": {"alice": {"pubkey": "a" * 64}}
    }

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "alice")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "a" * 64)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "b" * 64)
    monkeypatch.setenv("WEALL_ALLOW_EXPLICIT_VALIDATOR_SIGNING_OVERRIDE", "1")

    assert ex.observer_mode() is True
    assert ex._explicit_validator_signing_override() is False
    assert ex._validator_signing_permitted() is False


def test_prod_observer_mode_refuses_local_block_production(tmp_path: Path, monkeypatch) -> None:
    ex = _mk_executor(tmp_path, monkeypatch, observer=True)

    result = ex.produce_block(allow_empty=True)

    assert result.ok is False
    assert result.applied_count == 0
    assert result.error.startswith("block_production_forbidden:")


def _bootstrap_state(*, active_validator_count: int) -> dict:
    active = [f"validator-{idx}" for idx in range(active_validator_count)]
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {
                "nonce": 0,
                "pubkey": "alice-pk",
                "pubkeys": ["alice-pk"],
                "poh_tier": 0,
            }
        },
        "params": {
            "system_signer": "SYSTEM",
            "poh_bootstrap_open": True,
            "poh_bootstrap_max_height": 50,
        },
        "poh": {},
        "roles": {"validators": {"active_set": active}},
    }


def _bootstrap_tx() -> dict:
    return TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="alice",
        nonce=1,
        system=False,
        payload={"account_id": "alice"},
    ).to_json()


def test_bootstrap_tier2_grant_allowed_before_regular_validator_quorum() -> None:
    state = _bootstrap_state(active_validator_count=max(0, int(BFT_MIN_VALIDATORS) - 1))

    apply_tx(state, _bootstrap_tx())

    assert state["accounts"]["alice"]["poh_tier"] == 2
    assert state["accounts"]["alice"]["poh_bootstrap_granted"] is True


def test_bootstrap_tier2_grant_auto_locks_at_regular_validator_quorum() -> None:
    state = _bootstrap_state(active_validator_count=int(BFT_MIN_VALIDATORS))

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _bootstrap_tx())

    assert excinfo.value.reason == "bootstrap_auto_locked_validator_quorum"
    assert excinfo.value.details["active_validators"] == int(BFT_MIN_VALIDATORS)
    assert excinfo.value.details["required_active_validators"] == int(BFT_MIN_VALIDATORS)
    assert state["accounts"]["alice"]["poh_tier"] == 0
