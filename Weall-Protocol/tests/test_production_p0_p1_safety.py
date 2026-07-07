from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import runtime_vrf_required
from weall.runtime.tx_admission_types import TxEnvelope


ROOT = Path(__file__).resolve().parents[1]


def _load_genesis_verifier():
    path = ROOT / "scripts/assert_production_genesis_artifacts.py"
    spec = importlib.util.spec_from_file_location("assert_production_genesis_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify



def _write_empty_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_prod_direct_config_loads_default_chain_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.delenv("WEALL_REQUIRE_CHAIN_MANIFEST", raising=False)
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST_PATH", raising=False)
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST", raising=False)
    monkeypatch.delenv("WEALL_USE_DEFAULT_CHAIN_MANIFEST", raising=False)

    cfg = load_chain_config()
    issues = production_bootstrap_issues(cfg)

    assert cfg.chain_manifest_path.endswith("configs/chains/weall-genesis.json")
    assert cfg.expected_tx_index_hash
    assert not [issue for issue in issues if "chain_manifest" in issue]


def test_prod_rejects_explicitly_disabled_chain_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "0")
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST_PATH", raising=False)
    monkeypatch.delenv("WEALL_CHAIN_MANIFEST", raising=False)

    with pytest.raises(ValueError, match="WEALL_REQUIRE_CHAIN_MANIFEST"):
        load_chain_config()


def test_production_vrf_is_pinned_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_REQUIRE_VRF", raising=False)

    assert runtime_vrf_required() is True


def test_production_genesis_founder_tier2_has_bootstrap_audit_receipt() -> None:
    genesis = json.loads((ROOT / "configs/genesis.ledger.prod.json").read_text(encoding="utf-8"))
    founder_id = genesis["params"]["bootstrap_founder_account"]
    founder = genesis["accounts"][founder_id]

    assert founder["poh_tier"] == 2
    assert founder["poh_bootstrap_grant_id"].startswith("poh_bootstrap_grant:")
    assert founder["poh_bootstrap_receipt_id"].startswith("poh_bootstrap_receipt:")

    grants = genesis["poh"]["bootstrap_grants"]
    grant_id = founder["poh_bootstrap_grant_id"]
    grant = grants["by_id"][grant_id]
    assert grant["account_id"] == founder_id
    assert grant["grant_type"] == "poh_tier2_live_verified"
    assert grant["auditable"] is True
    assert grant["transitional"] is True
    assert grant["receipt_id"] == founder["poh_bootstrap_receipt_id"]
    assert grants["by_account"][founder_id] == [grant_id]

    report = _load_genesis_verifier()(
        manifest_path=ROOT / "configs/chains/weall-genesis.json",
        genesis_path=ROOT / "configs/genesis.ledger.prod.json",
        tx_index_path=ROOT / "generated/tx_index.json",
    )
    assert report["ok"] is True, report["issues"]


def test_prod_disables_explicit_validator_signing_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tx_index = tmp_path / "tx_index.json"
    _write_empty_tx_index(tx_index)
    pubkey = "a" * 64
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "alice")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "b" * 64)
    monkeypatch.setenv("WEALL_ALLOW_EXPLICIT_VALIDATOR_SIGNING_OVERRIDE", "1")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="alice",
        chain_id="weall-test",
        tx_index_path=str(tx_index),
    )
    ex.state.setdefault("roles", {})["validators"] = {"active_set": ["alice"]}
    ex.state.setdefault("consensus", {})["validators"] = {
        "registry": {"alice": {"pubkey": pubkey, "status": "active"}}
    }

    assert ex._explicit_validator_signing_override() is False


def test_storage_payout_execute_requires_economics_activation() -> None:
    state = {
        "chain_id": "weall-test",
        "height": 1,
        "time": 10,
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 100,
            "economics_enabled": False,
            "system_signer": "SYSTEM",
        },
        "storage": {},
    }
    env = TxEnvelope(
        tx_type="STORAGE_PAYOUT_EXECUTE",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"payout_id": "payout-1", "operator_id": "alice", "amount": 25},
    ).to_json()

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, env)
    assert excinfo.value.reason == "economics_time_locked"
    assert state.get("storage", {}).get("payouts") in (None, [])

    state["time"] = 101
    with pytest.raises(ApplyError) as excinfo2:
        apply_tx(state, env)
    assert excinfo2.value.reason == "economics_disabled"
    assert state.get("storage", {}).get("payouts") in (None, [])

    state["params"]["economics_enabled"] = True
    result = apply_tx(state, env)
    assert result["applied"] == "STORAGE_PAYOUT_EXECUTE"
    assert state["storage"]["payouts"][0]["payout_id"] == "payout-1"
