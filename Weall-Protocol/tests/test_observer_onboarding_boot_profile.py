from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env


ROOT = Path(__file__).resolve().parents[1]


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def _mk_executor(tmp_path: Path, monkeypatch, *, lifecycle_state: str = "observer_onboarding") -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", lifecycle_state)
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.delenv("WEALL_SERVICE_ROLES", raising=False)
    monkeypatch.delenv("WEALL_BOUND_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)
    return WeAllExecutor(db_path=str(db_path), node_id="new-node", chain_id="weall-test", tx_index_path=str(tx_index_path))


def test_runtime_config_accepts_observer_onboarding_state(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding")
    monkeypatch.delenv("WEALL_SERVICE_ROLES", raising=False)
    cfg = resolve_node_runtime_config_from_env()
    assert cfg.requested_state == "observer_onboarding"
    assert cfg.requested_roles == ()
    assert cfg.invalid_roles == ()


def test_observer_onboarding_boot_has_no_service_authority(tmp_path: Path, monkeypatch) -> None:
    ex = _mk_executor(tmp_path, monkeypatch)
    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["requested_state"] == "observer_onboarding"
    assert lifecycle["effective_state"] == "observer_onboarding"
    assert lifecycle["promotion_preflight_passed"] is False
    assert lifecycle["service_roles_effective"] == []
    assert lifecycle["helper_enabled_effective"] is False
    assert lifecycle["bft_enabled_effective"] is False
    assert ex.observer_mode() is True


def test_production_node_operator_requires_tier2_active_role_and_registered_node_device(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_POH_TIER", raising=False)
    monkeypatch.setenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", "0")

    base_state = {
        "accounts": {"@op": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation_milli": 6000, "keys": {"by_id": {"main": {"pubkey": "account-pub", "revoked": False}}}, "devices": {"by_id": {"node:primary": {"device_type": "node", "pubkey": "node-pub", "revoked": False}}}}},
        "roles": {"node_operators": {"by_id": {"@op": {"enrolled": True, "active": True}}, "active_set": ["@op"]}},
    }

    def check(state):
        return evaluate_production_preflight(
            state=state,
            node_id="node-1",
            chain_id="weall-prod",
            schema_version="1",
            tx_index_hash="txhash",
            runtime_profile_hash="profilehash",
            requested_roles=("node_operator",),
            helper_requested=False,
            bft_requested=False,
            sigverify_required=True,
            trusted_anchor_required=True,
        )

    tier1 = check(base_state)
    assert tier1.poh_tier_required == 2
    assert tier1.poh_tier_actual == 1
    assert "POH_TIER_INSUFFICIENT" in tier1.maintenance_reasons
    assert not tier1.passed

    no_role_state = json.loads(json.dumps(base_state))
    no_role_state["accounts"]["@op"]["poh_tier"] = 2
    no_role_state["roles"]["node_operators"] = {"by_id": {"@op": {"enrolled": True, "active": False}}, "active_set": []}
    no_role = check(no_role_state)
    assert "ROLE_NOT_ACTIVE" in no_role.maintenance_reasons
    assert not no_role.passed

    wrong_key_state = json.loads(json.dumps(base_state))
    wrong_key_state["accounts"]["@op"]["poh_tier"] = 2
    wrong_key_state["accounts"]["@op"]["devices"]["by_id"]["node:primary"]["pubkey"] = "different-node-pub"
    wrong_key = check(wrong_key_state)
    assert "NODE_KEY_NOT_AUTHORIZED" in wrong_key.maintenance_reasons
    assert not wrong_key.passed

    ready_state = json.loads(json.dumps(base_state))
    ready_state["accounts"]["@op"]["poh_tier"] = 2
    ready = check(ready_state)
    assert ready.passed
    assert ready.node_key_authorized is True
    assert ready.effective_roles == ("general_service", "node_operator")


def test_split_boot_scripts_document_safe_and_service_paths() -> None:
    onboarding = (ROOT / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")
    service = (ROOT / "scripts" / "boot_node_operator.sh").read_text(encoding="utf-8")
    default_boot = (ROOT / "scripts" / "boot_weall_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"' in onboarding
    assert 'WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"' in onboarding
    assert 'WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"' in onboarding
    assert "Blocked: validator signing, block proposal, helper authority" in onboarding
    assert 'WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-production_service}"' in service
    assert 'WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-node_operator}"' in service
    assert "WEALL_BOUND_ACCOUNT" in service
    assert "WEALL_NODE_PRIVKEY_FILE" in service
    assert "fail-closed" in service
    assert 'WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"' in default_boot
    assert 'WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"' in default_boot
