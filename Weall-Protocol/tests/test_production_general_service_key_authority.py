from __future__ import annotations

from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight


def _state(*, node_key: bool = True, active: bool = True) -> dict:
    account: dict = {
        "nonce": 0,
        "poh_tier": 2,
        "reputation_milli": 6000,
        "banned": False,
        "locked": False,
        "devices": {"by_id": {}},
    }
    if node_key:
        account["devices"]["by_id"]["node:primary"] = {
            "device_type": "node",
            "pubkey": "node-pub",
            "revoked": False,
        }
    return {
        "accounts": {"@op": account},
        "roles": {
            "node_operators": {
                "by_id": {"@op": {"account_id": "@op", "enrolled": True, "active": bool(active)}},
                "active_set": ["@op"] if active else [],
            }
        },
    }


def _preflight(state: dict, *, roles: tuple[str, ...] = ("general_service",)):
    return evaluate_production_preflight(
        state=state,
        node_id="node-1",
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="txhash",
        runtime_profile_hash="profilehash",
        requested_roles=roles,
        helper_requested=False,
        bft_requested=False,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_bound_account_alone_is_not_node_key_authority(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)

    result = _preflight(_state(node_key=False, active=True), roles=("node_operator",))

    assert result.node_key_authorized is False
    assert "NODE_KEY_NOT_AUTHORIZED" in result.maintenance_reasons
    assert not result.passed
    assert result.effective_roles == ()


def test_general_service_cannot_bypass_node_operator_activation(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)

    inactive = _preflight(_state(node_key=True, active=False), roles=("general_service",))
    assert not inactive.passed
    assert "ROLE_NOT_ACTIVE" in inactive.maintenance_reasons
    assert inactive.effective_roles == ()

    active = _preflight(_state(node_key=True, active=True), roles=("general_service",))
    assert active.passed
    assert active.effective_roles == ("general_service",)


def test_general_service_is_only_added_after_a_requested_service_role_is_effective(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)

    result = _preflight(_state(node_key=True, active=True), roles=("node_operator",))

    assert result.passed
    assert result.effective_roles == ("general_service", "node_operator")
