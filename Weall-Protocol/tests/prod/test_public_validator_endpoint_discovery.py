from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from weall.api.app import create_app


def _registry():
    return {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "genesis-hash-test",
        "protocol_profile_hash": "profile-hash-test",
        "tx_index_hash": "tx-index-hash-test",
        "seed_api_urls": ["http://127.0.0.1:8000"],
        "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": [
            {
                "account_id": "@validator1",
                "node_pubkey": "node-key-1",
                "api_base_url": "http://127.0.0.1:8001",
                "p2p_url": "tcp://127.0.0.1:30304",
                "verified": True,
                "signature": "test-signature",
                "last_seen_ms": 123,
            },
            {
                "account_id": "@not-active",
                "api_base_url": "http://127.0.0.1:8002",
                "verified": False,
            },
        ],
    }


class _FakeExecutor:
    def read_state(self):
        return {
            "roles": {
                "validators": {
                    "active_set": ["@validator1", "@validator2"],
                    "by_id": {
                        "@validator1": {"active": True, "node_pubkey": "node-key-1", "readiness_status": "verified"},
                        "@validator2": {"active": True, "node_pubkey": "node-key-2", "readiness_status": "ready"},
                    },
                }
            }
        }


def test_public_validator_endpoint_route_distinguishes_protocol_membership_from_hints(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(_registry()), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(path))

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    r = TestClient(app).get("/v1/nodes/validators")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["public_testnet"] is True
    assert j["active_validator_count"] == 2
    assert j["verified_endpoint_count"] == 1
    assert j["endpoint_authority_boundary"]["endpoint_advertisement_grants_validator_status"] is False

    by_acct = {v["account_id"]: v for v in j["validators"]}
    assert by_acct["@validator1"]["active_in_protocol_state"] is True
    assert by_acct["@validator1"]["verified_endpoint_count"] == 1
    assert by_acct["@validator2"]["verified_endpoint_count"] == 0
    assert by_acct["@validator2"]["endpoint_records"] == []
    assert j["unverified_endpoint_hints"][0]["account_id"] == "@not-active"
