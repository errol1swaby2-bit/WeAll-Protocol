from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.routes_public_parts import poh as poh_routes


def test_poh_email_oracle_authority_route_exposes_active_validator_bootstrap_founder_and_node_operator(monkeypatch) -> None:
    state = {
        "chain_id": "weall-dev",
        "height": 7,
        "accounts": {
            "@validator": {
                "keys": {
                    "aa" * 32: {"active": True},
                }
            },
            "@genesis": {
                "keys": {
                    "bb" * 32: {"active": True},
                }
            },
            "@operator": {
                "keys": {
                    "by_id": {
                        "main": {"pubkey": "cc" * 32, "active": True},
                    }
                }
            },
        },
        "roles": {
            "validators": {"active_set": ["@validator"]},
            "node_operators": {"active_set": ["@operator"]},
        },
        "consensus": {
            "validators": {
                "registry": {
                    "@validator": {"pubkey": "aa" * 32, "status": "active"},
                }
            }
        },
        "params": {
            "bootstrap_founder_account": "@genesis",
            "bootstrap_allowlist": {
                "@genesis": {"pubkey": "bb" * 32},
            },
        },
    }

    monkeypatch.setattr(poh_routes, "_snapshot", lambda _request: state)
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    resp = client.get("/v1/poh/email/oracle-authority")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["chain_id"] == "weall-dev"
    assert set(body["authorized_accounts"]) == {"@validator", "@genesis", "@operator"}
    assert "aa" * 32 in body["authorized_pubkeys"]
    assert "bb" * 32 in body["authorized_pubkeys"]
    assert "cc" * 32 in body["authorized_pubkeys"]
    assert body["registry"]["@validator"]["reasons"] == ["active_validator"]
    assert "bootstrap_founder" in body["registry"]["@genesis"]["reasons"]
    assert "active_node_operator" in body["registry"]["@operator"]["reasons"]
