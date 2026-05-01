from __future__ import annotations

from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from weall.api.app import create_app
from weall.api.routes_public_parts import poh as poh_routes
from weall.poh.oracle_authority_snapshot import verify_authority_snapshot_signature


def _state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 11,
        "meta": {
            "schema_version": "1",
            "tx_index_hash": "d" * 64,
        },
        "chain": {
            "block_hash": "b" * 64,
            "state_root": "c" * 64,
        },
        "accounts": {
            "@operator": {
                "poh_tier": 2,
                "locked": False,
                "banned": False,
                "keys": {
                    "by_id": {
                        "main": {"pubkey": "aa" * 32, "active": True},
                    }
                },
            },
        },
        "reputation": {"accounts": {"@operator": {"reputation_units": 1}}},
        "roles": {
            "node_operators": {"active_set": ["@operator"]},
            "validators": {"active_set": []},
        },
        "consensus": {
            "epochs": {"current": 0},
            "validator_set": {"set_hash": "e" * 64, "active_set": []},
        },
    }


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(poh_routes, "_snapshot", lambda _request: _state())
    return TestClient(create_app(boot_runtime=False))


def test_prod_oracle_authority_route_requires_dedicated_signer_batch244(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY", raising=False)
    monkeypatch.delenv("WEALL_ORACLE_AUTHORITY_PUBKEYS", raising=False)
    monkeypatch.delenv("WEALL_TRUSTED_AUTHORITY_PUBKEYS", raising=False)

    resp = _client(monkeypatch).get("/v1/poh/email/oracle-authority")

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "missing_oracle_authority_signer"


def test_prod_oracle_authority_route_rejects_untrusted_dedicated_signer_batch244(monkeypatch) -> None:
    key = SigningKey(bytes.fromhex("11" * 32))
    pubkey = key.verify_key.encode().hex()

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT", "@authority")
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY", key.encode().hex())
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_PUBKEYS", "22" * 32)

    resp = _client(monkeypatch).get("/v1/poh/email/oracle-authority")

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "oracle_authority_signer_not_trusted"


def test_prod_oracle_authority_route_signs_with_dedicated_trusted_authority_batch244(monkeypatch) -> None:
    key = SigningKey(bytes.fromhex("33" * 32))
    pubkey = key.verify_key.encode().hex()

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT", "@authority")
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY", key.encode().hex())
    monkeypatch.setenv("WEALL_ORACLE_AUTHORITY_PUBKEYS", pubkey)

    resp = _client(monkeypatch).get("/v1/poh/email/oracle-authority")

    assert resp.status_code == 200
    body = resp.json()
    assert body["signatures"]
    assert body["signatures"][0]["signer"] == "@authority"
    assert body["signatures"][0]["pubkey"] == pubkey
    assert verify_authority_snapshot_signature(body, trusted_pubkeys={pubkey}) is True
    assert body["registry"]["@operator"]["eligible"] is True
