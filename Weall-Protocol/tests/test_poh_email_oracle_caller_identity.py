from __future__ import annotations

import os

from fastapi import FastAPI, Request

from weall.api.routes_public_parts.poh import _oracle_caller_identity


def test_oracle_caller_identity_accepts_active_node_operator_pubkey(monkeypatch) -> None:
    state = {
        "accounts": {
            "@operator": {
                "keys": {
                    "by_id": {
                        "main": {"pubkey": "cc" * 32, "active": True},
                    }
                }
            }
        },
        "roles": {
            "validators": {"active_set": []},
            "node_operators": {"active_set": ["@operator"]},
        },
        "consensus": {"validators": {"registry": {}}},
        "params": {},
    }

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@operator")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "cc" * 32)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "11" * 32)

    app = FastAPI()
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "scheme": "http",
        "app": app,
    }
    request = Request(scope)
    request.scope["app"] = app

    ident = _oracle_caller_identity(request, state)
    assert ident is not None
    assert ident.operator_account == "@operator"
    assert ident.node_pubkey == "cc" * 32
    assert ident.node_privkey == "11" * 32
