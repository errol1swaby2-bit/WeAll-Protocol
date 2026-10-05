from __future__ import annotations

import pytest
from starlette.requests import Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts import tx as tx_routes


def _loopback_request(token: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"x-weall-operator-token", token.encode("utf-8")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/v1/observer/edge/status",
        "raw_path": b"/v1/observer/edge/status",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8000),
    }
    return Request(scope)


def _configure_operator_auth(monkeypatch: pytest.MonkeyPatch, *, mode: str) -> None:
    monkeypatch.setenv("WEALL_MODE", mode)
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_OPERATOR_AUTH", "1")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")
    monkeypatch.delenv("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("WEALL_OBSERVER_EDGE_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL", raising=False)


def test_prod_loopback_requires_operator_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_operator_auth(monkeypatch, mode="prod")

    with pytest.raises(ApiError) as missing:
        tx_routes._require_observer_edge_operator(_loopback_request())
    assert missing.value.status_code == 403
    assert missing.value.code == "forbidden"

    with pytest.raises(ApiError) as bad:
        tx_routes._require_observer_edge_operator(_loopback_request("wrong-secret"))
    assert bad.value.status_code == 403
    assert bad.value.code == "forbidden"

    tx_routes._require_observer_edge_operator(_loopback_request("edge-secret"))


def test_nonprod_loopback_convenience_is_explicitly_hardenable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_operator_auth(monkeypatch, mode="dev")

    tx_routes._require_observer_edge_operator(_loopback_request())

    monkeypatch.setenv("WEALL_OBSERVER_EDGE_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL", "1")
    with pytest.raises(ApiError) as hardened:
        tx_routes._require_observer_edge_operator(_loopback_request())
    assert hardened.value.status_code == 403
    assert hardened.value.code == "forbidden"
