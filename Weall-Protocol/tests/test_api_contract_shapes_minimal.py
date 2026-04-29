from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


def _assert_ok_shape(j: dict) -> None:
    assert isinstance(j, dict)
    assert "ok" in j
    assert isinstance(j.get("ok"), bool)


def test_public_nodes_routes_have_ok_shape(monkeypatch):
    """Schema-lite contract: the web depends on these public node-discovery routes.

    We intentionally run with boot_runtime=False to keep the test fast and to
    ensure these endpoints do not depend on executor wiring.
    """

    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")

    app = create_app(boot_runtime=False)
    c = TestClient(app)

    for path in ("/v1/nodes/known", "/v1/nodes/seeds"):
        r = c.get(path)
        assert r.status_code == 200
        _assert_ok_shape(r.json())
