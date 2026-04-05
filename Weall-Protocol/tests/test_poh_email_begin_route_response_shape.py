from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.routes_public_parts import poh as poh_routes


class _FakeEmailVerificationService:
    def begin(self, *, account: str, email: str, turnstile_token: str | None = None) -> dict[str, object]:
        assert account == "@satoshi"
        assert email == "errol1swaby2@gmail.com"
        assert turnstile_token == "turnstile-ok"
        return {
            "ok": True,
            "request_id": "challenge-123",
            "challenge_id": "challenge-123",
            "expires_at_ms": 1234567890,
        }


def test_poh_email_begin_route_accepts_service_dict_response(monkeypatch) -> None:
    monkeypatch.setattr(poh_routes, "_svc", lambda _request: _FakeEmailVerificationService())

    app = create_app(boot_runtime=False)
    client = TestClient(app)

    resp = client.post(
        "/v1/poh/email/begin",
        json={
            "account": "@satoshi",
            "email": "errol1swaby2@gmail.com",
            "turnstile_token": "turnstile-ok",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "request_id": "challenge-123",
        "expires_ms": 1234567890,
    }
