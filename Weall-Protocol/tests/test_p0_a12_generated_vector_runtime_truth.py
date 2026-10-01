from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI, Request

from weall.api.errors import ApiError
from weall.api.poh_route_auth import enforce_poh_read_authorization


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _generated_vectors() -> dict[str, dict]:
    path = _repo_root() / "generated" / "api_response_vectors_v1_5.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    vectors = payload.get("vectors")
    assert isinstance(vectors, list)
    return {
        str(vector.get("id")): vector
        for vector in vectors
        if isinstance(vector, dict) and vector.get("id")
    }


class _ReadStateExecutor:
    def read_state(self) -> dict:
        return {}


def _request(*, path: str, selector: str, account: str) -> Request:
    app = FastAPI()
    app.state.executor = _ReadStateExecutor()
    query = f"{selector}={account}".encode("utf-8")
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": query,
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "app": app,
            "path_params": {},
        }
    )


@pytest.mark.parametrize(
    "vector_id",
    [
        "poh-async-my-cases-requires-session",
        "poh-tier2-my-cases-session",
        "poh-live-my-cases-session",
    ],
)
def test_generated_poh_queue_auth_vectors_match_runtime_authorization(
    monkeypatch: pytest.MonkeyPatch,
    vector_id: str,
) -> None:
    """A12-F001/A18-F002: generated auth claims must execute truthfully at runtime."""

    from weall.api import poh_route_auth

    vector = _generated_vectors()[vector_id]
    assert vector["method"] == "GET"
    assert vector["expected_http_statuses"] == [403]
    assert vector["expected_error_envelope"]["error"]["code"] == "poh_session_required"
    assert "poh_session_required" in vector["error_codes"]
    assert "poh_session_identity_mismatch" in vector["error_codes"]

    request = _request(
        path=str(vector["path"]),
        selector="account",
        account="@alice",
    )

    def missing_session(_request: Request, _state: dict) -> str:
        raise PermissionError("session_missing")

    monkeypatch.setattr(poh_route_auth, "require_account_session", missing_session)
    with pytest.raises(ApiError) as missing_exc:
        enforce_poh_read_authorization(request)
    assert missing_exc.value.status_code == 403
    assert (
        missing_exc.value.code
        == vector["expected_error_envelope"]["error"]["code"]
        == "poh_session_required"
    )

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _request, _state: "@mallory",
    )
    with pytest.raises(ApiError) as mismatch_exc:
        enforce_poh_read_authorization(request)
    assert mismatch_exc.value.status_code == 403
    assert mismatch_exc.value.code == "poh_session_identity_mismatch"
    assert mismatch_exc.value.code in vector["error_codes"]

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _request, _state: "@alice",
    )
    assert enforce_poh_read_authorization(request) is None
