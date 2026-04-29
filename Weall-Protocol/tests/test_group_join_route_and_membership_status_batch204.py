from __future__ import annotations

from weall.api.routes_public_parts import groups as groups_routes


class _DummyRequest:
    def __init__(self) -> None:
        self.query_params = {}


class _DummyRequestWithQuery:
    def __init__(self, **query: str) -> None:
        self.query_params = query


def _base_state() -> dict[str, object]:
    return {
        "chain_id": "groups-test",
        "height": 7,
        "tip": "7:test-tip",
        "accounts": {
            "@alice": {
                "banned": False,
                "locked": False,
                "nonce": 3,
                "poh_tier": 3,
                "devices": {"by_id": {}},
                "keys": {"by_id": {}},
                "recovery": {"config": None, "proposals": {}},
                "reputation": 0,
                "session_keys": {"sess-ok": {"revoked": False}},
            }
        },
        "blocks": {},
        "params": {},
        "poh": {},
        "groups_by_id": {
            "g:public": {
                "group_id": "g:public",
                "meta": {"visibility": "public"},
                "members": {"@alice": {"joined_via": "request_auto_accept"}},
            },
            "g:private": {
                "group_id": "g:private",
                "meta": {"visibility": "private"},
                "membership_requests": {"@alice": {"requested_at_nonce": 8}},
            },
        },
    }


def test_group_join_route_accepts_existing_public_group_without_500(monkeypatch) -> None:
    state = _base_state()
    monkeypatch.setattr(groups_routes, "_snapshot", lambda request: state)
    monkeypatch.setattr(groups_routes, "require_account_session", lambda request, st: "@alice")

    req = groups_routes.GroupJoinLeaveRequest(group_id="g:public")
    result = groups_routes.v1_group_join(req, _DummyRequest())

    assert result.ok is True
    assert result.tx.tx_type == "GROUP_MEMBERSHIP_REQUEST"
    assert result.tx.payload["group_id"] == "g:public"


def test_group_membership_status_reports_member_and_pending_states(monkeypatch) -> None:
    state = _base_state()
    monkeypatch.setattr(groups_routes, "_snapshot", lambda request: state)
    monkeypatch.setattr(groups_routes, "require_account_session", lambda request, st: "@alice")

    body_member = groups_routes.v1_group_membership("g:public", _DummyRequest())
    assert body_member["group_exists"] is True
    assert body_member["phase"] == "member"
    assert body_member["is_member"] is True
    assert body_member["is_pending"] is False

    body_pending = groups_routes.v1_group_membership("g:private", _DummyRequest())
    assert body_pending["group_exists"] is True
    assert body_pending["phase"] == "pending"
    assert body_pending["is_member"] is False
    assert body_pending["is_pending"] is True


def test_group_membership_status_supports_query_account_fallback(monkeypatch) -> None:
    state = _base_state()
    monkeypatch.setattr(groups_routes, "_snapshot", lambda request: state)
    monkeypatch.setattr(groups_routes, "require_account_session", lambda request, st: (_ for _ in ()).throw(PermissionError()))

    body = groups_routes.v1_group_membership("g:private", _DummyRequestWithQuery(account="@alice"))
    assert body["account"] == "@alice"
    assert body["phase"] == "pending"
