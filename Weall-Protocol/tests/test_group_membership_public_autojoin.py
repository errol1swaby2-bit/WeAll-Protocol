from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.tx_admission import TxEnvelope


def _request(
    state: dict, *, signer: str = "@alice", nonce: int = 7, note: str | None = None
) -> dict:
    payload: dict[str, object] = {"group_id": "g:public"}
    if note is not None:
        payload["note"] = note
    result = apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_MEMBERSHIP_REQUEST",
            signer=signer,
            nonce=nonce,
            payload=payload,
            system=False,
            parent=None,
        ),
    )
    assert result is not None
    return result


def _decision(
    state: dict, *, account: str = "@alice", decision: str = "accept", nonce: int = 8
) -> dict:
    result = apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_MEMBERSHIP_DECIDE",
            signer="@owner",
            nonce=nonce,
            payload={"group_id": "g:public", "account": account, "decision": decision},
            system=False,
            parent=None,
        ),
    )
    assert result is not None
    return result


def test_legacy_group_without_membership_mode_defaults_to_open() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "meta": {"visibility": "public"},
                }
            }
        }
    }

    result = _request(state)

    assert result["membership"] == "accepted"
    assert result["membership_mode"] == "open"
    group = state["roles"]["groups_by_id"]["g:public"]
    assert group["membership_mode"] == "open"
    assert group["meta"]["membership_mode"] == "open"
    assert group["members"]["@alice"]["joined_via"] == "request_auto_accept"
    assert group.get("membership_requests", {}) == {}


def test_explicit_open_group_request_auto_accepts() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "open",
                    "meta": {"visibility": "public", "membership_mode": "open"},
                }
            }
        }
    }

    result = _request(state, note="hello")

    assert result["membership"] == "accepted"
    assert result["auto_accepted"] is True
    assert "@alice" in state["roles"]["groups_by_id"]["g:public"]["members"]


def test_approval_required_request_stays_pending_and_preserves_public_read() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "approval_required",
                    "meta": {"visibility": "public", "membership_mode": "approval_required"},
                    "members": {"@owner": {"role": "creator"}},
                }
            }
        }
    }

    result = _request(state, note="Please approve")

    assert result["membership"] == "pending"
    assert result["auto_accepted"] is False
    group = state["roles"]["groups_by_id"]["g:public"]
    assert "@alice" not in group["members"]
    assert group["membership_requests"]["@alice"] == {
        "account": "@alice",
        "requested_at_nonce": 7,
        "requested_by": "@alice",
        "status": "pending",
        "note": "Please approve",
    }
    assert group["read_visibility"] == "public"
    assert group["meta"]["visibility"] == "public"


def test_duplicate_approval_request_is_deterministically_deduped() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "approval_required",
                    "members": {},
                    "membership_requests": {},
                }
            }
        }
    }

    first = _request(state, nonce=7)
    second = _request(state, nonce=8)

    assert first.get("deduped") is not True
    assert second["membership"] == "pending"
    assert second["deduped"] is True
    assert (
        state["roles"]["groups_by_id"]["g:public"]["membership_requests"]["@alice"][
            "requested_at_nonce"
        ]
        == 7
    )


def test_approval_accept_consumes_request_and_creates_member() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "approval_required",
                    "members": {"@owner": {"role": "creator"}},
                    "membership_requests": {
                        "@alice": {
                            "account": "@alice",
                            "requested_at_nonce": 7,
                            "requested_by": "@alice",
                            "status": "pending",
                        }
                    },
                }
            }
        }
    }

    result = _decision(state)

    assert result["decision"] == "accept"
    assert result["request_consumed"] is True
    group = state["roles"]["groups_by_id"]["g:public"]
    assert group["membership_requests"] == {}
    assert group["members"]["@alice"]["joined_via"] == "moderator_accept"
    assert group["members"]["@alice"]["decided_by"] == "@owner"
    assert group["members"]["@alice"]["requested_at_nonce"] == 7


def test_approval_reject_consumes_request_without_membership() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "approval_required",
                    "members": {"@owner": {"role": "creator"}},
                    "membership_requests": {"@alice": {"requested_at_nonce": 7}},
                }
            }
        }
    }

    result = _decision(state, decision="reject")

    assert result["decision"] == "reject"
    group = state["roles"]["groups_by_id"]["g:public"]
    assert group["membership_requests"] == {}
    assert "@alice" not in group["members"]


def test_decision_requires_matching_pending_request() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "approval_required",
                    "members": {"@owner": {"role": "creator"}},
                    "membership_requests": {},
                }
            }
        }
    }

    with pytest.raises(GroupsApplyError) as exc:
        _decision(state)

    assert exc.value.code == "not_found"
    assert exc.value.reason == "membership_request_not_found"


def test_open_group_rejects_spurious_membership_decision() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:public": {
                    "group_id": "g:public",
                    "membership_mode": "open",
                    "members": {"@owner": {"role": "creator"}},
                    "membership_requests": {"@alice": {"requested_at_nonce": 7}},
                }
            }
        }
    }

    with pytest.raises(GroupsApplyError) as exc:
        _decision(state)

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "membership_decision_not_required"
