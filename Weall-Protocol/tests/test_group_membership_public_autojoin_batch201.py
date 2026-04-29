from __future__ import annotations

from weall.runtime.apply.groups import apply_groups
from weall.runtime.tx_admission import TxEnvelope


def test_public_group_membership_request_auto_accepts_for_demo_safe_join_surface() -> None:
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
    env = TxEnvelope(
        tx_type="GROUP_MEMBERSHIP_REQUEST",
        signer="@alice",
        nonce=7,
        payload={"group_id": "g:public"},
        system=False,
        parent=None,
    )

    result = apply_groups(state, env)

    assert result is not None
    assert result["membership"] == "accepted"
    group = state["roles"]["groups_by_id"]["g:public"]
    assert "@alice" in group["members"]
    assert group["members"]["@alice"]["joined_via"] == "request_auto_accept"
    assert group.get("membership_requests", {}) == {}


def test_private_group_membership_request_remains_pending() -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "g:private": {
                    "group_id": "g:private",
                    "meta": {"visibility": "private"},
                }
            }
        }
    }
    env = TxEnvelope(
        tx_type="GROUP_MEMBERSHIP_REQUEST",
        signer="@alice",
        nonce=8,
        payload={"group_id": "g:private"},
        system=False,
        parent=None,
    )

    result = apply_groups(state, env)

    assert result is not None
    assert result["membership"] == "pending"
    group = state["roles"]["groups_by_id"]["g:private"]
    assert "members" not in group or "@alice" not in group.get("members", {})
    assert group["membership_requests"]["@alice"]["requested_at_nonce"] == 8
