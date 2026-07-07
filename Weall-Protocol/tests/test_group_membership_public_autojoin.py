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


def test_legacy_restricted_group_membership_request_autojoins_public_group() -> None:
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
    assert result["membership"] == "accepted"
    group = state["roles"]["groups_by_id"]["g:private"]
    assert group.get("visibility") in {None, "public"}
    assert group.get("read_visibility") in {None, "public"}
    assert group.get("meta", {}).get("visibility") == "public"
    assert group["members"]["@alice"]["role"] == "member"
