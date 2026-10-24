"""Group identity is descriptive; canonical membership and group IDs gate civic writes."""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import apply_groups
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import GovProposalCreatePayload


def _env(tx_type: str, actor: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=actor, nonce=nonce, payload=payload, sig="")


def _state() -> dict:
    state = {
        "height": 10,
        "chain_id": "weall-controlled-testnet",
        "accounts": {
            actor: {"poh_tier": 2, "nonce": 0, "banned": False, "locked": False}
            for actor in ("@alice", "@bob", "@outsider")
        },
        "params": {"mode": "controlled-testnet"},
        "gov_config": {},
    }
    apply_groups(
        state,
        _env("GROUP_CREATE", "@alice", 1, {"group_id": "g:town-a", "charter": "Town discussion"}),
    )
    apply_groups(
        state,
        _env("GROUP_CREATE", "@bob", 1, {"group_id": "g:town-b", "charter": "Town discussion"}),
    )
    return state


def _group_proposal(proposal_id: str = "scope-a", group_id: str = "g:town-a") -> dict:
    return {
        "proposal_id": proposal_id,
        "group_id": group_id,
        "title": "Community proposal",
        "rules": {"start_stage": "draft", "electorate_scope": "group_members"},
    }


def test_scoped_create_schema_accepts_explicit_group_and_electorate_fields() -> None:
    obj = GovProposalCreatePayload.model_validate(_group_proposal())
    assert obj.group_id == "g:town-a"


def test_outsider_cannot_create_in_other_groups_scope() -> None:
    state = _state()
    for group_id in ("g:town-a", "g:town-b"):
        with pytest.raises(ApplyError) as error:
            apply_governance(
                state,
                _env("GOV_PROPOSAL_CREATE", "@outsider", 2, _group_proposal("attack", group_id)),
            )
        assert error.value.reason == "group_governance_participation_required"
    assert "attack" not in state.get("gov_proposals_by_id", {})


def test_member_can_create_in_own_scope_not_similarly_named_scope() -> None:
    state = _state()
    assert apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 2, _group_proposal()))[
        "applied"
    ]
    with pytest.raises(ApplyError) as error:
        apply_governance(
            state, _env("GOV_PROPOSAL_CREATE", "@alice", 3, _group_proposal("other", "g:town-b"))
        )
    assert error.value.reason == "group_governance_participation_required"


def test_invalid_group_and_conflicting_group_identifiers_rejected() -> None:
    state = _state()
    with pytest.raises(ApplyError) as missing:
        apply_governance(
            state,
            _env("GOV_PROPOSAL_CREATE", "@alice", 2, _group_proposal("no-group", "g:missing")),
        )
    assert missing.value.reason == "governance_group_not_found"
    payload = _group_proposal("conflict")
    payload["rules"]["group_id"] = "g:town-b"
    with pytest.raises(ApplyError) as conflict:
        apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 3, payload))
    assert conflict.value.reason == "proposal_group_scope_conflict"


def test_departed_or_suspended_member_cannot_create() -> None:
    state = _state()
    member = state["roles"]["groups_by_id"]["g:town-a"]["members"]
    member["@alice"]["status"] = "removed"
    # The creator initially holds independent signer and moderator roles.
    # Removing membership alone cannot revoke those separate authorities.
    # Clear both to isolate the membership participation check.
    group = state["roles"]["groups_by_id"]["g:town-a"]
    assert "@alice" in group["moderators"]
    group["signers"] = []
    group["moderators"] = []
    with pytest.raises(ApplyError) as removed:
        apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 2, _group_proposal()))
    assert removed.value.reason == "group_governance_participation_required"
    member["@alice"]["status"] = "active"
    state["accounts"]["@alice"]["suspended"] = True
    with pytest.raises(ApplyError) as suspended:
        apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 3, _group_proposal()))
    assert suspended.value.reason == "group_governance_participant_not_eligible"


def test_scoped_comments_use_group_permission_and_public_read_remains_unchanged() -> None:
    state = _state()
    apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 2, _group_proposal()))
    proposal = state["gov_proposals_by_id"]["scope-a"]
    before = deepcopy(proposal)
    comment = {"proposal_id": "scope-a", "body": "Outside comment"}
    with pytest.raises(ApplyError) as blocked:
        apply_governance(state, _env("GOV_PROPOSAL_COMMENT", "@outsider", 3, comment))
    assert blocked.value.reason == "group_governance_participation_required"
    assert proposal == before
    assert apply_governance(state, _env("GOV_PROPOSAL_COMMENT", "@alice", 4, comment))["applied"]
    assert len(proposal["comments"]) == 1


def test_group_can_explicitly_open_proposals_and_comments_to_public_tier2() -> None:
    state = _state()
    group = state["roles"]["groups_by_id"]["g:town-a"]
    group["permissions"]["post"] = "public"
    group["permissions"]["comment"] = "public"
    apply_governance(
        state, _env("GOV_PROPOSAL_CREATE", "@outsider", 2, _group_proposal("public-input"))
    )
    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_COMMENT",
            "@outsider",
            3,
            {"proposal_id": "public-input", "body": "A concern"},
        ),
    )
    assert len(state["gov_proposals_by_id"]["public-input"]["comments"]) == 1


def test_proposal_scope_cannot_change_when_author_edits_rules() -> None:
    state = _state()
    apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 2, _group_proposal()))
    before = deepcopy(state["gov_proposals_by_id"]["scope-a"])
    for rules in ({"group_id": "g:town-b"}, {"electorate_scope": "protocol_tier2"}):
        with pytest.raises(ApplyError) as failure:
            apply_governance(
                state,
                _env("GOV_PROPOSAL_EDIT", "@alice", 3, {"proposal_id": "scope-a", "rules": rules}),
            )
        assert failure.value.reason == "proposal_scope_immutable"
        assert state["gov_proposals_by_id"]["scope-a"] == before


def test_protocol_wide_proposals_remain_accessible_to_verified_users() -> None:
    state = _state()
    assert (
        apply_governance(
            state,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@outsider",
                3,
                {
                    "proposal_id": "protocol-discussion",
                    "rules": {"start_stage": "draft", "electorate_scope": "protocol_tier2"},
                },
            ),
        )["applied"]
        is True
    )


def test_revoked_group_roles_do_not_grant_governance_authorship() -> None:
    state = _state()
    group = state["roles"]["groups_by_id"]["g:town-a"]
    group["permissions"]["post"] = "moderators"
    group["signers"] = []
    group["moderators"] = []
    group["roles"] = {"moderators": {"@outsider": {"status": "revoked"}}}
    with pytest.raises(ApplyError) as revoked:
        apply_governance(
            state,
            _env("GOV_PROPOSAL_CREATE", "@outsider", 6, _group_proposal("revoked-author")),
        )
    assert revoked.value.reason == "group_governance_participation_required"

    group["roles"] = {"moderators": ["@outsider"]}
    assert (
        apply_governance(
            state, _env("GOV_PROPOSAL_CREATE", "@outsider", 7, _group_proposal("active-author"))
        )["applied"]
        is True
    )


def test_revoked_group_signer_record_is_not_admin_permission() -> None:
    state = _state()
    group = state["roles"]["groups_by_id"]["g:town-a"]
    group["permissions"]["post"] = "admins"
    group["signers"] = ["@outsider"]
    group["signer_statuses"] = {"@outsider": {"status": "revoked"}}
    with pytest.raises(ApplyError) as revoked:
        apply_governance(
            state, _env("GOV_PROPOSAL_CREATE", "@outsider", 8, _group_proposal("revoked-signer"))
        )
    assert revoked.value.reason == "group_governance_participation_required"
