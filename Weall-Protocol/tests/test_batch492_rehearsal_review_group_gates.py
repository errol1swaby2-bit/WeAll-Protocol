from __future__ import annotations

from weall.runtime.gate_expr import eval_gate
from weall.runtime.apply.content import _require_group_post_authority


def _tier2_account(account: str) -> dict:
    return {
        "poh_tier": 2,
        "status": "active",
        "banned": False,
        "locked": False,
    }


def test_case_assigned_tier2_reviewer_satisfies_dispute_juror_gate_batch492() -> None:
    ledger = {
        "chain_id": "weall-controlled-devnet",
        "accounts": {
            "@observer-user": _tier2_account("@observer-user"),
            "@devnet-genesis": _tier2_account("@devnet-genesis"),
        },
        "roles": {},
        "disputes_by_id": {
            "dispute:1": {
                "dispute_id": "dispute:1",
                "target_type": "content",
                "target_id": "post:1",
                "target_owner": "@devnet-genesis",
                "assigned_jurors": ["@observer-user"],
                "eligible_juror_ids": ["@observer-user"],
                "jurors": {"@observer-user": {"status": "assigned"}},
            }
        },
    }

    ok, meta = eval_gate(
        "Juror",
        signer="@observer-user",
        state=ledger,
        payload={"dispute_id": "dispute:1"},
        tx_type="DISPUTE_JUROR_ACCEPT",
    )

    assert ok is True, meta


def test_target_owner_does_not_satisfy_dispute_juror_gate_even_if_misassigned_batch492() -> None:
    ledger = {
        "accounts": {
            "@observer-user": _tier2_account("@observer-user"),
            "@devnet-genesis": _tier2_account("@devnet-genesis"),
        },
        "roles": {},
        "disputes_by_id": {
            "dispute:1": {
                "dispute_id": "dispute:1",
                "target_type": "content",
                "target_id": "post:1",
                "target_owner": "@devnet-genesis",
                "assigned_jurors": ["@devnet-genesis"],
                "eligible_juror_ids": ["@devnet-genesis"],
                "jurors": {"@devnet-genesis": {"status": "assigned"}},
            }
        },
    }

    ok, _meta = eval_gate(
        "Juror",
        signer="@devnet-genesis",
        state=ledger,
        payload={"dispute_id": "dispute:1"},
        tx_type="DISPUTE_JUROR_ACCEPT",
    )

    assert ok is False


def test_group_self_leave_satisfies_group_moderator_gate_only_for_self_removal_batch492() -> None:
    ledger = {
        "accounts": {
            "@observer-user": _tier2_account("@observer-user"),
            "@other": _tier2_account("@other"),
        },
        "roles": {
            "groups_by_id": {
                "g:test": {
                    "group_id": "g:test",
                    "members": {
                        "@observer-user": {"joined_at_nonce": 1},
                        "@other": {"joined_at_nonce": 1},
                    },
                    "moderators": [],
                }
            }
        },
    }

    ok_self, meta_self = eval_gate(
        "GroupModerator",
        signer="@observer-user",
        state=ledger,
        payload={"group_id": "g:test", "account": "@observer-user"},
        tx_type="GROUP_MEMBERSHIP_REMOVE",
    )
    ok_other, _meta_other = eval_gate(
        "GroupModerator",
        signer="@observer-user",
        state=ledger,
        payload={"group_id": "g:test", "account": "@other"},
        tx_type="GROUP_MEMBERSHIP_REMOVE",
    )
    ok_decide, _meta_decide = eval_gate(
        "GroupModerator",
        signer="@observer-user",
        state=ledger,
        payload={"group_id": "g:test", "account": "@other"},
        tx_type="GROUP_MEMBERSHIP_DECIDE",
    )

    assert ok_self is True, meta_self
    assert ok_other is False
    assert ok_decide is False


def test_group_post_authority_matches_account_alias_variants_batch492() -> None:
    state = {
        "accounts": {
            "observer-user": _tier2_account("observer-user"),
        },
        "roles": {
            "groups_by_id": {
                "g:test": {
                    "group_id": "g:test",
                    "members": {
                        "@observer-user": {"joined_at_nonce": 1},
                    },
                    "signers": [],
                    "roles": {},
                }
            }
        },
    }

    group_id, tag_targets = _require_group_post_authority(
        state,
        signer="observer-user",
        payload={"visibility": "group", "group_id": "g:test"},
    )

    assert group_id == "g:test"
    assert tag_targets == []


from weall.runtime.apply.content import _apply_content_escalate_to_dispute
from weall.runtime.tx_admission import TxEnvelope


def test_content_escalation_uses_target_scoped_dispute_ids_for_system_nonce_zero_batch492() -> None:
    state = {
        "height": 1,
        "accounts": {
            "@author1": _tier2_account("@author1"),
            "@author2": _tier2_account("@author2"),
            "@reporter": _tier2_account("@reporter"),
        },
        "content": {
            "posts": {
                "post:one": {"post_id": "post:one", "author": "@author1"},
                "post:two": {"post_id": "post:two", "author": "@author2"},
            },
            "comments": {},
            "flags": {},
            "moderation": {"targets": {}},
        },
        "roles": {},
        "params": {},
    }

    first = _apply_content_escalate_to_dispute(
        state,
        TxEnvelope(
            tx_type="CONTENT_ESCALATE_TO_DISPUTE",
            signer="SYSTEM",
            nonce=0,
            payload={"target_type": "content", "target_id": "post:one", "flagged_by": "@reporter"},
            system=True,
            parent="CONTENT_FLAG:1",
        ),
    )
    second = _apply_content_escalate_to_dispute(
        state,
        TxEnvelope(
            tx_type="CONTENT_ESCALATE_TO_DISPUTE",
            signer="SYSTEM",
            nonce=0,
            payload={"target_type": "content", "target_id": "post:two", "flagged_by": "@reporter"},
            system=True,
            parent="CONTENT_FLAG:2",
        ),
    )

    assert first["dispute_id"] == "dispute:content:post:one"
    assert second["dispute_id"] == "dispute:content:post:two"
    assert sorted(state["disputes_by_id"].keys()) == [
        "dispute:content:post:one",
        "dispute:content:post:two",
    ]
