from __future__ import annotations

import pytest

from weall.runtime.apply import content as content_apply_module
from weall.runtime.apply.content import apply_content, repair_pending_content_escalations
from weall.runtime.apply.dispute import (
    DisputeApplyError,
    apply_dispute,
    repair_unassigned_dispute_panels,
)
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.ballot_policy import CONTROLLED_TESTNET_BALLOT_PROFILE
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="",
        system=system,
        parent=parent,
    )


def _strict_state() -> dict:
    return {
        "height": 100,
        "chain_id": "weall-controlled-m3",
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
        },
        "ballot_profile": {
            "profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE,
            "active": True,
        },
        "accounts": {
            "@alice": {"poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"poh_tier": 2, "banned": False, "locked": False},
            "@carol": {"poh_tier": 2, "banned": False, "locked": False},
            "@validator": {"poh_tier": 1, "banned": False, "locked": False},
        },
        "roles": {
            "validators": {"active_set": ["@validator"], "by_id": {"@validator": {"active": True}}},
            "groups_by_id": {},
            "jurors": {"active_set": [], "by_id": {}},
        },
        "gov_proposals_by_id": {},
        "system_queue": [],
    }


def _create_protocol_proposal(state: dict, proposal_id: str = "m3-final-ballot") -> dict:
    result = apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": proposal_id,
                "title": "M3 immutable ballot",
                "rules": {
                    "start_stage": "voting",
                    "electorate_scope": "protocol_tier2",
                    "voting_period_blocks": 10,
                },
            },
        ),
    )
    assert result and result["applied"] is True
    return state["gov_proposals_by_id"][proposal_id]


def test_strict_governance_enforces_snapshot_first_ballot_finality_and_no_revoke() -> None:
    state = _strict_state()
    proposal = _create_protocol_proposal(state)
    assert proposal["eligible_voter_ids"] == ["@alice", "@bob", "@carol"]

    state["accounts"]["@dave"] = {"poh_tier": 2, "banned": False, "locked": False}
    with pytest.raises(ApplyError) as outside:
        apply_governance(
            state,
            _env(
                "GOV_VOTE_CAST", "@dave", 1, {"proposal_id": proposal["proposal_id"], "vote": "yes"}
            ),
        )
    assert outside.value.reason == "governance_vote_requires_active_round_member"

    apply_governance(
        state,
        _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": proposal["proposal_id"], "vote": "yes"}),
    )
    with pytest.raises(ApplyError) as duplicate:
        apply_governance(
            state,
            _env(
                "GOV_VOTE_CAST", "@alice", 3, {"proposal_id": proposal["proposal_id"], "vote": "no"}
            ),
        )
    assert duplicate.value.reason == "ballot_already_final"

    with pytest.raises(ApplyError) as revoke:
        apply_governance(
            state,
            _env("GOV_VOTE_REVOKE", "@alice", 4, {"proposal_id": proposal["proposal_id"]}),
        )
    assert revoke.value.reason == "ballot_revocation_forbidden"
    assert proposal["votes"] == {}
    assert proposal["vote_counts"] == {"yes": 1}
    assert len(proposal["ballot_nullifiers"]) == 1
    assert "@alice" not in str(proposal["vote_counts"])


def test_strict_no_action_governance_uses_system_finalization_and_receipts() -> None:
    state = _strict_state()
    proposal_id = "m3-strict-no-action-finalization"

    result = apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": proposal_id,
                "title": "M3 strict no-action finalization",
                "rules": {
                    "start_stage": "voting",
                    "electorate_scope": "protocol_tier2",
                    "quorum_bps": 5000,
                    "voting_period_blocks": 20,
                },
                "actions": [],
            },
        ),
    )
    assert result and result["applied"] is True

    proposal = state["gov_proposals_by_id"][proposal_id]
    assert proposal["required_votes"] == 2
    assert proposal["electorate_round"] == 1

    apply_governance(
        state,
        _env(
            "GOV_VOTE_CAST",
            "@alice",
            2,
            {"proposal_id": proposal_id, "vote": "yes"},
        ),
    )
    apply_governance(
        state,
        _env(
            "GOV_VOTE_CAST",
            "@bob",
            1,
            {"proposal_id": proposal_id, "vote": "yes"},
        ),
    )

    # Strict live governance must not finalize inside the user ballot apply.
    assert proposal["stage"] == "voting"
    assert proposal["vote_counts"] == {"yes": 2}
    assert proposal["votes"] == {}
    assert len(proposal["ballot_nullifiers"]) == 2

    queue = state["system_queue"]
    queued_types = [
        item.get("tx_type")
        for item in queue
        if isinstance(item, dict) and (item.get("payload") or {}).get("proposal_id") == proposal_id
    ]
    assert queued_types[:4] == [
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    ]

    for index, tx_type in enumerate(
        (
            "GOV_VOTING_CLOSE",
            "GOV_TALLY_PUBLISH",
            "GOV_EXECUTE",
            "GOV_PROPOSAL_FINALIZE",
        ),
        start=1,
    ):
        item = next(
            row
            for row in state["system_queue"]
            if isinstance(row, dict)
            and row.get("tx_type") == tx_type
            and (row.get("payload") or {}).get("proposal_id") == proposal_id
        )
        apply_governance(
            state,
            _env(
                tx_type,
                "SYSTEM",
                index,
                dict(item["payload"]),
                system=True,
                parent=str(item.get("parent") or "gov:test"),
            ),
        )

    assert proposal["stage"] == "finalized"
    assert proposal["closed_at_height"] > 0
    assert proposal["tallied_at_height"] > 0
    assert proposal["executed_at_height"] > 0
    assert proposal["finalized_at_height"] > 0
    assert proposal["result"]["passed"] is True
    assert proposal["result"]["quorum_met"] is True
    assert proposal["result"]["yes"] == 2

    current_round = proposal["electorate_rounds"][-1]
    assert current_round["status"] == "closed"
    assert current_round["ballot_count"] == 2
    assert current_round["close_reason"] == "quorum_reached"

    receipt_types = {
        item.get("tx_type")
        for item in state["system_queue"]
        if isinstance(item, dict) and (item.get("payload") or {}).get("proposal_id") == proposal_id
    }
    assert "GOV_EXECUTION_RECEIPT" in receipt_types
    assert "GOV_PROPOSAL_RECEIPT" in receipt_types


def test_strict_governance_fails_closed_without_active_ballot_profile() -> None:
    state = _strict_state()
    state["ballot_profile"] = {"profile_id": "UNASSIGNED_LAUNCH_GATED", "active": False}
    proposal = _create_protocol_proposal(state, "m3-launch-gate")
    with pytest.raises(ApplyError) as exc:
        apply_governance(
            state,
            _env(
                "GOV_VOTE_CAST",
                "@alice",
                2,
                {"proposal_id": proposal["proposal_id"], "vote": "yes"},
            ),
        )
    assert exc.value.reason == "BALLOT_PROFILE_INACTIVE"


def test_group_scope_snapshots_only_active_tier2_members() -> None:
    state = _strict_state()
    state["roles"]["groups_by_id"]["g:commons"] = {
        "group_id": "g:commons",
        "members": {
            "@alice": {"status": "active"},
            "@bob": {"status": "active"},
            "@validator": {"status": "active"},
            "@carol": {"status": "removed"},
        },
    }
    result = apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            5,
            {
                "proposal_id": "m3-group-vote",
                "title": "Group decision",
                "group_id": "g:commons",
                "rules": {"start_stage": "voting", "electorate_scope": "group_members"},
            },
        ),
    )
    assert result and result["applied"] is True
    proposal = state["gov_proposals_by_id"]["m3-group-vote"]
    assert proposal["electorate_scope"] == "group_members"
    assert proposal["eligible_voter_ids"] == ["@alice", "@bob"]


def test_strict_group_ranked_ballots_are_anonymous_and_final() -> None:
    state = _strict_state()
    apply_groups(
        state,
        _env("GROUP_CREATE", "@alice", 1, {"group_id": "g:m3-election", "charter": "public"}),
    )
    group = state["roles"]["groups_by_id"]["g:m3-election"]
    group["members"] = {
        account: {"status": "active"} for account in ("@alice", "@bob", "@carol", "@dana", "@erin")
    }
    for account in ("@dana", "@erin"):
        state["accounts"][account] = {"poh_tier": 2, "banned": False, "locked": False}
    apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@alice",
            2,
            {
                "group_id": "g:m3-election",
                "election_id": "e:m3-election",
                "seats": 5,
                "candidates": ["@alice", "@bob", "@carol", "@dana", "@erin"],
                "start_height": 100,
                "end_height": 120,
            },
        ),
    )
    apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_BALLOT_CAST",
            "@bob",
            3,
            {"election_id": "e:m3-election", "ranking": ["@bob", "@alice", "@carol"]},
        ),
    )
    assert state["group_emissary_ballots"]["e:m3-election"] == {}
    box = state["group_emissary_ballot_boxes"]["e:m3-election"]
    assert len(box) == 1
    assert list(box.values())[0]["count"] == 1
    assert all(len(commitment) == 64 for commitment in box)
    assert all(set(record) == {"ranking", "count"} for record in box.values())
    assert len(state["group_emissary_ballot_nullifiers"]["e:m3-election"]) == 1

    with pytest.raises(GroupsApplyError) as duplicate:
        apply_groups(
            state,
            _env(
                "GROUP_EMISSARY_BALLOT_CAST",
                "@bob",
                4,
                {"election_id": "e:m3-election", "ranking": ["@alice", "@bob"]},
            ),
        )
    assert duplicate.value.reason == "ballot_already_final"


def _reviewer_role() -> dict:
    return {
        "active": True,
        "responsibilities": {
            "reviewer": {
                "dispute_review": {"opted_in": True, "active": True},
                "content_review": {"opted_in": True, "active": True},
            }
        },
    }


def _strict_dispute_state(reviewer_count: int = 24) -> dict:
    state = _strict_state()
    state["accounts"]["@owner"] = {"poh_tier": 2, "banned": False, "locked": False}
    state["accounts"]["@reporter"] = {"poh_tier": 2, "banned": False, "locked": False}
    by_id = state["roles"]["jurors"]["by_id"]
    for index in range(reviewer_count):
        account = f"@reviewer-{index:02d}"
        state["accounts"][account] = {"poh_tier": 2, "banned": False, "locked": False}
        by_id[account] = _reviewer_role()
    state["roles"]["jurors"]["active_set"] = sorted(by_id)
    state["content"] = {
        "posts": {
            "post:@owner:1": {
                "post_id": "post:@owner:1",
                "author": "@owner",
                "body": "reported",
                "visibility": "public",
                "deleted": False,
            }
        },
        "comments": {},
        "reactions": {},
        "flags": {},
        "moderation": {"receipts": [], "targets": {}},
    }
    state["disputes_by_id"] = {}
    return state


def test_dispute_panel_has_constitutional_size_substitutes_and_fresh_appeal_panel() -> None:
    state = _strict_dispute_state()
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d:m3-panel",
                "target_type": "content",
                "target_id": "post:@owner:1",
                "reported_by": "@reporter",
                "severity": "low",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d:m3-panel"]
    original = set(dispute["assigned_jurors"])
    original_subs = set(dispute["substitute_juror_ids"])
    assert len(original) == 7
    assert len(original_subs) == 2
    assert "@owner" not in original
    assert "@reporter" not in original

    dispute["stage"] = "appeal_window"
    dispute["appeal_allowed_accounts"] = ["@owner"]
    dispute["appeal_deadline_height"] = 150
    apply_dispute(
        state,
        _env("DISPUTE_APPEAL", "@owner", 2, {"dispute_id": "d:m3-panel", "reason": "incorrect"}),
    )
    appeal = set(dispute["appeal_panel_juror_ids"])
    assert len(appeal) == 7
    assert appeal.isdisjoint(original | original_subs)
    assert dispute["stage"] == "appeal_review"


def test_strict_dispute_ballot_state_is_aggregate_only() -> None:
    state = _strict_dispute_state()
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d:m3-aggregate",
                "target_type": "content",
                "target_id": "post:@owner:1",
                "reported_by": "@reporter",
                "severity": "low",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d:m3-aggregate"]
    juror = dispute["assigned_jurors"][0]
    apply_dispute(
        state,
        _env("DISPUTE_JUROR_ACCEPT", juror, 2, {"dispute_id": "d:m3-aggregate"}),
    )
    apply_dispute(
        state,
        _env(
            "DISPUTE_VOTE_SUBMIT",
            juror,
            3,
            {
                "dispute_id": "d:m3-aggregate",
                "vote": "yes",
                "resolution": {"summary": "remove"},
            },
        ),
    )
    assert dispute["votes"] == {}
    assert dispute["vote_counts"] == {"yes": 1}
    assert dispute["voted_juror_ids"] == [juror]
    assert len(dispute["ballot_nullifiers"]) == 1
    assert all(juror not in str(item) for item in dispute["resolution_options"].values())

    with pytest.raises(DisputeApplyError) as duplicate:
        apply_dispute(
            state,
            _env(
                "DISPUTE_VOTE_SUBMIT",
                juror,
                4,
                {"dispute_id": "d:m3-aggregate", "vote": "no"},
            ),
        )
    assert duplicate.value.reason == "dispute_ballot_already_final"


def test_strict_appeal_ballot_state_is_aggregate_only_and_final() -> None:
    state = _strict_dispute_state()
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d:m3-appeal-aggregate",
                "target_type": "content",
                "target_id": "post:@owner:1",
                "reported_by": "@reporter",
                "severity": "low",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d:m3-appeal-aggregate"]
    dispute["stage"] = "appeal_window"
    dispute["appeal_allowed_accounts"] = ["@owner"]
    dispute["appeal_deadline_height"] = 150
    apply_dispute(
        state,
        _env(
            "DISPUTE_APPEAL",
            "@owner",
            2,
            {"dispute_id": "d:m3-appeal-aggregate", "reason": "incorrect"},
        ),
    )
    juror = dispute["appeal_panel_juror_ids"][0]
    apply_dispute(
        state,
        _env(
            "DISPUTE_JUROR_ACCEPT",
            juror,
            3,
            {"dispute_id": "d:m3-appeal-aggregate"},
        ),
    )
    apply_dispute(
        state,
        _env(
            "DISPUTE_VOTE_SUBMIT",
            juror,
            4,
            {
                "dispute_id": "d:m3-appeal-aggregate",
                "appeal_decision": "reverse",
                "appeal_resolution": {"decision": "reverse", "summary": "reverse result"},
            },
        ),
    )
    assert dispute["appeal_panel_votes"] == {}
    assert dispute["appeal_vote_counts"] == {"reverse": 1}
    assert dispute["appeal_voted_juror_ids"] == [juror]
    assert len(dispute["appeal_ballot_nullifiers"]) == 1
    assert all(juror not in str(item) for item in dispute["appeal_resolution_options"].values())

    with pytest.raises(DisputeApplyError) as duplicate:
        apply_dispute(
            state,
            _env(
                "DISPUTE_VOTE_SUBMIT",
                juror,
                5,
                {"dispute_id": "d:m3-appeal-aggregate", "appeal_decision": "uphold"},
            ),
        )
    assert duplicate.value.reason == "dispute_ballot_already_final"


def test_strict_appeal_quorum_queues_deterministic_final_receipt() -> None:
    state = _strict_dispute_state()
    state["meta"] = {
        "constitutional_clock": {
            "enabled": True,
            "target_block_interval_ms": 20_000,
            "empty_blocks_enabled": True,
        }
    }
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d:m3-appeal-final",
                "target_type": "content",
                "target_id": "post:@owner:1",
                "reported_by": "@reporter",
                "severity": "low",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d:m3-appeal-final"]
    dispute["resolution"] = {
        "outcome": "report_not_upheld",
        "summary": "content remains public",
        "actions": [],
    }
    dispute["resolved"] = True
    dispute["stage"] = "appeal_window"
    dispute["appeal_allowed_accounts"] = ["@owner"]
    dispute["appeal_deadline_height"] = 150

    apply_dispute(
        state,
        _env(
            "DISPUTE_APPEAL",
            "@owner",
            2,
            {"dispute_id": "d:m3-appeal-final", "reason": "review"},
        ),
    )

    panel = list(dispute["appeal_panel_juror_ids"])
    required = int(dispute["required_votes"])
    assert len(panel) == 7
    assert required == 5

    for index, juror in enumerate(panel, start=1):
        apply_dispute(
            state,
            _env(
                "DISPUTE_JUROR_ACCEPT",
                juror,
                10 + index,
                {"dispute_id": "d:m3-appeal-final"},
            ),
        )

    for index, juror in enumerate(panel[:required], start=1):
        result = apply_dispute(
            state,
            _env(
                "DISPUTE_VOTE_SUBMIT",
                juror,
                30 + index,
                {
                    "dispute_id": "d:m3-appeal-final",
                    "appeal_decision": "uphold",
                    "appeal_resolution": {
                        "decision": "uphold",
                        "summary": "appeal panel affirms the original result",
                        "actions": [],
                    },
                },
            ),
        )
        assert result["appeal_panel_result"]["reached"] is (index == required)

    assert dispute["stage"] == "appeal_resolved"
    assert dispute["appeal_panel_result"]["decision"] == "uphold"
    assert dispute["appeal_vote_counts"] == {"uphold": 5}
    assert len(dispute["appeal_voted_juror_ids"]) == 5
    assert len(dispute["appeal_ballot_nullifiers"]) == 5
    assert dispute["appeal_panel_votes"] == {}

    queued = tick_dispute_lifecycle(state, next_height=101)
    assert queued == 1
    assert dispute["stage"] == "finalizing"

    receipts = [
        item
        for item in state.get("system_queue", [])
        if item.get("tx_type") == "DISPUTE_FINAL_RECEIPT"
    ]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["due_height"] == 101
    assert receipt["phase"] == "pre"
    assert receipt["payload"]["dispute_id"] == "d:m3-appeal-final"
    assert receipt["payload"]["appeal_resolution"]["decision"] == "uphold"

    # The once-bound scheduler is idempotent after the case enters finalizing.
    assert tick_dispute_lifecycle(state, next_height=101) == 0

    final = apply_dispute(
        state,
        _env(
            "DISPUTE_FINAL_RECEIPT",
            "SYSTEM",
            99,
            dict(receipt["payload"]),
            system=True,
            parent=receipt["parent"],
        ),
    )
    assert final["appeal_finalization"]["decision"] == "uphold"
    assert dispute["stage"] == "finalized"
    accountability = dispute["juror_accountability"]
    assert set(accountability["jurors"]) == set(panel[required:])
    assert not set(accountability["jurors"]).intersection(panel[:required])
    post = state["content"]["posts"]["post:@owner:1"]
    assert post["visibility"] == "public"
    assert post["deleted"] is False


def test_unassigned_dispute_panel_repairs_only_when_full_panel_and_substitutes_exist() -> None:
    state = _strict_dispute_state(reviewer_count=0)
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d:m3-repair-panel",
                "target_type": "content",
                "target_id": "post:@owner:1",
                "reported_by": "@reporter",
                "severity": "low",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d:m3-repair-panel"]
    assert dispute["stage"] == "unassigned"
    assert repair_unassigned_dispute_panels(state, next_height=101) == 0

    by_id = state["roles"]["jurors"]["by_id"]
    for index in range(9):
        account = f"@late-reviewer-{index:02d}"
        state["accounts"][account] = {"poh_tier": 2, "banned": False, "locked": False}
        by_id[account] = _reviewer_role()
    state["roles"]["jurors"]["active_set"] = sorted(by_id)

    assert repair_unassigned_dispute_panels(state, next_height=102) == 1
    assert dispute["stage"] == "juror_review"
    assert len(dispute["assigned_jurors"]) == 7
    assert len(dispute["substitute_juror_ids"]) == 2
    assert all(
        record["assignment_source"] == "deterministic_panel_repair"
        for record in dispute["jurors"].values()
    )


def test_content_flag_queue_failure_creates_repairable_canonical_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _strict_state()
    state["accounts"]["@reporter"] = {"poh_tier": 1, "banned": False, "locked": False}
    state["content"] = {
        "posts": {},
        "comments": {},
        "reactions": {},
        "flags": {},
        "moderation": {"receipts": [], "targets": {}},
    }

    real_enqueue = content_apply_module.enqueue_system_tx

    def fail_enqueue(*args, **kwargs):
        raise RuntimeError("queue unavailable")

    monkeypatch.setattr(content_apply_module, "enqueue_system_tx", fail_enqueue)
    result = apply_content(
        state,
        _env(
            "CONTENT_FLAG",
            "@reporter",
            1,
            {"target_id": "post:@owner:1", "flag_id": "flag:m3", "reason": "policy"},
        ),
    )
    assert result and result["escalation_status"] == "pending_repair"
    pending = state["content"]["pending_escalations"]["flag:m3"]
    assert pending["status"] == "pending"

    monkeypatch.setattr(content_apply_module, "enqueue_system_tx", real_enqueue)
    assert repair_pending_content_escalations(state, next_height=101) == 1
    assert pending["status"] == "queued"
    assert any(
        item.get("tx_type") == "CONTENT_ESCALATE_TO_DISPUTE" for item in state["system_queue"]
    )


def test_public_content_mutations_append_immutable_history_chain() -> None:
    state = _strict_state()
    apply_content(
        state,
        _env("CONTENT_POST_CREATE", "@alice", 1, {"post_id": "post:m3", "body": "v1"}),
    )
    apply_content(
        state,
        _env(
            "CONTENT_POST_EDIT",
            "@alice",
            2,
            {"post_id": "post:m3", "body": "v2", "reason": "clarity"},
        ),
    )
    apply_content(
        state,
        _env(
            "CONTENT_POST_DELETE",
            "@alice",
            3,
            {"post_id": "post:m3", "reason": "author withdrawal"},
        ),
    )

    chain = state["content"]["history"]["posts"]["post:m3"]
    assert [entry["action"] for entry in chain] == ["create", "edit", "delete"]
    assert chain[0]["previous_receipt_commitment"] == ""
    assert chain[1]["previous_receipt_commitment"] == chain[0]["receipt_commitment"]
    assert chain[2]["previous_receipt_commitment"] == chain[1]["receipt_commitment"]
    assert chain[0]["after"]["body"] == "v1"
    assert chain[1]["before"]["body"] == "v1"
    assert chain[1]["after"]["body"] == "v2"
    assert chain[2]["after"]["deleted"] is True


def _public_api_client(state: dict):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from weall.api.routes_public_parts.content import router as content_router
    from weall.api.routes_public_parts.gov import router as gov_router

    class StaticExecutor:
        def read_state(self):
            return state

    app = FastAPI()
    app.state.executor = StaticExecutor()
    app.include_router(content_router, prefix="/v1")
    app.include_router(gov_router, prefix="/v1")
    return TestClient(app, raise_server_exceptions=True)


def test_public_history_and_ballot_profile_routes_preserve_truth_boundaries() -> None:
    state = _strict_state()
    apply_content(
        state,
        _env("CONTENT_POST_CREATE", "@alice", 1, {"post_id": "post:m3-api", "body": "v1"}),
    )
    apply_content(
        state,
        _env("CONTENT_POST_EDIT", "@alice", 2, {"post_id": "post:m3-api", "body": "v2"}),
    )

    client = _public_api_client(state)
    profile = client.get("/v1/gov/ballot-profile")
    assert profile.status_code == 200
    assert profile.json()["ballot_profile"] == {
        "profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE,
        "active": True,
        "strict": True,
        "mode": "controlled-testnet",
        "reason": "active_controlled_testnet_profile",
    }

    history = client.get("/v1/content/post:m3-api/history?limit=1")
    assert history.status_code == 200
    body = history.json()
    assert body["append_only"] is True
    assert body["items"][0]["action"] == "edit"
    assert body["items"][0]["version"] == 2
    assert body["next_before_version"] == 2
    assert len(body["latest_receipt_commitment"]) == 64
