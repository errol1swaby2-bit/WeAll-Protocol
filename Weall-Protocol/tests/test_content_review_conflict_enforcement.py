from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


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


def _base_state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "@genesis": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@errol": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "validators": {"active_set": ["@genesis"]},
            "jurors": {
                "active_set": ["@reviewer"],
                "by_id": {"@reviewer": {"active": True, "enrolled": True}},
            },
        },
        "params": {
            "bootstrap_operator": "@genesis",
            "genesis_bootstrap_account": "@genesis",
        },
        "system_queue": [],
        "content": {
            "posts": {
                "post:@genesis:1": {
                    "post_id": "post:@genesis:1",
                    "id": "post:@genesis:1",
                    "author": "@genesis",
                    "body": "flag me",
                    "created_nonce": 1,
                    "visibility": "public",
                    "locked": False,
                    "labels": [],
                    "deleted": False,
                }
            },
            "comments": {},
            "reactions": {},
            "flags": {},
            "moderation": {"receipts": [], "targets": {}},
        },
    }



def test_flag_escalation_is_admitted_by_strict_block_schema() -> None:
    """A real CONTENT_FLAG child must pass block-context admission, not only apply_tx."""
    idx = _load_index()
    state = _base_state()
    apply_tx(
        state,
        _env(
            "CONTENT_FLAG",
            "@errol",
            1,
            {"target_id": "post:@genesis:1", "reason": "report"},
        ),
    )
    emitted = system_tx_emitter(state, canon=idx, next_height=1, phase="post")
    assert len(emitted) == 1
    escalation = emitted[0]
    assert escalation.tx_type == "CONTENT_ESCALATE_TO_DISPUTE"
    assert escalation.payload["flag_id"] == "flag:@errol:1"
    assert escalation.payload["flagged_by"] == "@errol"
    verdict = admit_tx(escalation, state, canon=idx, context="block")
    assert verdict.ok, (verdict.code, verdict.reason, verdict.details)
    apply_tx(state, escalation)
    report = next(iter(state["disputes_by_id"].values()))
    assert report["flagged_by"] == "@errol"
    assert report["target_id"] == "post:@genesis:1"


def test_flag_escalation_strict_block_schema_rejects_unknown_fields() -> None:
    idx = _load_index()
    state = _base_state()
    apply_tx(
        state,
        _env(
            "CONTENT_FLAG",
            "@errol",
            1,
            {"target_id": "post:@genesis:1", "reason": "report"},
        ),
    )
    escalation = system_tx_emitter(state, canon=idx, next_height=1, phase="post")[0]
    tampered = _env(
        escalation.tx_type,
        escalation.signer,
        escalation.nonce,
        {**escalation.payload, "invented_authority": "bypass"},
        system=True,
        parent=escalation.parent,
    )
    verdict = admit_tx(tampered, state, canon=idx, context="block")
    assert not verdict.ok
    assert verdict.code == "invalid_payload"
    assert verdict.reason == "schema_validation_failed"


def test_content_flag_excludes_original_poster_from_assignment_and_uses_unconflicted_reviewer() -> (
    None
):
    idx = _load_index()
    st = _base_state()

    apply_tx(
        st, _env("CONTENT_FLAG", "@errol", 1, {"target_id": "post:@genesis:1", "reason": "policy"})
    )
    emitted = system_tx_emitter(st, canon=idx, next_height=1, phase="post")
    assert [env.tx_type for env in emitted] == ["CONTENT_ESCALATE_TO_DISPUTE"]
    for env in emitted:
        apply_tx(st, env)

    dispute = next(iter(st["disputes_by_id"].values()))
    assert dispute["target_owner"] == "@genesis"
    assert dispute["flagged_by"] == "@errol"
    assert "@genesis" not in dispute.get("assigned_jurors", [])
    assert dispute.get("conflict_policy") == "target_owner_excluded_from_content_review"
    assert dispute["assigned_jurors"] == ["@reviewer"]


def test_later_system_content_escalation_uses_collision_safe_deterministic_id() -> None:
    idx = _load_index()

    def execute() -> tuple[str, dict]:
        state = _base_state()

        state["disputes_by_id"] = {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "stage": "finalized",
                "target_type": "content",
                "target_id": "post:historical",
                "resolved": True,
            }
        }

        apply_tx(
            state,
            _env(
                "CONTENT_FLAG",
                "@errol",
                1,
                {
                    "flag_id": "flag:m3:negative",
                    "target_id": "post:@genesis:1",
                    "reason": "policy",
                },
            ),
        )

        emitted = system_tx_emitter(
            state,
            canon=idx,
            next_height=1,
            phase="post",
        )

        assert [envelope.tx_type for envelope in emitted] == ["CONTENT_ESCALATE_TO_DISPUTE"]

        result = apply_tx(
            state,
            emitted[0],
        )

        dispute_id = str(result.get("dispute_id") or "")

        assert dispute_id.startswith("dispute:content:")

        assert dispute_id != ("dispute:SYSTEM:0")

        assert "dispute:SYSTEM:0" in state["disputes_by_id"]

        assert dispute_id in state["disputes_by_id"]

        dispute = state["disputes_by_id"][dispute_id]

        assert dispute["target_id"] == ("post:@genesis:1")

        target = state["content"]["moderation"]["targets"]["post:@genesis:1"]

        assert target["dispute_id"] == (dispute_id)

        return dispute_id, state

    first_id, first_state = execute()
    second_id, second_state = execute()

    assert first_id == second_id

    assert (
        first_state["disputes_by_id"][first_id]["panel_commitment"]
        == second_state["disputes_by_id"][second_id]["panel_commitment"]
    )


def test_original_poster_cannot_be_assigned_or_vote_on_own_content_report() -> None:
    st = _base_state()
    apply_tx(
        st,
        _env(
            "DISPUTE_OPEN",
            "@errol",
            1,
            {
                "dispute_id": "d-own",
                "target_type": "content",
                "target_id": "post:@genesis:1",
                "reason": "policy",
            },
        ),
    )

    with pytest.raises(Exception) as assign_error:
        apply_tx(
            st,
            _env(
                "DISPUTE_JUROR_ASSIGN",
                "SYSTEM",
                2,
                {"dispute_id": "d-own", "juror": "@genesis"},
                system=True,
                parent="test",
            ),
        )
    assert "juror_conflict_target_owner" in str(assign_error.value)

    dispute = st["disputes_by_id"]["d-own"]
    dispute["jurors"]["@genesis"] = {"status": "accepted", "attendance": {"present": True}}
    dispute["assigned_jurors"] = ["@genesis"]
    dispute["eligible_juror_ids"] = ["@genesis"]
    dispute["required_votes"] = 1

    with pytest.raises(Exception) as vote_error:
        apply_tx(
            st, _env("DISPUTE_VOTE_SUBMIT", "@genesis", 3, {"dispute_id": "d-own", "vote": "yes"})
        )
    assert "juror_conflict_target_owner" in str(vote_error.value)


def test_unconflicted_remove_vote_applies_content_removal() -> None:
    st = _base_state()
    apply_tx(
        st,
        _env(
            "DISPUTE_OPEN",
            "@errol",
            1,
            {
                "dispute_id": "d-remove",
                "target_type": "content",
                "target_id": "post:@genesis:1",
                "reason": "policy",
            },
        ),
    )
    apply_tx(
        st,
        _env(
            "DISPUTE_JUROR_ASSIGN",
            "SYSTEM",
            2,
            {"dispute_id": "d-remove", "juror": "@reviewer"},
            system=True,
            parent="test",
        ),
    )
    apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "@reviewer", 3, {"dispute_id": "d-remove"}))
    apply_tx(
        st,
        _env(
            "DISPUTE_VOTE_SUBMIT",
            "@reviewer",
            4,
            {
                "dispute_id": "d-remove",
                "vote": "yes",
                "resolution": {"outcome": "report_upheld", "actions": []},
            },
        ),
    )

    dispute = st["disputes_by_id"]["d-remove"]
    post = st["content"]["posts"]["post:@genesis:1"]
    assert dispute["resolution"]["outcome"] == "report_upheld"
    assert post["visibility"] == "hidden"
    assert post.get("deleted") is not True
    assert post["locked"] is True


def test_flag_escalation_with_only_reporter_and_author_is_visible_unassigned() -> None:
    idx = _load_index()
    state = _base_state()
    # The reporter and author are distinct parties, not impartial jurors.
    # Removing the independent reviewer must not erase the canonical report.
    state["roles"]["jurors"]["active_set"] = []
    state["roles"]["jurors"]["by_id"] = {}
    state["accounts"].pop("@reviewer")
    flagged = apply_tx(
        state,
        _env(
            "CONTENT_FLAG",
            "@errol",
            1,
            {"target_id": "post:@genesis:1", "reason": "two-party-report"},
        ),
    )
    assert flagged["escalation_status"] == "queued"
    emitted = system_tx_emitter(state, canon=idx, next_height=1, phase="post")
    assert [envelope.tx_type for envelope in emitted] == ["CONTENT_ESCALATE_TO_DISPUTE"]
    for envelope in emitted:
        apply_tx(state, envelope)
    assert len(state["disputes_by_id"]) == 1
    dispute = next(iter(state["disputes_by_id"].values()))
    assert dispute["target_id"] == "post:@genesis:1"
    assert dispute["reported_by"] == "@errol"
    assert dispute["opened_by"] == "SYSTEM"
    assert dispute["stage"] == "unassigned"
    assert dispute["assigned_jurors"] == []
    assert dispute["assignment_blocked_reason"]
    target = state["content"]["moderation"]["targets"]["post:@genesis:1"]
    assert target["dispute_id"] == dispute["id"]
