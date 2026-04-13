# tests/p0/test_p0_governance_pipeline.py
from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError

Json = dict[str, Any]


def clone_state(state: Json) -> Json:
    return copy.deepcopy(state)


def env(
    tx_type: str,
    payload: dict[str, Any] | None = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    e: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        e["parent"] = parent
    return e


def apply_ok(state: Json, envelope: Json) -> dict[str, Any]:
    out = apply_tx(state, envelope)
    assert isinstance(out, dict)
    applied = out.get("applied")
    assert applied is True or applied == envelope["tx_type"]
    return out


def apply_err(state: Json, envelope: Json) -> ApplyError:
    with pytest.raises(ApplyError) as ei:
        apply_tx(state, envelope)
    return ei.value


def _iter_dicts(obj: Any) -> Iterable[dict[str, Any]]:
    stack: list[Any] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            for v in cur.values():
                stack.append(v)
        elif isinstance(cur, list):
            for v in cur:
                stack.append(v)


def _find_proposal_container_and_obj(
    state: Json, proposal_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    for key in ("gov_proposals_by_id", "gov_proposals", "governance_proposals"):
        root = state.get(key)
        if isinstance(root, dict):
            pr = root.get(proposal_id)
            if isinstance(pr, dict):
                return root, pr

    for d in _iter_dicts(state):
        pr = d.get(proposal_id)
        if isinstance(pr, dict):
            if "stage" in pr or "creator" in pr or "proposal_id" in pr:
                return d, pr

    raise AssertionError(
        f"Could not locate proposal object for proposal_id={proposal_id!r} in state"
    )


def _get_proposal(state: Json, proposal_id: str) -> dict[str, Any]:
    _, pr = _find_proposal_container_and_obj(state, proposal_id)
    return pr


def _find_latest_stage_receipt(state: Json, proposal_id: str) -> dict[str, Any] | None:
    """
    Prefer the canonical receipt list if present.
    Avoid accidentally returning the proposal dict itself (it also has proposal_id + stage).
    """
    receipts = state.get("gov_stage_set_receipts")
    if isinstance(receipts, list):
        matches = [
            r for r in receipts if isinstance(r, dict) and r.get("proposal_id") == proposal_id
        ]
        return matches[-1] if matches else None

    # Fallback: scan nested dicts but only accept things that look like receipts
    # (have _height and/or _parent fields).
    candidates: list[dict[str, Any]] = []
    for d in _iter_dicts(state):
        if (
            d.get("proposal_id") == proposal_id
            and "stage" in d
            and ("_parent" in d or "_height" in d)
        ):
            candidates.append(d)
    return candidates[-1] if candidates else None


def _find_vote_store(pr: dict[str, Any], key_candidates: list[str]) -> dict[str, Any] | None:
    for k in key_candidates:
        v = pr.get(k)
        if isinstance(v, dict):
            return v
    for _, v in pr.items():
        if isinstance(v, dict):
            for _, inner in v.items():
                if isinstance(inner, dict) and ("vote" in inner or "choice" in inner):
                    return v
    return None


def _stage_set(proposal_id: str, stage: str, *, nonce: int, parent: str) -> Json:
    return env(
        "GOV_STAGE_SET",
        {"proposal_id": proposal_id, "stage": stage},
        signer="SYSTEM",
        nonce=nonce,
        system=True,
        parent=parent,
    )


def _vote_revoke(proposal_id: str, *, signer: str, nonce: int) -> Json:
    return env(
        "GOV_VOTE_REVOKE", {"proposal_id": proposal_id}, signer=signer, nonce=nonce, system=False
    )


def _proposal_edit(proposal_id: str, *, signer: str, nonce: int, title: str) -> Json:
    return env(
        "GOV_PROPOSAL_EDIT",
        {"proposal_id": proposal_id, "title": title},
        signer=signer,
        nonce=nonce,
        system=False,
    )


def _proposal_withdraw(proposal_id: str, *, signer: str, nonce: int) -> Json:
    return env(
        "GOV_PROPOSAL_WITHDRAW",
        {"proposal_id": proposal_id},
        signer=signer,
        nonce=nonce,
        system=False,
    )




def test_gov_proposal_create_sets_creator_and_default_stage(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-create"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))
    pr = _get_proposal(st, pid)

    assert pr.get("creator") == "alice"
    assert pr.get("proposal_id") in (None, pid) or pr.get("proposal_id") == pid
    assert pr.get("stage") in (
        "draft",
        "poll",
        "voting",
        "vote",
        "revision",
        "finalized",
        "withdrawn",
    )

    poll_votes = _find_vote_store(pr, ["poll_votes", "poll_votes_by_account"])
    votes = _find_vote_store(pr, ["votes", "votes_by_account"])
    assert poll_votes is not None
    assert votes is not None


def test_gov_proposal_create_respects_rules_start_stage(base_state) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-start-stage"

    apply_ok(
        st,
        env(
            "GOV_PROPOSAL_CREATE",
            {
                "proposal_id": pid,
                "rules": {"start_stage": "voting"},
                "title": "p0",
                "body": "p0",
                "kind": "generic",
            },
            signer="alice",
            nonce=1,
            system=False,
        ),
    )
    pr = _get_proposal(st, pid)
    assert pr.get("stage") in ("voting", "vote")


def test_gov_stage_set_updates_stage_and_writes_receipt(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-stage-set"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    apply_ok(st, _stage_set(pid, "poll", nonce=2, parent="txid:create"))
    pr = _get_proposal(st, pid)
    assert pr.get("stage") == "poll"

    r1 = _find_latest_stage_receipt(st, pid)
    assert isinstance(r1, dict)
    assert r1.get("proposal_id") == pid
    assert r1.get("stage") == "poll"
    assert str(r1.get("_parent") or r1.get("parent") or "") == "txid:create"

    apply_ok(st, _stage_set(pid, "voting", nonce=3, parent="txid:poll"))
    pr2 = _get_proposal(st, pid)
    assert pr2.get("stage") in ("voting", "vote")


def test_gov_vote_cast_rejected_when_not_voteable(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-vote-gated"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))
    err = apply_err(st, txf.gov_vote_cast("alice", pid, "yes", nonce=2))
    assert err.code == "forbidden"
    assert err.reason == "proposal_not_voteable"


def test_gov_vote_cast_poll_vs_vote_storage(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-vote-storage"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    apply_ok(st, _stage_set(pid, "poll", nonce=2, parent="txid:create"))
    apply_ok(st, txf.gov_vote_cast("alice", pid, "yes", nonce=3))
    pr = _get_proposal(st, pid)

    poll_votes = _find_vote_store(pr, ["poll_votes", "poll_votes_by_account"])
    votes = _find_vote_store(pr, ["votes", "votes_by_account"])
    assert poll_votes is not None and votes is not None

    assert "alice" in poll_votes
    inner = poll_votes["alice"]
    assert isinstance(inner, dict)
    assert str(inner.get("vote") or inner.get("choice") or "").lower() == "yes"

    apply_ok(st, _stage_set(pid, "voting", nonce=4, parent="txid:poll"))
    apply_ok(st, txf.gov_vote_cast("bob", pid, "no", nonce=1))
    pr2 = _get_proposal(st, pid)

    votes2 = _find_vote_store(pr2, ["votes", "votes_by_account"])
    assert votes2 is not None
    assert "bob" in votes2
    inner2 = votes2["bob"]
    assert isinstance(inner2, dict)
    assert str(inner2.get("vote") or inner2.get("choice") or "").lower() == "no"


def test_gov_vote_revoke_removes_vote_and_is_tolerated_post_close(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-vote-revoke"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))
    apply_ok(st, _stage_set(pid, "voting", nonce=2, parent="txid:create"))

    apply_ok(st, txf.gov_vote_cast("alice", pid, "yes", nonce=2))
    pr = _get_proposal(st, pid)
    votes = _find_vote_store(pr, ["votes", "votes_by_account"])
    assert votes is not None and "alice" in votes

    apply_ok(st, _vote_revoke(pid, signer="alice", nonce=3))
    pr2 = _get_proposal(st, pid)
    votes2 = _find_vote_store(pr2, ["votes", "votes_by_account"])
    assert votes2 is not None and "alice" not in votes2

    apply_ok(st, txf.gov_voting_close(pid, nonce=100))
    apply_ok(st, _vote_revoke(pid, signer="bob", nonce=2))


def test_gov_proposal_edit_only_creator_and_only_editable_stages(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-edit"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    err = apply_err(st, _proposal_edit(pid, signer="bob", nonce=1, title="nope"))
    assert err.code == "forbidden"
    assert err.reason == "only_creator_can_edit"

    apply_ok(st, _proposal_edit(pid, signer="alice", nonce=2, title="draft edit"))
    pr = _get_proposal(st, pid)
    assert pr.get("title") == "draft edit"

    apply_ok(st, _stage_set(pid, "poll", nonce=3, parent="txid:create"))
    err2 = apply_err(st, _proposal_edit(pid, signer="alice", nonce=3, title="should fail"))
    assert err2.code == "forbidden"
    assert err2.reason == "proposal_not_editable"

    apply_ok(st, _stage_set(pid, "revision", nonce=4, parent="txid:poll"))
    apply_ok(st, _proposal_edit(pid, signer="alice", nonce=4, title="revision edit"))
    pr2 = _get_proposal(st, pid)
    assert pr2.get("title") == "revision edit"


def test_gov_proposal_withdraw_only_creator_and_not_if_finalized(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-withdraw"

    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    err = apply_err(st, _proposal_withdraw(pid, signer="bob", nonce=1))
    assert err.code == "forbidden"
    assert err.reason == "only_creator_can_withdraw"

    apply_ok(st, _proposal_withdraw(pid, signer="alice", nonce=2))
    pr = _get_proposal(st, pid)
    assert pr.get("stage") == "withdrawn"

    st2 = clone_state(base_state)
    pid2 = "p0-gov-withdraw-finalized"
    apply_ok(st2, txf.gov_proposal_create("alice", pid2, nonce=1))
    apply_ok(st2, _stage_set(pid2, "finalized", nonce=2, parent="txid:create"))
    err2 = apply_err(st2, _proposal_withdraw(pid2, signer="alice", nonce=2))
    assert err2.code == "forbidden"
    assert err2.reason == "proposal_already_finalized"



def _tally_publish(
    proposal_id: str,
    *,
    nonce: int,
    passed: bool = True,
    signer: str = "SYSTEM",
) -> Json:
    return env(
        "GOV_TALLY_PUBLISH",
        {
            "proposal_id": proposal_id,
            "tally": {"yes": 1 if passed else 0, "no": 0 if passed else 1, "abstain": 0},
            "total_votes": 1,
            "quorum_required": 0,
            "quorum_met": True,
            "passed": passed,
        },
        signer=signer,
        nonce=nonce,
        system=(signer == "SYSTEM"),
        parent="txid:gov_block",
    )


def _gov_execute(
    proposal_id: str,
    *,
    nonce: int,
    signer: str = "SYSTEM",
) -> Json:
    return env(
        "GOV_EXECUTE",
        {"proposal_id": proposal_id},
        signer=signer,
        nonce=nonce,
        system=(signer == "SYSTEM"),
        parent="txid:gov_block",
    )


def _gov_finalize(
    proposal_id: str,
    *,
    nonce: int,
    signer: str = "SYSTEM",
) -> Json:
    return env(
        "GOV_PROPOSAL_FINALIZE",
        {"proposal_id": proposal_id},
        signer=signer,
        nonce=nonce,
        system=(signer == "SYSTEM"),
        parent="txid:gov_block",
    )


def test_gov_stage_set_rejects_backward_transition(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-invalid-transition"
    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))
    apply_ok(st, _stage_set(pid, "voting", nonce=2, parent="txid:create"))

    err = apply_err(st, _stage_set(pid, "poll", nonce=3, parent="txid:voting"))
    assert err.code == "forbidden"
    assert err.reason == "invalid_stage_transition"


def test_gov_tally_publish_requires_vote_close_like_stage(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-tally-stage"
    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    err = apply_err(st, _tally_publish(pid, nonce=2, passed=True))
    assert err.code == "forbidden"
    assert err.reason == "proposal_not_tallyable"

    apply_ok(st, _stage_set(pid, "poll", nonce=3, parent="txid:create"))
    apply_ok(st, _stage_set(pid, "revision", nonce=4, parent="txid:poll"))
    apply_ok(st, _stage_set(pid, "validation", nonce=5, parent="txid:revision"))
    apply_ok(st, _stage_set(pid, "voting", nonce=6, parent="txid:validation"))
    apply_ok(st, txf.gov_voting_close(pid, nonce=7))
    apply_ok(st, _tally_publish(pid, nonce=8, passed=True))
    pr = _get_proposal(st, pid)
    assert pr.get("stage") == "tallied"


def test_gov_execute_legacy_system_path_and_tallied_success_path(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-execute"
    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))

    # Current canon preserves a legacy SYSTEM execution path used by queued governance followups.
    apply_ok(st, _gov_execute(pid, nonce=2))
    pr = _get_proposal(st, pid)
    assert pr.get("stage") == "executed"

    st2 = clone_state(base_state)
    pid2 = "p0-gov-execute-pass"
    apply_ok(st2, txf.gov_proposal_create("alice", pid2, nonce=1))
    apply_ok(st2, _stage_set(pid2, "poll", nonce=2, parent="txid:create"))
    apply_ok(st2, _stage_set(pid2, "revision", nonce=3, parent="txid:poll"))
    apply_ok(st2, _stage_set(pid2, "validation", nonce=4, parent="txid:revision"))
    apply_ok(st2, _stage_set(pid2, "voting", nonce=5, parent="txid:validation"))
    apply_ok(st2, txf.gov_voting_close(pid2, nonce=6))
    apply_ok(st2, _tally_publish(pid2, nonce=7, passed=True))
    apply_ok(st2, _gov_execute(pid2, nonce=8))
    pr2 = _get_proposal(st2, pid2)
    assert pr2.get("stage") == "executed"


def test_gov_finalize_legacy_system_path_and_post_execute_success(base_state, txf) -> None:
    st = clone_state(base_state)
    pid = "p0-gov-finalize"
    apply_ok(st, txf.gov_proposal_create("alice", pid, nonce=1))
    apply_ok(st, _stage_set(pid, "poll", nonce=2, parent="txid:create"))
    apply_ok(st, _stage_set(pid, "revision", nonce=3, parent="txid:poll"))
    apply_ok(st, _stage_set(pid, "validation", nonce=4, parent="txid:revision"))
    apply_ok(st, _stage_set(pid, "voting", nonce=5, parent="txid:validation"))
    apply_ok(st, txf.gov_voting_close(pid, nonce=6))
    apply_ok(st, _tally_publish(pid, nonce=7, passed=True))

    # Current canon preserves a legacy SYSTEM finalize path used by queued governance followups.
    apply_ok(st, _gov_finalize(pid, nonce=8))
    pr = _get_proposal(st, pid)
    assert pr.get("stage") == "finalized"

    st2 = clone_state(base_state)
    pid2 = "p0-gov-finalize-post-execute"
    apply_ok(st2, txf.gov_proposal_create("alice", pid2, nonce=1))
    apply_ok(st2, _stage_set(pid2, "poll", nonce=2, parent="txid:create"))
    apply_ok(st2, _stage_set(pid2, "revision", nonce=3, parent="txid:poll"))
    apply_ok(st2, _stage_set(pid2, "validation", nonce=4, parent="txid:revision"))
    apply_ok(st2, _stage_set(pid2, "voting", nonce=5, parent="txid:validation"))
    apply_ok(st2, txf.gov_voting_close(pid2, nonce=6))
    apply_ok(st2, _tally_publish(pid2, nonce=7, passed=True))
    apply_ok(st2, _gov_execute(pid2, nonce=8))
    apply_ok(st2, _gov_finalize(pid2, nonce=9))
    pr2 = _get_proposal(st2, pid2)
    assert pr2.get("stage") == "finalized"
