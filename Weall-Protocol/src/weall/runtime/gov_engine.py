# src/weall/runtime/gov_engine.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = Dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _count_votes(prop: Json) -> Dict[str, int]:
    votes = prop.get("votes")
    if not isinstance(votes, dict):
        return {"yes": 0, "no": 0, "abstain": 0}

    yes = no = abstain = 0
    for v in votes.values():
        if not isinstance(v, dict):
            continue
        choice = str(v.get("vote") or "").strip().lower()
        if choice == "yes":
            yes += 1
        elif choice == "no":
            no += 1
        else:
            abstain += 1
    return {"yes": yes, "no": no, "abstain": abstain}


def _count_votes_with_delegation(
    prop: Json,
    *,
    delegations: Optional[Dict[str, Any]] = None,
    votes_key: str = "votes",
) -> Dict[str, int]:
    """Count votes for a proposal, applying delegation in a deterministic way.

    Rules:
      - A signer who voted directly on this proposal ALWAYS counts their own vote.
      - If a signer did not vote directly but has a delegation mapping, they inherit
        their delegatee's vote *iff* the delegatee voted directly on this proposal.
      - Each signer counts at most once.

    NOTE: This does not attempt to count "all eligible PoH" (we do not have that
    set here). It counts only direct votes + delegated weight where the delegatee
    has cast a direct vote.
    """

    votes = prop.get(votes_key)
    if not isinstance(votes, dict):
        votes = {}

    delmap = delegations if isinstance(delegations, dict) else {}

    # Normalize choices for direct voters.
    direct_choice: Dict[str, str] = {}
    for signer, v in votes.items():
        if not isinstance(v, dict):
            continue
        choice = str(v.get("vote") or "").strip().lower()
        if choice:
            direct_choice[str(signer)] = choice

    yes = no = abstain = 0

    def _add(choice: str) -> None:
        nonlocal yes, no, abstain
        c = (choice or "").strip().lower()
        if c == "yes":
            yes += 1
        elif c == "no":
            no += 1
        else:
            abstain += 1

    # 1) Count direct votes.
    for _, choice in direct_choice.items():
        _add(choice)

    # 2) Count delegated weight for delegators who did not vote directly.
    # Deterministic ordering.
    for delegator in sorted(delmap.keys(), key=lambda x: str(x)):
        delegator_s = str(delegator)
        if delegator_s in direct_choice:
            continue
        delegatee = delmap.get(delegator)
        if delegatee is None:
            continue
        delegatee_s = str(delegatee)
        choice = direct_choice.get(delegatee_s)
        if choice:
            _add(choice)

    return {"yes": yes, "no": no, "abstain": abstain}


def _proposal_rules(prop: Json) -> Dict[str, Any]:
    """
    Strict mode:
      Governance lifecycle rules MUST come from the stored proposal record
      (prop["rules"]) and MUST NEVER fall back to user-supplied payload.rules.

    Accepting payload.rules is a stealth override vector (e.g., quorum, delays,
    auto lifecycle) and makes lifecycle behavior depend on untrusted bytes.
    """

    rules = prop.get("rules")
    return rules if isinstance(rules, dict) else {}


def _proposal_actions(prop: Json) -> List[Dict[str, Any]]:
    # Legacy note: apply_governance stores actions at proposal root.
    # Older snapshots may store proposal payload under prop["payload"].
    if isinstance(prop.get("actions"), list):
        out: List[Dict[str, Any]] = []
        for a in _as_list(prop.get("actions")):
            if isinstance(a, dict):
                out.append(a)
        return out

    payload = _as_dict(prop.get("payload"))
    actions = payload.get("actions")
    out = []
    for a in _as_list(actions):
        if isinstance(a, dict):
            out.append(a)
    return out


def _is_auto(prop: Json) -> bool:
    rules = _proposal_rules(prop)
    v = rules.get("auto_lifecycle")
    if v is None:
        v = rules.get("auto")
    if v is None:
        v = True
    return bool(v)


def _draft_period_blocks(prop: Json, *, default: int = 1) -> int:
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("draft_period_blocks"), default))


def _poll_period_blocks(prop: Json, *, default: int = 72) -> int:
    rules = _proposal_rules(prop)
    return max(1, _as_int(rules.get("poll_period_blocks"), default))


def _revision_period_blocks(prop: Json, *, default: int = 24) -> int:
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("revision_period_blocks"), default))


def _validation_period_blocks(prop: Json, *, default: int = 24) -> int:
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("validation_period_blocks"), default))


def _voting_period_blocks(prop: Json, *, default: int = 144) -> int:
    rules = _proposal_rules(prop)
    return max(1, _as_int(rules.get("voting_period_blocks"), default))


def _execute_delay_blocks(prop: Json, *, default: int = 1) -> int:
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("execute_delay_blocks"), default))


def _finalize_delay_blocks(prop: Json, *, default: int = 1) -> int:
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("finalize_delay_blocks"), default))


def _quorum_required(prop: Json) -> int:
    q = prop.get("quorum")
    if isinstance(q, int):
        return max(0, q)
    rules = _proposal_rules(prop)
    return max(0, _as_int(rules.get("quorum"), 0))


def tick_governance_lifecycle(state: Json, *, next_height: int) -> int:
    """Enqueue deterministic SYSTEM txs that progress governance proposals.

    Spec lifecycle: Draft → Poll → Revision → Validation → Vote → Execution.

    Canon note:
    - Many governance follow-up txs are marked receipt_only, so they must carry a
      parent pointer. We synthesize a stable parent ref per proposal + due height.

    Backward compatibility:
    - Proposals created before the stage machine change may already be in "voting"
      or later stages. Those continue to function.
    """

    props = state.get("gov_proposals_by_id")
    if not isinstance(props, dict) or not props:
        return 0

    enq = 0

    delegations = state.get("gov_delegations")
    delegations_dict = delegations if isinstance(delegations, dict) else {}

    for pid, pr in list(props.items()):
        if not isinstance(pr, dict):
            continue
        if not _is_auto(pr):
            continue

        stage = str(pr.get("stage") or "").strip().lower() or "draft"

        created_h = pr.get("created_at_height")
        if not isinstance(created_h, int) or created_h <= 0:
            created_h = int(next_height)
            pr["created_at_height"] = int(created_h)
            props[pid] = pr

        parent_ref = f"gov:{pid}:{int(next_height)}"

        # --- DRAFT -> POLL ---
        if stage == "draft":
            draft_h = pr.get("draft_at_height")
            if not isinstance(draft_h, int) or draft_h <= 0:
                pr["draft_at_height"] = int(created_h)
                props[pid] = pr

            draft_period = _draft_period_blocks(pr)
            poll_open_h = int(created_h) + int(draft_period) + 1
            if int(next_height) >= int(poll_open_h):
                enqueue_system_tx(
                    state,
                    tx_type="GOV_STAGE_SET",
                    payload={"proposal_id": pid, "stage": "poll", "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

        # --- POLL -> REVISION (with poll summary) ---
        if stage == "poll":
            poll_h = pr.get("poll_opened_at_height")
            if not isinstance(poll_h, int) or poll_h <= 0:
                # If stage was set without stamping, stamp deterministically.
                poll_h = int(next_height)
                pr["poll_opened_at_height"] = int(poll_h)
                props[pid] = pr

            poll_period = _poll_period_blocks(pr)
            poll_close_h = int(poll_h) + int(poll_period)
            if int(next_height) >= int(poll_close_h):
                tally = _count_votes_with_delegation(pr, delegations=delegations_dict, votes_key="poll_votes")
                yes = int(tally["yes"])
                no = int(tally["no"])
                abstain = int(tally["abstain"])
                total = yes + no + abstain

                enqueue_system_tx(
                    state,
                    tx_type="GOV_STAGE_SET",
                    payload={
                        "proposal_id": pid,
                        "stage": "revision",
                        "poll_tally": tally,
                        "poll_total_votes": total,
                        "_parent_ref": parent_ref,
                    },
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

        # --- REVISION -> VALIDATION ---
        if stage == "revision":
            rev_h = pr.get("revision_opened_at_height")
            if not isinstance(rev_h, int) or rev_h <= 0:
                rev_h = int(next_height)
                pr["revision_opened_at_height"] = int(rev_h)
                props[pid] = pr

            rev_period = _revision_period_blocks(pr)
            val_open_h = int(rev_h) + int(rev_period) + 1
            if int(next_height) >= int(val_open_h):
                enqueue_system_tx(
                    state,
                    tx_type="GOV_STAGE_SET",
                    payload={"proposal_id": pid, "stage": "validation", "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

        # --- VALIDATION -> VOTING ---
        if stage == "validation":
            val_h = pr.get("validation_opened_at_height")
            if not isinstance(val_h, int) or val_h <= 0:
                val_h = int(next_height)
                pr["validation_opened_at_height"] = int(val_h)
                props[pid] = pr

            val_period = _validation_period_blocks(pr)
            vote_open_h = int(val_h) + int(val_period) + 1
            if int(next_height) >= int(vote_open_h):
                enqueue_system_tx(
                    state,
                    tx_type="GOV_STAGE_SET",
                    payload={"proposal_id": pid, "stage": "voting", "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

        # --- CLOSE + TALLY (same block: close pre, tally post) ---
        if stage in {"voting", "vote"}:
            vote_opened_h = pr.get("voting_opened_at_height")
            if not isinstance(vote_opened_h, int) or vote_opened_h <= 0:
                vote_opened_h = int(next_height)
                pr["voting_opened_at_height"] = int(vote_opened_h)
                props[pid] = pr

            vote_period = _voting_period_blocks(pr)
            close_h = int(vote_opened_h) + int(vote_period)

            if int(next_height) >= int(close_h):
                enqueue_system_tx(
                    state,
                    tx_type="GOV_VOTING_CLOSE",
                    payload={"proposal_id": pid, "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

                tally = _count_votes_with_delegation(pr, delegations=delegations_dict, votes_key="votes")
                yes = int(tally["yes"])
                no = int(tally["no"])
                abstain = int(tally["abstain"])
                total = yes + no + abstain
                quorum = _quorum_required(pr)
                quorum_met = (total >= quorum) if quorum > 0 else True
                passed = bool(quorum_met and (yes > no))

                enqueue_system_tx(
                    state,
                    tx_type="GOV_TALLY_PUBLISH",
                    payload={
                        "proposal_id": pid,
                        "tally": tally,
                        "total_votes": total,
                        "quorum_required": quorum,
                        "quorum_met": quorum_met,
                        "passed": passed,
                        "_parent_ref": parent_ref,
                    },
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="post",
                )
                enq += 1

        # --- EXECUTE ---
        if stage == "tallied":
            tallied_h = pr.get("tallied_at_height")
            if not isinstance(tallied_h, int) or tallied_h <= 0:
                tallied_h = int(next_height)
                pr["tallied_at_height"] = int(tallied_h)
                props[pid] = pr

            delay = _execute_delay_blocks(pr)
            exec_h = int(tallied_h) + int(delay) + 1

            passed = False
            tallies = pr.get("tallies")
            if isinstance(tallies, list) and tallies:
                last = tallies[-1]
                if isinstance(last, dict):
                    pay = _as_dict(last.get("payload"))
                    passed = bool(pay.get("passed") is True)

            if passed and int(next_height) >= int(exec_h):
                actions = _proposal_actions(pr)
                enqueue_system_tx(
                    state,
                    tx_type="GOV_EXECUTE",
                    payload={"proposal_id": pid, "actions": actions, "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

        # --- FINALIZE (safety net; execute also schedules finalize) ---
        if stage == "executed":
            exec_h = pr.get("executed_at_height")
            if not isinstance(exec_h, int) or exec_h <= 0:
                exec_h = int(next_height)
                pr["executed_at_height"] = int(exec_h)
                props[pid] = pr

            delay = _finalize_delay_blocks(pr)
            fin_h = int(exec_h) + int(delay) + 1
            if int(next_height) >= int(fin_h):
                enqueue_system_tx(
                    state,
                    tx_type="GOV_PROPOSAL_FINALIZE",
                    payload={"proposal_id": pid, "_parent_ref": parent_ref},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="pre",
                )
                enq += 1

    return enq
