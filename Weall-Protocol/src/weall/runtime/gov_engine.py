# src/weall/runtime/gov_engine.py
from __future__ import annotations

from typing import Any, Dict, List

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


def _proposal_rules(prop: Json) -> Dict[str, Any]:
    # Prefer explicit stored rules, else allow payload.rules as a convenience for MVP
    rules = prop.get("rules")
    if isinstance(rules, dict) and rules:
        return rules
    payload = _as_dict(prop.get("payload"))
    r2 = payload.get("rules")
    return r2 if isinstance(r2, dict) else {}


def _proposal_actions(prop: Json) -> List[Dict[str, Any]]:
    payload = _as_dict(prop.get("payload"))
    actions = payload.get("actions")
    out: List[Dict[str, Any]] = []
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

    NOTE: In the canon, these lifecycle txs are marked `receipt_only`, meaning the
    system emitter will only include them if a non-empty `parent` is provided.
    We therefore synthesize a stable parent ref per proposal + due height.
    """
    props = state.get("gov_proposals_by_id")
    if not isinstance(props, dict) or not props:
        return 0

    enq = 0

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

        vote_period = _voting_period_blocks(pr)
        close_h = int(created_h) + int(vote_period)

        parent_ref = f"gov:{pid}:{int(next_height)}"

        # --- CLOSE + TALLY (same block: close pre, tally post) ---
        if stage in {"draft", "voting"} and int(next_height) >= int(close_h):
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

            tally = _count_votes(pr)
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
