"""Experimental deterministic juror-pool replenishment, default OFF.

No local-wall-clock timers: all deadlines are replicated block heights.
This code only changes panel membership for explicitly classified S4 account
cases on a separate experimental state gate. It does not grant sanction
authority, decide ballot disputes, or emit ACCOUNT_BAN.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from weall.runtime.ballot_policy import strict_civic_governance_enabled
from weall.runtime.constitutional_clock import policy_from_state
from weall.runtime.reviewer_responsibilities import (
    DISPUTE_REVIEW_LANE,
    eligible_reviewer_ids,
)
from weall.runtime.severe_sanction_boundary import is_explicit_severe_account_sanction

Json = dict[str, Any]
TERMINATED = frozenset({"declined", "withdrawn", "timed_out"})


def _identity(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        return ""
    stripped = value.removeprefix("@")
    return stripped if stripped else ""


def _commit(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _clean_roster(value: Any, size: int) -> list[str] | None:
    if not isinstance(value, list) or len(value) != size:
        return None
    norm = [_identity(item) for item in value]
    if any(not item for item in norm) or len(set(norm)) != size:
        return None
    return list(value)


def _response_window(state: Json) -> int:
    # A consensus-state parameter, never environment or wall clock. Clamp to
    # avoid immediate replacement from zero/negative or absurd values.
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    config = params.get("dispute")
    config = config if isinstance(config, dict) else {}
    n = config.get("experimental_juror_response_window_blocks", 45)
    return n if type(n) is int and 1 <= n <= 10080 else 45


def _snapshot_valid(dispute: Json, *, appeal: bool) -> bool:
    ids_key = "appeal_voted_juror_ids" if appeal else "voted_juror_ids"
    counts_key = "appeal_vote_counts" if appeal else "vote_counts"
    nullifier_key = "appeal_ballot_nullifiers" if appeal else "ballot_nullifiers"
    ids = dispute.get(ids_key, [])
    counts = dispute.get(counts_key, {})
    nullifiers = dispute.get(nullifier_key, {})
    if (
        not isinstance(ids, list)
        or not isinstance(counts, dict)
        or not isinstance(nullifiers, dict)
    ):
        return False
    normalized = [_identity(item) for item in ids]
    if any(not item for item in normalized) or len(normalized) != len(set(normalized)):
        return False
    if not all(type(v) is int and 0 <= v <= 25 for v in counts.values()):
        return False
    return sum(counts.values()) == len(normalized) == len(nullifiers)


def _case_conflict_identities(state: Json, dispute: Json) -> set[str]:
    """Reuse the authoritative dispute conflict enumeration at promotion time."""
    from weall.runtime.apply.dispute import _dispute_conflict_account_ids

    return {_identity(item) for item in _dispute_conflict_account_ids(state, dispute)}


def _eligible_new_candidate(
    state: Json,
    dispute: Json,
    *,
    dispute_id: str,
    round_no: int,
    next_height: int,
    slot: int,
    excluded: set[str],
    historic: list[Json],
) -> str:
    # Shared role eligibility and case-party exclusions; never choose a
    # previously assigned, declined, timed-out, or original appeal juror.
    conflicts = _case_conflict_identities(state, dispute)
    options: dict[str, str] = {}
    for juror in eligible_reviewer_ids(state, DISPUTE_REVIEW_LANE):
        k = _identity(juror)
        if k and k not in excluded and k not in conflicts:
            options.setdefault(k, juror)
    jurors = dispute.get("jurors")
    if isinstance(jurors, dict):
        unavailable = {_identity(j) for j in jurors}
        options = {k: v for k, v in options.items() if k not in unavailable}
    for entry in historic:
        if isinstance(entry, dict):
            options.pop(_identity(entry.get("outgoing")), None)
    if not options:
        return ""
    seed = {
        "domain": "weall.experimental.severe-juror-backfill.v0",
        "chain_id": state.get("chain_id", ""),
        "dispute_id": dispute_id,
        "round": round_no,
        "height": next_height,
        "slot": slot,
        "prior_tip": dispute.get("experimental_juror_replacement_tip", ""),
    }
    return min(
        options.values(),
        key=lambda candidate: (
            _commit({**seed, "juror": _identity(candidate)}),
            _identity(candidate),
        ),
    )


def replenish_severe_juror_pool(
    state: Json, *, dispute_id: str, dispute: Json, next_height: int
) -> int:
    """Replace unresponsive/nonvoting seats while retaining a full 25+5.

    A no-response juror is eligible for replacement only AFTER the assigned
    block-height deadline; accepted jurors are replaced only after the
    canonical timeout receipt has recorded status=timed_out. Replacement
    never removes a recorded ballot, lowers the 20-vote threshold, changes
    original panel commitments, or finalizes a sanction.
    """
    params = state.get("params")
    if (
        not isinstance(params, dict)
        or params.get("experimental_severe_juror_replenishment_v0") is not True
        or not policy_from_state(state).enabled
        or not strict_civic_governance_enabled(state)
        or not is_explicit_severe_account_sanction(dispute)
        or type(next_height) is not int
        or next_height < 0
    ):
        return 0

    stage = dispute.get("stage")
    appeal = stage == "appeal_review"
    if (
        stage not in {"juror_review", "appeal_review"}
        or dispute.get("resolved") is True
        and not appeal
    ):
        return 0
    if appeal:
        panel_key = "appeal_panel_juror_ids"
        reserve_key = "appeal_substitute_juror_ids"
        panel_status = "appeal_panel_status"
        panel_round = "appeal_panel_round"
        commitment = "appeal_panel_commitment"
        original = _clean_roster(dispute.get("original_panel_juror_ids"), 25)
        old_reserve = _clean_roster(dispute.get("original_substitute_juror_ids"), 5)
        if original is None or old_reserve is None:
            return 0
        previous = original + old_reserve
        round_no = 2
    else:
        panel_key = "assigned_jurors"
        reserve_key = "substitute_juror_ids"
        panel_status = "panel_status"
        panel_round = "panel_round"
        commitment = "panel_commitment"
        previous = []
        round_no = 1

    panel = _clean_roster(dispute.get(panel_key), 25)
    reserve = _clean_roster(dispute.get(reserve_key), 5)
    current = _clean_roster(dispute.get("assigned_jurors"), 25)
    if panel is None or reserve is None or current is None or panel != current:
        return 0
    all_identities = [_identity(x) for x in previous + panel + reserve]
    if len(set(all_identities)) != len(all_identities):
        return 0
    if (
        dispute.get(panel_status) != "assigned"
        or type(dispute.get(panel_round)) is not int
        or dispute[panel_round] != round_no
        or not isinstance(dispute.get(commitment), str)
        or not dispute[commitment].strip()
        or not _snapshot_valid(dispute, appeal=appeal)
    ):
        return 0

    jurors = dispute.get("jurors")
    if not isinstance(jurors, dict):
        return 0
    history = dispute.get("experimental_juror_replacements", [])
    if not isinstance(history, list) or any(not isinstance(x, dict) for x in history):
        return 0
    voted_key = "appeal_voted_juror_ids" if appeal else "voted_juror_ids"
    voted = {_identity(x) for x in dispute.get(voted_key, [])}
    elapsed = _response_window(state)
    count = 0
    # Panel seat order, reserve FIFO, and per-event deterministic candidate
    # ordering make the transition replay-identical for every node.
    for slot, outgoing in enumerate(list(panel)):
        record = jurors.get(outgoing)
        if not isinstance(record, dict) or _identity(outgoing) in voted:
            continue
        status = record.get("status")
        reason = ""
        if status in TERMINATED:
            reason = str(status)
        elif status == "assigned":
            since = record.get("assigned_at_height")
            if type(since) is int and since >= 0 and next_height > since + elapsed:
                reason = "no_response"
        # An accepted juror is *not* displaced just because the scheduler
        # observes a past deadline; the existing SYSTEM timeout receipt must
        # run and authenticate that transition first.
        if not reason:
            continue
        if not reserve:
            break
        incoming = reserve[0]
        incoming_identity = _identity(incoming)
        # Pool eligibility is not enough: a reserve can become a case party,
        # beneficiary, or material/financial conflict after assignment. Never
        # promote such an account even if its original panel was valid.
        if (
            incoming_identity in voted
            or incoming_identity in {_identity(x) for x in previous + panel}
            or incoming_identity in _case_conflict_identities(state, dispute)
            or incoming_identity in {_identity(x.get("outgoing")) for x in history}
            or incoming_identity in {_identity(x) for x in jurors}
        ):
            continue
        excluded = {_identity(x) for x in previous + panel + reserve}
        excluded.update(_identity(x.get("outgoing")) for x in history)
        newcomer = _eligible_new_candidate(
            state,
            dispute,
            dispute_id=dispute_id,
            round_no=round_no,
            next_height=next_height,
            slot=slot,
            excluded=excluded,
            historic=history,
        )
        if not newcomer:
            continue
        # Validate promoted reserve eligibility before changing any state.
        if _identity(incoming) not in {
            _identity(j) for j in eligible_reviewer_ids(state, DISPUTE_REVIEW_LANE)
        }:
            continue

        before = _commit({"panel": panel, "reserve": reserve})
        panel[slot] = incoming
        reserve = reserve[1:] + [newcomer]
        record["replaced_at_height"] = next_height
        record["replacement_reason"] = reason
        record["replaced_by"] = incoming
        if status == "assigned":
            record["status"] = "replaced_no_response"
        jurors[outgoing] = record
        jurors[incoming] = {
            "status": "assigned",
            "assigned_at_height": next_height,
            "panel_round": round_no,
            "assignment_source": "experimental_timeout_substitute_promotion",
        }
        event: Json = {
            "dispute_id": dispute_id,
            "round": round_no,
            "height": next_height,
            "seat": slot,
            "outgoing": outgoing,
            "incoming": incoming,
            "replenished_substitute": newcomer,
            "reason": reason,
            "old_roster_hash": before,
            "new_roster_hash": _commit({"panel": panel, "reserve": reserve}),
            "prior_event_hash": dispute.get("experimental_juror_replacement_tip", ""),
        }
        event["event_hash"] = _commit(event)
        history.append(event)
        dispute["experimental_juror_replacement_tip"] = event["event_hash"]
        count += 1

    if count:
        dispute[panel_key] = panel
        dispute[reserve_key] = reserve
        dispute["assigned_jurors"] = list(panel)
        dispute["eligible_juror_ids"] = list(panel)
        dispute["eligible_validator_count"] = 25
        dispute["required_votes"] = max(20, int(dispute.get("required_votes") or 0))
        dispute["jurors"] = jurors
        dispute["experimental_juror_replacements"] = history
    return count
