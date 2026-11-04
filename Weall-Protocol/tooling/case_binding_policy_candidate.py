"""PR77 read-only CASE binding v2 policy classifier.

NOT imported by runtime, block production/replay, governance, or scheduler.
Never grants authority or changes a consensus state transition.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

STATUS = "UNAPPROVED_CASE_BINDING_POLICY_CANDIDATE"
BLOCKERS = (
    "lawful_system_parent_and_scheduler_origin_unproven",
    "consensus_activation_selector_unimplemented",
    "historical_cross_version_replay_unproven",
    "queue_conflict_liveness_policy_unimplemented",
    "semantic_review_and_public_release_no_go",
)


def _ident(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip() or None


def review_case_binding_candidate(
    state: Mapping[str, Any], *, case_id: str, dispute_id: str,
) -> dict[str, Any]:
    """Inspect one binding; even matching IDs are not proof of authorization.

    Deliberately ignores purported state-side approval/activation metadata.
    Only an independently established chain-committed version rule can enable
    new execution semantics in an actual future protocol change.
    """
    key, target = _ident(case_id), _ident(dispute_id)
    stored = None
    if not isinstance(state, Mapping):
        category = "MALFORMED_ROOT"
    elif key is None or target is None:
        category = "INVALID_REQUEST"
    else:
        cases = state.get("cases")
        if cases is not None and not isinstance(cases, Mapping):
            category = "MALFORMED_CASES"
        else:
            cases = cases if isinstance(cases, Mapping) else {}
            bindings = cases.get("bindings")
            if bindings is not None and not isinstance(bindings, Mapping):
                category = "MALFORMED_BINDINGS"
            else:
                bindings = bindings if isinstance(bindings, Mapping) else {}
                if key not in bindings:
                    category = "UNBOUND"
                elif not isinstance(bindings[key], Mapping):
                    category = "MALFORMED_EXISTING_BINDING"
                else:
                    stored = _ident(bindings[key].get("dispute_id"))
                    if stored is None:
                        category = "MALFORMED_EXISTING_BINDING"
                    elif stored == target:
                        category = "IDENTICAL_TARGET"
                    else:
                        category = "CONFLICTING_TARGET"

    candidate_effect = {
        "UNBOUND": "FIRST_BIND_AFTER_AUTHORITY_CHECK",
        "IDENTICAL_TARGET": "IDEMPOTENT_AFTER_PROVENANCE_CHECK",
        "CONFLICTING_TARGET": "DETERMINISTIC_CONFLICT_REJECTION",
    }.get(category, "REJECT_UNVERIFIED_OR_MALFORMED")
    return {
        "schema": "weall.pr77.case-binding-policy-candidate.v0",
        "status": STATUS,
        "classification": category,
        "case_id": key,
        "requested_dispute_id": target,
        "stored_dispute_id": stored,
        "candidate_future_effect": candidate_effect,
        "authorization": "NOT_ESTABLISHED",
        "historical_replay": "NOT_PROVEN",
        "blocking_reasons": list(BLOCKERS),
        "may_mutate_state": False,
        "may_enqueue_system_tx": False,
        "may_activate_policy": False,
    }
