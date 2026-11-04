"""Issue #72: compatibility indicators must not grant or subtract reputation."""

from __future__ import annotations

import copy
import json

from weall.runtime.reputation_events import (
    REPUTATION_DIMENSIONS,
    append_reputation_event,
    reduce_reputation_events,
)
from weall.runtime.reputation_matrix import derive_reputation_matrix


def _state() -> dict:
    return {
        "height": 11,
        "accounts": {
            "@alice": {
                "reputation": "-5",
                "reputation_milli": -5000,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            }
        },
    }


def _canonical_event(state: dict, *, delta: int = -5000) -> dict:
    return append_reputation_event(
        state,
        actor_id="@alice",
        event_code="VALIDATOR_DOUBLE_SIGN",
        source_flow="validator",
        source_tx_id="slash:1",
        source_object_id="block:1",
        occurred_at_block=11,
        delta=delta,
    )


def test_one_cause_is_only_one_authoritative_score_even_with_legacy_mirrors() -> None:
    state = _state()
    event = _canonical_event(state)
    baseline = derive_reputation_matrix(state, "@alice", include_events=True)

    state["reputation"]["deltas"] = [
        {
            "delta_id": "legacy:slash:1",
            "account_id": "@alice",
            "delta_milli": -5000,
            "reason": "equivocation",
            "payload": {"source": "consensus", "slash_id": "slash:1"},
        }
    ]
    state["slashing"] = {"executions": {"slash:1": {"validator": "@alice", "type": "equivocation"}}}
    state["validators"] = {"registry": {"@alice": {"status": "active"}}}
    before = json.dumps(state, sort_keys=True, separators=(",", ":"))
    mirrored = derive_reputation_matrix(state, "@alice", include_events=True)

    assert mirrored["aggregate_public_score_milli"] == baseline["aggregate_public_score_milli"]
    assert (
        mirrored["dimensions"]["validator_reputation"]["score_milli"]
        == baseline["dimensions"]["validator_reputation"]["score_milli"]
        == -5000
    )
    assert mirrored["dimensions"]["validator"]["weight_bps"] == 0
    assert mirrored["dimensions"]["validator"]["score_authority"] == "legacy_observation_only"
    assert mirrored["dimensions"]["validator_reputation"]["score_authority"] == (
        "canonical_event_ledger"
    )
    assert mirrored["eligibility"] == baseline["eligibility"]
    assert any(ev["source"] == "reputation_delta" for ev in mirrored["events"])
    assert (
        sum(
            1
            for ev in mirrored["events"]
            if ev["contributes_to_canonical_score"] and ev["source_ref"] == event["event_id"]
        )
        == 1
    )
    assert json.dumps(state, sort_keys=True, separators=(",", ":")) == before
    assert mirrored == derive_reputation_matrix(copy.deepcopy(state), "@alice", include_events=True)


def test_aliases_are_public_but_non_additive_even_without_legacy_domain_records() -> None:
    state = _state()
    _canonical_event(state)
    matrix = derive_reputation_matrix(state, "@alice", include_events=True)
    for name, rec in matrix["dimensions"].items():
        if name in REPUTATION_DIMENSIONS:
            assert rec["score_authority"] == "canonical_event_ledger"
        else:
            assert rec["weight_bps"] == 0
            assert rec["contributes_to_aggregate"] is False
    aliases = [ev for ev in matrix["events"] if ev["source"] == "reputation_event_ledger_alias"]
    assert aliases
    assert all(ev["contributes_to_canonical_score"] is False for ev in aliases)
    assert matrix["formula"]["role_authorization"] == "not_derived_from_aggregate"


def test_canonical_ordered_clamping_matches_exact_reducer_not_unclamped_event_sum() -> None:
    state = _state()
    _canonical_event(state, delta=200000)
    append_reputation_event(
        state,
        actor_id="@alice",
        event_code="VALIDATOR_DOUBLE_SIGN",
        source_flow="validator",
        source_tx_id="slash:2",
        source_object_id="block:2",
        occurred_at_block=12,
        delta=-200000,
    )
    reduced = reduce_reputation_events(state["reputation"]["events"])
    expected = reduced["actors"]["@alice"]["dimensions"]["validator_reputation"]
    matrix = derive_reputation_matrix(state, "@alice")
    assert expected["score_milli"] == -100000
    assert matrix["dimensions"]["validator_reputation"]["score_milli"] == expected["score_milli"]
    assert matrix["dimensions"]["validator_reputation"]["event_count"] == expected["event_count"]


def test_legacy_only_observations_cannot_mint_canonical_role_score() -> None:
    state = _state()
    state["reputation"] = {
        "deltas": [
            {
                "delta_id": "legacy:grant",
                "account_id": "@alice",
                "delta_milli": 100000,
                "reason": "content_post_matured",
            }
        ]
    }
    matrix = derive_reputation_matrix(state, "@alice", include_events=True)
    assert matrix["scalar_reputation"]["score_milli"] == -5000
    assert matrix["aggregate_public_score_milli"] == 0
    assert matrix["canonical_dimensions"] == {}
    assert matrix["dimensions"]["creator_reputation"]["score_milli"] == 0
    assert matrix["dimensions"]["creator"]["event_count"] >= 1
    assert matrix["eligibility"]["creator_trust"]["eligible"] is True
