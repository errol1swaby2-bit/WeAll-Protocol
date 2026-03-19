# tests/p0/test_p0_apply_determinism.py
from __future__ import annotations

import copy
import json
from typing import Any

from weall.runtime.domain_dispatch import apply_tx

Json = dict[str, Any]


def _stable(obj: Any) -> str:
    """
    Canonical JSON rendering for deterministic comparisons.

    We sort keys to eliminate dict insertion-order effects.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _clone(state: Json) -> Json:
    return copy.deepcopy(state)


def _drop_keys(d: Json, keys: set[str]) -> Json:
    out = {}
    for k, v in d.items():
        if k in keys:
            continue
        # deep copy defensive (tests mutate state)
        out[k] = copy.deepcopy(v)
    return out


def _stable_state_without_time(state: Json) -> str:
    # State can legitimately differ in "time" because the test sets it differently.
    return _stable(_drop_keys(state, {"time"}))


def _run(state: Json, seq: list[Json]) -> tuple[Json, list[Json]]:
    receipts: list[Json] = []
    for env in seq:
        receipts.append(apply_tx(state, env))
    return state, receipts


def _system_env(tx_type: str, payload: Json, *, nonce: int, parent: str = "txid:p0") -> Json:
    # Minimal SYSTEM envelope compatible with your canon checks.
    return {
        "tx_type": tx_type,
        "signer": "SYSTEM",
        "nonce": nonce,
        "sig": "",
        "payload": payload,
        "parent": parent,
        "system": True,
    }


def test_apply_determinism_same_sequence_same_final_state(base_state, txf) -> None:
    """
    Core P0 invariant:
      identical initial state + identical tx sequence => identical receipts + final state.

    Apply-layer only (no executor/SQLite) to avoid duplicating your crash-recovery/restart tests.
    """
    st1 = _clone(base_state)
    st2 = _clone(base_state)

    seq = [
        txf.balance_transfer("alice", "bob", 10, nonce=1),
        txf.balance_transfer("bob", "carol", 5, nonce=1),
        txf.balance_transfer("alice", "carol", 7, nonce=2),
    ]

    end1, r1 = _run(st1, seq)
    end2, r2 = _run(st2, seq)

    assert _stable(r1) == _stable(r2)
    assert _stable(end1) == _stable(end2)


def test_apply_determinism_vote_order_equivalence_same_vote_set(base_state, txf) -> None:
    """
    Governance should converge deterministically when the *final vote set* is the same,
    even if votes arrive in a different order.

    IMPORTANT: Your governance engine does not allow voting in "draft".
    We must move the proposal into a voteable stage ("voting") via GOV_STAGE_SET (SYSTEM).
    """
    proposal_id = "p0-prop-order-invariant"

    def _make_voteable(state: Json) -> None:
        # Set the proposal stage to "voting" so GOV_VOTE_CAST is allowed.
        apply_tx(
            state,
            _system_env(
                "GOV_STAGE_SET",
                {"proposal_id": proposal_id, "stage": "voting"},
                nonce=10_000,
            ),
        )

    # Path A: alice votes then bob
    st_a = _clone(base_state)
    out_create_a = apply_tx(st_a, txf.gov_proposal_create("alice", proposal_id, nonce=1))
    _make_voteable(st_a)
    out_vote_a1 = apply_tx(st_a, txf.gov_vote_cast("alice", proposal_id, "yes", nonce=2))
    out_vote_a2 = apply_tx(st_a, txf.gov_vote_cast("bob", proposal_id, "yes", nonce=1))
    out_close_a = apply_tx(st_a, txf.gov_voting_close(proposal_id, nonce=100))
    out_tally_a = apply_tx(
        st_a, txf.gov_tally_publish(proposal_id, nonce=101, tally={"yes": 2, "no": 0})
    )

    # Path B: bob votes then alice
    st_b = _clone(base_state)
    out_create_b = apply_tx(st_b, txf.gov_proposal_create("alice", proposal_id, nonce=1))
    _make_voteable(st_b)
    out_vote_b1 = apply_tx(st_b, txf.gov_vote_cast("bob", proposal_id, "yes", nonce=1))
    out_vote_b2 = apply_tx(st_b, txf.gov_vote_cast("alice", proposal_id, "yes", nonce=2))
    out_close_b = apply_tx(st_b, txf.gov_voting_close(proposal_id, nonce=100))
    out_tally_b = apply_tx(
        st_b, txf.gov_tally_publish(proposal_id, nonce=101, tally={"yes": 2, "no": 0})
    )

    # Proposal object must be identical across both paths.
    assert "gov_proposals_by_id" in st_a and proposal_id in st_a["gov_proposals_by_id"]
    assert "gov_proposals_by_id" in st_b and proposal_id in st_b["gov_proposals_by_id"]
    prop_a = st_a["gov_proposals_by_id"][proposal_id]
    prop_b = st_b["gov_proposals_by_id"][proposal_id]
    assert _stable(prop_a) == _stable(prop_b)

    # Tx outputs should be deterministic as well.
    assert _stable(out_create_a) == _stable(out_create_b)
    assert _stable(out_vote_a1) == _stable(out_vote_b2)  # alice vote receipt should match
    assert _stable(out_vote_a2) == _stable(out_vote_b1)  # bob vote receipt should match
    assert _stable(out_close_a) == _stable(out_close_b)
    assert _stable(out_tally_a) == _stable(out_tally_b)


def test_apply_determinism_not_sensitive_to_state_time_when_unlocked(base_state, txf) -> None:
    """
    Guard against accidental time-dependence in apply logic for non-time-dependent txs.

    Given:
      - economic_unlock_time == 0
      - economics_enabled == True

    BALANCE_TRANSFER outcomes should match regardless of state['time'].
    We compare receipts and state EXCLUDING the 'time' field (which we intentionally vary).
    """
    st1 = _clone(base_state)
    st2 = _clone(base_state)
    st2["time"] = 999_999_999  # intentionally different

    seq = [
        txf.balance_transfer("alice", "bob", 1, nonce=1),
        txf.balance_transfer("alice", "bob", 1, nonce=2),
        txf.balance_transfer("alice", "bob", 1, nonce=3),
    ]

    end1, r1 = _run(st1, seq)
    end2, r2 = _run(st2, seq)

    assert _stable(r1) == _stable(r2)
    assert _stable_state_without_time(end1) == _stable_state_without_time(end2)
