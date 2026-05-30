from __future__ import annotations

from weall.runtime.poh.eligibility import get_required_poh_tier


def test_assigned_dispute_review_actions_are_tier2_gated_not_unknown_batch491() -> None:
    """Tier 2 assigned reviewers must reach dispute-specific neutrality checks.

    The local two-node rehearsal found that DISPUTE_JUROR_ACCEPT was rejected
    before apply-time assignment/neutrality logic ran because the generic PoH
    tier gate treated it as an unknown action.  These txs are still protected by
    dispute.py; this test only proves the generic gate recognizes the canonical
    review actions.
    """

    for tx_type in (
        "DISPUTE_JUROR_ACCEPT",
        "DISPUTE_JUROR_DECLINE",
        "DISPUTE_JUROR_ATTENDANCE",
        "DISPUTE_VOTE_SUBMIT",
    ):
        assert get_required_poh_tier(tx_type) == 2


def test_unrecognized_dispute_review_typo_still_fails_closed_batch491() -> None:
    assert get_required_poh_tier("DISPUTE_JUROR_ACCEPTED") == 99
