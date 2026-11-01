"""Review-only severe sanction evidence: adversarial fail-closed checks."""

from __future__ import annotations

import copy
import unittest

from tooling.severe_sanction_candidate_review import (
    STATUS,
    review_severe_sanction_candidate,
)


def _plausible_case() -> dict:
    first = [f"j{i:02d}" for i in range(25)]
    second = [f"a{i:02d}" for i in range(25)]
    return {
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "target_type": "account",
                "target_id": "@target",
                "severity": "severe",
                "original_panel_juror_ids": first,
                "panel_commitment": "self-asserted-first-panel",
                "resolution": {
                    "outcome": "report_upheld",
                    "tally": {"yes": 20, "no": 5},
                },
                "appeal_panel_juror_ids": second,
                "appeal_panel_commitment": "self-asserted-fresh-panel",
                "appeal_panel_result": {
                    "reached": True,
                    "decision": "uphold",
                    "counts": {"uphold": 20, "reverse": 5},
                },
                "automatic_appeal_receipt": {
                    "id": "unverified-auto-appeal-claim"
                },
                "final_resolution": {"summary": "Claimed reasoned final outcome"},
                "stage": "finalized",
            },
        },
        "dispute_receipts": {
            "r1": {
                "payload": {"dispute_id": "d1"},
                "appeal_finalization": {"decision": "uphold"},
            }
        },
    }


def _review(state: dict) -> dict:
    return review_severe_sanction_candidate(
        state, dispute_id="d1", account_id="@target"
    )


class SevereSanctionCandidateReviewTests(unittest.TestCase):
    def test_plausible_full_case_is_still_not_authorized(self) -> None:
        state = _plausible_case()
        before = copy.deepcopy(state)
        result = _review(state)
        self.assertEqual(result["status"], STATUS)
        self.assertTrue(all(result["observations"].values()))
        self.assertEqual(result["constitutional_authorization"], "NOT_ESTABLISHED")
        self.assertFalse(result["may_enqueue_account_ban"])
        self.assertIn(
            "canonical_system_producer_parent_binding_not_implemented",
            result["blocking_reasons"],
        )
        self.assertEqual(state, before)

    def test_repeatable_pure_review(self) -> None:
        state = _plausible_case()
        self.assertEqual(_review(state), _review(copy.deepcopy(state)))

    def test_missing_dispute_fails_closed(self) -> None:
        out = _review({})
        self.assertFalse(out["observations"]["case_exists"])
        self.assertFalse(out["may_enqueue_account_ban"])

    def test_wrong_target_fails_closed(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["target_id"] = "@different"
        self.assertFalse(_review(state)["observations"]["account_target_bound"])

    def test_wrong_case_class_fails_closed(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["severity"] = "low"
        self.assertFalse(_review(state)["observations"]["severe_class_declared"])

    def test_24_juror_initial_panel_rejected(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["original_panel_juror_ids"].pop()
        self.assertFalse(_review(state)["observations"]["initial_25_distinct"])

    def test_duplicate_initial_identity_rejected(self) -> None:
        state = _plausible_case()
        jurors = state["disputes_by_id"]["d1"]["original_panel_juror_ids"]
        jurors[-1] = jurors[0]
        self.assertFalse(_review(state)["observations"]["initial_25_distinct"])

    def test_19_yes_initial_votes_rejected(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["resolution"]["tally"]["yes"] = 19
        self.assertFalse(_review(state)["observations"]["initial_20_yes_observed"])

    def test_string_vote_count_never_converts_to_approval(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["resolution"]["tally"]["yes"] = "20"
        self.assertFalse(_review(state)["observations"]["initial_20_yes_observed"])

    def test_fresh_appeal_must_not_reuse_initial_jurors(self) -> None:
        state = _plausible_case()
        d = state["disputes_by_id"]["d1"]
        d["appeal_panel_juror_ids"][-1] = d["original_panel_juror_ids"][0]
        self.assertFalse(_review(state)["observations"]["fresh_appeal_25_distinct"])

    def test_19_appeal_approvals_rejected(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["appeal_panel_result"]["counts"]["uphold"] = 19
        self.assertFalse(_review(state)["observations"]["appeal_20_uphold_observed"])

    def test_reversed_appeal_not_upheld(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["appeal_panel_result"]["decision"] = "reverse"
        self.assertFalse(_review(state)["observations"]["appeal_20_uphold_observed"])

    def test_claimed_waiver_does_not_bypass_automatic_appeal(self) -> None:
        state = _plausible_case()
        d = state["disputes_by_id"]["d1"]
        d.pop("automatic_appeal_receipt")
        d["appeal_waived"] = True
        d["full_reasoned_outcome_delivered"] = True
        self.assertFalse(_review(state)["observations"]["automatic_appeal_recorded"])
        self.assertFalse(_review(state)["may_enqueue_account_ban"])

    def test_missing_finalization_receipt_rejected(self) -> None:
        state = _plausible_case()
        state["dispute_receipts"] = {}
        self.assertFalse(_review(state)["observations"]["final_receipt_observed"])

    def test_forged_receipt_for_different_case_rejected(self) -> None:
        state = _plausible_case()
        state["dispute_receipts"]["r1"]["payload"]["dispute_id"] = "d2"
        self.assertFalse(_review(state)["observations"]["final_receipt_observed"])

    def test_public_reason_missing_rejected(self) -> None:
        state = _plausible_case()
        state["disputes_by_id"]["d1"]["final_resolution"]["summary"] = ""
        self.assertFalse(_review(state)["observations"]["public_reason_present"])

    def test_untrusted_non_dict_shapes_cannot_authorize(self) -> None:
        state = {"disputes_by_id": {"d1": []}, "dispute_receipts": []}
        out = _review(state)
        self.assertEqual(out["constitutional_authorization"], "NOT_ESTABLISHED")
        self.assertFalse(out["may_enqueue_account_ban"])


if __name__ == "__main__":
    unittest.main()
