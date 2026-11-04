"""Review-only CASE v2 candidate tests; no runtime semantics are modified."""
from __future__ import annotations
import copy
import unittest
from tooling.case_binding_policy_candidate import (
    BLOCKERS, STATUS, review_case_binding_candidate,
)

def check(state: object, case_id: object = "case-a", dispute_id: object = "dispute-a") -> dict:
    return review_case_binding_candidate(state, case_id=case_id, dispute_id=dispute_id)

class CaseBindingPolicyCandidateTests(unittest.TestCase):
    def safe(self, result: dict) -> None:
        self.assertEqual(result["status"], STATUS)
        self.assertEqual(result["authorization"], "NOT_ESTABLISHED")
        self.assertEqual(result["historical_replay"], "NOT_PROVEN")
        self.assertEqual(result["blocking_reasons"], list(BLOCKERS))
        self.assertFalse(result["may_mutate_state"])
        self.assertFalse(result["may_enqueue_system_tx"])
        self.assertFalse(result["may_activate_policy"])

    def test_unbound_does_not_initialize_case_state(self) -> None:
        state = {"height": 10}
        original = copy.deepcopy(state)
        out = check(state)
        self.assertEqual(out["classification"], "UNBOUND")
        self.assertEqual(out["candidate_future_effect"], "FIRST_BIND_AFTER_AUTHORITY_CHECK")
        self.assertEqual(state, original)
        self.safe(out)

    def test_matching_binding_is_not_alone_approved(self) -> None:
        state = {"cases": {"bindings": {"case-a": {
            "dispute_id": "dispute-a", "bound_at_nonce": 8,
        }}}}
        original = copy.deepcopy(state)
        out = check(state)
        self.assertEqual(out["classification"], "IDENTICAL_TARGET")
        self.assertEqual(out["candidate_future_effect"], "IDEMPOTENT_AFTER_PROVENANCE_CHECK")
        self.assertEqual(out["stored_dispute_id"], "dispute-a")
        self.assertEqual(state, original)
        self.safe(out)

    def test_conflicting_binding_is_detected_without_rebinding(self) -> None:
        state = {"cases": {"bindings": {"case-a": {
            "dispute_id": "dispute-original", "bound_at_nonce": 8,
        }}}}
        original = copy.deepcopy(state)
        out = check(state, dispute_id="dispute-conflicting")
        self.assertEqual(out["classification"], "CONFLICTING_TARGET")
        self.assertEqual(out["candidate_future_effect"], "DETERMINISTIC_CONFLICT_REJECTION")
        self.assertEqual(out["stored_dispute_id"], "dispute-original")
        self.assertEqual(state, original)
        self.safe(out)

    def test_malformed_request_and_stored_records_are_fail_closed(self) -> None:
        examples = [
            ({}, "", "dispute-a", "INVALID_REQUEST"),
            ({}, "case-a", "   ", "INVALID_REQUEST"),
            ({}, 2, "dispute-a", "INVALID_REQUEST"),
            ({}, "case-a", ["x"], "INVALID_REQUEST"),
            ([], "case-a", "dispute-a", "MALFORMED_ROOT"),
            ({"cases": []}, "case-a", "dispute-a", "MALFORMED_CASES"),
            ({"cases": {"bindings": []}}, "case-a", "dispute-a", "MALFORMED_BINDINGS"),
            ({"cases": {"bindings": {"case-a": []}}}, "case-a", "dispute-a", "MALFORMED_EXISTING_BINDING"),
            ({"cases": {"bindings": {"case-a": {}}}}, "case-a", "dispute-a", "MALFORMED_EXISTING_BINDING"),
            ({"cases": {"bindings": {"case-a": {"dispute_id": 17}}}}, "case-a", "dispute-a", "MALFORMED_EXISTING_BINDING"),
        ]
        for state, case_id, dispute_id, category in examples:
            with self.subTest(category=category, state=state):
                original = copy.deepcopy(state)
                out = check(state, case_id, dispute_id)
                self.assertEqual(out["classification"], category)
                self.assertEqual(out["candidate_future_effect"], "REJECT_UNVERIFIED_OR_MALFORMED")
                self.assertEqual(state, original)
                self.safe(out)

    def test_forged_activation_and_approval_fields_do_not_change_result(self) -> None:
        state = {
            "height": 999999,
            "params": {"case_binding_policy_version": 2, "gov_action_allowlist": ["CASE_BIND_TO_DISPUTE"]},
            "approval": {"signed": True, "constitutional": True},
            "cases": {"bindings": {"case-a": {"dispute_id": "dispute-original"}}},
        }
        original = copy.deepcopy(state)
        a = check(state, dispute_id="dispute-conflicting")
        b = check(copy.deepcopy(state), dispute_id="dispute-conflicting")
        self.assertEqual(a, b)
        self.assertEqual(a["classification"], "CONFLICTING_TARGET")
        self.assertEqual(state, original)
        self.safe(a)

    def test_per_case_scoping_and_explicit_target_normalization(self) -> None:
        state = {"cases": {"bindings": {
            "case-a": {"dispute_id": " dispute-a "},
            "case-b": {"dispute_id": "dispute-b"},
        }}}
        self.assertEqual(check(state, dispute_id=" dispute-a ")["classification"], "IDENTICAL_TARGET")
        self.assertEqual(check(state, "case-c", "dispute-c")["classification"], "UNBOUND")
        self.assertEqual(check(state, "case-b", "dispute-a")["classification"], "CONFLICTING_TARGET")

if __name__ == "__main__":
    unittest.main()
