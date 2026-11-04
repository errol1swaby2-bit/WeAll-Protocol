"""PR77 review-only S4 admission-origin binding; no runtime authorization."""

from __future__ import annotations

import copy
import unittest

from tooling.severe_case_origin_candidate import (
    CANDIDATE_KIND,
    SCHEMA,
    STATUS,
    review_severe_case_origin,
)

OPEN_ID = "a" * 64
RECORD_ID = "b" * 64


def _fixture() -> dict:
    return {
        "chain_id": "weall-testnet-review",
        "case": {
            "id": "d1",
            "target_type": "account",
            "target_id": "@target",
            "opened_by": "@reporter",
            "opened_at_height": 100,
            "opened_at_nonce": 7,
        },
        "opening": {
            "tx_type": "DISPUTE_OPEN",
            "tx_id": OPEN_ID,
            "chain_id": "weall-testnet-review",
            "height": 100,
            "nonce": 7,
            "signer": "@reporter",
            "payload": {
                "dispute_id": "d1",
                "target_type": "account",
                "target_id": "@target",
            },
        },
        "classification": {
            "record_kind": CANDIDATE_KIND,
            "record_id": RECORD_ID,
            "chain_id": "weall-testnet-review",
            "dispute_id": "d1",
            "opening_tx_id": OPEN_ID,
            "target_type": "account",
            "target_id": "@target",
            "sanction_class": "S4",
            "severity": "severe",
            "alleged_violation_class": "intentional_catastrophic_harm",
            "evidence_root": "c" * 64,
            "policy_digest": "d" * 64,
            "height": 102,
            "reason": "Alleged harm; independent adjudication not established.",
        },
    }


def _review(fixture: dict) -> dict:
    return review_severe_case_origin(**fixture)


class SevereCaseOriginReviewTests(unittest.TestCase):
    def test_plausible_forged_origin_is_consistent_but_never_authorized(self) -> None:
        fixture = _fixture()
        before = copy.deepcopy(fixture)
        result = _review(fixture)
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["status"], STATUS)
        self.assertTrue(all(result["observations"].values()))
        self.assertTrue(result["structurally_consistent_claims"])
        self.assertEqual(len(result["review_fingerprint_not_authority"]), 64)
        self.assertEqual(result["constitutional_authorization"], "NOT_ESTABLISHED")
        self.assertFalse(result["may_classify_canonical_case"])
        self.assertFalse(result["may_enqueue_account_ban"])
        self.assertTrue(result["blocking_reasons"])
        self.assertEqual(fixture, before)
        self.assertEqual(result, _review(copy.deepcopy(fixture)))

    def test_user_claimed_severity_is_not_an_authority_record(self) -> None:
        f = _fixture()
        f["opening"]["payload"].update(severity="severe", sanction_class="S4")
        f["case"].update(severity="severe", sanction_class="S4")
        f["classification"] = {}
        result = _review(f)
        self.assertFalse(result["observations"]["classification_separate_record_shape_observed"])
        self.assertFalse(result["structurally_consistent_claims"])
        self.assertFalse(result["may_classify_canonical_case"])

    def test_spoofed_signature_verification_flags_never_grant_authority(self) -> None:
        f = _fixture()
        f["opening"]["signature_verified"] = True
        f["classification"]["authorized"] = True
        f["classification"]["verified_by_consensus"] = True
        r = _review(f)
        self.assertTrue(r["structurally_consistent_claims"])
        self.assertFalse(r["may_classify_canonical_case"])
        self.assertFalse(r["may_enqueue_account_ban"])

    def test_cross_case_and_cross_chain_splicing_fails(self) -> None:
        for path, value, key in (
            (("opening", "chain_id"), "other-chain", "opening_chain_bound"),
            (
                ("classification", "chain_id"),
                "other-chain",
                "classification_matches_origin_and_target",
            ),
            (
                ("classification", "opening_tx_id"),
                "f" * 64,
                "classification_matches_origin_and_target",
            ),
            (("classification", "dispute_id"), "d2", "classification_matches_origin_and_target"),
            (("classification", "target_id"), "@other", "classification_matches_origin_and_target"),
            (("opening", "payload", "dispute_id"), "d2", "opening_matches_case_fields"),
            (("opening", "payload", "target_id"), "@other", "opening_matches_case_fields"),
            (("opening", "signer"), "@other", "opening_matches_case_fields"),
            (("opening", "nonce"), 8, "opening_matches_case_fields"),
            (("opening", "height"), 99, "opening_matches_case_fields"),
        ):
            with self.subTest(path=path):
                f = _fixture()
                cur = f
                for part in path[:-1]:
                    cur = cur[part]
                cur[path[-1]] = value
                r = _review(f)
                self.assertFalse(r["observations"][key])
                self.assertFalse(r["structurally_consistent_claims"])
                self.assertIsNone(r["review_fingerprint_not_authority"])

    def test_noncanonical_identifiers_and_digest_claims_fail(self) -> None:
        for path, value, key in (
            (("opening", "tx_id"), "A" * 64, "opening_envelope_shape_observed"),
            (("opening", "tx_id"), "0" * 64, "opening_envelope_shape_observed"),
            (("opening", "tx_id"), "abc", "opening_envelope_shape_observed"),
            (
                ("classification", "record_id"),
                OPEN_ID,
                "classification_separate_record_shape_observed",
            ),
            (
                ("classification", "record_id"),
                "b" * 63,
                "classification_separate_record_shape_observed",
            ),
            (
                ("classification", "evidence_root"),
                "0" * 64,
                "evidence_and_policy_commitment_shapes_observed",
            ),
            (
                ("classification", "policy_digest"),
                "bad",
                "evidence_and_policy_commitment_shapes_observed",
            ),
            (("classification", "height"), 99, "classification_not_before_opening"),
            (("classification", "height"), True, "classification_separate_record_shape_observed"),
            (("opening", "nonce"), True, "opening_envelope_shape_observed"),
            (("classification", "sanction_class"), "S3", "explicit_s4_claim_observed"),
            (
                ("classification", "record_kind"),
                "DISPUTE_OPEN",
                "classification_separate_record_shape_observed",
            ),
            (("classification", "reason"), "", "reasoned_admission_claim_observed"),
        ):
            with self.subTest(path=path):
                f = _fixture()
                f[path[0]][path[1]] = value
                r = _review(f)
                self.assertFalse(r["observations"][key])
                self.assertFalse(r["may_enqueue_account_ban"])

    def test_missing_malformed_records_fail_closed(self) -> None:
        for part in ("case", "opening", "classification"):
            with self.subTest(part=part):
                f = _fixture()
                f[part] = []
                r = _review(f)
                self.assertFalse(r["structurally_consistent_claims"])
                self.assertFalse(r["may_classify_canonical_case"])

    def test_candidate_fingerprint_changes_with_evidence(self) -> None:
        f = _fixture()
        first = _review(f)
        f["classification"]["evidence_root"] = "e" * 64
        second = _review(f)
        self.assertNotEqual(
            first["review_fingerprint_not_authority"],
            second["review_fingerprint_not_authority"],
        )
        self.assertFalse(first["may_enqueue_account_ban"])
        self.assertFalse(second["may_enqueue_account_ban"])


if __name__ == "__main__":
    unittest.main()
