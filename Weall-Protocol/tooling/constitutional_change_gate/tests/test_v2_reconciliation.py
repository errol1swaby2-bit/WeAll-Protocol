from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import reconcile_v2 as rv
import weall_change_gate as cg
from test_change_gate import mk_repo


def fixture():
    t = {
        "schema": "weall.v2.tx_contract_matrix",
        "transaction_count": 2,
        "provenance": {
            "implementation_commit": "1" * 40,
            "normative_pdf_sha256": "f" * 64,
            "normative_authority_status": "V2_0_FIRST_DRAFT_NOT_AUTHORIZED",
        },
        "rows": [
            {
                "tx_type": "DISPUTE_RESOLVE",
                "numeric_id": 43,
                "stable_id": "TX-0043",
                "domain": "Dispute",
                "origin": "SYSTEM",
                "context": "block",
                "implementation_source": {
                    "path": "src/weall/runtime/apply/dispute.py",
                    "function": "apply_dispute",
                },
                "tests": ["tests/test_d.py"],
                "semantic_derivation": "domain_scope_fallback",
                "semantic_review": {"independent_review": False},
            },
            {
                "tx_type": "ACCOUNT_LOCK",
                "numeric_id": 44,
                "stable_id": "TX-0044",
                "domain": "Identity",
                "origin": "SYSTEM",
                "context": "block",
                "implementation_source": {
                    "path": "src/weall/runtime/apply/identity.py",
                    "function": "apply_identity",
                },
                "tests": ["tests/test_a.py"],
                "semantic_derivation": "function_static",
                "semantic_review": {"independent_review": False},
            },
        ],
    }
    r = {
        "schema": "weall.v2.requirement_traceability",
        "count": 3,
        "provenance": {"implementation_commit": "1" * 40, "normative_pdf_sha256": "f" * 64},
        "rows": [
            {
                "id": "ACC-003",
                "title": "ACC-003",
                "status": "normative_target",
                "verification_result": "SPECIFICATION_DEFINED;IMPLEMENTATION_NOT_VERIFIED",
                "reviewer": "PENDING_INDEPENDENT_REVIEW",
                "implementation_paths": ["src/weall/runtime/tx_schema.py"],
                "contract_ids": [],
                "test_run_id": "NOT_RUN",
                "implementation_commit": None,
                "activation_receipt": None,
            },
            {
                "id": "DISP-001",
                "title": "DISP-001",
                "status": "normative_target",
                "verification_result": "SPECIFICATION_DEFINED;IMPLEMENTATION_NOT_VERIFIED",
                "reviewer": "PENDING_INDEPENDENT_REVIEW",
                "implementation_paths": ["src/weall/runtime/apply/dispute.py"],
                "contract_ids": ["TX-0043"],
                "test_run_id": "NOT_RUN",
                "implementation_commit": None,
                "activation_receipt": None,
            },
            {
                "id": "GOV-EXEC-001",
                "title": "GOV-EXEC-001",
                "status": "launch_gated",
                "verification_result": "SPECIFICATION_DEFINED;IMPLEMENTATION_NOT_VERIFIED",
                "reviewer": "PENDING_INDEPENDENT_REVIEW",
                "implementation_paths": ["src/weall/runtime/scheduler_pipeline.py"],
                "contract_ids": ["SYS_GOV_EXECUTE_DUE"],
                "test_run_id": "NOT_RUN",
                "implementation_commit": None,
                "activation_receipt": None,
            },
        ],
    }
    return t, r


class V2ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = mk_repo(Path(self.tmp.name))
        self.rows = cg.extract_routes(self.repo)
        self.idx = cg.read_json(self.repo / cg.INDEX)
        self.tx, self.req = fixture()

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, changes=None):
        return rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            changes or ["Weall-Protocol/src/weall/runtime/apply/dispute.py"],
            checkout_commit=cg.repo_commit(self.repo),
        )

    def test_two_way_join_and_domain_reference(self):
        a = self.check()
        self.assertEqual(a["canonical_tx_count"], 2)
        self.assertEqual(a["canonical_name_domain_origin_context_numeric_join"], "MATCHED")
        self.assertEqual(a["tx_independent_review_count"], 0)
        self.assertEqual(a["v2_requirement_count"], 3)

    def test_numeric_id_distinct_from_hex_tx_id(self):
        a = self.check()
        x = {x["tx_type"]: x for x in a["transactions"]}
        self.assertEqual(x["DISPUTE_RESOLVE"]["numeric_id"], 43)
        self.assertEqual(x["DISPUTE_RESOLVE"]["canonical_hex_id"], "a")

    def test_stale_impl_pin_not_passed(self):
        a = self.check()
        self.assertFalse(a["v2_source_commit_matches_checkout"])
        self.assertTrue(a["gate"].startswith("BLOCKED"))

    def test_path_based_requirement_is_candidate_only(self):
        a = self.check()
        x = {x["id"]: x for x in a["requirements"]}
        self.assertEqual(x["DISP-001"]["candidate_relation"], "SOURCE_PATH_MATCH_REVIEW_CANDIDATE")
        self.assertEqual(x["ACC-003"]["candidate_relation"], "UNLINKED_NOT_SAFE_TO_DISMISS")
        self.assertEqual(x["DISP-001"]["link_authority"].startswith("UNVERIFIED"), True)

    def test_schema_diff_marks_requirement_path(self):
        a = self.check(["Weall-Protocol/src/weall/runtime/tx_schema.py"])
        x = {x["id"]: x for x in a["requirements"]}
        self.assertEqual(x["ACC-003"]["candidate_relation"], "SOURCE_PATH_MATCH_REVIEW_CANDIDATE")

    def test_noncanonical_scheduler_ref_not_silently_dropped(self):
        a = self.check()
        self.assertEqual(a["non_tx_contract_identifiers_not_in_canon"], ["SYS_GOV_EXECUTE_DUE"])
        self.assertEqual(a["requirements_with_explicit_canonical_contract_link"], 1)

    def test_v2_missing_tx_is_fail_closed(self):
        self.tx["rows"].pop()
        self.tx["transaction_count"] = 1
        with self.assertRaisesRegex(cg.ContractError, "v2_to_code_tx_set_mismatch"):
            self.check()

    def test_v2_numeric_mismatch_is_fail_closed(self):
        self.tx["rows"][0]["numeric_id"] = 44
        with self.assertRaisesRegex(cg.ContractError, "v2_numeric_id_mismatch"):
            self.check()

    def test_v2_requirement_duplicate_ids_are_fail_closed(self):
        self.req["rows"][1]["id"] = "ACC-003"
        with self.assertRaisesRegex(cg.ContractError, "v2_requirement_duplicate"):
            self.check()

    def test_drift_between_two_derivative_pins_fails(self):
        self.req["provenance"]["implementation_commit"] = "2" * 40
        with self.assertRaisesRegex(cg.ContractError, "v2_derivative_provenance_mismatch"):
            self.check()

    def test_path_traversal_rejected(self):
        for path in [
            "../../etc/passwd",
            "src/../weall/runtime/apply/dispute.py",
            "/etc/passwd",
            "C:/secret",
        ]:
            with self.subTest(path=path):
                self.assertIsNone(rv.normalize_source_path(path))

    def test_web_path_normalization(self):
        self.assertEqual(
            rv.normalize_source_path("../web/src/pages/DisputeReview.tsx"),
            "web/src/pages/DisputeReview.tsx",
        )

    def test_dir_prefix_not_substring(self):
        self.assertTrue(
            rv.path_matches(
                "Weall-Protocol/src/weall/runtime/apply/dispute.py",
                "Weall-Protocol/src/weall/runtime/apply/",
            )
        )
        self.assertFalse(
            rv.path_matches(
                "Weall-Protocol/src/weall/runtime/apply/disputes.py",
                "Weall-Protocol/src/weall/runtime/apply/dispute.py",
            )
        )

    def test_pr61_manifest_33_unique_paths(self):
        m = cg.read_json(ROOT / "reference/PR61_changed_files.json")
        self.assertEqual(len(m["changed_files"]), 33)
        self.assertEqual(len(set(m["changed_files"])), 33)
        self.assertEqual(m["head"], rv.REVIEWED_PR61)

    def test_all_pr61_paths_classified_conservatively(self):
        m = cg.read_json(ROOT / "reference/PR61_changed_files.json")
        a = cg.impacted_paths(self.repo, self.rows, m["changed_files"], cg.load_policy())
        self.assertEqual(len(a["tx_types"]), 2)
        self.assertEqual(len(a["changed_paths"]), 33)
        self.assertEqual(a["unmapped_paths"], [])
        self.assertIn(
            "generated_contract_or_compiler_surface_conservative",
            [x["reason"] for x in a["changed_paths"]],
        )

    def test_candidate_edges_are_bidirectional_and_unreviewed(self):
        result = self.check(["web/src/unrelated.tsx"])
        req = {row["id"]: row for row in result["requirements"]}
        tx = {row["tx_type"]: row for row in result["tx_requirement_candidates"]}
        self.assertEqual(req["DISP-001"]["candidate_canonical_txs"], ["DISPUTE_RESOLVE"])
        self.assertEqual(req["DISP-001"]["handler_source_candidate_txs"], ["DISPUTE_RESOLVE"])
        self.assertEqual(req["ACC-003"]["candidate_canonical_txs"], [])
        self.assertEqual(tx["ACCOUNT_LOCK"]["candidate_requirement_count"], 0)
        self.assertEqual(
            tx["DISPUTE_RESOLVE"]["candidate_requirements"][0]["requirement_id"], "DISP-001"
        )
        self.assertEqual(
            tx["DISPUTE_RESOLVE"]["link_authority"], "UNVERIFIED_STATIC_CANDIDATE_ONLY"
        )
        self.assertTrue(result["gate"].startswith("BLOCKED"))

    def test_handler_directory_binding_without_explicit_id_remains_candidate(self):
        self.req["rows"][1]["contract_ids"] = []
        self.req["rows"][1]["implementation_paths"] = ["src/weall/runtime/apply/"]
        result = self.check(["web/src/unrelated.tsx"])
        req = {row["id"]: row for row in result["requirements"]}
        self.assertEqual(
            req["DISP-001"]["candidate_relation"],
            "HANDLER_SOURCE_MATCH_REVIEW_CANDIDATE",
        )
        self.assertEqual(
            req["DISP-001"]["candidate_canonical_txs"],
            ["ACCOUNT_LOCK", "DISPUTE_RESOLVE"],
        )
        self.assertEqual(result["requirements_with_explicit_canonical_contract_link"], 0)

    def test_similar_handler_filename_does_not_create_false_link(self):
        self.req["rows"][1]["contract_ids"] = []
        self.req["rows"][1]["implementation_paths"] = ["src/weall/runtime/apply/disputes.py"]
        result = self.check(["web/src/unrelated.tsx"])
        req = {row["id"]: row for row in result["requirements"]}
        self.assertEqual(req["DISP-001"]["candidate_canonical_txs"], [])
        self.assertEqual(req["DISP-001"]["candidate_relation"], "UNLINKED_NOT_SAFE_TO_DISMISS")

    def test_effect_import_source_links_to_requirement_without_approval(self):
        self.req["rows"][1]["contract_ids"] = []
        self.req["rows"][1]["implementation_paths"] = ["src/weall/runtime/helper_effects.py"]
        effects = {
            "transaction_count": 2,
            "transactions": [
                {
                    "tx_type": "DISPUTE_RESOLVE",
                    "imported_function_candidates": [
                        {
                            "target_source_path": "Weall-Protocol/src/weall/runtime/helper_effects.py",
                            "status": "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE",
                        }
                    ],
                },
                {"tx_type": "ACCOUNT_LOCK", "imported_function_candidates": []},
            ],
        }
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            ["web/src/unrelated.tsx"],
            checkout_commit=cg.repo_commit(self.repo),
            effects=effects,
        )
        req = {row["id"]: row for row in result["requirements"]}["DISP-001"]
        self.assertEqual(req["candidate_relation"], "TRACED_IMPORT_SOURCE_MATCH_REVIEW_CANDIDATE")
        self.assertEqual(req["imported_effect_candidate_txs"], ["DISPUTE_RESOLVE"])
        tx = {row["tx_type"]: row for row in result["tx_requirement_candidates"]}["DISPUTE_RESOLVE"]
        self.assertIn(
            "TRACED_IMPORT_SOURCE_PATH_UNREVIEWED",
            tx["candidate_requirements"][0]["candidate_reasons"],
        )
        self.assertTrue(result["gate"].startswith("BLOCKED"))

    def test_incomplete_effect_inventory_fails_closed(self):
        effects = {"transaction_count": 2, "transactions": [{"tx_type": "DISPUTE_RESOLVE"}]}
        with self.assertRaisesRegex(cg.ContractError, "effect_tx_coverage_mismatch"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
            )

    def test_transitive_import_candidate_is_not_authorization(self):
        self.req["rows"][1]["contract_ids"] = []
        self.req["rows"][1]["implementation_paths"] = ["src/weall/runtime/deep_effects.py"]
        effects = {
            "source_commit": cg.repo_commit(self.repo),
            "transaction_count": 2,
            "transactions": [
                {
                    "tx_type": "DISPUTE_RESOLVE",
                    "imported_function_candidates": [],
                    "transitive_imported_function_candidates": [
                        {
                            "status": "TRANSITIVE_EXPLICIT_STATE_HANDOFF_CANDIDATE",
                            "target_source_path": "Weall-Protocol/src/weall/runtime/deep_effects.py",
                        },
                    ],
                },
                {
                    "tx_type": "ACCOUNT_LOCK",
                    "imported_function_candidates": [],
                    "transitive_imported_function_candidates": [],
                },
            ],
        }
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=cg.repo_commit(self.repo),
            effects=effects,
        )
        row = {r["id"]: r for r in result["requirements"]}["DISP-001"]
        self.assertEqual(
            row["candidate_relation"],
            "TRANSITIVE_IMPORT_SOURCE_MATCH_REVIEW_CANDIDATE",
        )
        self.assertEqual(row["transitive_effect_candidate_txs"], ["DISPUTE_RESOLVE"])
        self.assertEqual(result["requirements_with_transitive_effect_candidates"], 1)
        self.assertTrue(result["gate"].startswith("BLOCKED"))

    def test_require_effect_pin_rejects_unverified_and_wrong_commit(self):
        effects = {
            "source_commit": "0" * 40,
            "source_pin": {"status": "SCANNED_FILES_TRACKED_AND_CLEAN_AT_HEAD"},
            "transaction_count": 2,
            "transactions": [],
        }
        with self.assertRaisesRegex(cg.ContractError, "effect_source_commit_mismatch"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
                require_effect_pin=True,
            )
        effects["source_commit"] = cg.repo_commit(self.repo)
        effects["source_pin"]["status"] = "UNVERIFIED_WORKTREE"
        with self.assertRaisesRegex(cg.ContractError, "effect_source_pin_unverified"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
                require_effect_pin=True,
            )

    def test_authority_write_candidates_join_only_by_source_and_keep_evidence_status(self):
        effects = {
            "source_commit": cg.repo_commit(self.repo),
            "transaction_count": 2,
            "transactions": [
                {
                    "tx_type": "DISPUTE_RESOLVE",
                    "authority_sensitive_write_candidates": [
                        {
                            "state_root": "disputes",
                            "authority_area": "DISPUTE_OR_ENFORCEMENT_REVIEW",
                            "source_path": "Weall-Protocol/src/weall/runtime/apply/dispute.py",
                            "source_function": "apply_dispute",
                            "import_depth": 0,
                            "write_signal": "DIRECT_STATE_ROOT",
                        },
                        {
                            "state_root": "validators",
                            "authority_area": "VALIDATOR_AUTHORITY_REVIEW",
                            "source_path": "Weall-Protocol/src/weall/runtime/unreferenced.py",
                            "source_function": "_change",
                            "import_depth": 1,
                            "write_signal": "MUTABLE_ALIAS_ROOT",
                        },
                    ],
                },
                {"tx_type": "ACCOUNT_LOCK", "authority_sensitive_write_candidates": []},
            ],
        }
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=cg.repo_commit(self.repo),
            effects=effects,
        )
        self.assertEqual(result["authority_sensitive_write_candidate_count"], 2)
        self.assertEqual(result["authority_write_candidates_without_requirement_path_link"], 1)
        linked = next(
            x for x in result["authority_write_review_candidates"] if x["state_root"] == "disputes"
        )
        self.assertEqual(linked["candidate_requirement_ids"], ["DISP-001"])
        self.assertEqual(linked["candidate_requirement_evidence"][0]["test_run_id"], "NOT_RUN")
        self.assertEqual(linked["constitutional_authorization"], "NOT_ESTABLISHED")
        unlinked = next(
            x
            for x in result["authority_write_review_candidates"]
            if x["state_root"] == "validators"
        )
        self.assertEqual(unlinked["candidate_requirement_ids"], [])
        self.assertTrue(unlinked["unlinked_requirement_review_required"])
        reverse = {x["tx_type"]: x for x in result["tx_requirement_candidates"]}
        self.assertEqual(reverse["DISPUTE_RESOLVE"]["authority_sensitive_write_count"], 2)
        self.assertEqual(reverse["ACCOUNT_LOCK"]["authority_sensitive_write_count"], 0)
        with tempfile.TemporaryDirectory() as folder:
            rv.write_results(result, Path(folder))
            csv_text = (Path(folder) / "v2_authority_write_review_candidates.csv").read_text()
            self.assertIn("DISP-001", csv_text)
            self.assertIn("NOT_RUN", csv_text)
            self.assertIn("NOT_ESTABLISHED", csv_text)

    def test_authority_write_candidate_unknown_root_is_rejected(self):
        effects = {
            "transaction_count": 2,
            "transactions": [
                {
                    "tx_type": "DISPUTE_RESOLVE",
                    "authority_sensitive_write_candidates": [
                        {
                            "state_root": "made_up",
                            "authority_area": "VALIDATOR_AUTHORITY_REVIEW",
                            "source_path": "Weall-Protocol/src/weall/runtime/apply/dispute.py",
                        }
                    ],
                },
                {"tx_type": "ACCOUNT_LOCK"},
            ],
        }
        with self.assertRaisesRegex(cg.ContractError, "invalid_authority_write_provenance"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
            )

    def _review_queue_fixture(self):
        path = "Weall-Protocol/src/weall/runtime/apply/dispute.py"
        effects = {
            "source_commit": cg.repo_commit(self.repo),
            "source_pin": {
                "status": "SCANNED_FILES_TRACKED_AND_CLEAN_AT_HEAD",
                "scanned_files": [{"path": path, "sha256": "a" * 64}],
            },
            "transaction_count": 2,
            "transactions": [
                {
                    "tx_type": "DISPUTE_RESOLVE",
                    "authority_sensitive_write_candidates": [
                        {
                            "state_root": "disputes",
                            "authority_area": "DISPUTE_OR_ENFORCEMENT_REVIEW",
                            "source_path": path,
                            "source_function": "apply_dispute",
                            "import_depth": 0,
                            "write_signal": "DIRECT_STATE_ROOT",
                        },
                    ],
                },
                {"tx_type": "ACCOUNT_LOCK", "authority_sensitive_write_candidates": []},
            ],
        }
        return effects

    def test_review_queue_unique_stable_keys_and_unmatched_obligation(self):
        effects = self._review_queue_fixture()
        item = effects["transactions"][0]["authority_sensitive_write_candidates"][0]
        effects["transactions"][0]["authority_sensitive_write_candidates"].append(dict(item))
        effects["transactions"][0]["authority_sensitive_write_candidates"].append(
            {
                **item,
                "state_root": "validators",
                "authority_area": "VALIDATOR_AUTHORITY_REVIEW",
                "source_path": "Weall-Protocol/src/weall/runtime/unmatched.py",
            }
        )
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=cg.repo_commit(self.repo),
            effects=effects,
        )
        queue = result["authority_review_queue"]
        self.assertEqual(result["authority_sensitive_write_candidate_count"], 3)
        self.assertEqual(len(queue), 2)
        self.assertEqual(result["authority_review_queue_unmatched_count"], 1)
        linked = next(q for q in queue if q["state_root"] == "disputes")
        self.assertEqual(linked["candidate_observation_count"], 2)
        self.assertTrue(linked["review_key"].startswith("AWC-"))
        self.assertEqual(linked["source_file_sha256"], "a" * 64)
        self.assertEqual(linked["candidate_requirement_ids"], ["DISP-001"])
        self.assertEqual(linked["submission_status"], "OPEN_NO_REVIEW_SUBMISSION")
        self.assertFalse(linked["review_complete"])
        self.assertEqual(result["independently_authenticated_reviews"], 0)
        unlinked = next(q for q in queue if q["state_root"] == "validators")
        self.assertEqual(unlinked["triage_bucket"], "NO_DECLARED_V2_REQUIREMENT_PATH_MATCH")
        reversed_effects = self._review_queue_fixture()
        baseline = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=cg.repo_commit(self.repo),
            effects=reversed_effects,
        )
        self.assertEqual(linked["review_key"], baseline["authority_review_queue"][0]["review_key"])

    def test_self_reported_review_never_closes_queue_or_authorizes(self):
        effects = self._review_queue_fixture()
        commit = cg.repo_commit(self.repo)
        baseline = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=commit,
            effects=effects,
            require_effect_pin=True,
        )
        key = baseline["authority_review_queue"][0]["review_key"]
        claim = {
            "review_key": key,
            "source_file_sha256": "a" * 64,
            "reviewer_id": "independent-reviewer-fixture",
            "review_decision": "NO_EFFECT_CLAIMED",
            "rationale": "Fixture requires separate independent verification",
            "evidence_ref": "artifacts/fixture-review.txt",
            "evidence_sha256": "b" * 64,
            "requirement_ids": ["DISP-001"],
        }
        payload = {
            "schema": "weall.v2.authority-review-submissions.v0.1",
            "source_commit": commit,
            "records": [claim],
        }
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=commit,
            effects=effects,
            require_effect_pin=True,
            review_submissions=payload,
        )
        q = result["authority_review_queue"][0]
        self.assertEqual(q["submission_status"], "RECORDED_UNAUTHENTICATED_NOT_ADJUDICATED")
        self.assertEqual(result["review_submissions_recorded_unverified"], 1)
        self.assertEqual(result["review_evidence_files_sha256_checked"], 0)
        self.assertEqual(result["review_evidence_submissions_without_byte_checks"], 1)
        self.assertEqual(
            q["evidence_byte_integrity"]["status"],
            "METADATA_ONLY_BYTES_NOT_INSPECTED",
        )
        self.assertEqual(result["authority_review_queue_open_count"], 1)
        self.assertEqual(result["independently_authenticated_reviews"], 0)
        self.assertFalse(q["review_complete"])
        self.assertEqual(q["constitutional_authorization"], "NOT_ESTABLISHED")
        self.assertTrue(result["gate"].startswith("BLOCKED"))
        with tempfile.TemporaryDirectory() as directory:
            rv.write_results(result, Path(directory))
            self.assertIn(key, (Path(directory) / "v2_authority_review_queue.csv").read_text())
            self.assertIn(
                "RECORDED_UNAUTHENTICATED_NOT_ADJUDICATED",
                (Path(directory) / "v2_authority_review_queue.json").read_text(),
            )

    def test_review_submission_stale_unknown_or_authorized_claim_fails_closed(self):
        effects = self._review_queue_fixture()
        commit = cg.repo_commit(self.repo)
        baseline = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=commit,
            effects=effects,
        )
        claim = {
            "review_key": baseline["authority_review_queue"][0]["review_key"],
            "source_file_sha256": "a" * 64,
            "reviewer_id": "review-fixture",
            "review_decision": "EFFECT_CLAIMED",
            "rationale": "Fixture",
            "evidence_ref": "reference/fixture",
            "evidence_sha256": "b" * 64,
            "requirement_ids": ["DISP-001"],
        }
        payload = {
            "schema": "weall.v2.authority-review-submissions.v0.1",
            "source_commit": commit,
            "records": [claim],
        }
        for changed, message in [
            ({"source_commit": "f" * 40}, "invalid_or_stale_review_submission_manifest"),
            (
                {"records": [{**claim, "review_key": "AWC-not-present"}]},
                "unknown_review_candidate_key",
            ),
            ({"records": [claim, claim]}, "duplicate_review_submission"),
            (
                {"records": [{**claim, "review_decision": "AUTHORIZED"}]},
                "unsupported_review_decision",
            ),
            (
                {"records": [{**claim, "source_file_sha256": "c" * 64}]},
                "review_submission_source_digest_mismatch",
            ),
            (
                {"records": [{**claim, "requirement_ids": ["GOV-EXEC-001"]}]},
                "review_submission_unmapped_requirement",
            ),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(cg.ContractError, message):
                    rv.reconcile(
                        self.idx,
                        self.rows,
                        self.tx,
                        self.req,
                        [],
                        checkout_commit=commit,
                        effects=effects,
                        require_effect_pin=True,
                        review_submissions={**payload, **changed},
                    )

    def test_review_submissions_require_pinned_source_scan(self):
        effects = self._review_queue_fixture()
        with self.assertRaisesRegex(cg.ContractError, "review_submissions_require_pinned_effects"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
                review_submissions={
                    "schema": "weall.v2.authority-review-submissions.v0.1",
                    "source_commit": cg.repo_commit(self.repo),
                    "records": [],
                },
            )

    def test_evidence_bytes_verified_without_authorizing_claim(self):
        root = Path(self.tmp.name) / "review_bundle"
        (root / "artifacts").mkdir(parents=True)
        evidence = root / "artifacts" / "review.txt"
        content = b"non-authoritative review fixture: not a passing test"
        evidence.write_bytes(content)
        sha = hashlib.sha256(content).hexdigest()
        effects = self._review_queue_fixture()
        commit = cg.repo_commit(self.repo)
        baseline = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=commit,
            effects=effects,
            require_effect_pin=True,
        )
        claim = {
            "review_key": baseline["authority_review_queue"][0]["review_key"],
            "source_file_sha256": "a" * 64,
            "reviewer_id": "reviewer-fixture-unverified",
            "review_decision": "FALSE_POSITIVE_CLAIMED",
            "rationale": "Synthetic file cannot settle any real authority effects",
            "evidence_ref": "artifacts/review.txt",
            "evidence_sha256": sha,
            "requirement_ids": ["DISP-001"],
        }
        manifest = {
            "schema": "weall.v2.authority-review-submissions.v0.1",
            "source_commit": commit,
            "records": [claim],
        }
        result = rv.reconcile(
            self.idx,
            self.rows,
            self.tx,
            self.req,
            [],
            checkout_commit=commit,
            effects=effects,
            require_effect_pin=True,
            review_submissions=manifest,
            review_evidence_root=root,
        )
        item = result["authority_review_queue"][0]
        self.assertEqual(result["review_evidence_files_sha256_checked"], 1)
        self.assertEqual(result["review_evidence_submissions_without_byte_checks"], 0)
        self.assertEqual(
            item["evidence_byte_integrity"]["status"],
            "LOCAL_BYTES_SHA256_MATCH_NOT_CONTENT_OR_IDENTITY_ATTESTATION",
        )
        self.assertEqual(item["evidence_byte_integrity"]["bytes_read"], len(content))
        self.assertFalse(item["review_complete"])
        self.assertEqual(result["independently_authenticated_reviews"], 0)
        self.assertTrue(result["gate"].startswith("BLOCKED"))
        evidence.write_bytes(content + b"\nTAMPERED")
        with self.assertRaisesRegex(cg.ContractError, "review_evidence_digest_mismatch"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=commit,
                effects=effects,
                require_effect_pin=True,
                review_submissions=manifest,
                review_evidence_root=root,
            )

    def test_evidence_ref_escape_symlink_missing_and_empty_are_rejected(self):
        root = Path(self.tmp.name) / "bundle"
        root.mkdir()
        safe = root / "safe.log"
        safe.write_bytes(b"review")
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_bytes(b"external")
        (root / "linked.log").symlink_to(outside)
        digest = hashlib.sha256(b"review").hexdigest()
        for ref, code in [
            ("../outside.txt", "review_evidence_ref_unsafe"),
            ("/tmp/evidence.log", "review_evidence_ref_unsafe"),
            ("C:/system32", "review_evidence_ref_unsafe"),
            ("./safe.log", "review_evidence_ref_unsafe"),
            ("a//file", "review_evidence_ref_unsafe"),
            ("linked.log", "review_evidence_symlink_rejected"),
            ("absent.log", "review_evidence_file_missing"),
        ]:
            with self.subTest(ref=ref):
                with self.assertRaisesRegex(cg.ContractError, code):
                    rv.verify_review_evidence_file(root, ref, digest)
        safe.write_bytes(b"")
        with self.assertRaisesRegex(cg.ContractError, "review_evidence_size_invalid"):
            rv.verify_review_evidence_file(root, "safe.log", digest)

    def test_review_evidence_root_without_submissions_is_rejected(self):
        effects = self._review_queue_fixture()
        with self.assertRaisesRegex(cg.ContractError, "review_evidence_root_without_submissions"):
            rv.reconcile(
                self.idx,
                self.rows,
                self.tx,
                self.req,
                [],
                checkout_commit=cg.repo_commit(self.repo),
                effects=effects,
                review_evidence_root=Path(self.tmp.name),
            )

    def test_unmatched_triage_preserves_distinct_reading_vs_link(self):
        origins = [
            ("CONTENT_POST_CREATE", "content.py", "P2_REVIEW_NONCE_AND_CONTENT_PERMISSION_EFFECTS"),
            ("ACCOUNT_BAN", "reputation.py", "P0_REVIEW_POSSIBLE_EXCLUSION_AND_REPUTATION_EFFECTS"),
            (
                "BLOCK_REWARD_DISTRIBUTE",
                "rewards.py",
                "P1_REVIEW_BALANCE_AND_ISSUANCE_CONSERVATION",
            ),
            ("CUSTOM", "unknown.py", "UNCLASSIFIED_REVIEW_REQUIRED"),
        ]
        queue = [
            {
                "review_key": "AWC-fixture-" + str(i),
                "source_commit": cg.repo_commit(self.repo),
                "source_file_sha256": "a" * 64,
                "tx_type": tx,
                "state_root": "accounts",
                "source_path": "Weall-Protocol/src/weall/runtime/apply/" + name,
                "source_function": "_apply_fixture",
                "write_signal": "DIRECT_STATE_ROOT",
                "triage_bucket": "NO_DECLARED_V2_REQUIREMENT_PATH_MATCH",
                "candidate_requirement_ids": [],
            }
            for i, (tx, name, _priority) in enumerate(origins)
        ]
        rows = [
            {
                "id": "CONT-001",
                "normative_sentence": "Edits SHALL keep canonical historical receipts.",
                "pdf_page": 15,
                "pdf_row_digest": "c" * 64,
                "implementation_paths": ["src/weall/runtime/apply/social.py"],
                "status": "normative_target",
                "test_run_id": "NOT_RUN",
            },
            {
                "id": "SAN-005",
                "normative_sentence": "Exclusion SHALL require independent review and an appeal path.",
                "pdf_page": 18,
                "pdf_row_digest": "d" * 64,
                "implementation_paths": ["src/weall/runtime/sanctions/"],
                "status": "normative_target",
                "test_run_id": "NOT_RUN",
            },
            {
                "id": "ECO-108",
                "normative_sentence": "New issuance SHALL be divided among buckets.",
                "pdf_page": 21,
                "pdf_row_digest": "e" * 64,
                "implementation_paths": ["src/weall/ledger/issuance.py"],
                "status": "normative_target",
                "test_run_id": "NOT_RUN",
            },
        ]
        triage = rv.build_unmatched_review_triage(queue, rows)
        self.assertEqual(len(triage), 4)
        for item, (_, _, priority) in zip(triage, origins, strict=True):
            self.assertEqual(item["priority"], priority)
            self.assertEqual(item["candidate_requirement_ids"], [])
            self.assertTrue(item["thematic_reading_list_only"])
            self.assertEqual(item["constitutional_authorization"], "NOT_ESTABLISHED")
            self.assertEqual(
                item["triage_disposition"], "OPEN_REQUIRES_HUMAN_SOURCE_AND_NORMATIVE_REVIEW"
            )
        self.assertEqual(triage[0]["thematic_reading_list"][0]["id"], "CONT-001")
        self.assertEqual(
            triage[0]["thematic_reading_list"][0]["normative_sentence"],
            rows[0]["normative_sentence"],
        )
        self.assertEqual(triage[1]["thematic_reading_list"][3]["id"], "SAN-005")
        self.assertEqual(triage[2]["thematic_reading_list"][0]["id"], "ECO-108")
        self.assertEqual(triage[3]["thematic_reading_list"], [])
        self.assertTrue(
            any(
                x["register_presence"] == "ABSENT_REVIEW_REQUIRED"
                for x in triage[0]["thematic_reading_list"]
            )
        )

    def test_unmatched_triage_cannot_hide_new_register_path_match(self):
        path = "Weall-Protocol/src/weall/runtime/apply/content.py"
        queue = [
            {
                "review_key": "AWC-test",
                "source_commit": cg.repo_commit(self.repo),
                "source_file_sha256": "a" * 64,
                "tx_type": "CONTENT_POST_EDIT",
                "state_root": "accounts",
                "source_path": path,
                "source_function": "_apply_post_edit",
                "write_signal": "DIRECT_STATE_ROOT",
                "triage_bucket": "NO_DECLARED_V2_REQUIREMENT_PATH_MATCH",
                "candidate_requirement_ids": [],
            }
        ]
        updated_register = [
            {
                "id": "CONT-001",
                "implementation_paths": [path],
                "normative_sentence": "Test fixture update",
            }
        ]
        with self.assertRaisesRegex(
            cg.ContractError, "unmatched_triage_register_path_changed_reconcile_required"
        ):
            rv.build_unmatched_review_triage(queue, updated_register)

    def test_write_reports_external_only(self):
        a = self.check()
        output = Path(self.tmp.name) / "out"
        rv.write_results(a, output)
        self.assertEqual(len(list(output.iterdir())), 10)
        self.assertIn(
            "DISPUTE_RESOLVE",
            (output / "v2_tx_requirement_candidates.csv").read_text(),
        )
        self.assertIn("DISP-001", (output / "v2_requirement_impact_candidates.csv").read_text())


if __name__ == "__main__":
    unittest.main()
