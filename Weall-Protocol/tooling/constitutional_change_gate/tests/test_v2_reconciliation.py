from __future__ import annotations

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

    def test_write_reports_external_only(self):
        a = self.check()
        output = Path(self.tmp.name) / "out"
        rv.write_results(a, output)
        self.assertEqual(len(list(output.iterdir())), 5)
        self.assertIn(
            "DISPUTE_RESOLVE",
            (output / "v2_tx_requirement_candidates.csv").read_text(),
        )
        self.assertIn("DISP-001", (output / "v2_requirement_impact_candidates.csv").read_text())


if __name__ == "__main__":
    unittest.main()
