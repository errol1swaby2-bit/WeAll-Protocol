"""Candidate semantic joins must preserve missing/stale edges as review blockers."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import semantic_impact_candidates as semantic


class SemanticImpactFixture(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.repo = self.root / "r"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "ci@example.invalid")
        self.executor = "Weall-Protocol/src/weall/runtime/executor.py"
        self.frontend = "web/src/App.tsx"
        self.cfg = "Weall-Protocol/configs/chain.json"
        self.write(self.executor, "ORIGINAL\n")
        self.write(self.frontend, "APP\n")
        self.write("Weall-Protocol/generated/v2/current_tx_canon.json", "{}\n")
        self.set_registers(
            [
                self.row(
                    "src/weall/runtime/executor.py",
                    self.executor,
                    ["M-018", "TX-0001", "STATE-0001"],
                ),
                self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
            ]
        )
        self.commit()
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def write(self, path, content):
        f = self.repo / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)

    def digest(self, path):
        return hashlib.sha256((self.repo / path).read_bytes()).hexdigest()

    def row(self, v2, physical, mappings):
        return {"path": v2, "sha256": self.digest(physical), "mappings": mappings}

    def set_registers(self, rows):
        prefix = "Weall-Protocol/generated/v2/"
        registry = "Weall-Protocol/specs/v2/source/source_mappings.json"
        if not (self.repo / registry).is_file():
            self.write(
                registry,
                json.dumps(
                    {
                        "schema": "weall.v2.source_mapping_registry",
                        "mappings": [],
                    }
                ),
            )
        output = "generated/v2/current_tx_canon.json"
        self.write(
            "Weall-Protocol/specs/v2/source/manifest.json", json.dumps({"outputs": [output]})
        )
        self.write(
            prefix + "spec_compilation_manifest.json",
            json.dumps(
                {
                    "schema": "weall.v2.spec_compilation_manifest",
                    "output_hashes": {output: self.digest("Weall-Protocol/" + output)},
                }
            ),
        )
        self.write(
            prefix + "source_coverage_map.json",
            json.dumps(
                {
                    "schema": "weall.v2.source_coverage_map",
                    "file_count": len(rows),
                    "files": rows,
                    "unmapped": [],
                    "unmapped_count": 0,
                }
            ),
        )
        self.write(
            prefix + "mechanism_registry.json",
            json.dumps(
                {
                    "count": 2,
                    "rows": [
                        {
                            "id": "M-018",
                            "title": "Consensus",
                            "required_evidence": ["replay"],
                            "specification_sections": ["S1"],
                        },
                        {
                            "id": "M-069",
                            "title": "Frontend",
                            "required_evidence": ["browser"],
                            "specification_sections": ["S2"],
                        },
                    ],
                }
            ),
        )
        self.write(
            prefix + "tx_contract_matrix.json",
            json.dumps(
                {
                    "schema": "weall.v2.tx_contract_matrix",
                    "transaction_count": 1,
                    "rows": [{"stable_id": "TX-0001", "tx_type": "TEST_TX"}],
                }
            ),
        )
        self.write(
            prefix + "requirement_traceability.json",
            json.dumps(
                {
                    "schema": "weall.v2.requirement_traceability",
                    "count": 2,
                    "rows": [
                        {
                            "id": "R-001",
                            "implementation_paths": ["src/weall/runtime/executor.py"],
                            "contract_ids": ["TX-0001"],
                        },
                        {
                            "id": "R-002",
                            "implementation_paths": ["../web/src/App.tsx"],
                            "contract_ids": [],
                        },
                    ],
                }
            ),
        )

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture update")
        return self.git("rev-parse", "HEAD")

    def test_modified_tx_source_and_unmapped_config_are_explicit(self):
        self.write(self.executor, "MODIFIED\n")
        self.write(self.cfg, '{"id":1}\n')
        self.set_registers(
            [
                self.row(
                    "src/weall/runtime/executor.py",
                    self.executor,
                    ["M-018", "TX-0001", "STATE-0001"],
                ),
                self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
            ]
        )
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        self.assertEqual(
            result["semantic_review_gate"],
            "BLOCKED_PENDING_TRANSITIVE_TRACING_EXACT_RUNS_AND_INDEPENDENT_ADJUDICATION",
        )
        self.assertIn(self.cfg, result["critical_unmapped_change_paths"])
        self.assertIn(self.cfg, result["global_semantic_inventory"]["unlinked_paths"])
        self.assertEqual(
            result["global_semantic_inventory"]["status"],
            "BLOCKED_OPEN_WHOLE_REPOSITORY_SEMANTIC_BACKLOG",
        )
        affected = next(x for x in result["changes"] if x["change"]["path"] == self.executor)
        link = affected["candidate_links"][0]
        self.assertEqual(link["candidate_txs"][0]["stable_id"], "TX-0001")
        self.assertEqual(link["candidate_mechanisms"][0]["id"], "M-018")
        self.assertEqual(link["direct_requirement_ids"], ["R-001"])
        self.assertEqual(link["source_digest_status"], "MATCH_EXACT_HEAD_BYTES")
        self.assertEqual(result["reviewed_semantic_edges"], 0)

    def test_digest_drift_is_not_silently_accepted(self):
        self.write(self.executor, "DRIFTED\n")
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        src = next(x for x in result["changes"] if x["change"]["path"] == self.executor)[
            "candidate_links"
        ][0]
        self.assertEqual(src["source_digest_status"], "STALE_SHA256_SOURCE_CANDIDATE")
        self.assertIn(self.executor, result["stale_sha256_source_paths"])

    def test_rename_reads_before_side_from_base_and_keeps_unlinked_after(self):
        self.git("mv", self.frontend, "web/src/Renamed.tsx")
        # Current derived register must no longer claim the deleted old path.
        # The base register remains available for before-side impact.
        self.set_registers(
            [
                self.row(
                    "src/weall/runtime/executor.py",
                    self.executor,
                    ["M-018", "TX-0001", "STATE-0001"],
                ),
            ]
        )
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        entry = next(x for x in result["changes"] if x["change"]["status"].startswith("R"))
        self.assertEqual(entry["candidate_links"][0]["side"], "after")
        self.assertEqual(
            entry["candidate_links"][0]["v2_link_status"], "NO_DECLARED_SOURCE_EDGE_REVIEW_REQUIRED"
        )
        self.assertEqual(entry["candidate_links"][1]["side"], "before")
        self.assertEqual(entry["candidate_links"][1]["candidate_mechanisms"][0]["id"], "M-069")

    def test_register_ghost_mapping_is_rejected(self):
        self.set_registers(
            [{"path": "src/weall/runtime/ghost.py", "sha256": "0" * 64, "mappings": ["M-018"]}]
        )
        head = self.commit()
        with self.assertRaisesRegex(semantic.ImpactError, "source_register_ghost_path"):
            semantic.semantic_report(self.repo, self.base, head)

    def test_unknown_mechanism_rejected(self):
        self.write(self.executor, "MODIFIED\n")
        self.set_registers(
            [
                self.row("src/weall/runtime/executor.py", self.executor, ["M-999"]),
                self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
            ]
        )
        head = self.commit()
        with self.assertRaisesRegex(semantic.ImpactError, "unresolved_v2_edge_ids"):
            semantic.semantic_report(self.repo, self.base, head)

    def test_declared_derivative_requires_compiler_digest_and_review(self):
        output = "Weall-Protocol/generated/v2/current_tx_canon.json"
        self.write(output, '{"changed":true}\n')
        self.set_registers(
            [
                self.row(
                    "src/weall/runtime/executor.py",
                    self.executor,
                    ["M-018", "TX-0001", "STATE-0001"],
                ),
                self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
            ]
        )
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        self.assertIn(output, result["declared_compiler_derivative_paths"])
        self.assertNotIn(output, result["global_semantic_inventory"]["unlinked_paths"])
        self.assertNotIn(output, result["unmapped_change_paths"])
        entry = next(x for x in result["changes"] if x["change"]["path"] == output)
        self.assertEqual(
            entry["candidate_links"][0]["source_digest_status"], "MATCH_DECLARED_COMPILATION_HASH"
        )
        self.assertEqual(entry["candidate_links"][0]["candidate_txs"], [])
        self.assertEqual(entry["semantic_disposition"], "OPEN_UNREVIEWED_POTENTIAL_IMPACT")

    def test_explicit_unscanned_script_mapping_stays_review_only(self):
        path = "Weall-Protocol/tooling/validate.sh"
        self.write(path, "echo validation\n")
        self.write(
            "Weall-Protocol/specs/v2/source/source_mappings.json",
            json.dumps(
                {
                    "schema": "weall.v2.source_mapping_registry",
                    "mappings": [
                        {
                            "path": "tooling/validate.sh",
                            "primary_mechanism_id": "M-018",
                            "classification": "verification_tooling",
                        }
                    ],
                }
            ),
        )
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        self.assertIn(path, result["declared_unscanned_source_paths"])
        self.assertNotIn(path, result["global_semantic_inventory"]["unlinked_paths"])
        self.assertNotIn(path, result["unmapped_change_paths"])
        item = next(x for x in result["changes"] if x["change"]["path"] == path)
        link = item["candidate_links"][0]
        self.assertEqual(link["v2_link_status"], "DECLARED_UNSCANNED_SOURCE_MAPPING_UNREVIEWED")
        self.assertEqual(link["candidate_mechanisms"][0]["id"], "M-018")
        self.assertEqual(result["reviewed_semantic_edges"], 0)

    def test_unlinked_shell_script_is_observed_not_approved(self):
        launcher = "Weall-Protocol/scripts/operator_boot.sh"
        other = "Weall-Protocol/scripts/preflight.sh"
        self.write(other, "echo checks\n")
        self.write(
            launcher,
            "#!/bin/sh\n"
            "WEALL_MODE=prod\n"
            'bash "${SCRIPT_DIR}/preflight.sh"\n'
            'rm -rf "${WEALL_DEVNET_DIR}"\n',
        )
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        observed = result["global_semantic_inventory"]["operational_static_candidates"]
        self.assertEqual(observed["status"], "UNREVIEWED_STATIC_CANDIDATES_NOT_SEMANTIC_CLOSURE")
        row = next(x for x in observed["files"] if x["path"] == launcher)
        self.assertIn(other, row["possible_dependencies"])
        self.assertTrue(
            any(
                x["target"] == other and x["kind"] == "SCRIPT_DIR_PATH"
                for x in row["dependency_evidence"]
            )
        )
        self.assertIn("WEALL_MODE", row["environment_tokens"])
        self.assertIn("recursive_delete_command_present", row["hazard_observations"])
        self.assertEqual(row["review_status"], "OPEN_UNADJUDICATED")
        self.assertIn(launcher, result["global_semantic_inventory"]["unlinked_paths"])

    def test_binary_priority_file_never_claims_dependencies(self):
        path = "Weall-Protocol/configs/binary.dat"
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"src/weall/runtime/executor.py\x00")
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        row = next(
            x
            for x in result["global_semantic_inventory"]["operational_static_candidates"]["files"]
            if x["path"] == path
        )
        self.assertEqual(row["scan_status"], "UNINSPECTED_BINARY")
        self.assertEqual(row["possible_dependencies"], [])
        self.assertEqual(row["review_status"], "OPEN_UNADJUDICATED")

    def test_reverse_literal_dependencies_are_candidates_only(self):
        import operational_impact as ops

        rows = [
            {
                "path": "Weall-Protocol/scripts/preflight.sh",
                "possible_dependencies": [
                    "Weall-Protocol/configs/chain.json",
                ],
            },
            {
                "path": "Weall-Protocol/scripts/boot.sh",
                "possible_dependencies": [
                    "Weall-Protocol/scripts/preflight.sh",
                ],
            },
        ]
        result = ops.reverse_candidates(
            [
                {"path": "Weall-Protocol/configs/chain.json", "previous_path": None},
            ],
            rows,
        )
        self.assertEqual(
            result[0]["candidate_upstream_dependents"],
            [
                {"path": "Weall-Protocol/scripts/preflight.sh", "minimum_literal_hops": 1},
                {"path": "Weall-Protocol/scripts/boot.sh", "minimum_literal_hops": 2},
            ],
        )
        self.assertEqual(
            result[0]["semantic_status"], "UNREVIEWED_LITERAL_CANDIDATE_NO_CAUSALITY_PROVEN"
        )

    def test_operational_source_anchor_drift_blocks_candidate_assertion(self):
        import operational_boundary_review as boundary

        case = boundary.CASES[1]  # IPFS partition recovery
        source = "\n".join(["#!/bin/bash"] + list(case["anchors"]))
        reproduced = boundary.adjudicate(case, source, "a" * 64)
        self.assertEqual(reproduced["status"], "OPEN_SOURCE_ANCHORS_REPRODUCED")
        self.assertEqual([e["observed"]["line"] for e in reproduced["evidence"]], [2, 3, 4])
        self.assertEqual(reproduced["semantic_authorization"], "NOT_ESTABLISHED")
        drifted = boundary.adjudicate(case, source.replace("rm -rf", "echo"), "b" * 64)
        self.assertEqual(drifted["status"], "BLOCKED_SOURCE_ANCHOR_MISSING_OR_CHANGED")
        self.assertIsNone(drifted["evidence"][-1]["observed"])

    def test_path_traversal_rejected(self):
        for raw in ("../../secrets", "../other/private", "/abs", "src//bad.py"):
            with self.assertRaises(semantic.ImpactError):
                semantic.normalize_v2_path(raw)
        self.assertEqual(semantic.normalize_v2_path("../web/src/App.tsx"), "web/src/App.tsx")


if __name__ == "__main__":
    unittest.main()
