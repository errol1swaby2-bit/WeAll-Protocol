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
        self.set_registers([
            self.row("src/weall/runtime/executor.py", self.executor,
                     ["M-018", "TX-0001", "STATE-0001"]),
            self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
        ])
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
        self.write(prefix + "source_coverage_map.json", json.dumps({
            "schema": "weall.v2.source_coverage_map", "file_count": len(rows),
            "files": rows, "unmapped": [], "unmapped_count": 0,
        }))
        self.write(prefix + "mechanism_registry.json", json.dumps({
            "count": 2, "rows": [
                {"id": "M-018", "title": "Consensus", "required_evidence": ["replay"],
                 "specification_sections": ["S1"]},
                {"id": "M-069", "title": "Frontend", "required_evidence": ["browser"],
                 "specification_sections": ["S2"]},
            ]
        }))
        self.write(prefix + "tx_contract_matrix.json", json.dumps({
            "schema": "weall.v2.tx_contract_matrix", "transaction_count": 1,
            "rows": [{"stable_id": "TX-0001", "tx_type": "TEST_TX"}],
        }))
        self.write(prefix + "requirement_traceability.json", json.dumps({
            "schema": "weall.v2.requirement_traceability", "count": 2,
            "rows": [
                {"id": "R-001", "implementation_paths": ["src/weall/runtime/executor.py"],
                 "contract_ids": ["TX-0001"]},
                {"id": "R-002", "implementation_paths": ["../web/src/App.tsx"],
                 "contract_ids": []},
            ],
        }))

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture update")
        return self.git("rev-parse", "HEAD")

    def test_modified_tx_source_and_unmapped_config_are_explicit(self):
        self.write(self.executor, "MODIFIED\n")
        self.write(self.cfg, '{"id":1}\n')
        self.set_registers([
            self.row("src/weall/runtime/executor.py", self.executor,
                     ["M-018", "TX-0001", "STATE-0001"]),
            self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
        ])
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        self.assertEqual(result["semantic_review_gate"],
                         "BLOCKED_PENDING_TRANSITIVE_TRACING_EXACT_RUNS_AND_INDEPENDENT_ADJUDICATION")
        self.assertIn(self.cfg, result["critical_unmapped_change_paths"])
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
        src = next(x for x in result["changes"]
                   if x["change"]["path"] == self.executor)["candidate_links"][0]
        self.assertEqual(src["source_digest_status"], "STALE_SHA256_SOURCE_CANDIDATE")
        self.assertIn(self.executor, result["stale_sha256_source_paths"])

    def test_rename_reads_before_side_from_base_and_keeps_unlinked_after(self):
        self.git("mv", self.frontend, "web/src/Renamed.tsx")
        head = self.commit()
        result = semantic.semantic_report(self.repo, self.base, head)
        entry = next(x for x in result["changes"] if x["change"]["status"].startswith("R"))
        self.assertEqual(entry["candidate_links"][0]["side"], "after")
        self.assertEqual(entry["candidate_links"][0]["v2_link_status"],
                         "NO_DECLARED_SOURCE_EDGE_REVIEW_REQUIRED")
        self.assertEqual(entry["candidate_links"][1]["side"], "before")
        self.assertEqual(entry["candidate_links"][1]["candidate_mechanisms"][0]["id"], "M-069")

    def test_register_ghost_mapping_is_rejected(self):
        self.set_registers([{"path": "src/weall/runtime/ghost.py",
                             "sha256": "0" * 64, "mappings": ["M-018"]}])
        head = self.commit()
        with self.assertRaisesRegex(semantic.ImpactError, "source_register_ghost_path"):
            semantic.semantic_report(self.repo, self.base, head)

    def test_unknown_mechanism_rejected(self):
        self.write(self.executor, "MODIFIED\n")
        self.set_registers([
            self.row("src/weall/runtime/executor.py", self.executor, ["M-999"]),
            self.row("../web/src/App.tsx", self.frontend, ["M-069"]),
        ])
        head = self.commit()
        with self.assertRaisesRegex(semantic.ImpactError, "unresolved_v2_edge_ids"):
            semantic.semantic_report(self.repo, self.base, head)

    def test_path_traversal_rejected(self):
        for raw in ("../../secrets", "../other/private", "/abs", "src//bad.py"):
            with self.assertRaises(semantic.ImpactError):
                semantic.normalize_v2_path(raw)
        self.assertEqual(semantic.normalize_v2_path("../web/src/App.tsx"),
                         "web/src/App.tsx")


if __name__ == "__main__":
    unittest.main()
