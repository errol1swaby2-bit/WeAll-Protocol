"""Independent miniature Git histories exercise complete file/path detection."""

from __future__ import annotations
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repository_coverage as gate


class RepositoryCoverageTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.repo = Path(self.t.name) / "r"
        self.repo.mkdir()
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "ci@example.invalid")
        self.run_git("config", "user.name", "Coverage Fixture")
        self.write("Weall-Protocol/src/weall/runtime/executor.py", "print(1)\n")
        self.write("web/src/App.tsx", "export default 1\n")
        self.write("Weall-Protocol/configs/genesis.json", "{}\n")
        self.write("scripts/fresh_clone_smoke.sh", "echo smoke\n")
        self.write("Weall-Protocol/requirements.lock", "pin\n")
        self.write(".github/workflows/check.yml", "name: check\n")
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "initial")
        self.base = self.sha()

    def run_git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def sha(self):
        return self.run_git("rev-parse", "HEAD")

    def write(self, p, content):
        path = self.repo / p
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "modify")
        return self.sha()

    def test_complete_inventory_including_configuration(self):
        out = gate.report(self.repo, self.base, self.sha())
        self.assertEqual(out["tracked_file_count"], 6)
        self.assertEqual(out["classified_file_count"], 6)
        self.assertEqual(out["coverage_gate"], "PASS_FILE_CLASSIFICATION_ONLY")
        self.assertEqual(out["changed_entry_count"], 0)
        self.assertEqual(len(out["report_sha256"]), 64)

    def test_renamed_deleted_added_and_modified_visible(self):
        self.run_git("mv", "web/src/App.tsx", "web/src/Proposal.tsx")
        (self.repo / "Weall-Protocol/requirements.lock").unlink()
        self.write("Weall-Protocol/configs/genesis.json", '{"changed": true}\n')
        self.write("docker/new.Dockerfile", "FROM scratch\n")
        head = self.commit()
        out = gate.report(self.repo, self.base, head)
        changes = out["changes"]
        self.assertEqual(len(changes), 4)
        self.assertEqual(set(x["status"][0] for x in changes), set("ARMD"))
        self.assertEqual(
            next(x for x in changes if x["status"].startswith("R"))["previous_path"],
            "web/src/App.tsx",
        )
        self.assertEqual(out["coverage_gate"], "PASS_FILE_CLASSIFICATION_ONLY")
        self.assertIn(
            "locked_reproducibility",
            next(x for x in changes if x["status"] == "D")["review_obligations"],
        )

    def test_unknown_path_fails_closed(self):
        self.write("unexpected/authority_switch.rs", "privilege\n")
        head = self.commit()
        out = gate.report(self.repo, self.base, head)
        self.assertEqual(out["coverage_gate"], "BLOCKED_UNCLASSIFIED")
        self.assertEqual(out["unclassified_changed_paths"], ["unexpected/authority_switch.rs"])
        self.assertEqual(out["unclassified_paths"], ["unexpected/authority_switch.rs"])

    def test_unknown_previous_rename_path_blocks_change(self):
        self.write("unlisted/old.py", "unchanged content\n")
        old_head = self.commit()
        self.run_git("mv", "unlisted/old.py", "web/src/exposed.ts")
        new_head = self.commit()
        out = gate.report(self.repo, old_head, new_head)
        self.assertEqual(out["classified_file_count"], out["tracked_file_count"])
        self.assertEqual(out["coverage_gate"], "BLOCKED_UNCLASSIFIED")
        self.assertEqual(out["unclassified_changed_paths"], ["web/src/exposed.ts"])
        self.assertEqual(out["changes"][0]["classifications"], ["frontend", "UNCLASSIFIED"])

    def test_symlink_not_treated_as_complete_file_coverage(self):
        (self.repo / "web/src/link.ts").symlink_to("App.tsx")
        head = self.commit()
        out = gate.report(self.repo, self.base, head)
        self.assertEqual(out["coverage_gate"], "BLOCKED_UNCLASSIFIED")
        self.assertIn("web/src/link.ts", out["unclassified_paths"])

    def test_head_must_match_actual_checkout(self):
        self.write("web/src/a.ts", "one\n")
        head = self.commit()
        with self.assertRaises(gate.CoverageError):
            gate.report(self.repo, self.base, self.base)
        self.assertEqual(gate.report(self.repo, self.base, head)["source_commit"], head)

    def test_critical_paths_classified(self):
        examples = {
            "Weall-Protocol/configs/consensus_profiles/weall-prod.json": "chain_config",
            "Weall-Protocol/requirements-dev.lock": "dependencies",
            "Weall-Protocol/docker-compose.prod.yml": "deployment",
            "scripts/fresh_clone_smoke.sh": "deployment",
            "web/vite.config.ts": "frontend_build",
            "Weall-Protocol/generated/v2/tx_contract_matrix.json": "generated",
            "Weall-Protocol/specs/tx_canon/tx_canon.yaml": "specification",
            "Weall-Protocol/src/weall/runtime/apply/reputation.py": "consensus_runtime",
        }
        for p, expected in examples.items():
            self.assertEqual(gate.classify(p), expected)
        for bad in ("../../secrets", "/absolute", "a//b", "unknown/new_critical.py"):
            self.assertIsNone(gate.classify(bad))


if __name__ == "__main__":
    unittest.main()
