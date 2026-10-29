from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import weall_change_gate as cg


def mk_repo(base: Path) -> Path:
    repo = base / "repo"
    api = repo / "Weall-Protocol/src/weall/runtime"
    (api / "apply").mkdir(parents=True)
    (repo / "Weall-Protocol/generated").mkdir(parents=True)
    (api / "apply/dispute.py").write_text(
        """DISPUTE_TX_TYPES: set[str] = {"DISPUTE_RESOLVE"}\ndef apply_dispute(state, env):\n    return True\n"""
    )
    (api / "apply/identity.py").write_text(
        """IDENTITY_TX_TYPES: frozenset[str] = frozenset({"ACCOUNT_LOCK"})\ndef apply_identity(state, env):\n    return True\n"""
    )
    (
        api / "tx_contracts.py"
    ).write_text("""from weall.runtime.apply.dispute import DISPUTE_TX_TYPES, apply_dispute
from weall.runtime.apply.identity import IDENTITY_TX_TYPES, apply_identity
HANDLER_REGISTRY: tuple = (
    ("dispute", apply_dispute, frozenset(DISPUTE_TX_TYPES)),
    ("identity", apply_identity, IDENTITY_TX_TYPES),
)
""")
    (api / "tx_schema.py").write_text("""class DisputeResolvePayload: pass
class AccountLockPayload: pass
TX_PAYLOADS: dict = {
    "DISPUTE_RESOLVE": DisputeResolvePayload,
    "ACCOUNT_LOCK": AccountLockPayload,
}
""")
    txs = [
        {
            "name": "DISPUTE_RESOLVE",
            "id": "a",
            "domain": "Dispute",
            "origin": "SYSTEM",
            "context": "block",
        },
        {
            "name": "ACCOUNT_LOCK",
            "id": "b",
            "domain": "Identity",
            "origin": "SYSTEM",
            "context": "block",
        },
    ]
    (repo / cg.INDEX).write_text(
        json.dumps(
            {
                "tx_types": txs,
                "by_name": {"DISPUTE_RESOLVE": 0, "ACCOUNT_LOCK": 1},
                "by_id": {"43": 0, "44": 1},
                "meta": {"version": "fixture"},
            }
        )
    )
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "fixture"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    return repo


class TestGate(unittest.TestCase):
    def setUp(self):
        self.ctx = tempfile.TemporaryDirectory()
        self.base = Path(self.ctx.name)
        self.repo = mk_repo(self.base)
        self.rows = cg.extract_routes(self.repo)
        self.policy = cg.load_policy()

    def tearDown(self):
        self.ctx.cleanup()

    def test_one_to_one_route_and_numeric_keys(self):
        self.assertEqual(set(self.rows), {"ACCOUNT_LOCK", "DISPUTE_RESOLVE"})
        self.assertEqual(self.rows["DISPUTE_RESOLVE"]["repository_numeric_keys"], ["43"])
        self.assertEqual(
            self.rows["ACCOUNT_LOCK"]["source_path"],
            "Weall-Protocol/src/weall/runtime/apply/identity.py",
        )

    def test_domain_change_triggers_other_domains_and_authority_requirements(self):
        a = cg.impacted_paths(
            self.repo, self.rows, ["Weall-Protocol/src/weall/runtime/apply/dispute.py"], self.policy
        )
        self.assertEqual(a["tx_types"], ["DISPUTE_RESOLVE"])
        self.assertIn("Identity", a["affected_domains"])
        self.assertIn("C-II-4", [x["id"] for x in a["requirements"]])
        self.assertIn("E-DISPUTE-003", [x["id"] for x in a["requirements"]])

    def test_shared_consensus_change_triggers_all(self):
        a = cg.impacted_paths(
            self.repo, self.rows, ["Weall-Protocol/src/weall/runtime/block_builder.py"], self.policy
        )
        self.assertEqual(len(a["tx_types"]), 2)

    def test_unknown_path_never_silent_pass(self):
        a = cg.impacted_paths(self.repo, self.rows, ["new-unmapped-special-layer.rs"], self.policy)
        self.assertEqual(a["unmapped_paths"], ["new-unmapped-special-layer.rs"])
        x = cg.evaluate_evidence(a, None, cg.repo_commit(self.repo), None)
        self.assertEqual(x["gate_decision"], "BLOCKED")

    def test_empty_manifest_blocks_gate(self):
        a = cg.impacted_paths(
            self.repo, self.rows, ["Weall-Protocol/src/weall/runtime/apply/dispute.py"], self.policy
        )
        x = cg.evaluate_evidence(a, None, cg.repo_commit(self.repo), None)
        self.assertIn("ACC-003", x["missing_requirement_evidence"])
        self.assertEqual(x["gate_decision"], "BLOCKED")

    def test_evidence_wrong_digest_rejected(self):
        a = cg.impacted_paths(
            self.repo, self.rows, ["Weall-Protocol/src/weall/runtime/apply/dispute.py"], self.policy
        )
        ev = self.base / "evidence.json"
        ev.write_text(
            json.dumps(
                {
                    "claims": [
                        {
                            "requirement_id": "ACC-003",
                            "commit_sha": cg.repo_commit(self.repo),
                            "result": "PASS",
                            "exit_code": 0,
                            "evidence_class": "canonical_index_roundtrip",
                            "independent_reviewer": "external",
                            "test_id": "test_A",
                            "command": "pytest",
                            "timestamp_utc": "2026-10-28T21:00:00Z",
                            "run_id": "local1",
                            "log_path": "test.log",
                            "log_sha256": "0" * 64,
                        }
                    ]
                }
            )
        )
        x = cg.evaluate_evidence(a, ev, cg.repo_commit(self.repo), "owner")
        self.assertIn(
            "log_missing_or_digest_mismatch_or_unsafe_path",
            [e["reason"] for e in x["invalid_claims"]],
        )

    def test_double_handler_blocks_generation(self):
        p = self.repo / "Weall-Protocol/src/weall/runtime/tx_contracts.py"
        p.write_text(
            p.read_text().replace(
                '("identity", apply_identity, IDENTITY_TX_TYPES),',
                '("identity", apply_identity, IDENTITY_TX_TYPES),\n    ("duplicate", apply_identity, frozenset({"DISPUTE_RESOLVE"})),',
            )
        )
        with self.assertRaisesRegex(cg.ContractError, "handler_cardinality"):
            cg.extract_routes(self.repo)

    def test_missing_schema_blocks_generation(self):
        p = self.repo / "Weall-Protocol/src/weall/runtime/tx_schema.py"
        p.write_text(p.read_text().replace('"ACCOUNT_LOCK": AccountLockPayload,', ""))
        with self.assertRaisesRegex(cg.ContractError, "schema_missing"):
            cg.extract_routes(self.repo)

    def test_cli_build_and_impact_writes_outside_checkout(self):
        out = self.base / "output"
        rc = cg.main(["build", "--repo", str(self.repo), "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertEqual(
            len(json.loads((out / "tx_implementation_matrix.json").read_text())["transactions"]), 2
        )
        self.assertEqual(
            json.loads((out / "tx_effect_candidates.json").read_text())["transaction_count"], 2
        )
        rc = cg.main(
            [
                "impact",
                "--repo",
                str(self.repo),
                "--out",
                str(out),
                "--changed",
                "Weall-Protocol/src/weall/runtime/apply/dispute.py",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertIn("E-DISPUTE-003", (out / "impact.md").read_text())

    def test_gate_fails_without_evidence(self):
        rc = cg.main(
            [
                "gate",
                "--repo",
                str(self.repo),
                "--out",
                str(self.base / "output"),
                "--changed",
                "Weall-Protocol/src/weall/runtime/apply/dispute.py",
            ]
        )
        self.assertEqual(rc, 2)

    def test_cannot_write_inside_checkout(self):
        with self.assertRaisesRegex(cg.ContractError, "outside_repository"):
            cg.main(["build", "--repo", str(self.repo), "--out", str(self.repo / "generated")])

    def test_existing_contract_map_is_reconciled(self):
        p = self.repo / "Weall-Protocol/generated/tx_contract_map.json"
        arr = [
            {
                "tx_type": n,
                "handler": r["handler"],
                "claim_count": 1,
                "schema_covered": True,
                "unsupported": False,
                "domain": r["domain"],
                "origin": r["origin"],
                "context": r["context"],
            }
            for n, r in sorted(self.rows.items())
        ]
        p.write_text(json.dumps({"contracts": arr, "summary": {"total": 2}}))
        again = cg.extract_routes(self.repo)
        self.assertEqual(
            {v["existing_contract_map_status"] for v in again.values()},
            {"MATCHED_SOURCE_DERIVATIVE"},
        )
        arr[0]["claim_count"] = 0
        p.write_text(json.dumps({"contracts": arr}))
        with self.assertRaisesRegex(cg.ContractError, "existing_contract_map_disagrees"):
            cg.extract_routes(self.repo)

    def test_dot_github_is_preserved_and_triggers_shared_review(self):
        a = cg.impacted_paths(self.repo, self.rows, [".github/workflows/backend.yml"], self.policy)
        self.assertEqual(a["unmapped_paths"], [])
        self.assertEqual(a["changed_paths"][0]["path"], ".github/workflows/backend.yml")
        self.assertEqual(len(a["tx_types"]), 2)

    def test_partial_evidence_classes_never_close_requirement(self):
        a = cg.impacted_paths(
            self.repo, self.rows, ["Weall-Protocol/src/weall/runtime/apply/dispute.py"], self.policy
        )
        ev = self.base / "evidence.json"
        (self.base / "good.log").write_text("1 passed\n")
        claim = {
            "requirement_id": "ACC-003",
            "evidence_class": "canonical_index_roundtrip",
            "commit_sha": cg.repo_commit(self.repo),
            "result": "PASS",
            "exit_code": 0,
            "independent_reviewer": "third_party",
            "test_id": "t1",
            "command": "pytest",
            "timestamp_utc": "2026-10-28T21:00:00Z",
            "run_id": "one",
            "log_path": "good.log",
            "log_sha256": cg.digest(self.base / "good.log"),
        }
        ev.write_text(json.dumps({"claims": [claim]}))
        res = cg.evaluate_evidence(a, ev, cg.repo_commit(self.repo), "owner")
        self.assertIn("canonical_index_roundtrip", res["validated_classes"]["ACC-003"])
        self.assertIn(
            "replay_and_api_surface_review", res["missing_requirement_evidence"]["ACC-003"]
        )
        self.assertEqual(res["gate_decision"], "BLOCKED")

    def test_static_effect_trace_follows_local_route_not_unrelated_functions(self):
        filename = self.repo / "Weall-Protocol/src/weall/runtime/apply/dispute.py"
        filename.write_text(
            'DISPUTE_TX_TYPES: set[str] = {"DISPUTE_RESOLVE"}\n'
            'def _apply_resolve(state, env):\n'
            '    value = state.get("cases")\n'
            '    state["cases"] = {}\n'
            '    cases = value or {}\n'
            '    cases["marker"] = True\n'
            '    _enforce_lock(state)\n'
            '    return state\n'
            'def _enforce_lock(state):\n'
            '    state.setdefault("locks", {})\n'
            '    return state\n'
            'def _not_reachable(state):\n'
            '    state["unrelated"] = True\n'
            'def apply_dispute(state, env):\n'
            '    t = env.tx_type\n'
            '    if t == "DISPUTE_RESOLVE":\n'
            '        return _apply_resolve(state, env)\n'
            '    return None\n'
        )
        rows = cg.extract_routes(self.repo)
        report = cg.trace_effect_candidates(self.repo, rows)
        t = {x["tx_type"]: x for x in report["transactions"]}["DISPUTE_RESOLVE"]
        self.assertEqual(t["anchor_function"], "_apply_resolve")
        self.assertIn("_enforce_lock", t["local_functions_visited"])
        self.assertNotIn("_not_reachable", t["local_functions_visited"])
        self.assertIn("cases", t["direct_state_root_read_candidates"])
        self.assertIn("cases", t["direct_state_root_write_candidates"])
        self.assertIn("locks", t["direct_state_root_write_candidates"])
        self.assertNotIn("unrelated", t["direct_state_root_write_candidates"])
        self.assertGreaterEqual(t["potential_alias_write_sites"], 1)
        self.assertIn("_enforce_lock", t["authority_name_signals"])
        self.assertFalse(report["invariants"]["runtime_authorization_verified"])

    def test_scheduler_inventory_is_separate_from_transaction_causality(self):
        fn = self.repo / "Weall-Protocol/src/weall/runtime/scheduler_pipeline.py"
        fn.write_text(
            'def run_leader_pre_schedulers(state):\n'
            '    schedulers.tick_dispute_lifecycle(state)\n'
            'def run_replay_pre_schedulers(state):\n'
            '    schedulers.tick_dispute_lifecycle(state)\n'
        )
        report = cg.trace_effect_candidates(self.repo, self.rows)
        names = {x["function"] for x in report["scheduler_inventory"]}
        self.assertEqual(names, {"run_leader_pre_schedulers", "run_replay_pre_schedulers"})
        self.assertTrue(
            all(
                x["static_call_sites"][0]["target"] == "schedulers.tick_dispute_lifecycle"
                for x in report["scheduler_inventory"]
            )
        )
        self.assertFalse(report["invariants"]["scheduler_transaction_causality_verified"])

    def test_trace_without_route_is_explicitly_ambiguous(self):
        report = cg.trace_effect_candidates(self.repo, self.rows)
        self.assertEqual(report["transaction_count"], 2)
        self.assertTrue(
            all(x["anchor_status"] == "SHARED_ENTRYPOINT_AMBIGUOUS"
                for x in report["transactions"])
        )
        self.assertEqual(report["scheduler_status"], "SCHEDULER_SOURCE_ABSENT_UNRESOLVED")
        self.assertEqual(report["release_verdict"],
                         "BLOCKED_PENDING_SEMANTIC_TRACING_AND_INDEPENDENT_REVIEW")

    def test_source_snapshot_inventory_is_unique(self):
        groups = {}
        for line in (ROOT / "reference/pinned_domain_names.txt").read_text().splitlines():
            domain, txs = line.split("|", 1)
            groups[domain] = txs.split()
        all_t = [t for ts in groups.values() for t in ts]
        self.assertEqual(len(groups), 20)
        self.assertEqual(len(all_t), 236)
        self.assertEqual(len(set(all_t)), 236)


if __name__ == "__main__":
    unittest.main()
