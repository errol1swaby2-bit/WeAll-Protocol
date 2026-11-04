from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import field_trace
from weall_change_gate import ContractError


class FieldTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.path = "Weall-Protocol/src/weall/runtime/apply/reputation.py"
        self.file = self.repo / self.path
        self.file.parent.mkdir(parents=True)

    def triage(self, text: str, anchor: str = "_apply_tx") -> list[dict]:
        self.file.write_text(text, encoding="utf-8")
        sha = hashlib.sha256(self.file.read_bytes()).hexdigest()
        return [
            {
                "review_key": "AWC-fixture",
                "source_path": self.path,
                "source_file_sha256": sha,
                "source_commit": "a" * 40,
                "source_function": anchor,
                "state_root": "accounts",
            }
        ]

    def test_nested_account_fields_with_bounded_local_call(self) -> None:
        triage = self.triage(
            "def _apply_tx(state, user):\n"
            '    accounts = state.setdefault("accounts", {})\n'
            "    acct = accounts.setdefault(user, {})\n"
            '    acct["nonce"] = 3\n'
            "    _ban(state, user)\n"
            "def _ban(state, user):\n"
            '    accounts = state.get("accounts")\n'
            "    acct = accounts.get(user)\n"
            '    acct["banned"] = True\n'
        )
        result = field_trace.scan_account_field_review(self.repo, triage)
        self.assertEqual(len(result), 1)
        observation = result[0]
        by_field = {x["field"]: x for x in observation["field_write_candidates"]}
        self.assertIn("nonce", by_field)
        self.assertIn("banned", by_field)
        self.assertEqual(by_field["nonce"]["line"], 4)
        self.assertEqual(by_field["banned"]["same_file_call_depth"], 1)
        self.assertEqual(by_field["banned"]["account_path"][0], "accounts")
        self.assertTrue(observation["unknown_or_external_helper_effects_unproven"])
        self.assertEqual(observation["constitutional_authorization"], "NOT_ESTABLISHED")

    def test_local_account_record_helper_return_alias_is_unverified_candidate(self) -> None:
        triage = self.triage(
            "def _ensure_account(state, user):\n"
            '    accounts = state.setdefault("accounts", {})\n'
            "    return accounts.setdefault(user, {})\n"
            "def _apply_tx(state, user):\n"
            "    acct = _ensure_account(state, user)\n"
            '    acct["banned"] = True\n'
            '    acct["reputation"] = "0"\n'
            '    acct["balance"] = 12\n'
        )
        result = field_trace.scan_account_field_review(self.repo, triage)[0]
        self.assertTrue(result["account_record_helper_name_heuristic_used"])
        self.assertEqual(
            {"balance", "banned", "reputation"},
            {
                write["field"]
                for write in result["field_write_candidates"]
                if write["category"] == "ACCOUNT_FIELD_CANDIDATE"
            },
        )
        self.assertEqual(
            result["status"],
            "SOURCE_ORDER_STATIC_FIELD_CUES_NOT_TX_CAUSALITY_OR_AUTHORITY",
        )

    def test_unknown_key_remains_visible_not_safe(self) -> None:
        triage = self.triage(
            "def _apply_tx(state, user, key):\n"
            '    accounts = state["accounts"]\n'
            "    acct = accounts[user]\n"
            "    acct[key] = 7\n"
        )
        result = field_trace.scan_account_field_review(self.repo, triage)
        self.assertIn(
            "<dynamic-key>",
            {w["field"] for w in result[0]["field_write_candidates"]},
        )
        self.assertEqual(
            result[0]["status"],
            "SOURCE_ORDER_STATIC_FIELD_CUES_NOT_TX_CAUSALITY_OR_AUTHORITY",
        )

    def test_source_integrity_and_function_binding_fail_closed(self) -> None:
        triage = self.triage('def _apply_tx(state):\n    state["accounts"] = {}\n')
        self.file.write_text(self.file.read_text() + "# tampered\n")
        with self.assertRaisesRegex(ContractError, "unmatched_field_trace_source_sha_mismatch"):
            field_trace.scan_account_field_review(self.repo, triage)
        self.file.write_text('def _apply_tx(state):\n    state["accounts"] = {}\n')
        triage[0]["source_function"] = "_missing"
        with self.assertRaisesRegex(ContractError, "unmatched_field_anchor_absent"):
            field_trace.scan_account_field_review(self.repo, triage)

    def test_outside_runtime_source_rejected(self) -> None:
        triage = self.triage("def _apply_tx(state):\n    return state\n")
        triage[0]["source_path"] = "../secrets.py"
        with self.assertRaisesRegex(ContractError, "unmatched_field_trace_invalid_source_pin"):
            field_trace.scan_account_field_review(self.repo, triage)


if __name__ == "__main__":
    unittest.main()
