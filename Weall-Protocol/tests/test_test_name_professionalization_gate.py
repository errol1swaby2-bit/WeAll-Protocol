from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "audit_test_names.py"
SPEC = importlib.util.spec_from_file_location("audit_test_names", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
audit_test_names = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_test_names)


def test_professionalization_gate_finds_no_active_batch_named_pytest_files():
    assert audit_test_names.batch_named_test_files() == []


def test_professionalization_gate_finds_no_reviewer_facing_batch_test_references():
    assert audit_test_names.reviewer_facing_batch_references() == []


def test_professionalization_gate_cli_check_passes():
    assert audit_test_names.main(["--check"]) == 0
