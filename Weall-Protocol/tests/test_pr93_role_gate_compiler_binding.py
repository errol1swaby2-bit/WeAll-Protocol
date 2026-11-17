"""Exact source/dispatcher binding for the V2 role failure inventory; no approval."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from scripts import compile_v2_spec as compiler

ROOT = Path(__file__).resolve().parents[1]


def test_role_gate_source_fingerprint_and_new_stable_failure_ids() -> None:
    source = ROOT / "src/weall/runtime/reputation_role_gate.py"
    assert hashlib.sha256(source.read_text(encoding="utf-8").encode()).hexdigest() == (
        compiler._ROLE_GATE_SOURCE_SHA256
    )
    registry = compiler.StableIdRegistry.from_payload(
        compiler._load_json(ROOT / "specs/v2/source/stable_ids.json")
    )
    for key in ("forbidden:policy_unknown", "forbidden:canonical_role_reputation_ineligible"):
        expected = "FAIL-" + hashlib.sha256(key.encode()).hexdigest()[:16].upper()
        assert registry.resolve("failure", key) == expected


@pytest.mark.parametrize("active", [False, True])
def test_specialized_reviewer_lane_excludes_opposite_branch(active: bool) -> None:
    original = ast.parse(
        "def handler(active):\n"
        "    if active:\n"
        "        raise RolesApplyError('forbidden', 'activation_guard')\n"
        "    else:\n"
        "        raise RolesApplyError('not_found', 'withdrawal_guard')\n"
    )
    before = ast.dump(original)
    result = compiler._specialize_reviewer_lane(original, active=active)
    expected = "activation_guard" if active else "withdrawal_guard"
    assert [item["reason"] for item in compiler._extract_failures(result)] == [expected]
    assert ast.dump(original) == before


def test_specialization_refuses_mutated_active_parameter() -> None:
    node = ast.parse("def handler(active):\n    active = False\n    if active:\n        pass\n")
    with pytest.raises(compiler.CompileError, match="reviewer_lane_active_parameter_reassigned"):
        compiler._specialize_reviewer_lane(node, active=True)


def test_source_drift_fails_closed_before_publishing_role_failure_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler, "_ROLE_GATE_SOURCE_SHA256", "0" * 64)
    with pytest.raises(compiler.CompileError, match="role_gate_failure_source_changed"):
        compiler._reviewed_role_gate_failures("ROLE_JUROR_ENROLL", [], ast.parse("pass"))
