from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "weall_compile_v2_spec_audit_test", ROOT / "scripts" / "compile_v2_spec.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _fn(source: str):
    return ast.parse(source).body[0]


def test_scheduler_evidence_does_not_promote_string_mentions_to_emissions() -> None:
    node = _fn("def consumer():\n    return {'applied': 'STATE_SNAPSHOT_DECLARE'}\n")
    assert MODULE._direct_emitted_system_transactions(node, {"STATE_SNAPSHOT_DECLARE"}) == []


def test_scheduler_evidence_detects_literal_enqueue_tx_type() -> None:
    node = _fn(
        "def producer(state):\n"
        "    enqueue_system_tx(state, tx_type='STATE_SNAPSHOT_DECLARE', payload={}, due_height=1)\n"
    )
    assert MODULE._direct_emitted_system_transactions(node, {"STATE_SNAPSHOT_DECLARE"}) == [
        "STATE_SNAPSHOT_DECLARE"
    ]


def test_dynamic_typed_error_code_is_unresolved_not_exception_class() -> None:
    node = _fn(
        "def apply(state, decision):\n"
        "    raise RolesApplyError(str(decision['code']), str(decision['reason']), {})\n"
    )
    expected = [{"code": "runtime_apply_error", "reason": "see_handler"}]
    assert MODULE._extract_failures(node) == expected


def test_dynamic_first_error_argument_does_not_shift_later_literal_reason() -> None:
    node = _fn(
        "def apply(state):\n"
        "    raise RolesApplyError(state['error_code'], 'literal_second_argument')\n"
    )
    expected = [{"code": "runtime_apply_error", "reason": "see_handler"}]
    assert MODULE._extract_failures(node) == expected


def test_literal_error_codes_and_reasons_remain_precise() -> None:
    node = _fn(
        "def apply(state):\n    raise RolesApplyError('forbidden', 'live_verification_required')\n"
    )
    expected = [{"code": "forbidden", "reason": "live_verification_required"}]
    assert MODULE._extract_failures(node) == expected


def test_real_role_gate_error_uses_unresolved_static_marker() -> None:
    path = ROOT / "src" / "weall" / "runtime" / "apply" / "roles.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    target = next(
        fn
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef) and fn.name == "_require_role_activation_eligible"
    )
    failures = MODULE._extract_failures(target)
    assert {"code": "runtime_apply_error", "reason": "see_handler"} in failures
    assert {"code": "RolesApplyError", "reason": "runtime_apply_failure"} not in failures


def test_review_lane_static_false_prunes_unreachable_opt_in_failures() -> None:
    branch = _fn(
        "def review(active, lanes):\n"
        "    if active:\n"
        "        _require_role_activation_eligible()\n"
        "        raise RolesApplyError('forbidden', 'opt_in_only')\n"
        "    elif not active and lanes:\n"
        "        raise RolesApplyError('not_found', 'opt_out_lane')\n"
    )
    pruned = MODULE._specialize_reviewer_opt_out(branch)
    names = [
        item.func.id
        for item in ast.walk(pruned)
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
    ]
    assert "_require_role_activation_eligible" not in names
    assert MODULE._extract_failures(pruned) == [{"code": "not_found", "reason": "opt_out_lane"}]


def test_real_review_lane_failure_contract_respects_constant_active_dispatch() -> None:
    source = ROOT / "src" / "weall" / "runtime" / "apply" / "roles.py"
    tx_names = {"REVIEWER_LANE_OPT_IN", "REVIEWER_LANE_OPT_OUT"}
    inputs = {
        tx_type: MODULE._tx_function_analysis(
            tx_type,
            source,
            "apply_roles",
            tx_names=tx_names,
            system_tx_names=set(),
            domain_fallback=["roles"],
        )
        for tx_type in sorted(tx_names)
    }
    # Registry consumers enter the dedicated handler directly, while
    # focused tests can traverse the shared apply_roles dispatcher.
    # Both compiler entry modes must bind the same literal false branch.
    dedicated = MODULE._tx_function_analysis(
        "REVIEWER_LANE_OPT_OUT",
        source,
        "_apply_reviewer_lane_update",
        tx_names=tx_names,
        system_tx_names=set(),
        domain_fallback=["roles"],
    )
    # The direct-handler and dispatcher paths have different precision
    # metadata but must derive identical source-contract fields.
    assert dedicated["semantic_precision"] == "function_static"
    assert inputs["REVIEWER_LANE_OPT_OUT"]["semantic_precision"] == "tx_specific_static"
    for key in (
        "function",
        "line",
        "state_reads",
        "state_writes",
        "failure_codes",
        "return_keys",
        "system_followups",
    ):
        assert dedicated[key] == inputs["REVIEWER_LANE_OPT_OUT"][key]
    for row in inputs.values():
        assert row["function"] == "_apply_reviewer_lane_update"
    opt_in = inputs["REVIEWER_LANE_OPT_IN"]["failure_codes"]
    opt_out = inputs["REVIEWER_LANE_OPT_OUT"]["failure_codes"]
    unresolved = {"code": "runtime_apply_error", "reason": "see_handler"}
    assert unresolved in opt_in
    assert unresolved not in opt_out
    assert {"code": "not_found", "reason": "juror_not_enrolled"} in opt_out
    assert {
        "code": "forbidden",
        "reason": "only_account_can_update_reviewer_lane",
    } in opt_out
