"""Guard transaction-specific V2 extraction without approving semantic digests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compile_v2_spec as compiler  # noqa: E402


def test_dispute_open_selects_direct_leaf_not_shared_dispatcher() -> None:
    source = compiler.ROOT / "src" / "weall" / "runtime" / "apply" / "dispute.py"
    result = compiler._tx_function_analysis(
        "DISPUTE_OPEN",
        source,
        "apply_dispute",
        {"DISPUTE_OPEN", "DISPUTE_APPEAL", "DISPUTE_RESOLVE"},
        set(),
        ["disputes_by_id"],
    )
    assert result["function"] == "dispute_open"
    assert result["semantic_precision"] == "tx_specific_static"
    assert {"code": "invalid_payload", "reason": "missing_target"} in result["failure_codes"]
    assert {"code": "forbidden", "reason": "active_proposal_dispute_protected"} in result[
        "failure_codes"
    ]
    assert {"code": "duplicate", "reason": "dispute_id_exists"} in result["failure_codes"]
    assert "key:gov_proposals_by_id" in result["state_reads"]
    # Static extraction currently captures the dispute identity token; it is
    # not an exhaustive dynamic state-root read/write analysis.
    assert "key:dispute_id" in result["state_reads"]


def test_direct_branch_dispatch_is_not_restricted_to_apply_prefix(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(compiler, "ROOT", tmp_path)
    source = tmp_path / "synthetic_dispatch.py"
    source.write_text(
        "def open_case(state, env):\n"
        "    state['case'] = 1\n"
        "    return {'applied': 'CASE_OPEN'}\n"
        "def close_case(state, env):\n"
        "    state['closed'] = 1\n"
        "    return {'applied': 'CASE_CLOSE'}\n"
        "def apply_cases(state, env):\n"
        "    if env.tx_type == 'CASE_OPEN':\n"
        "        return open_case(state, env)\n"
        "    if env.tx_type == 'CASE_CLOSE':\n"
        "        return close_case(state, env)\n",
        encoding="utf-8",
    )
    result = compiler._tx_function_analysis(
        "CASE_OPEN", source, "apply_cases", {"CASE_OPEN", "CASE_CLOSE"}, set(), ["cases"]
    )
    assert result["function"] == "open_case"
    assert "key:case" in result["state_writes"]
    assert "key:closed" not in result["state_writes"]


def test_case_receipt_dispatch_does_not_select_as_str_utility() -> None:
    source = compiler.ROOT / "src" / "weall" / "runtime" / "apply" / "dispute.py"
    for tx_type in ("CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE"):
        result = compiler._tx_function_analysis(
            tx_type,
            source,
            "apply_dispute",
            {"CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE", "CASE_OUTCOME_RECEIPT"},
            set(),
            ["cases"],
        )
        assert result["function"] == "_apply_case_receipt"
        assert {"code": "forbidden", "reason": "system_only"} in result["failure_codes"]
        assert "key:cases" in result["state_reads"]
        assert "applied" in result["return_keys"]


def test_canonical_case_receipt_dispatch_preserves_handler_not_as_str_utility() -> None:
    """Canonical CASE appliers declare the shared receipt function, not apply_dispute."""
    appliers = json.loads(
        (compiler.ROOT / "specs/v2/source/tx_appliers.json").read_text(encoding="utf-8")
    )
    by_tx = {row["tx_type"]: row for row in appliers["rows"]}
    expected = {
        "CASE_TYPE_REGISTER": ("invalid_payload", "missing_case_type"),
        "CASE_BIND_TO_DISPUTE": ("invalid_payload", "missing_dispute_id"),
    }
    for tx_type, (code, reason) in expected.items():
        row = by_tx[tx_type]
        assert row["dispatch_function"] == "_apply_case_receipt"
        result = compiler._tx_function_analysis(
            tx_type,
            compiler.ROOT / row["path"],
            row["dispatch_function"],
            set(expected) | {"CASE_OUTCOME_RECEIPT"},
            set(expected) | {"CASE_OUTCOME_RECEIPT"},
            ["cases"],
        )
        assert result["function"] == "_apply_case_receipt"
        assert result["semantic_precision"] == "function_static"
        assert {"code": code, "reason": reason} in result["failure_codes"]
        assert {"code": "forbidden", "reason": "system_only"} in result["failure_codes"]
        assert "applied" in result["return_keys"]
        assert "key:cases" in result["state_reads"]


def test_non_returning_single_utility_call_is_not_handler_dispatch(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(compiler, "ROOT", tmp_path)
    source = tmp_path / "synthetic_utility.py"
    source.write_text(
        "def normalize(raw):\n"
        "    return str(raw)\n"
        "def apply_cases(state, env):\n"
        "    if env.tx_type == 'CASE_BIND':\n"
        "        normalize(env.payload)\n"
        "        state['bound'] = True\n"
        "    return {'applied': True}\n",
        encoding="utf-8",
    )
    result = compiler._tx_function_analysis(
        "CASE_BIND", source, "apply_cases", {"CASE_BIND"}, set(), ["cases"]
    )
    assert result["function"] == "apply_cases"
    assert "key:bound" in result["state_writes"]
