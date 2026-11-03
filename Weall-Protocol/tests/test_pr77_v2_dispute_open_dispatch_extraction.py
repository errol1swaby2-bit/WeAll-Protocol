"""Guard transaction-specific V2 extraction without approving semantic digests."""

from __future__ import annotations

from scripts import compile_v2_spec as compiler


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
    assert "key:disputes_by_id" in result["state_reads"] or any(
        key.endswith("disputes_by_id") for key in result["state_reads"]
    )


def test_direct_branch_dispatch_is_not_restricted_to_apply_prefix(tmp_path) -> None:
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
