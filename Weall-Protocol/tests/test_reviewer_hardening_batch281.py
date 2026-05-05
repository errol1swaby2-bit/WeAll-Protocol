from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from weall.runtime.errors import ApplyError
from weall.runtime.gate_expr import eval_gate
from weall.runtime.poh.eligibility import (
    ACTION_REQUIRED_POH_TIER,
    can_account_perform_action,
    get_required_poh_tier,
    require_poh_tier,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_gate_expr_invalid_character_fails_closed_without_hanging_batch281() -> None:
    ok, meta = eval_gate(
        "Tier2+ @",
        signer="alice",
        ledger={"accounts": {"alice": {"poh_tier": 2}}},
        payload={},
    )

    assert ok is False
    assert str(meta.get("error", "")).startswith("parse:")
    assert meta["expr"] == "Tier2+ @"


def test_unknown_user_origin_poh_eligibility_action_fails_closed_batch281() -> None:
    state = {"accounts": {"alice": {"poh_tier": 2}}}
    unknown = "UNREGISTERED_USER_MUTATION"

    assert get_required_poh_tier(unknown) == 99
    assert can_account_perform_action(state, "alice", unknown) is False

    with pytest.raises(ApplyError) as exc:
        require_poh_tier(state, "alice", unknown)

    assert exc.value.reason == "unknown_poh_eligibility_action"
    assert exc.value.details["tx_type"] == unknown


def test_tier_gated_user_origin_txs_are_explicit_in_poh_eligibility_table_batch281() -> None:
    canon_path = _repo_root() / "specs" / "tx_canon" / "tx_canon.yaml"
    canon = yaml.safe_load(canon_path.read_text(encoding="utf-8"))

    missing: list[tuple[str, str]] = []
    for tx in canon.get("txs", []):
        if tx.get("origin") != "USER" or tx.get("context") != "mempool":
            continue
        gate = str(tx.get("gate") or "")
        if not gate.startswith("Tier"):
            continue
        name = str(tx.get("name") or "").strip().upper()
        if name not in ACTION_REQUIRED_POH_TIER:
            missing.append((name, gate))

    assert missing == []


def test_poh_case_assignment_without_active_juror_role_fails_batch281() -> None:
    ledger = {
        "accounts": {"alice": {"poh_tier": 2}},
        "roles": {"jurors": {"by_id": {}, "active_set": []}},
        "poh": {
            "async_cases": {
                "case:1": {
                    "case_id": "case:1",
                    "jurors": {"alice": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate("Juror", signer="alice", ledger=ledger, payload={"case_id": "case:1"})

    assert ok is False


def test_active_juror_without_case_assignment_fails_case_action_batch281() -> None:
    ledger = {
        "accounts": {"alice": {"poh_tier": 2}},
        "roles": {"jurors": {"by_id": {"alice": {"active": True}}, "active_set": ["alice"]}},
        "poh": {"async_cases": {"case:1": {"case_id": "case:1", "jurors": {}}}},
    }

    ok, _meta = eval_gate("Juror", signer="alice", ledger=ledger, payload={"case_id": "case:1"})

    assert ok is False


def test_active_tier2_juror_with_case_assignment_passes_batch281() -> None:
    ledger = {
        "accounts": {"alice": {"poh_tier": 2}},
        "roles": {"jurors": {"by_id": {"alice": {"active": True}}, "active_set": ["alice"]}},
        "poh": {
            "async_cases": {
                "case:1": {
                    "case_id": "case:1",
                    "jurors": {"alice": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate("Juror", signer="alice", ledger=ledger, payload={"case_id": "case:1"})

    assert ok is True


def test_root_readme_declares_mpl_2_license_batch281() -> None:
    root = _repo_root().parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")

    assert "## License" in readme
    assert "Mozilla Public License 2.0" in readme
    assert "Mozilla Public License" in license_text
    assert "Version 2.0" in license_text
