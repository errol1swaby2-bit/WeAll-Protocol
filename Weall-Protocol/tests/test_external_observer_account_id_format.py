from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_external_observer_live_gate_default_account_id_is_prod_valid_batch467() -> None:
    script = (ROOT / "scripts" / "external_observer_live_gate.sh").read_text(encoding="utf-8")

    assert '@extobs_${ACCOUNT_SUFFIX}' in script
    assert '@external-observer-${ACCOUNT_SUFFIX}' not in script


def test_account_id_policy_documents_no_hyphen_prod_handles_batch467() -> None:
    policy = (ROOT / "src" / "weall" / "runtime" / "account_id.py").read_text(encoding="utf-8")

    assert r"^@[a-z0-9_]{1,32}$" in policy
