from __future__ import annotations

from pathlib import Path


def test_tx_admission_passes_tx_type_to_gate_expr_batch497() -> None:
    src = Path("src/weall/runtime/tx_admission.py").read_text(encoding="utf-8")

    assert "tx_type=env.tx_type or """ in src
    assert "payload=env.payload or {}" in src


def test_group_self_leave_gate_has_tx_type_context_batch497() -> None:
    src = Path("src/weall/runtime/gate_expr.py").read_text(encoding="utf-8")

    assert "def _is_group_moderator" in src
    assert 'tx_type: str = ""' in src
    assert 'GROUP_MEMBERSHIP_REMOVE' in src
    assert 'payload.get("account")' in src
