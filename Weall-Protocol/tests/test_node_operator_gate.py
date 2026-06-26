from __future__ import annotations

from weall.runtime.gate_expr import eval_gate


def _ledger(*, tier: int = 2, active: bool = True, banned: bool = False, locked: bool = False, suspended_record: bool = False) -> dict:
    return {
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": tier,
                "banned": banned,
                "locked": locked,
                "reputation_milli": 6000,
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "@op": {
                        "enrolled": True,
                        "active": active,
                        "suspended": suspended_record,
                        "status": "suspended" if suspended_record else ("active" if active else "pending"),
                    }
                },
                "active_set": ["@op"] if active else [],
            }
        },
    }


def test_node_operator_gate_allows_tier2_active_operator() -> None:
    ok, meta = eval_gate("NodeOperator", signer="@op", state=_ledger(), payload={})
    assert ok is True
    assert meta["expr"] == "NodeOperator"


def test_node_operator_gate_rejects_tier1_operator() -> None:
    ok, _meta = eval_gate("NodeOperator", signer="@op", state=_ledger(tier=1), payload={})
    assert ok is False


def test_node_operator_gate_rejects_missing_active_role() -> None:
    ok, _meta = eval_gate("NodeOperator", signer="@op", state=_ledger(active=False), payload={})
    assert ok is False


def test_node_operator_gate_rejects_banned_or_locked_or_suspended_operator() -> None:
    assert eval_gate("NodeOperator", signer="@op", state=_ledger(banned=True), payload={})[0] is False
    assert eval_gate("NodeOperator", signer="@op", state=_ledger(locked=True), payload={})[0] is False
    assert eval_gate("NodeOperator", signer="@op", state=_ledger(suspended_record=True), payload={})[0] is False
