from weall.runtime.operator_incident_actions import evaluate_incident_actions


def test_actions_for_critical():
    r = {"summary": {"severity": "critical"}}
    out = evaluate_incident_actions(r)
    assert "HALT_BLOCK_PRODUCTION" in out["actions"]
    assert out["action_count"] == 2


def test_actions_for_ok():
    r = {"summary": {"severity": "ok"}}
    out = evaluate_incident_actions(r)
    assert out["actions"] == []
