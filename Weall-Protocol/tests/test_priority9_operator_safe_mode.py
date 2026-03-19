from weall.runtime.operator_safe_mode import safe_mode_gate, should_halt_block_production


def test_safe_mode_gate_halts_on_critical_severity() -> None:
    report = {"summary": {"severity": "critical"}}
    gate = safe_mode_gate(report=report, actions=None)

    assert gate["mode"] == "halted"
    assert gate["halt_block_production"] is True
    assert gate["allow_block_production"] is False
    assert should_halt_block_production(report=report, actions=None) is True


def test_safe_mode_gate_observes_on_warning() -> None:
    report = {"summary": {"severity": "warning"}}
    gate = safe_mode_gate(report=report, actions=None)

    assert gate["mode"] == "observe"
    assert gate["halt_block_production"] is False
    assert gate["allow_block_production"] is True
    assert gate["request_peer_reports"] is True


def test_safe_mode_gate_respects_explicit_halt_action() -> None:
    report = {"summary": {"severity": "ok"}}
    actions = {"actions": ["HALT_BLOCK_PRODUCTION"]}
    gate = safe_mode_gate(report=report, actions=actions)

    assert gate["mode"] == "halted"
    assert gate["halt_block_production"] is True
    assert gate["allow_block_production"] is False
