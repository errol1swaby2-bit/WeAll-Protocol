from weall.runtime.executor_safe_mode import executor_safe_mode_guard


def test_executor_blocks_when_critical():
    report = {"summary": {"severity": "critical"}}
    out = executor_safe_mode_guard(report=report, actions=None)
    assert out["halt_block_production"] is True
    assert out["allow_block_production"] is False


def test_executor_allows_when_ok():
    report = {"summary": {"severity": "ok"}}
    out = executor_safe_mode_guard(report=report, actions=None)
    assert out["halt_block_production"] is False
    assert out["allow_block_production"] is True
