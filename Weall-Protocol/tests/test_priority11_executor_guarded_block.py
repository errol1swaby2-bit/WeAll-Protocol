from weall.runtime.executor_safe_mode_integration import guarded_produce_block


def test_guard_blocks_production():
    report = {"summary": {"severity": "critical"}}

    def fake_produce():
        return {"block": 1}

    out = guarded_produce_block(report=report, actions=None, produce_fn=fake_produce)

    assert out["ok"] is False
    assert out["error"] == "SAFE_MODE_HALTED"


def test_guard_allows_production():
    report = {"summary": {"severity": "ok"}}

    def fake_produce():
        return {"block": 1}

    out = guarded_produce_block(report=report, actions=None, produce_fn=fake_produce)

    assert out["ok"] is True
    assert out["result"]["block"] == 1
