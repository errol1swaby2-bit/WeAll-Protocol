from __future__ import annotations

import pytest

from weall.runtime.chain_config import validate_runtime_env


def test_prod_fail_closed_prefers_specific_reason_over_generic_batch44(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    with pytest.raises(Exception) as excinfo:
        validate_runtime_env()

    message = str(excinfo.value)
    assert message, "startup rejection should surface a non-empty diagnostic"
    lowered = message.lower()
    assert "unsafe" in lowered or "sigverify" in lowered or "signature" in lowered, message


def test_mixed_posture_rejection_mentions_posture_terms_batch44(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")

    with pytest.raises(Exception) as excinfo:
        validate_runtime_env()

    message = str(excinfo.value)
    assert message, "mixed-posture rejection should surface a non-empty diagnostic"
    lowered = message.lower()
    assert "observer" in lowered or "bft" in lowered or "posture" in lowered, message
