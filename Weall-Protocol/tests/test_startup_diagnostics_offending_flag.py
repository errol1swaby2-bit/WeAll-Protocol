from __future__ import annotations

import pytest

from weall.runtime.chain_config import validate_runtime_env


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("WEALL_UNSAFE_DEV", "1"),
        ("WEALL_SIGVERIFY", "0"),
        ("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1"),
        ("WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS", "1"),
    ],
)
def test_prod_fail_closed_error_mentions_offending_flag_batch44(monkeypatch, env_name, env_value):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv(env_name, env_value)

    with pytest.raises(Exception) as excinfo:
        validate_runtime_env()

    message = str(excinfo.value)
    assert message, "startup rejection should surface a non-empty diagnostic"
    assert env_name in message or env_name.lower() in message.lower(), message
