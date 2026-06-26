import pytest

from weall.runtime.startup_checks import validate_environment


def test_missing_env_fails_batch112(monkeypatch):
    monkeypatch.delenv("WEALL_MODE", raising=False)

    with pytest.raises(RuntimeError):
        validate_environment()


def test_prod_unsafe_flag_fails_batch112(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ALLOW_UNSIGNED_TXS", "1")

    with pytest.raises(RuntimeError):
        validate_environment()
