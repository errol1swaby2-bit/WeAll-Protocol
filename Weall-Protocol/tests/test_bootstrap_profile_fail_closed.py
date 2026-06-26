from __future__ import annotations

import os


def test_prod_profile_requires_chain_id_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_CHAIN_ID", raising=False)

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("prod startup did not fail closed when WEALL_CHAIN_ID was missing")


def test_prod_profile_rejects_unsafe_dev_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("prod startup did not fail closed when WEALL_UNSAFE_DEV=1")


def test_prod_profile_requires_signature_verification_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("prod startup did not fail closed when signature verification was disabled")
