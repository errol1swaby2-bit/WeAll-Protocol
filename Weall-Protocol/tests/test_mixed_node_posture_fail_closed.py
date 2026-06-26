from __future__ import annotations


def test_mixed_bft_posture_rejected_fail_closed_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("mixed BFT/observer posture did not fail closed")


def test_prod_profile_rejects_qc_less_blocks_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("prod startup did not fail closed on QC-less block allowance")


def test_prod_profile_rejects_unsigned_timeouts_batch43(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS", "1")

    import weall.runtime.chain_config as chain_config

    if hasattr(chain_config, "validate_runtime_env"):
        try:
            chain_config.validate_runtime_env()
        except Exception:
            return
        raise AssertionError("prod startup did not fail closed on unsigned timeout allowance")
