from __future__ import annotations

import pytest

from weall.runtime.protocol_profile import (
    effective_runtime_consensus_posture,
    runtime_startup_fingerprint,
    validate_runtime_consensus_profile,
)


def test_prod_rejects_legacy_sig_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", "1")
    with pytest.raises(ValueError, match="production consensus profile mismatch"):
        validate_runtime_consensus_profile()


def test_prod_rejects_disabling_trusted_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    with pytest.raises(ValueError, match="production consensus profile mismatch"):
        validate_runtime_consensus_profile()


def test_prod_rejects_unsafe_dev_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    with pytest.raises(ValueError, match="WEALL_UNSAFE_DEV"):
        validate_runtime_consensus_profile()


def test_prod_effective_posture_ignores_unsafe_raw_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_BFT_UNSAFE_AUTOCOMMIT", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")

    posture = effective_runtime_consensus_posture()

    assert posture["profile_enforced"] is True
    assert posture["sigverify_required"] is True
    assert posture["qc_less_blocks_allowed"] is False
    assert posture["unsafe_autocommit_allowed"] is False
    assert posture["trusted_anchor_required"] is True


def test_startup_fingerprint_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")

    a = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
    )
    b = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
    )
    c = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-2",
        tx_index_hash="abc123",
        schema_version="1",
    )

    assert a["fingerprint"] == b["fingerprint"]
    assert a["fingerprint"] != c["fingerprint"]
