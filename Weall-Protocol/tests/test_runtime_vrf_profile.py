from __future__ import annotations

import pytest

from weall.runtime.protocol_profile import (
    effective_runtime_consensus_posture,
    runtime_vrf_required,
    validate_runtime_consensus_profile,
)


def test_prod_rejects_vrf_disabled_override_when_profile_requires_vrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    with pytest.raises(ValueError, match="WEALL_REQUIRE_VRF"):
        validate_runtime_consensus_profile()


def test_prod_effective_posture_pins_vrf_requirement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_REQUIRE_VRF", raising=False)

    posture = effective_runtime_consensus_posture()

    assert posture["profile_enforced"] is True
    assert posture["vrf_required"] is True
    assert runtime_vrf_required() is True
