from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from weall.runtime.helper_release_gate import (
    HelperReleaseGateReport,
    build_helper_release_gate_report,
)


@dataclass(frozen=True, slots=True)
class ProductionPreflightInput:
    chain_id_ok: bool = True
    protocol_profile_ok: bool = True
    validator_set_ok: bool = True
    trusted_anchor_ok: bool = True
    sqlite_wal_ok: bool = True
    helper_release_gate: HelperReleaseGateReport | None = None
    helper_mode_enabled: bool = False


@dataclass(frozen=True, slots=True)
class ProductionPreflightDecision:
    accepted: bool
    code: str
    helper_required: bool
    helper_ready: bool
    release_score: int


def decide_production_preflight(
    *,
    preflight: ProductionPreflightInput,
) -> ProductionPreflightDecision:
    """
    Repo-native production preflight gate.

    Current architecture boundary:
    - HotStuff remains canonical consensus
    - helper execution is optional and can remain disabled
    - if helper mode is enabled, helper release gates must all pass
    """
    if not bool(preflight.chain_id_ok):
        return ProductionPreflightDecision(
            accepted=False,
            code="chain_id_not_ready",
            helper_required=bool(preflight.helper_mode_enabled),
            helper_ready=False,
            release_score=0,
        )
    if not bool(preflight.protocol_profile_ok):
        return ProductionPreflightDecision(
            accepted=False,
            code="protocol_profile_not_ready",
            helper_required=bool(preflight.helper_mode_enabled),
            helper_ready=False,
            release_score=0,
        )
    if not bool(preflight.validator_set_ok):
        return ProductionPreflightDecision(
            accepted=False,
            code="validator_set_not_ready",
            helper_required=bool(preflight.helper_mode_enabled),
            helper_ready=False,
            release_score=0,
        )
    if not bool(preflight.trusted_anchor_ok):
        return ProductionPreflightDecision(
            accepted=False,
            code="trusted_anchor_not_ready",
            helper_required=bool(preflight.helper_mode_enabled),
            helper_ready=False,
            release_score=0,
        )
    if not bool(preflight.sqlite_wal_ok):
        return ProductionPreflightDecision(
            accepted=False,
            code="sqlite_wal_not_ready",
            helper_required=bool(preflight.helper_mode_enabled),
            helper_ready=False,
            release_score=0,
        )

    helper_gate = preflight.helper_release_gate
    helper_ready = bool(helper_gate.all_required_passed()) if helper_gate is not None else False

    if bool(preflight.helper_mode_enabled):
        if helper_gate is None:
            return ProductionPreflightDecision(
                accepted=False,
                code="helper_release_gate_missing",
                helper_required=True,
                helper_ready=False,
                release_score=0,
            )
        if not helper_ready:
            return ProductionPreflightDecision(
                accepted=False,
                code="helper_release_gate_failed",
                helper_required=True,
                helper_ready=False,
                release_score=int(helper_gate.readiness_score),
            )
        return ProductionPreflightDecision(
            accepted=True,
            code="preflight_ready_with_helpers",
            helper_required=True,
            helper_ready=True,
            release_score=int(helper_gate.readiness_score),
        )

    return ProductionPreflightDecision(
        accepted=True,
        code="preflight_ready_serial_only",
        helper_required=False,
        helper_ready=helper_ready,
        release_score=int(helper_gate.readiness_score) if helper_gate is not None else 0,
    )
