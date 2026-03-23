from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.helper_preflight_gate import (
    ProductionPreflightDecision,
    ProductionPreflightInput,
    decide_production_preflight,
)


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperStartupConfig:
    helper_mode_requested: bool = False
    chain_id_ok: bool = True
    protocol_profile_ok: bool = True
    validator_set_ok: bool = True
    trusted_anchor_ok: bool = True
    sqlite_wal_ok: bool = True


@dataclass(frozen=True, slots=True)
class HelperStartupStatus:
    startup_allowed: bool
    startup_mode: str  # serial_only | helper_enabled | blocked
    code: str
    helper_mode_active: bool
    helper_release_score: int

    def to_json(self) -> Json:
        return {
            "startup_allowed": self.startup_allowed,
            "startup_mode": self.startup_mode,
            "code": self.code,
            "helper_mode_active": self.helper_mode_active,
            "helper_release_score": self.helper_release_score,
        }


def evaluate_helper_startup(
    *,
    config: HelperStartupConfig,
    helper_release_gate=None,
) -> HelperStartupStatus:
    """
    Repo-native startup evaluation layer for helper mode.

    This is intentionally narrow:
    - serial-only startup remains allowed when helper mode is not requested
    - helper-enabled startup requires the helper release gate to pass
    - blocked startup is returned only when core runtime prerequisites fail or
      helper mode was explicitly requested but is not production-ready
    """
    decision: ProductionPreflightDecision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            chain_id_ok=bool(config.chain_id_ok),
            protocol_profile_ok=bool(config.protocol_profile_ok),
            validator_set_ok=bool(config.validator_set_ok),
            trusted_anchor_ok=bool(config.trusted_anchor_ok),
            sqlite_wal_ok=bool(config.sqlite_wal_ok),
            helper_release_gate=helper_release_gate,
            helper_mode_enabled=bool(config.helper_mode_requested),
        )
    )

    if not decision.accepted:
        return HelperStartupStatus(
            startup_allowed=False,
            startup_mode="blocked",
            code=str(decision.code),
            helper_mode_active=False,
            helper_release_score=int(decision.release_score),
        )

    if bool(config.helper_mode_requested):
        return HelperStartupStatus(
            startup_allowed=True,
            startup_mode="helper_enabled",
            code=str(decision.code),
            helper_mode_active=True,
            helper_release_score=int(decision.release_score),
        )

    return HelperStartupStatus(
        startup_allowed=True,
        startup_mode="serial_only",
        code=str(decision.code),
        helper_mode_active=False,
        helper_release_score=int(decision.release_score),
    )
