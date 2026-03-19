from __future__ import annotations

from typing import Any

from weall.runtime.operator_safe_mode import should_halt_block_production

Json = dict[str, Any]


def executor_safe_mode_guard(*, report: Json, actions: Json | None = None) -> Json:
    halt = should_halt_block_production(report=report, actions=actions)

    return {
        "halt_block_production": halt,
        "allow_block_production": not halt,
    }
