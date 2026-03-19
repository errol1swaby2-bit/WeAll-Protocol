from __future__ import annotations

from typing import Any, Dict

from weall.runtime.executor_safe_mode import executor_safe_mode_guard

Json = Dict[str, Any]


def guarded_produce_block(*, report: Json, actions: Json | None, produce_fn):
    decision = executor_safe_mode_guard(report=report, actions=actions)

    if not decision["allow_block_production"]:
        return {
            "ok": False,
            "error": "SAFE_MODE_HALTED",
            "decision": decision,
        }

    result = produce_fn()

    return {
        "ok": True,
        "result": result,
        "decision": decision,
    }
