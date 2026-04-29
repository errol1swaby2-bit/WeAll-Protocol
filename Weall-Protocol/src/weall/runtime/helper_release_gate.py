from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class HelperReleaseGateReport:
    deterministic_replay_ok: bool
    timeout_fallback_ok: bool
    conflicting_replay_ok: bool
    restart_recovery_ok: bool
    merge_admission_ok: bool
    fail_closed_ok: bool
    serial_degrade_ok: bool
    soak_ok: bool
    total_gates: int
    passed_gates: int
    readiness_score: int

    def all_required_passed(self) -> bool:
        return self.passed_gates == self.total_gates


def _score(flags: Iterable[bool]) -> tuple[int, int, int]:
    values = tuple(bool(x) for x in flags)
    total = len(values)
    passed = sum(1 for x in values if x)
    score = int((passed / total) * 100) if total else 0
    return total, passed, score


def build_helper_release_gate_report(
    *,
    deterministic_replay_ok: bool,
    timeout_fallback_ok: bool,
    conflicting_replay_ok: bool,
    restart_recovery_ok: bool,
    merge_admission_ok: bool,
    fail_closed_ok: bool,
    serial_degrade_ok: bool,
    soak_ok: bool,
) -> HelperReleaseGateReport:
    total, passed, score = _score(
        (
            deterministic_replay_ok,
            timeout_fallback_ok,
            conflicting_replay_ok,
            restart_recovery_ok,
            merge_admission_ok,
            fail_closed_ok,
            serial_degrade_ok,
            soak_ok,
        )
    )
    return HelperReleaseGateReport(
        deterministic_replay_ok=bool(deterministic_replay_ok),
        timeout_fallback_ok=bool(timeout_fallback_ok),
        conflicting_replay_ok=bool(conflicting_replay_ok),
        restart_recovery_ok=bool(restart_recovery_ok),
        merge_admission_ok=bool(merge_admission_ok),
        fail_closed_ok=bool(fail_closed_ok),
        serial_degrade_ok=bool(serial_degrade_ok),
        soak_ok=bool(soak_ok),
        total_gates=total,
        passed_gates=passed,
        readiness_score=score,
    )
