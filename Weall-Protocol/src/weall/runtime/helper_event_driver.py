from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Sequence

from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.parallel_execution import LanePlan
from weall.runtime.helper_certificates import HelperExecutionCertificate


Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class HelperEvent:
    kind: str  # start | cert | timeout
    started_ms: int = 0
    now_ms: int = 0
    cert: HelperExecutionCertificate | None = None
    peer_id: str = ""


@dataclass(frozen=True, slots=True)
class HelperEventOutcomeSummary:
    resolved_lanes: tuple[str, ...]
    finalized_modes: tuple[tuple[str, str], ...]
    event_codes: tuple[str, ...]
    outcome_hash: str

    def to_json(self) -> Json:
        return {
            "resolved_lanes": list(self.resolved_lanes),
            "finalized_modes": [[lane_id, mode] for lane_id, mode in self.finalized_modes],
            "event_codes": list(self.event_codes),
            "outcome_hash": self.outcome_hash,
        }


def _build_outcome_hash(
    *,
    resolved_lanes: Sequence[str],
    finalized_modes: Sequence[tuple[str, str]],
    event_codes: Sequence[str],
) -> str:
    return _sha256_hex(
        {
            "resolved_lanes": list(resolved_lanes),
            "finalized_modes": [[lane_id, mode] for lane_id, mode in finalized_modes],
            "event_codes": list(event_codes),
        }
    )


def run_helper_event_sequence(
    *,
    context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    events: Sequence[HelperEvent],
    helper_pubkeys: dict[str, str] | None = None,
    journal: HelperLaneJournal | None = None,
    helper_timeout_ms: int = 5000,
) -> HelperEventOutcomeSummary:
    """
    Deterministic integrated helper-path event driver.

    This is a repo-native adversarial test harness for:
    - duplicate helper certificate delivery
    - conflicting helper replays
    - timeout-driven fallback
    - late traffic after fallback
    - repeated timeout calls
    - restart-equivalent event processing when journal state is reused

    It intentionally uses the existing proposer orchestrator + replay guard path.
    """
    orchestrator = HelperProposalOrchestrator(
        context=context,
        lane_plans=tuple(lane_plans),
        helper_pubkeys=dict(helper_pubkeys or {}),
        journal=journal,
        helper_timeout_ms=helper_timeout_ms,
    )
    guard = HelperReplayGuard(
        orchestrator=orchestrator,
        journal=journal,
    )

    codes: list[str] = []
    for event in events:
        kind = str(event.kind or "")
        if kind == "start":
            orchestrator.start_collection(started_ms=int(event.started_ms))
            codes.append("start")
        elif kind == "cert":
            if event.cert is None:
                codes.append("missing_cert")
                continue
            outcome = guard.ingest_certificate(
                cert=event.cert,
                peer_id=str(event.peer_id or ""),
            )
            codes.append(str(outcome.code))
        elif kind == "timeout":
            outcomes = guard.finalize_timeouts(now_ms=int(event.now_ms))
            if not outcomes:
                codes.append("timeout_noop")
            else:
                for outcome in outcomes:
                    codes.append(str(outcome.code))
        else:
            codes.append("unknown_event")

    finalized = tuple(
        (str(item.lane_id), str(item.mode))
        for item in orchestrator.finalized_resolutions()
    )
    resolved_lanes = tuple(sorted(guard.resolved_lanes()))
    return HelperEventOutcomeSummary(
        resolved_lanes=resolved_lanes,
        finalized_modes=finalized,
        event_codes=tuple(codes),
        outcome_hash=_build_outcome_hash(
            resolved_lanes=resolved_lanes,
            finalized_modes=finalized,
            event_codes=tuple(codes),
        ),
    )
