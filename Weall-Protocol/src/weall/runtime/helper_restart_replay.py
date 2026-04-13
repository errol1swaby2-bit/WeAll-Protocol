from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence

from weall.runtime.helper_assembly_gate import (
    HelperAssemblyProfile,
    decide_helper_block_assembly,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint


Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def _lane_plan_map(lane_plans: Sequence[LanePlan]) -> dict[str, LanePlan]:
    return {str(plan.lane_id): plan for plan in tuple(lane_plans or ())}


def _lane_plan_digest(lane_plans: Sequence[LanePlan]) -> tuple[dict[str, Any], ...]:
    digest = []
    for plan in sorted(tuple(lane_plans or ()), key=lambda item: str(item.lane_id)):
        digest.append(
            {
                "lane_id": str(plan.lane_id),
                "helper_id": str(plan.helper_id or ""),
                "tx_ids": list(tuple(str(tx_id) for tx_id in tuple(plan.tx_ids or ()))),
            }
        )
    return tuple(digest)


def _journal_history_consistent(*, journal: HelperLaneJournal | None, plan_id: str, lane_plans: Sequence[LanePlan]) -> tuple[bool, str]:
    if journal is None:
        return True, ""
    expected_lanes = _lane_plan_digest(lane_plans)
    for record in journal.load():
        if str(record.get("kind") or "") != "helper_plan":
            continue
        record_plan_id = str(record.get("plan_id") or "")
        if record_plan_id and record_plan_id != str(plan_id or ""):
            return False, "journal_history_plan_id_mismatch"
        lanes = record.get("lanes")
        if not isinstance(lanes, list):
            return False, "journal_history_plan_shape_invalid"
        normalized = []
        for item in lanes:
            if not isinstance(item, dict):
                return False, "journal_history_plan_shape_invalid"
            normalized.append({
                "lane_id": str(item.get("lane_id") or ""),
                "helper_id": str(item.get("helper_id") or ""),
                "tx_ids": list(str(tx_id) for tx_id in list(item.get("tx_ids") or [])),
            })
        normalized.sort(key=lambda item: item["lane_id"])
        if tuple(normalized) != expected_lanes:
            return False, "journal_history_lane_plan_mismatch"
    return True, ""


@dataclass(frozen=True, slots=True)
class HelperRestartSnapshot:
    unresolved_lanes: tuple[str, ...]
    finalized_modes: tuple[tuple[str, str], ...]
    assembly_mode: str
    assembly_code: str
    assembly_accepted: bool
    receipts_root: str
    merged_state_delta_hash: str
    plan_id: str = ""
    journal_plan_id: str = ""

    def to_json(self) -> Json:
        return {
            "unresolved_lanes": list(self.unresolved_lanes),
            "finalized_modes": [[lane_id, mode] for lane_id, mode in self.finalized_modes],
            "assembly_mode": self.assembly_mode,
            "assembly_code": self.assembly_code,
            "assembly_accepted": self.assembly_accepted,
            "receipts_root": self.receipts_root,
            "merged_state_delta_hash": self.merged_state_delta_hash,
            "plan_id": self.plan_id,
            "journal_plan_id": self.journal_plan_id,
        }

    def snapshot_hash(self) -> str:
        return _sha256_hex(self.to_json())


def build_helper_restart_snapshot(
    *,
    profile: HelperAssemblyProfile,
    context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    lane_results_by_id: Mapping[str, Mapping[str, Any]],
    journal: HelperLaneJournal | None = None,
    helper_pubkeys: Mapping[str, str] | None = None,
    helper_timeout_ms: int = 5000,
    serial_equivalence_fn=None,
) -> HelperRestartSnapshot:
    orchestrator = HelperProposalOrchestrator(
        context=context,
        lane_plans=tuple(lane_plans),
        helper_pubkeys=dict(helper_pubkeys or {}),
        journal=journal,
        helper_timeout_ms=helper_timeout_ms,
    )
    resolutions = orchestrator.finalized_resolutions()
    journal_state = journal.load_resolution_state() if journal is not None else {}
    decision = decide_helper_block_assembly(
        profile=profile,
        resolutions=resolutions,
        lane_results_by_id=lane_results_by_id,
        serial_equivalence_fn=serial_equivalence_fn,
    )
    expected_plan_id = str(context.plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))
    journal_ok, journal_code = _journal_history_consistent(journal=journal, plan_id=expected_plan_id, lane_plans=lane_plans)
    if not journal_ok:
        return HelperRestartSnapshot(
            unresolved_lanes=orchestrator.unresolved_lanes(),
            finalized_modes=tuple(
                (str(item.lane_id), str(item.mode))
                for item in sorted(resolutions, key=lambda item: item.lane_id)
            ),
            assembly_mode="helper_assisted",
            assembly_code=str(journal_code),
            assembly_accepted=False,
            receipts_root="",
            merged_state_delta_hash="",
            plan_id=expected_plan_id,
            journal_plan_id=str(journal_state.get("plan_id") or ""),
        )

    merge_decision = decision.merge_decision
    return HelperRestartSnapshot(
        unresolved_lanes=orchestrator.unresolved_lanes(),
        finalized_modes=tuple(
            (str(item.lane_id), str(item.mode))
            for item in sorted(resolutions, key=lambda item: item.lane_id)
        ),
        assembly_mode=str(decision.mode),
        assembly_code=str(decision.code),
        assembly_accepted=bool(decision.accepted),
        receipts_root=str(merge_decision.receipts_root if merge_decision else ""),
        merged_state_delta_hash=str(
            merge_decision.merged_state_delta_hash if merge_decision else ""
        ),
        plan_id=expected_plan_id,
        journal_plan_id=str(journal_state.get("plan_id") or ""),
    )
