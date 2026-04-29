from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from weall.runtime.helper_certificates import HelperExecutionCertificate
from weall.runtime.helper_dispatch import (
    HelperCertificateStore,
    HelperDispatchContext,
    HelperDispatchStatus,
)
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint

Json = dict[str, Any]


def _expected_helper_id_for_lane(lane_plans: dict[str, "LanePlan"], lane_id: str) -> str:
    lane = lane_plans.get(str(lane_id or ""))
    return str(getattr(lane, "helper_id", "") or "") if lane is not None else ""


def _certificate_matches_context(cert: HelperExecutionCertificate, context: HelperDispatchContext) -> bool:
    return (
        str(cert.chain_id or "") == str(context.chain_id or "")
        and int(cert.block_height) == int(context.block_height)
        and int(cert.view) == int(context.view)
        and str(cert.leader_id or "") == str(context.leader_id or "")
        and int(cert.validator_epoch) == int(context.validator_epoch)
        and str(cert.validator_set_hash or "") == str(context.validator_set_hash or "")
    )


@dataclass(frozen=True, slots=True)
class HelperLaneResolution:
    lane_id: str
    helper_id: str
    mode: str
    certificate: HelperExecutionCertificate | None = None


class HelperProposalOrchestrator:
    def __init__(
        self,
        *,
        context: HelperDispatchContext,
        lane_plans: tuple[LanePlan, ...],
        helper_pubkeys: dict[str, str] | None = None,
        journal: HelperLaneJournal | None = None,
        helper_timeout_ms: int = 5000,
    ) -> None:
        computed_plan_id = str(context.plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))
        if computed_plan_id and computed_plan_id != str(context.plan_id or ""):
            context = replace(context, plan_id=computed_plan_id)
        self.context = context
        self.plan_id = computed_plan_id
        self.lane_plans = {plan.lane_id: plan for plan in lane_plans}
        self.journal = journal
        if self.journal is not None:
            lanes = [
                {
                    "lane_id": str(plan.lane_id),
                    "helper_id": str(plan.helper_id or ""),
                    "tx_ids": list(plan.tx_ids),
                }
                for plan in tuple(lane_plans or ())
            ]
            self.journal.append_plan(plan_id=self.plan_id, lanes=lanes)
        self.store = HelperCertificateStore(
            context=context,
            lane_plans=lane_plans,
            helper_pubkeys=helper_pubkeys,
            journal=journal,
            helper_timeout_ms=helper_timeout_ms,
        )
        self._resolutions: dict[str, HelperLaneResolution] = {}
        if self.journal is not None:
            self._recover_from_journal()

    def _recover_from_journal(self) -> None:
        state = self.journal.load_resolution_state()
        journal_plan_id = str(state.get("plan_id") or "")
        if journal_plan_id and self.plan_id and journal_plan_id != self.plan_id:
            return
        for record in self.journal.load():
            kind = str(record.get("kind") or "")
            if kind == "helper_finalized":
                cert_obj = record.get("certificate")
                if not isinstance(cert_obj, dict):
                    continue
                try:
                    cert_obj = dict(cert_obj)
                    tx_ids = cert_obj.get("tx_ids")
                    if isinstance(tx_ids, list):
                        cert_obj["tx_ids"] = tuple(str(x) for x in tx_ids)
                    cert = HelperExecutionCertificate(**cert_obj)
                except Exception:
                    continue
                if self.plan_id and str(getattr(cert, "plan_id", "") or "") not in {"", self.plan_id}:
                    continue
                if not _certificate_matches_context(cert, self.context):
                    continue
                lane_id = str(record.get("lane_id") or cert.lane_id or "")
                helper_id = str(record.get("helper_id") or cert.helper_id or "")
                if not lane_id or lane_id not in self.lane_plans:
                    continue
                expected_helper_id = _expected_helper_id_for_lane(self.lane_plans, lane_id)
                if expected_helper_id and helper_id and helper_id != expected_helper_id:
                    continue
                self._resolutions[lane_id] = HelperLaneResolution(
                    lane_id=lane_id,
                    helper_id=helper_id or expected_helper_id,
                    mode="helper",
                    certificate=cert,
                )
            elif kind == "fallback_finalized":
                lane_id = str(record.get("lane_id") or "")
                helper_id = str(record.get("helper_id") or "")
                plan_id = str(record.get("plan_id") or "")
                if self.plan_id and plan_id and plan_id != self.plan_id:
                    continue
                if not lane_id or lane_id not in self.lane_plans:
                    continue
                expected_helper_id = _expected_helper_id_for_lane(self.lane_plans, lane_id)
                if expected_helper_id and helper_id and helper_id != expected_helper_id:
                    continue
                self._resolutions[lane_id] = HelperLaneResolution(
                    lane_id=lane_id,
                    helper_id=helper_id or expected_helper_id,
                    mode="fallback",
                    certificate=None,
                )

    def start_collection(self, *, started_ms: int) -> None:
        for lane_id in sorted(self.lane_plans.keys()):
            if lane_id in self._resolutions:
                continue
            self.store.start_request(lane_id=lane_id, started_ms=started_ms)

    def ingest_certificate(self, *, cert: HelperExecutionCertificate, peer_id: str) -> HelperDispatchStatus:
        lane_id = str(cert.lane_id or "")
        helper_id = str(cert.helper_id or "")

        existing = self._resolutions.get(lane_id)
        if existing is not None:
            return HelperDispatchStatus(False, "lane_already_resolved", lane_id, helper_id)

        status = self.store.ingest_certificate(cert=cert, peer_id=peer_id)
        if status.accepted:
            resolution = HelperLaneResolution(
                lane_id=lane_id,
                helper_id=helper_id,
                mode="helper",
                certificate=cert,
            )
            self._resolutions[lane_id] = resolution
            if self.journal is not None:
                self.journal.append(
                    {
                        "kind": "helper_finalized",
                        "lane_id": lane_id,
                        "helper_id": helper_id,
                        "certificate": cert.to_json(),
                        "plan_id": self.plan_id,
                    }
                )
        return status

    def finalize_timeouts(self, *, now_ms: int) -> tuple[HelperLaneResolution, ...]:
        finalized: list[HelperLaneResolution] = []
        for lane_id in self.store.timed_out_lanes(now_ms=now_ms):
            if lane_id in self._resolutions:
                continue
            self.store.close_request(lane_id=lane_id, reason="timeout")
            lane_plan = self.lane_plans.get(lane_id)
            if lane_plan is None:
                continue
            resolution = HelperLaneResolution(
                lane_id=lane_id,
                helper_id=str(lane_plan.helper_id or ""),
                mode="fallback",
                certificate=None,
            )
            self._resolutions[lane_id] = resolution
            finalized.append(resolution)
            if self.journal is not None:
                self.journal.append_fallback(
                    plan_id=self.plan_id,
                    lane_id=lane_id,
                    helper_id=str(lane_plan.helper_id or ""),
                )
        finalized.sort(key=lambda item: item.lane_id)
        return tuple(finalized)

    def resolution_for_lane(self, lane_id: str) -> HelperLaneResolution | None:
        return self._resolutions.get(str(lane_id or ""))

    def unresolved_lanes(self) -> tuple[str, ...]:
        unresolved = [lane_id for lane_id in self.lane_plans.keys() if lane_id not in self._resolutions]
        unresolved.sort()
        return tuple(unresolved)

    def all_lanes_resolved(self) -> bool:
        return len(self._resolutions) == len(self.lane_plans)

    def finalized_resolutions(self) -> tuple[HelperLaneResolution, ...]:
        items = sorted(self._resolutions.values(), key=lambda item: item.lane_id)
        return tuple(items)
